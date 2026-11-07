use sha2::{Digest, Sha256};
use std::io::{Cursor, Read, Write};

use crate::changeset::model::ContentDigest;
use crate::vm_artifact::wire::{ChunkEntry, PayloadMediaType, PayloadRef, CHUNK_SIZE};
use crate::vm_artifact::{invalid, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChunkEncoding {
    Raw,
    Zstd,
}

pub struct ChunkEncoder {
    encoding: ChunkEncoding,
    context: Option<zstd::zstd_safe::CCtx<'static>>,
}
#[derive(Debug)]
pub struct EncodedChunk {
    pub entry: ChunkEntry,
    pub bytes: Vec<u8>,
}
impl ChunkEncoder {
    pub fn new(encoding: ChunkEncoding) -> Result<Self> {
        let context = match encoding {
            ChunkEncoding::Raw => None,
            ChunkEncoding::Zstd => Some(
                zstd::zstd_safe::CCtx::try_create()
                    .ok_or_else(|| invalid("zstd context allocation failed"))?,
            ),
        };
        Ok(Self { encoding, context })
    }
    pub fn encode(&mut self, decoded: &[u8]) -> Result<EncodedChunk> {
        let length = decoded.len() as u64;
        if length == 0 || length > CHUNK_SIZE {
            return Err(invalid("encoder chunk length outside bounds"));
        }
        if decoded.iter().all(|byte| *byte == 0) {
            return Ok(EncodedChunk {
                entry: ChunkEntry::Zero { length },
                bytes: Vec::new(),
            });
        }
        let digest = ContentDigest::of_bytes(decoded);
        let mut compressed = Vec::new();
        if self.encoding == ChunkEncoding::Zstd {
            let context = self
                .context
                .as_mut()
                .ok_or_else(|| invalid("missing encoder context"))?;
            context
                .reset(zstd::zstd_safe::ResetDirective::SessionAndParameters)
                .map_err(|code| {
                    invalid(format!(
                        "zstd context reset: {}",
                        zstd::zstd_safe::get_error_name(code)
                    ))
                })?;
            let mut encoder = zstd::stream::write::Encoder::with_context(&mut compressed, context);
            encoder.set_parameter(zstd::zstd_safe::CParameter::CompressionLevel(3))?;
            encoder.set_parameter(zstd::zstd_safe::CParameter::NbWorkers(0))?;
            encoder.include_dictid(false)?;
            encoder.include_contentsize(true)?;
            encoder.include_checksum(true)?;
            encoder.window_log(23)?;
            encoder.long_distance_matching(false)?;
            encoder.set_pledged_src_size(Some(length))?;
            encoder.write_all(decoded)?;
            encoder.finish()?;
        }
        let (bytes, media_type, encoded_digest) =
            if !compressed.is_empty() && compressed.len() < decoded.len() {
                let encoded_digest = ContentDigest::of_bytes(&compressed);
                (compressed, PayloadMediaType::ZstdChunk, encoded_digest)
            } else {
                (decoded.to_vec(), PayloadMediaType::RawChunk, digest)
            };
        let encoded = PayloadRef {
            media_type,
            digest: encoded_digest,
            size: bytes.len() as u64,
        };
        Ok(EncodedChunk {
            entry: ChunkEntry::Data {
                length,
                digest,
                encoded,
            },
            bytes,
        })
    }
}

/// Evidence for one completely verified decoded chunk, not a stream identity.
#[derive(Debug, Clone, Copy)]
pub struct VerifiedChunk {
    length: u64,
    digest: ContentDigest,
    zero: bool,
}
impl VerifiedChunk {
    pub fn length(&self) -> u64 {
        self.length
    }
    pub fn digest(&self) -> ContentDigest {
        self.digest
    }
    pub fn is_zero(&self) -> bool {
        self.zero
    }
}

pub fn decode_chunk(
    entry: &ChunkEntry,
    mut encoded_reader: impl Read,
    mut decoded_sink: impl Write,
) -> Result<VerifiedChunk> {
    entry.validate()?;
    let length = entry.length();
    if matches!(entry, ChunkEntry::Zero { .. }) {
        let mut extra = [0];
        if encoded_reader.read(&mut extra)? != 0 {
            return Err(invalid("zero chunk has encoded bytes"));
        }
        let zeros = [0; 32 * 1024];
        let mut remaining = length;
        let mut hash = Sha256::new();
        while remaining != 0 {
            let count = remaining.min(zeros.len() as u64) as usize;
            hash.update(&zeros[..count]);
            decoded_sink.write_all(&zeros[..count])?;
            remaining -= count as u64;
        }
        let digest = ContentDigest::from_sha256(hash.finalize().into());
        return Ok(VerifiedChunk {
            length,
            digest,
            zero: true,
        });
    }
    let ChunkEntry::Data {
        digest, encoded, ..
    } = entry
    else {
        return Err(invalid("invalid chunk variant"));
    };
    // Encoded bytes are bounded and authenticated before any decompressor sees
    // them. One extra byte detects an overlong body without unbounded reads.
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(encoded.size as usize)
        .map_err(|error| invalid(format!("encoded chunk allocation: {error}")))?;
    bytes.resize(encoded.size as usize, 0);
    encoded_reader.read_exact(&mut bytes)?;
    let mut extra = [0];
    if encoded_reader.read(&mut extra)? != 0 {
        return Err(invalid("encoded chunk exceeds descriptor size"));
    }
    if bytes.len() as u64 != encoded.size || ContentDigest::of_bytes(&bytes) != encoded.digest {
        return Err(invalid("encoded chunk size/SHA256 mismatch"));
    }
    let decoded = match encoded.media_type {
        PayloadMediaType::RawChunk => bytes,
        PayloadMediaType::ZstdChunk => {
            validate_zstd_header(&bytes, length)?;
            let mut decoder =
                zstd::stream::read::Decoder::with_buffer(Cursor::new(bytes.as_slice()))?
                    .single_frame();
            decoder.window_log_max(23)?;
            let mut output = Vec::new();
            output
                .try_reserve_exact(length as usize)
                .map_err(|error| invalid(format!("decoded chunk allocation: {error}")))?;
            output.resize(length as usize, 0);
            decoder.read_exact(&mut output)?;
            let mut extra = [0];
            // Reading through the frame end is required even after all expected
            // output arrived: this consumes and verifies the checksum/footer.
            if decoder.read(&mut extra)? != 0 {
                return Err(invalid("zstd output exceeds chunk length"));
            }
            if decoder.finish().position() != bytes.len() as u64 {
                return Err(invalid("zstd frame has trailing/concatenated bytes"));
            }
            output
        }
        _ => return Err(invalid("nonchunk media in decoder")),
    };
    // Raw encoded verification already established this same byte digest.
    if encoded.media_type != PayloadMediaType::RawChunk
        && ContentDigest::of_bytes(&decoded) != *digest
    {
        return Err(invalid("decoded chunk SHA256 mismatch"));
    }
    if decoded.iter().all(|byte| *byte == 0) {
        return Err(invalid("noncanonical data chunk containing only zeros"));
    }
    decoded_sink.write_all(&decoded)?;
    Ok(VerifiedChunk {
        length,
        digest: *digest,
        zero: false,
    })
}

fn validate_zstd_header(bytes: &[u8], length: u64) -> Result<()> {
    if bytes.get(..4) != Some(&[0x28, 0xb5, 0x2f, 0xfd]) {
        return Err(invalid("expected one ordinary zstd frame"));
    }
    let descriptor = *bytes
        .get(4)
        .ok_or_else(|| invalid("truncated zstd descriptor"))?;
    if descriptor & 0x08 != 0 || descriptor & 0x04 == 0 || descriptor & 0x03 != 0 {
        return Err(invalid("zstd reserved bit/checksum/dictionary profile"));
    }
    let single = descriptor & 0x20 != 0;
    let flag = descriptor >> 6;
    let mut cursor = 5;
    if !single {
        let window = *bytes
            .get(cursor)
            .ok_or_else(|| invalid("truncated zstd window"))?;
        cursor += 1;
        let base = 1_u64 << (10 + (window >> 3));
        let window_size = base + (base / 8) * u64::from(window & 7);
        if window_size > CHUNK_SIZE {
            return Err(invalid("zstd window exceeds chunk size"));
        }
    }
    let fcs_bytes = match flag {
        0 if single => 1,
        0 => return Err(invalid("zstd content size absent")),
        1 => 2,
        2 => 4,
        _ => 8,
    };
    let field = bytes
        .get(cursor..cursor + fcs_bytes)
        .ok_or_else(|| invalid("truncated zstd content size"))?;
    let mut content_size = 0_u64;
    for (index, byte) in field.iter().enumerate() {
        content_size |= u64::from(*byte) << (index * 8);
    }
    if flag == 1 {
        content_size += 256;
    }
    if content_size != length || (single && content_size > CHUNK_SIZE) {
        return Err(invalid("zstd content size differs from chunk"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::changeset::model::ContentDigest;
    use crate::vm_artifact::codec::{decode_chunk, ChunkEncoder, ChunkEncoding};
    use crate::vm_artifact::wire::{ChunkEntry, PayloadMediaType, PayloadRef, CHUNK_SIZE};
    use std::io::{self, Cursor, Write};

    fn entry(bytes: &[u8], decoded: &[u8]) -> ChunkEntry {
        ChunkEntry::Data {
            length: decoded.len() as u64,
            digest: ContentDigest::of_bytes(decoded),
            encoded: PayloadRef {
                media_type: PayloadMediaType::ZstdChunk,
                digest: ContentDigest::of_bytes(bytes),
                size: bytes.len() as u64,
            },
        }
    }
    #[test]
    fn raw_zstd_zero_and_short_tail_round_trip() {
        for encoding in [ChunkEncoding::Raw, ChunkEncoding::Zstd] {
            let mut encoder = ChunkEncoder::new(encoding).unwrap();
            for length in [1, 255, 256, 65_536, CHUNK_SIZE as usize] {
                for byte in [0, 37] {
                    let decoded = vec![byte; length];
                    let encoded = encoder.encode(&decoded).unwrap();
                    let mut output = Vec::new();
                    let verified =
                        decode_chunk(&encoded.entry, Cursor::new(encoded.bytes), &mut output)
                            .unwrap();
                    assert_eq!(verified.length(), length as u64);
                    assert_eq!(verified.digest(), ContentDigest::of_bytes(&decoded));
                    assert_eq!(verified.is_zero(), byte == 0);
                    assert_eq!(output, decoded);
                }
            }
            assert!(encoder.encode(&[]).is_err());
            assert!(encoder.encode(&vec![1; CHUNK_SIZE as usize + 1]).is_err());
        }
    }
    #[test]
    fn incompressible_short_data_falls_back_to_raw() {
        let encoded = ChunkEncoder::new(ChunkEncoding::Zstd)
            .unwrap()
            .encode(&[1, 2, 3])
            .unwrap();
        assert!(matches!(
            encoded.entry,
            ChunkEntry::Data {
                encoded: PayloadRef {
                    media_type: PayloadMediaType::RawChunk,
                    ..
                },
                ..
            }
        ));
    }
    #[test]
    fn authenticated_but_malformed_frames_are_rejected_before_sink() {
        let decoded = vec![73; 65536];
        let valid = ChunkEncoder::new(ChunkEncoding::Zstd)
            .unwrap()
            .encode(&decoded)
            .unwrap()
            .bytes;
        let mut cases = Vec::new();
        let mut bytes = valid.clone();
        bytes.push(0);
        cases.push(bytes);
        let mut bytes = valid.clone();
        bytes.extend_from_slice(&valid);
        cases.push(bytes);
        let mut bytes = valid.clone();
        bytes.pop();
        cases.push(bytes);
        let mut bytes = valid.clone();
        let last = bytes.len() - 1;
        bytes[last] ^= 1;
        cases.push(bytes);
        let mut bytes = valid.clone();
        bytes[4] &= !4;
        cases.push(bytes);
        let mut bytes = valid.clone();
        bytes[4] |= 8;
        cases.push(bytes);
        let mut bytes = valid.clone();
        bytes[4] |= 1;
        cases.push(bytes);
        let mut bytes = vec![0x50, 0x2a, 0x4d, 0x18, 0, 0, 0, 0];
        bytes.extend_from_slice(&valid);
        cases.push(bytes);
        for bytes in cases {
            let mut output = Vec::new();
            assert!(
                decode_chunk(&entry(&bytes, &decoded), Cursor::new(bytes), &mut output).is_err()
            );
            assert!(output.is_empty());
        }
    }
    #[test]
    fn missing_size_and_large_windows_reject() {
        let decoded = vec![73; 65536];
        for (size, checksum, window) in [(false, true, 23), (true, false, 23), (false, true, 24)] {
            let mut encoder = zstd::stream::write::Encoder::new(Vec::new(), 3).unwrap();
            encoder.include_contentsize(size).unwrap();
            encoder.include_checksum(checksum).unwrap();
            encoder.window_log(window).unwrap();
            if size {
                encoder
                    .set_pledged_src_size(Some(decoded.len() as u64))
                    .unwrap();
            }
            encoder.write_all(&decoded).unwrap();
            let bytes = encoder.finish().unwrap();
            assert!(
                decode_chunk(&entry(&bytes, &decoded), Cursor::new(bytes), io::sink()).is_err()
            );
        }
        let bytes = [0x28, 0xb5, 0x2f, 0xfd, 0x84, 0x70, 0, 0, 1, 0];
        assert!(decode_chunk(&entry(&bytes, &decoded), Cursor::new(bytes), io::sink()).is_err());
    }
    #[test]
    fn encoded_decoded_hash_and_zero_normalization_are_independent() {
        let decoded = vec![3; 1000];
        let encoded = ChunkEncoder::new(ChunkEncoding::Zstd)
            .unwrap()
            .encode(&decoded)
            .unwrap();
        let mut wrong = encoded.entry.clone();
        if let ChunkEntry::Data { digest, .. } = &mut wrong {
            *digest = ContentDigest::of_bytes(b"wrong");
        }
        assert!(decode_chunk(&wrong, Cursor::new(&encoded.bytes), io::sink()).is_err());
        let mut bytes = encoded.bytes.clone();
        bytes[0] ^= 1;
        assert!(decode_chunk(&encoded.entry, Cursor::new(bytes), io::sink()).is_err());
        let zero = vec![0; 1000];
        let mut encoder = zstd::stream::write::Encoder::new(Vec::new(), 3).unwrap();
        encoder.include_checksum(true).unwrap();
        encoder.set_pledged_src_size(Some(1000)).unwrap();
        encoder.write_all(&zero).unwrap();
        let bytes = encoder.finish().unwrap();
        assert!(decode_chunk(&entry(&bytes, &zero), Cursor::new(bytes), io::sink()).is_err());
        let raw = ChunkEntry::Data {
            length: 1000,
            digest: ContentDigest::of_bytes(&zero),
            encoded: PayloadRef {
                media_type: PayloadMediaType::RawChunk,
                digest: ContentDigest::of_bytes(&zero),
                size: 1000,
            },
        };
        assert!(decode_chunk(&raw, Cursor::new(zero), io::sink()).is_err());
    }
    #[test]
    fn raw_magic_is_not_sniffed_and_io_errors_propagate() {
        let bytes = vec![0x28, 0xb5, 0x2f, 0xfd];
        let encoded = ChunkEncoder::new(ChunkEncoding::Raw)
            .unwrap()
            .encode(&bytes)
            .unwrap();
        let mut output = Vec::new();
        decode_chunk(&encoded.entry, Cursor::new(&encoded.bytes), &mut output).unwrap();
        assert_eq!(output, bytes);
        struct FailedSink;
        impl Write for FailedSink {
            fn write(&mut self, _: &[u8]) -> io::Result<usize> {
                Err(io::Error::other("sink failed"))
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        assert!(decode_chunk(&encoded.entry, Cursor::new(&encoded.bytes), FailedSink).is_err());
        assert!(decode_chunk(&encoded.entry, Cursor::new([0; 5]), io::sink()).is_err());
    }
    #[test]
    fn unused_header_bit_is_not_reserved_and_fcs_mismatch_is_rejected() {
        let decoded = vec![17; 65536];
        let mut bytes = ChunkEncoder::new(ChunkEncoding::Zstd)
            .unwrap()
            .encode(&decoded)
            .unwrap()
            .bytes;
        bytes[4] |= 0x10;
        let mut output = Vec::new();
        decode_chunk(&entry(&bytes, &decoded), Cursor::new(&bytes), &mut output).unwrap();
        assert_eq!(output, decoded);
        // Independently authenticate a changed header with a wrong content size.
        let single = bytes[4] & 0x20 != 0;
        let size_offset = if single { 5 } else { 6 };
        bytes[size_offset] ^= 1;
        assert!(decode_chunk(&entry(&bytes, &decoded), Cursor::new(&bytes), io::sink()).is_err());
    }
    #[test]
    fn dictionary_references_are_not_satisfied_and_trailing_skippable_is_not_ignored() {
        let dictionary: Vec<_> = (0..65536_u32).flat_map(u32::to_le_bytes).collect();
        let decoded = dictionary[2000..18000].to_vec();
        let mut encoder =
            zstd::stream::write::Encoder::with_dictionary(Vec::new(), 3, &dictionary).unwrap();
        encoder.include_dictid(false).unwrap();
        encoder.include_checksum(true).unwrap();
        encoder
            .set_pledged_src_size(Some(decoded.len() as u64))
            .unwrap();
        encoder.write_all(&decoded).unwrap();
        let bytes = encoder.finish().unwrap();
        assert!(decode_chunk(&entry(&bytes, &decoded), Cursor::new(&bytes), io::sink()).is_err());
        let decoded = vec![7; 65536];
        let mut bytes = ChunkEncoder::new(ChunkEncoding::Zstd)
            .unwrap()
            .encode(&decoded)
            .unwrap()
            .bytes;
        bytes.extend_from_slice(&[0x50, 0x2a, 0x4d, 0x18, 0, 0, 0, 0]);
        assert!(decode_chunk(&entry(&bytes, &decoded), Cursor::new(bytes), io::sink()).is_err());
    }
}
