pub const MAGIC: [u8; 8] = *b"SLRSP001";
pub const REQUEST: u32 = 0x8045_6122;
pub const HEADER_LEN: usize = 24;
pub const PAYLOAD_LEN: usize = 1024;
pub const SUCCESS_LEN: usize = HEADER_LEN + PAYLOAD_LEN;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FrameError {
    WrongMagic,
    WrongRequest,
    InvalidResult,
    InvalidErrno,
    InvalidLength,
    Truncated,
    TrailingData,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Header {
    pub result: i32,
    pub errno: i32,
    pub payload_len: usize,
}

impl Header {
    pub fn success(result: i32) -> Result<Self, FrameError> {
        let header = Self {
            result,
            errno: 0,
            payload_len: PAYLOAD_LEN,
        };
        header.validate()?;
        Ok(header)
    }

    pub fn failure(errno: i32) -> Result<Self, FrameError> {
        let header = Self {
            result: -1,
            errno,
            payload_len: 0,
        };
        header.validate()?;
        Ok(header)
    }

    pub fn encode(self) -> Result<[u8; HEADER_LEN], FrameError> {
        self.validate()?;
        let mut bytes = [0u8; HEADER_LEN];
        bytes[0..8].copy_from_slice(&MAGIC);
        bytes[8..12].copy_from_slice(&REQUEST.to_le_bytes());
        bytes[12..16].copy_from_slice(&self.result.to_le_bytes());
        bytes[16..20].copy_from_slice(&self.errno.to_le_bytes());
        bytes[20..24].copy_from_slice(&(self.payload_len as u32).to_le_bytes());
        Ok(bytes)
    }

    fn validate(self) -> Result<(), FrameError> {
        match (self.result, self.errno, self.payload_len) {
            (result, 0, PAYLOAD_LEN) if result >= 0 => Ok(()),
            (-1, errno, 0) if errno > 0 => Ok(()),
            (result, _, _) if result < -1 => Err(FrameError::InvalidResult),
            (-1, errno, _) if errno <= 0 => Err(FrameError::InvalidErrno),
            (result, errno, _) if result >= 0 && errno != 0 => Err(FrameError::InvalidErrno),
            _ => Err(FrameError::InvalidLength),
        }
    }
}

#[derive(Eq, PartialEq)]
pub struct Frame<'a> {
    pub header: Header,
    pub payload: &'a [u8],
}

impl core::fmt::Debug for Frame<'_> {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("Frame")
            .field("header", &self.header)
            .field("payload_len", &self.payload.len())
            .finish()
    }
}

pub struct Decoder {
    header: [u8; HEADER_LEN],
    payload: [u8; PAYLOAD_LEN],
    received: usize,
    expected: Option<usize>,
    error: Option<FrameError>,
}

impl Decoder {
    pub const fn new() -> Self {
        Self {
            header: [0; HEADER_LEN],
            payload: [0; PAYLOAD_LEN],
            received: 0,
            expected: None,
            error: None,
        }
    }

    pub fn push(&mut self, input: &[u8]) -> Result<usize, FrameError> {
        if let Some(error) = self.error {
            return Err(error);
        }
        let expected = self.expected.unwrap_or(SUCCESS_LEN);
        if self.received == expected {
            return if input.is_empty() {
                Ok(0)
            } else {
                self.error = Some(FrameError::TrailingData);
                Err(FrameError::TrailingData)
            };
        }

        let count = core::cmp::min(input.len(), expected - self.received);
        let mut copied = 0;
        if self.received < HEADER_LEN {
            let header_count = core::cmp::min(count, HEADER_LEN - self.received);
            self.header[self.received..self.received + header_count]
                .copy_from_slice(&input[..header_count]);
            self.received += header_count;
            copied += header_count;
            if self.received == HEADER_LEN {
                let header = match decode_header(&self.header) {
                    Ok(header) => header,
                    Err(error) => {
                        self.error = Some(error);
                        return Err(error);
                    }
                };
                self.expected = Some(HEADER_LEN + header.payload_len);
            }
        }

        let expected = self.expected.unwrap_or(SUCCESS_LEN);
        let remaining_input = core::cmp::min(input.len() - copied, expected - self.received);
        if remaining_input > 0 {
            let payload_offset = self.received - HEADER_LEN;
            self.payload[payload_offset..payload_offset + remaining_input]
                .copy_from_slice(&input[copied..copied + remaining_input]);
            self.received += remaining_input;
            copied += remaining_input;
        }

        if copied < input.len() {
            self.error = Some(FrameError::TrailingData);
            return Err(FrameError::TrailingData);
        }
        Ok(copied)
    }

    pub fn finish(&self) -> Result<Frame<'_>, FrameError> {
        if let Some(error) = self.error {
            return Err(error);
        }
        if self.received < HEADER_LEN {
            return Err(FrameError::Truncated);
        }
        let header = decode_header(&self.header)?;
        if self.received != HEADER_LEN + header.payload_len {
            return Err(FrameError::Truncated);
        }
        Ok(Frame {
            header,
            payload: &self.payload[..header.payload_len],
        })
    }
}

impl Default for Decoder {
    fn default() -> Self {
        Self::new()
    }
}

fn decode_header(bytes: &[u8; HEADER_LEN]) -> Result<Header, FrameError> {
    if bytes[0..8] != MAGIC {
        return Err(FrameError::WrongMagic);
    }
    if u32::from_le_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]) != REQUEST {
        return Err(FrameError::WrongRequest);
    }
    let header = Header {
        result: i32::from_le_bytes([bytes[12], bytes[13], bytes[14], bytes[15]]),
        errno: i32::from_le_bytes([bytes[16], bytes[17], bytes[18], bytes[19]]),
        payload_len: u32::from_le_bytes([bytes[20], bytes[21], bytes[22], bytes[23]]) as usize,
    };
    header.validate()?;
    Ok(header)
}

#[cfg(test)]
mod tests {
    extern crate std;

    use crate::frame::{
        Decoder, FrameError, Header, HEADER_LEN, MAGIC, PAYLOAD_LEN, REQUEST, SUCCESS_LEN,
    };
    use std::format;
    use std::vec::Vec;

    fn success(result: i32) -> Vec<u8> {
        let payload = [0xaa; PAYLOAD_LEN];
        let mut frame = Header::success(result).unwrap().encode().unwrap().to_vec();
        frame.extend_from_slice(&payload);
        frame
    }

    #[test]
    fn exact_success_offsets_and_prefill_are_preserved() {
        let frame = success(1);
        assert_eq!(frame.len(), SUCCESS_LEN);
        assert_eq!(&frame[0..8], &MAGIC);
        assert_eq!(&frame[8..12], &REQUEST.to_le_bytes());
        assert_eq!(&frame[12..16], &1i32.to_le_bytes());
        assert_eq!(&frame[16..20], &[0; 4]);
        assert_eq!(&frame[20..24], &(PAYLOAD_LEN as u32).to_le_bytes());
        assert!(frame[HEADER_LEN..].iter().all(|byte| *byte == 0xaa));
    }

    #[test]
    fn exact_failure_offsets_have_no_payload() {
        let frame = Header::failure(25).unwrap().encode().unwrap();
        assert_eq!(frame.len(), HEADER_LEN);
        assert_eq!(&frame[0..8], &MAGIC);
        assert_eq!(&frame[8..12], &REQUEST.to_le_bytes());
        assert_eq!(&frame[12..16], &(-1i32).to_le_bytes());
        assert_eq!(&frame[16..20], &25i32.to_le_bytes());
        assert_eq!(&frame[20..24], &[0; 4]);
    }

    #[test]
    fn debug_redacts_payload_bytes() {
        const MARKER: &[u8] = b"synthetic-capture-marker";

        let mut bytes = success(0);
        bytes[HEADER_LEN..HEADER_LEN + MARKER.len()].copy_from_slice(MARKER);
        let mut decoder = Decoder::new();
        decoder.push(&bytes).unwrap();
        let debug = format!("{:?}", decoder.finish().unwrap());

        assert!(debug.contains("payload_len: 1024"));
        assert!(!debug.contains("synthetic-capture-marker"));
        assert!(!debug.contains("170, 170"));
    }

    #[test]
    fn every_two_part_split_decodes() {
        let frame = success(i32::MAX);
        for split in 0..=frame.len() {
            let mut decoder = Decoder::new();
            assert_eq!(decoder.push(&frame[..split]), Ok(split));
            assert_eq!(decoder.push(&frame[split..]), Ok(frame.len() - split));
            let decoded = decoder.finish().unwrap();
            assert_eq!(decoded.header.result, i32::MAX);
            assert_eq!(decoded.payload, &frame[HEADER_LEN..]);
        }
    }

    #[test]
    fn every_truncation_is_rejected() {
        let frame = success(0);
        for end in 0..frame.len() {
            let mut decoder = Decoder::new();
            let result = decoder.push(&frame[..end]);
            if result.is_ok() {
                assert_eq!(decoder.finish(), Err(FrameError::Truncated), "end={end}");
            }
        }
    }

    #[test]
    fn malformed_header_fields_are_rejected_independently() {
        let valid = Header::success(0).unwrap().encode().unwrap();
        let cases = [
            (0, 0xff, FrameError::WrongMagic),
            (8, valid[8] ^ 1, FrameError::WrongRequest),
            (16, 1, FrameError::InvalidErrno),
            (20, 0xff, FrameError::InvalidLength),
        ];
        for (offset, value, expected) in cases {
            let mut bytes = valid;
            bytes[offset] = value;
            let mut decoder = Decoder::new();
            assert_eq!(decoder.push(&bytes), Err(expected), "offset={offset}");
        }

        let mut invalid_result = valid;
        invalid_result[12..16].copy_from_slice(&(-2i32).to_le_bytes());
        let mut decoder = Decoder::new();
        assert_eq!(
            decoder.push(&invalid_result),
            Err(FrameError::InvalidResult)
        );
        assert_eq!(decoder.finish(), Err(FrameError::InvalidResult));
        assert_eq!(decoder.push(&valid), Err(FrameError::InvalidResult));
    }

    #[test]
    fn every_invalid_status_errno_length_family_is_rejected() {
        let invalid = [
            Header {
                result: -2,
                errno: 1,
                payload_len: 0,
            },
            Header {
                result: -1,
                errno: 0,
                payload_len: 0,
            },
            Header {
                result: -1,
                errno: -1,
                payload_len: 0,
            },
            Header {
                result: -1,
                errno: 1,
                payload_len: PAYLOAD_LEN,
            },
            Header {
                result: 0,
                errno: 1,
                payload_len: PAYLOAD_LEN,
            },
            Header {
                result: 0,
                errno: 0,
                payload_len: 0,
            },
            Header {
                result: 1,
                errno: 0,
                payload_len: PAYLOAD_LEN + 1,
            },
        ];
        for header in invalid {
            assert!(header.encode().is_err(), "header={header:?}");
        }
    }

    #[test]
    fn trailing_and_duplicate_records_are_rejected() {
        let frame = success(0);
        let mut with_trailing = frame.clone();
        with_trailing.push(0);
        let mut decoder = Decoder::new();
        assert_eq!(decoder.push(&with_trailing), Err(FrameError::TrailingData));
        assert_eq!(decoder.finish(), Err(FrameError::TrailingData));

        let mut decoder = Decoder::new();
        assert_eq!(decoder.push(&frame), Ok(frame.len()));
        assert_eq!(decoder.push(&frame), Err(FrameError::TrailingData));
    }

    #[test]
    fn failure_record_decodes_without_payload() {
        let frame = Header::failure(5).unwrap().encode().unwrap();
        let mut decoder = Decoder::new();
        assert_eq!(decoder.push(&frame), Ok(HEADER_LEN));
        let decoded = decoder.finish().unwrap();
        assert_eq!(
            decoded.header,
            Header {
                result: -1,
                errno: 5,
                payload_len: 0
            }
        );
        assert!(decoded.payload.is_empty());
    }
}
