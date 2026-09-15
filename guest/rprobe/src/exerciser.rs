pub const MAGIC: [u8; 8] = *b"SLR2E001";
pub const VERSION: u32 = 1;
pub const HEADER_LEN: usize = 28;
pub const PAYLOAD_LEN: usize = 1024;
pub const FRAME_LEN: usize = HEADER_LEN + PAYLOAD_LEN;

pub const CHECK_READ_ONLY_MOUNT: u32 = 1 << 0;
pub const CHECK_NAMESPACE: u32 = 1 << 1;
pub const CHECK_FILE_IDENTITY: u32 = 1 << 2;
pub const CHECK_REPEATED_READ: u32 = 1 << 3;
pub const CHECK_MMAP_READ: u32 = 1 << 4;
pub const CHECK_WRITE_REJECTED: u32 = 1 << 5;
pub const CHECK_TRUNCATE_REJECTED: u32 = 1 << 6;
pub const CHECK_METADATA_REJECTED: u32 = 1 << 7;
pub const CHECK_RENAME_REJECTED: u32 = 1 << 8;
pub const REQUIRED_CHECKS: u32 = CHECK_READ_ONLY_MOUNT
    | CHECK_NAMESPACE
    | CHECK_FILE_IDENTITY
    | CHECK_REPEATED_READ
    | CHECK_MMAP_READ
    | CHECK_WRITE_REJECTED
    | CHECK_TRUNCATE_REJECTED
    | CHECK_METADATA_REJECTED
    | CHECK_RENAME_REJECTED;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FrameError {
    InvalidVersion,
    InvalidChecks,
    InvalidResult,
    InvalidLength,
    Truncated,
    TrailingData,
}

#[derive(Eq, PartialEq)]
pub struct Frame<'a> {
    pub checks: u32,
    pub ioctl_result: i32,
    pub payload: &'a [u8; PAYLOAD_LEN],
}

impl core::fmt::Debug for Frame<'_> {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("Frame")
            .field("checks", &self.checks)
            .field("ioctl_result", &self.ioctl_result)
            .field("payload_len", &PAYLOAD_LEN)
            .finish()
    }
}

pub fn encode(
    checks: u32,
    ioctl_result: i32,
    payload: &[u8; PAYLOAD_LEN],
) -> Result<[u8; FRAME_LEN], FrameError> {
    validate(checks, ioctl_result, PAYLOAD_LEN)?;
    let mut frame = [0; FRAME_LEN];
    frame[0..8].copy_from_slice(&MAGIC);
    frame[8..12].copy_from_slice(&VERSION.to_le_bytes());
    frame[12..16].copy_from_slice(&checks.to_le_bytes());
    frame[16..20].copy_from_slice(&ioctl_result.to_le_bytes());
    frame[20..24].copy_from_slice(&(PAYLOAD_LEN as u32).to_le_bytes());
    frame[24..28].copy_from_slice(&0u32.to_le_bytes());
    frame[HEADER_LEN..].copy_from_slice(payload);
    Ok(frame)
}

pub struct Decoder {
    frame: [u8; FRAME_LEN],
    received: usize,
    magic_received: usize,
    complete: bool,
}

impl Decoder {
    pub const fn new() -> Self {
        Self {
            frame: [0; FRAME_LEN],
            received: 0,
            magic_received: 0,
            complete: false,
        }
    }

    pub fn push(&mut self, bytes: &[u8]) -> Result<(), FrameError> {
        for (index, byte) in bytes.iter().enumerate() {
            if self.complete {
                return Err(FrameError::TrailingData);
            }
            if self.received == 0 {
                if *byte == MAGIC[self.magic_received] {
                    self.magic_received += 1;
                    if self.magic_received == MAGIC.len() {
                        self.frame[..MAGIC.len()].copy_from_slice(&MAGIC);
                        self.received = MAGIC.len();
                    }
                } else {
                    self.magic_received = usize::from(*byte == MAGIC[0]);
                }
                continue;
            }
            self.frame[self.received] = *byte;
            self.received += 1;
            self.complete = self.received == FRAME_LEN;
            if self.complete && index + 1 != bytes.len() {
                return Err(FrameError::TrailingData);
            }
        }
        Ok(())
    }

    pub const fn is_complete(&self) -> bool {
        self.complete
    }

    pub const fn received_len(&self) -> usize {
        self.received
    }

    pub fn finish(&self) -> Result<Frame<'_>, FrameError> {
        if !self.complete {
            return Err(FrameError::Truncated);
        }
        let version = u32_at(&self.frame, 8);
        if version != VERSION {
            return Err(FrameError::InvalidVersion);
        }
        let checks = u32_at(&self.frame, 12);
        let ioctl_result = i32_at(&self.frame, 16);
        let payload_len = u32_at(&self.frame, 20) as usize;
        if u32_at(&self.frame, 24) != 0 {
            return Err(FrameError::InvalidLength);
        }
        validate(checks, ioctl_result, payload_len)?;
        let payload = self.frame[HEADER_LEN..]
            .try_into()
            .map_err(|_| FrameError::InvalidLength)?;
        Ok(Frame {
            checks,
            ioctl_result,
            payload,
        })
    }
}

impl Default for Decoder {
    fn default() -> Self {
        Self::new()
    }
}

fn validate(checks: u32, ioctl_result: i32, payload_len: usize) -> Result<(), FrameError> {
    if checks != REQUIRED_CHECKS {
        return Err(FrameError::InvalidChecks);
    }
    if ioctl_result < 0 {
        return Err(FrameError::InvalidResult);
    }
    if payload_len != PAYLOAD_LEN {
        return Err(FrameError::InvalidLength);
    }
    Ok(())
}

fn u32_at(bytes: &[u8; FRAME_LEN], offset: usize) -> u32 {
    u32::from_le_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
    ])
}

fn i32_at(bytes: &[u8; FRAME_LEN], offset: usize) -> i32 {
    i32::from_le_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
    ])
}

#[cfg(test)]
mod tests {
    use crate::exerciser::{encode, Decoder, FrameError, MAGIC, PAYLOAD_LEN, REQUIRED_CHECKS};

    #[test]
    fn frame_round_trips_after_arbitrary_console_prefixes_and_splits() {
        let payload = core::array::from_fn(|index| index as u8);
        let frame = encode(REQUIRED_CHECKS, 1, &payload).unwrap();
        for split in 0..=frame.len() {
            let mut decoder = Decoder::new();
            decoder.push(b"kernel diagnostics\r\nSLR").unwrap();
            decoder.push(&frame[..split]).unwrap();
            decoder.push(&frame[split..]).unwrap();
            let decoded = decoder.finish().unwrap();
            assert_eq!(decoded.checks, REQUIRED_CHECKS);
            assert_eq!(decoded.ioctl_result, 1);
            assert_eq!(decoded.payload, &payload);
        }
    }

    #[test]
    fn frame_rejects_missing_checks_and_trailing_bytes() {
        let payload = [0xaa; PAYLOAD_LEN];
        assert_eq!(
            encode(REQUIRED_CHECKS & !1, 1, &payload),
            Err(FrameError::InvalidChecks)
        );
        let frame = encode(REQUIRED_CHECKS, 1, &payload).unwrap();
        let mut decoder = Decoder::new();
        decoder.push(&frame).unwrap();
        assert_eq!(decoder.push(&[0]), Err(FrameError::TrailingData));

        let mut decoder = Decoder::new();
        let mut frame_with_trailer = frame.to_vec();
        frame_with_trailer.push(0);
        assert_eq!(
            decoder.push(&frame_with_trailer),
            Err(FrameError::TrailingData)
        );
    }

    #[test]
    fn frame_offsets_are_independently_fixed() {
        let payload = [0x5a; PAYLOAD_LEN];
        let frame = encode(REQUIRED_CHECKS, i32::MAX, &payload).unwrap();
        assert_eq!(&frame[0..8], &MAGIC);
        assert_eq!(&frame[8..12], &1u32.to_le_bytes());
        assert_eq!(&frame[12..16], &REQUIRED_CHECKS.to_le_bytes());
        assert_eq!(&frame[16..20], &i32::MAX.to_le_bytes());
        assert_eq!(&frame[20..24], &(PAYLOAD_LEN as u32).to_le_bytes());
        assert_eq!(&frame[24..28], &[0; 4]);
        assert_eq!(&frame[28..], &payload);
    }
}
