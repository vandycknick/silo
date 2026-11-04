//! Current, bounded root bootstrap and retained guest observation contract.
//! No allocator, host paths, external parser, or compatibility decoder is linked.
#![no_std]

pub mod upper_geometry;

use core::fmt::{self, Write};

pub const MAX_JSON_BYTES: usize = 65536;
pub const BOOTSTRAP_MEMBER: &str = "silo/rootfs.json";
pub const BOOTSTRAP_PATH: &str = "/silo/rootfs.json";
pub const OBSERVATION_PATH: &str = "/run/silo/rootfs/observation.json";
pub const LOWER_MOUNT: &str = "/run/silo/rootfs/lower";
pub const UPPER_MOUNT: &str = "/run/silo/rootfs/upperfs";
pub const OVERLAY_OPTIONS: &str =
    "index=on,metacopy=off,redirect_dir=nofollow,xino=on,nfs_export=off,uuid=null";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    TooLarge,
    BufferTooSmall,
    Syntax,
    UnknownField,
    DuplicateField,
    MissingField,
    InvalidValue,
    Overflow,
    TrailingContent,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::TooLarge => "root JSON exceeds 64 KiB",
            Self::BufferTooSmall => "root JSON output buffer is too small",
            Self::Syntax => "malformed root JSON",
            Self::UnknownField => "unknown root JSON field",
            Self::DuplicateField => "duplicate root JSON field",
            Self::MissingField => "missing root JSON field",
            Self::InvalidValue => "invalid root contract value",
            Self::Overflow => "root JSON integer overflow",
            Self::TrailingContent => "trailing root JSON content",
        })
    }
}

impl core::error::Error for Error {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bootstrap {
    pub root: Root,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Root {
    Raw,
    FlatOverlay(OverlayRoot),
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OverlayRoot {
    pub lower: DeviceExpectation,
    pub upper: DeviceExpectation,
    pub upper_profile: UpperProfile,
    pub overlay_profile: OverlayProfile,
    pub rendering_abi: OverlayRenderingAbi,
    pub temporary_directory: TemporaryDirectory,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeviceExpectation {
    pub serial: RootSerial,
    pub length_bytes: u64,
    pub logical_sector_size: u32,
    pub read_only: bool,
    pub filesystem_uuid: FilesystemUuid,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RootSerial {
    Lower,
    Upper,
}
impl RootSerial {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Lower => "silo-root-lower",
            Self::Upper => "silo-root-upper",
        }
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpperProfile {
    SiloUpperExt4V1,
}
impl UpperProfile {
    pub const fn as_str(self) -> &'static str {
        "silo-upper-ext4-v1"
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OverlayProfile {
    SiloOverlayV1,
}
impl OverlayProfile {
    pub const fn as_str(self) -> &'static str {
        "silo-overlay-v1"
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OverlayRenderingAbi {
    LinuxOverlayfsMountinfoV1,
}
impl OverlayRenderingAbi {
    pub const fn as_str(self) -> &'static str {
        "linux-overlayfs-mountinfo-v1"
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TemporaryDirectory {
    DiskBacked,
    Tmpfs { capacity_bytes: u64 },
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeviceNumber {
    pub major: u32,
    pub minor: u32,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Observation {
    pub root: OverlayRoot,
    pub lower_device: DeviceNumber,
    pub upper_device: DeviceNumber,
    pub upper_filesystem_bytes: u64,
    pub unusable_tail_bytes: u64,
    pub effective_overlay_profile: OverlayProfile,
}

/// Canonical nonzero filesystem UUID, independent of any host UUID package.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FilesystemUuid([u8; 16]);
impl FilesystemUuid {
    pub fn new(bytes: [u8; 16]) -> Result<Self, Error> {
        if bytes == [0; 16] {
            return Err(Error::InvalidValue);
        }
        Ok(Self(bytes))
    }
    pub const fn bytes(self) -> [u8; 16] {
        self.0
    }
    pub fn parse(text: &str) -> Result<Self, Error> {
        let source = text.as_bytes();
        if source.len() != 36 {
            return Err(Error::InvalidValue);
        }
        let mut bytes = [0; 16];
        let mut source_index = 0;
        for (index, byte) in bytes.iter_mut().enumerate() {
            if matches!(index, 4 | 6 | 8 | 10) {
                if source.get(source_index) != Some(&b'-') {
                    return Err(Error::InvalidValue);
                }
                source_index += 1;
            }
            let high = source
                .get(source_index)
                .copied()
                .ok_or(Error::InvalidValue)?;
            let low = source
                .get(source_index + 1)
                .copied()
                .ok_or(Error::InvalidValue)?;
            *byte = hex(high)?.checked_mul(16).ok_or(Error::Overflow)? + hex(low)?;
            source_index += 2;
        }
        Self::new(bytes)
    }
    pub fn write(&self, output: &mut [u8]) -> Result<usize, Error> {
        let mut writer = Writer::new(output);
        writer.uuid(self)?;
        Ok(writer.length)
    }
}
impl fmt::Display for FilesystemUuid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (index, byte) in self.0.iter().enumerate() {
            if matches!(index, 4 | 6 | 8 | 10) {
                f.write_str("-")?;
            }
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}
fn hex(byte: u8) -> Result<u8, Error> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        _ => Err(Error::InvalidValue),
    }
}

impl Bootstrap {
    pub fn validate(&self) -> Result<(), Error> {
        match &self.root {
            Root::Raw => Ok(()),
            Root::FlatOverlay(root) => root.validate(),
        }
    }
}
impl TemporaryDirectory {
    pub fn validate(self) -> Result<(), Error> {
        if let Self::Tmpfs { capacity_bytes } = self {
            if capacity_bytes == 0 || capacity_bytes > 1 << 40 || capacity_bytes % 4096 != 0 {
                return Err(Error::InvalidValue);
            }
        }
        Ok(())
    }
}
impl OverlayRoot {
    pub fn validate(&self) -> Result<(), Error> {
        for device in [&self.lower, &self.upper] {
            if device.length_bytes == 0
                || device.length_bytes > 1 << 40
                || device.length_bytes % 512 != 0
                || device.logical_sector_size != 512
            {
                return Err(Error::InvalidValue);
            }
        }
        if self.lower.serial != RootSerial::Lower
            || self.upper.serial != RootSerial::Upper
            || !self.lower.read_only
            || self.upper.read_only
            || self.lower.filesystem_uuid == self.upper.filesystem_uuid
        {
            return Err(Error::InvalidValue);
        }
        upper_geometry::UpperCapacity::new(self.upper.length_bytes)
            .map_err(|_| Error::InvalidValue)?;
        self.temporary_directory.validate()
    }
}
impl Observation {
    pub fn validate(&self) -> Result<(), Error> {
        self.root.validate()?;
        if self.lower_device == self.upper_device
            || self.upper_filesystem_bytes == 0
            || !self.upper_filesystem_bytes.is_multiple_of(4096)
            || self
                .upper_filesystem_bytes
                .checked_add(self.unusable_tail_bytes)
                != Some(self.root.upper.length_bytes)
            || self.effective_overlay_profile != self.root.overlay_profile
        {
            return Err(Error::InvalidValue);
        }
        Ok(())
    }
}

fn required<T>(value: Option<T>) -> Result<T, Error> {
    value.ok_or(Error::MissingField)
}

struct Parser<'a> {
    input: &'a [u8],
    position: usize,
}
impl<'a> Parser<'a> {
    fn new(input: &'a [u8]) -> Result<Self, Error> {
        if input.len() > MAX_JSON_BYTES {
            return Err(Error::TooLarge);
        }
        Ok(Self { input, position: 0 })
    }
    fn whitespace(&mut self) {
        while self
            .input
            .get(self.position)
            .is_some_and(|byte| matches!(byte, b' ' | b'\n' | b'\r' | b'\t'))
        {
            self.position += 1;
        }
    }
    fn consume(&mut self, byte: u8) -> bool {
        self.whitespace();
        if self.input.get(self.position) == Some(&byte) {
            self.position += 1;
            true
        } else {
            false
        }
    }
    fn expect(&mut self, byte: u8) -> Result<(), Error> {
        if self.consume(byte) {
            Ok(())
        } else {
            Err(Error::Syntax)
        }
    }
    fn string(&mut self) -> Result<&'a str, Error> {
        self.expect(b'"')?;
        let start = self.position;
        while let Some(&byte) = self.input.get(self.position) {
            if byte == b'"' {
                let text = self.input.get(start..self.position).ok_or(Error::Syntax)?;
                self.position += 1;
                return core::str::from_utf8(text).map_err(|_| Error::Syntax);
            }
            // All current strings have a closed canonical ASCII spelling.
            if !(b' '..=b'~').contains(&byte) || byte == b'\\' {
                return Err(Error::Syntax);
            }
            self.position += 1;
        }
        Err(Error::Syntax)
    }
    fn literal(&mut self, expected: &str) -> Result<(), Error> {
        if self.string()? == expected {
            Ok(())
        } else {
            Err(Error::InvalidValue)
        }
    }
    fn uint(&mut self) -> Result<u64, Error> {
        self.whitespace();
        let start = self.position;
        let mut value = 0u64;
        while let Some(&byte @ b'0'..=b'9') = self.input.get(self.position) {
            if self.position > start && self.input.get(start) == Some(&b'0') {
                return Err(Error::Syntax);
            }
            value = value
                .checked_mul(10)
                .and_then(|v| v.checked_add(u64::from(byte - b'0')))
                .ok_or(Error::Overflow)?;
            self.position += 1;
        }
        if self.position == start {
            return Err(Error::Syntax);
        }
        Ok(value)
    }
    fn u32(&mut self) -> Result<u32, Error> {
        self.uint()?.try_into().map_err(|_| Error::Overflow)
    }
    fn boolean(&mut self) -> Result<bool, Error> {
        self.whitespace();
        for (literal, value) in [(b"true".as_slice(), true), (b"false".as_slice(), false)] {
            if self.input.get(self.position..self.position + literal.len()) == Some(literal) {
                self.position += literal.len();
                return Ok(value);
            }
        }
        Err(Error::Syntax)
    }
    fn object(
        &mut self,
        fields: &[&str],
        mut parse: impl FnMut(&mut Self, usize) -> Result<(), Error>,
    ) -> Result<u16, Error> {
        self.expect(b'{')?;
        let mut seen = 0u16;
        if self.consume(b'}') {
            return Ok(seen);
        }
        loop {
            let key = self.string()?;
            let index = fields
                .iter()
                .position(|field| *field == key)
                .ok_or(Error::UnknownField)?;
            let bit = 1u16.checked_shl(index as u32).ok_or(Error::Overflow)?;
            if seen & bit != 0 {
                return Err(Error::DuplicateField);
            }
            seen |= bit;
            self.expect(b':')?;
            parse(self, index)?;
            if self.consume(b'}') {
                return Ok(seen);
            }
            self.expect(b',')?;
        }
    }
    fn finish(&mut self) -> Result<(), Error> {
        self.whitespace();
        if self.position == self.input.len() {
            Ok(())
        } else {
            Err(Error::TrailingContent)
        }
    }
}

fn parse_device(parser: &mut Parser<'_>) -> Result<DeviceExpectation, Error> {
    let (mut serial, mut length, mut sector, mut read_only, mut uuid) =
        (None, None, None, None, None);
    let seen = parser.object(
        &[
            "serial",
            "lengthBytes",
            "logicalSectorSize",
            "readOnly",
            "filesystem",
            "filesystemUuid",
        ],
        |p, field| {
            match field {
                0 => {
                    serial = Some(match p.string()? {
                        "silo-root-lower" => RootSerial::Lower,
                        "silo-root-upper" => RootSerial::Upper,
                        _ => return Err(Error::InvalidValue),
                    })
                }
                1 => length = Some(p.uint()?),
                2 => sector = Some(p.u32()?),
                3 => read_only = Some(p.boolean()?),
                4 => p.literal("ext4")?,
                5 => uuid = Some(FilesystemUuid::parse(p.string()?)?),
                _ => return Err(Error::UnknownField),
            }
            Ok(())
        },
    )?;
    if seen != 63 {
        return Err(Error::MissingField);
    }
    Ok(DeviceExpectation {
        serial: required(serial)?,
        length_bytes: required(length)?,
        logical_sector_size: required(sector)?,
        read_only: required(read_only)?,
        filesystem_uuid: required(uuid)?,
    })
}
fn parse_temporary(parser: &mut Parser<'_>) -> Result<TemporaryDirectory, Error> {
    let (mut kind, mut capacity) = (None, None);
    let seen = parser.object(&["kind", "capacityBytes"], |p, field| {
        match field {
            0 => kind = Some(p.string()?),
            1 => capacity = Some(p.uint()?),
            _ => return Err(Error::UnknownField),
        }
        Ok(())
    })?;
    let result = match (required(kind)?, seen) {
        ("disk-backed", 1) => TemporaryDirectory::DiskBacked,
        ("tmpfs", 3) => TemporaryDirectory::Tmpfs {
            capacity_bytes: required(capacity)?,
        },
        _ => return Err(Error::InvalidValue),
    };
    result.validate()?;
    Ok(result)
}
fn parse_root(parser: &mut Parser<'_>) -> Result<Root, Error> {
    let (mut kind, mut lower, mut upper, mut temporary) = (None, None, None, None);
    let seen = parser.object(
        &[
            "kind",
            "discovery",
            "lower",
            "upper",
            "upperProfile",
            "overlayProfile",
            "temporaryDirectory",
            "renderingAbi",
        ],
        |p, field| {
            match field {
                0 => kind = Some(p.string()?),
                1 => p.literal("virtio-block-serial")?,
                2 => lower = Some(parse_device(p)?),
                3 => upper = Some(parse_device(p)?),
                4 => p.literal("silo-upper-ext4-v1")?,
                5 => p.literal("silo-overlay-v1")?,
                6 => temporary = Some(parse_temporary(p)?),
                7 => p.literal("linux-overlayfs-mountinfo-v1")?,
                _ => return Err(Error::UnknownField),
            }
            Ok(())
        },
    )?;
    match (required(kind)?, seen) {
        ("opaque-raw-v1", 1) => Ok(Root::Raw),
        ("linux-flat-overlay-v1", 255) => {
            let root = OverlayRoot {
                lower: required(lower)?,
                upper: required(upper)?,
                upper_profile: UpperProfile::SiloUpperExt4V1,
                overlay_profile: OverlayProfile::SiloOverlayV1,
                rendering_abi: OverlayRenderingAbi::LinuxOverlayfsMountinfoV1,
                temporary_directory: required(temporary)?,
            };
            root.validate()?;
            Ok(Root::FlatOverlay(root))
        }
        _ => Err(Error::InvalidValue),
    }
}
fn parse_number(parser: &mut Parser<'_>) -> Result<DeviceNumber, Error> {
    let (mut major, mut minor) = (None, None);
    parser.object(&["major", "minor"], |p, field| {
        match field {
            0 => major = Some(p.u32()?),
            1 => minor = Some(p.u32()?),
            _ => return Err(Error::UnknownField),
        }
        Ok(())
    })?;
    Ok(DeviceNumber {
        major: required(major)?,
        minor: required(minor)?,
    })
}

pub fn decode_bootstrap(input: &[u8]) -> Result<Bootstrap, Error> {
    let mut parser = Parser::new(input)?;
    let mut root = None;
    let seen = parser.object(&["schemaVersion", "root"], |p, field| {
        match field {
            0 => {
                if p.uint()? != 1 {
                    return Err(Error::InvalidValue);
                }
            }
            1 => root = Some(parse_root(p)?),
            _ => return Err(Error::UnknownField),
        }
        Ok(())
    })?;
    if seen != 3 {
        return Err(Error::MissingField);
    }
    parser.finish()?;
    let result = Bootstrap {
        root: required(root)?,
    };
    result.validate()?;
    Ok(result)
}
pub fn decode_observation(input: &[u8]) -> Result<Observation, Error> {
    let mut parser = Parser::new(input)?;
    let (mut root, mut lower, mut upper, mut filesystem, mut tail) = (None, None, None, None, None);
    let seen = parser.object(
        &[
            "schemaVersion",
            "root",
            "lowerDevice",
            "upperDevice",
            "upperFilesystemBytes",
            "unusableTailBytes",
            "effectiveOverlayProfile",
        ],
        |p, field| {
            match field {
                0 => {
                    if p.uint()? != 1 {
                        return Err(Error::InvalidValue);
                    }
                }
                1 => {
                    root = Some(match parse_root(p)? {
                        Root::FlatOverlay(root) => root,
                        Root::Raw => return Err(Error::InvalidValue),
                    })
                }
                2 => lower = Some(parse_number(p)?),
                3 => upper = Some(parse_number(p)?),
                4 => filesystem = Some(p.uint()?),
                5 => tail = Some(p.uint()?),
                6 => p.literal("silo-overlay-v1")?,
                _ => return Err(Error::UnknownField),
            }
            Ok(())
        },
    )?;
    if seen != 127 {
        return Err(Error::MissingField);
    }
    parser.finish()?;
    let result = Observation {
        root: required(root)?,
        lower_device: required(lower)?,
        upper_device: required(upper)?,
        upper_filesystem_bytes: required(filesystem)?,
        unusable_tail_bytes: required(tail)?,
        effective_overlay_profile: OverlayProfile::SiloOverlayV1,
    };
    result.validate()?;
    Ok(result)
}

struct Writer<'a> {
    output: &'a mut [u8],
    length: usize,
}
impl<'a> Writer<'a> {
    fn new(output: &'a mut [u8]) -> Self {
        Self { output, length: 0 }
    }
    fn text(&mut self, text: &str) -> Result<(), Error> {
        let end = self.length.checked_add(text.len()).ok_or(Error::Overflow)?;
        if end > MAX_JSON_BYTES {
            return Err(Error::TooLarge);
        }
        self.output
            .get_mut(self.length..end)
            .ok_or(Error::BufferTooSmall)?
            .copy_from_slice(text.as_bytes());
        self.length = end;
        Ok(())
    }
    fn uint(&mut self, value: u64) -> Result<(), Error> {
        write!(self, "{value}").map_err(|_| Error::BufferTooSmall)
    }
    fn uuid(&mut self, value: &FilesystemUuid) -> Result<(), Error> {
        write!(self, "{value}").map_err(|_| Error::BufferTooSmall)
    }
    fn device(&mut self, value: &DeviceExpectation) -> Result<(), Error> {
        self.text("{\"serial\":\"")?;
        self.text(value.serial.as_str())?;
        self.text("\",\"lengthBytes\":")?;
        self.uint(value.length_bytes)?;
        self.text(",\"logicalSectorSize\":")?;
        self.uint(u64::from(value.logical_sector_size))?;
        self.text(",\"readOnly\":")?;
        self.text(if value.read_only { "true" } else { "false" })?;
        self.text(",\"filesystem\":\"ext4\",\"filesystemUuid\":\"")?;
        self.uuid(&value.filesystem_uuid)?;
        self.text("\"}")
    }
    fn root(&mut self, root: &Root) -> Result<(), Error> {
        match root {
            Root::Raw => self.text("{\"kind\":\"opaque-raw-v1\"}"),
            Root::FlatOverlay(root) => self.overlay_root(root),
        }
    }
    fn overlay_root(&mut self, root: &OverlayRoot) -> Result<(), Error> {
        self.text(
            "{\"kind\":\"linux-flat-overlay-v1\",\"discovery\":\"virtio-block-serial\",\"lower\":",
        )?;
        self.device(&root.lower)?;
        self.text(",\"upper\":")?;
        self.device(&root.upper)?;
        self.text(",\"upperProfile\":\"silo-upper-ext4-v1\",\"overlayProfile\":\"silo-overlay-v1\",\"renderingAbi\":\"linux-overlayfs-mountinfo-v1\",\"temporaryDirectory\":")?;
        match root.temporary_directory {
            TemporaryDirectory::DiskBacked => self.text("{\"kind\":\"disk-backed\"}")?,
            TemporaryDirectory::Tmpfs { capacity_bytes } => {
                self.text("{\"kind\":\"tmpfs\",\"capacityBytes\":")?;
                self.uint(capacity_bytes)?;
                self.text("}")?;
            }
        }
        self.text("}")
    }
    fn number(&mut self, number: DeviceNumber) -> Result<(), Error> {
        self.text("{\"major\":")?;
        self.uint(u64::from(number.major))?;
        self.text(",\"minor\":")?;
        self.uint(u64::from(number.minor))?;
        self.text("}")
    }
}
impl Write for Writer<'_> {
    fn write_str(&mut self, value: &str) -> fmt::Result {
        self.text(value).map_err(|_| fmt::Error)
    }
}
/// Encode into caller-owned storage. On error, an already-written prefix may
/// remain in `output`; publish bytes only after a successful returned length.
pub fn encode_bootstrap(value: &Bootstrap, output: &mut [u8]) -> Result<usize, Error> {
    value.validate()?;
    let mut writer = Writer::new(output);
    writer.text("{\"schemaVersion\":1,\"root\":")?;
    writer.root(&value.root)?;
    writer.text("}")?;
    Ok(writer.length)
}
/// Encode into caller-owned storage. On error, an already-written prefix may
/// remain in `output`; publish bytes only after a successful returned length.
pub fn encode_observation(value: &Observation, output: &mut [u8]) -> Result<usize, Error> {
    value.validate()?;
    let mut writer = Writer::new(output);
    writer.text("{\"schemaVersion\":1,\"root\":")?;
    writer.overlay_root(&value.root)?;
    writer.text(",\"lowerDevice\":")?;
    writer.number(value.lower_device)?;
    writer.text(",\"upperDevice\":")?;
    writer.number(value.upper_device)?;
    writer.text(",\"upperFilesystemBytes\":")?;
    writer.uint(value.upper_filesystem_bytes)?;
    writer.text(",\"unusableTailBytes\":")?;
    writer.uint(value.unusable_tail_bytes)?;
    writer.text(",\"effectiveOverlayProfile\":\"silo-overlay-v1\"}")?;
    Ok(writer.length)
}

#[cfg(test)]
extern crate std;

#[cfg(test)]
mod tests {
    use crate::{
        decode_bootstrap, decode_observation, encode_bootstrap, encode_observation, Bootstrap,
        Error, FilesystemUuid, Root, TemporaryDirectory, MAX_JSON_BYTES,
    };
    use std::vec;
    const OVERLAY: &[u8] = include_bytes!("../fixtures/overlay.json");
    const OBSERVATION: &[u8] = include_bytes!("../fixtures/observation.json");
    const RAW: &[u8] = include_bytes!("../fixtures/raw.json");

    #[test]
    fn independent_json_fixtures_round_trip() {
        for input in [RAW, OVERLAY] {
            let value = decode_bootstrap(input).expect("independent bootstrap fixture");
            let mut output = [0; 4096];
            let length = encode_bootstrap(&value, &mut output).unwrap();
            assert_eq!(decode_bootstrap(&output[..length]).unwrap(), value);
        }
        let observation = decode_observation(OBSERVATION).unwrap();
        let mut output = [0; 4096];
        let length = encode_observation(&observation, &mut output).unwrap();
        assert_eq!(decode_observation(&output[..length]).unwrap(), observation);
        assert_eq!(
            observation.root.temporary_directory,
            TemporaryDirectory::DiskBacked
        );
    }

    #[test]
    fn closed_schema_rejects_independent_negative_fixtures() {
        for fixture in [
            include_bytes!("../fixtures/invalid-duplicate.json").as_slice(),
            include_bytes!("../fixtures/invalid-unknown.json"),
            include_bytes!("../fixtures/invalid-old-schema.json"),
            include_bytes!("../fixtures/invalid-integer.json"),
            include_bytes!("../fixtures/invalid-uuid.json"),
        ] {
            assert!(
                decode_bootstrap(fixture).is_err(),
                "accepted {:?}",
                core::str::from_utf8(fixture)
            );
        }
        for fixture in [
            b"".as_slice(),
            b"{}",
            b"[]",
            b"null",
            b"{\"schemaVersion\":01,\"root\":{\"kind\":\"opaque-raw-v1\"}}",
            b"{\"schemaVersion\":1e0,\"root\":{\"kind\":\"opaque-raw-v1\"}}",
            b"{\"schemaVersion\":1,\"root\":{\"kind\":\"opaque-raw-v1\"},}",
            b"{\"schemaVersion\":1,\"root\":{\"kind\":\"opaque-raw-v1\"}}false",
        ] {
            assert!(decode_bootstrap(fixture).is_err());
        }
    }

    #[test]
    fn arbitrary_field_order_and_whitespace_are_valid() {
        assert_eq!(
            decode_bootstrap(
                b" \n{ \"root\" : { \"kind\" : \"opaque-raw-v1\" }, \"schemaVersion\" : 1 }\t"
            )
            .unwrap(),
            Bootstrap { root: Root::Raw }
        );
    }

    #[test]
    fn inclusive_input_bound_and_bounded_output() {
        let mut input = vec![b' '; MAX_JSON_BYTES];
        input[..RAW.len()].copy_from_slice(RAW);
        assert!(decode_bootstrap(&input).is_ok());
        input.push(b' ');
        assert_eq!(decode_bootstrap(&input), Err(Error::TooLarge));
        let value = decode_bootstrap(OVERLAY).unwrap();
        let mut output = [0; 4096];
        let length = encode_bootstrap(&value, &mut output).unwrap();
        assert_eq!(
            encode_bootstrap(&value, &mut output[..length - 1]),
            Err(Error::BufferTooSmall)
        );
        assert_eq!(
            encode_bootstrap(&value, &mut output[..length]).unwrap(),
            length
        );
    }

    #[test]
    fn every_truncation_and_integer_overflow_rejects() {
        for length in 0..OVERLAY.len() - 1 {
            assert!(decode_bootstrap(&OVERLAY[..length]).is_err());
        }
        assert_eq!(
            decode_bootstrap(
                b"{\"schemaVersion\":18446744073709551616,\"root\":{\"kind\":\"opaque-raw-v1\"}}"
            ),
            Err(Error::Overflow)
        );
    }

    #[test]
    fn uuid_requires_canonical_nonzero_bytes() {
        for value in [
            "00000000-0000-0000-0000-000000000000",
            "ABCDEF01-2345-6789-abcd-ef0123456789",
            "123",
            "12345678_1234-1234-1234-123456789abc",
        ] {
            assert!(FilesystemUuid::parse(value).is_err());
        }
        let text = "12345678-1234-1234-1234-123456789abc";
        let uuid = FilesystemUuid::parse(text).unwrap();
        let mut output = [0; 36];
        assert_eq!(uuid.write(&mut output).unwrap(), 36);
        assert_eq!(&output, text.as_bytes());
    }

    #[test]
    fn typed_values_cannot_bypass_geometry_roles_or_accounting() {
        let Root::FlatOverlay(mut root) = decode_bootstrap(OVERLAY).unwrap().root else {
            panic!("overlay fixture");
        };
        root.lower.read_only = false;
        assert!(root.validate().is_err());
        root.lower.read_only = true;
        root.upper.filesystem_uuid = root.lower.filesystem_uuid;
        assert!(root.validate().is_err());
        let mut observation = decode_observation(OBSERVATION).unwrap();
        observation.unusable_tail_bytes += 4096;
        assert!(observation.validate().is_err());
        observation.unusable_tail_bytes -= 4096;
        observation.upper_device = observation.lower_device;
        assert!(observation.validate().is_err());
    }

    #[test]
    fn retained_observation_rejects_truncation_unknown_duplicates_and_trailing_bytes() {
        assert!(
            decode_observation(include_bytes!("../fixtures/invalid-observation-tail.json"))
                .is_err()
        );
        for length in 0..OBSERVATION.len() - 1 {
            assert!(
                decode_observation(&OBSERVATION[..length]).is_err(),
                "{length}"
            );
        }
        for field in [b"\"schemaVersion\":1,".as_slice(), b"\"unknown\":0,"] {
            let mut input = vec![b'{'];
            input.extend_from_slice(field);
            input.extend_from_slice(&OBSERVATION[1..]);
            assert!(decode_observation(&input).is_err());
        }
        let mut trailing = OBSERVATION.to_vec();
        trailing.extend_from_slice(b"{}");
        assert_eq!(decode_observation(&trailing), Err(Error::TrailingContent));
        let observation = decode_observation(OBSERVATION).unwrap();
        assert_eq!(
            encode_observation(&observation, &mut [0; 1]),
            Err(Error::BufferTooSmall)
        );
    }

    fn replace_once(input: &[u8], before: &str, after: &str) -> std::vec::Vec<u8> {
        let text = core::str::from_utf8(input).unwrap();
        assert!(
            text.contains(before),
            "fixture mutation must change actual bytes"
        );
        text.replacen(before, after, 1).into_bytes()
    }

    #[test]
    fn nested_device_and_temporary_objects_reject_raw_duplicate_unknown_and_missing_members() {
        for (before, after) in [
            (
                "\"serial\":\"silo-root-lower\"",
                "\"serial\":\"silo-root-lower\",\"serial\":\"silo-root-lower\"",
            ),
            (
                "\"serial\":\"silo-root-lower\"",
                "\"serial\":\"silo-root-lower\",\"unknown\":0",
            ),
            ("\"serial\":\"silo-root-lower\",", ""),
            (
                "\"logicalSectorSize\":512",
                "\"logicalSectorSize\":512,\"logicalSectorSize\":512",
            ),
            (
                "{\"kind\":\"disk-backed\"}",
                "{\"kind\":\"disk-backed\",\"kind\":\"disk-backed\"}",
            ),
            (
                "{\"kind\":\"disk-backed\"}",
                "{\"kind\":\"disk-backed\",\"unknown\":0}",
            ),
            ("{\"kind\":\"disk-backed\"}", "{\"kind\":\"tmpfs\"}"),
            ("{\"kind\":\"disk-backed\"}", "{\"capacityBytes\":4096}"),
            (
                "{\"kind\":\"disk-backed\"}",
                "{\"kind\":\"tmpfs\",\"capacityBytes\":4096,\"capacityBytes\":4096}",
            ),
            (
                "{\"kind\":\"disk-backed\"}",
                "{\"kind\":\"tmpfs\",\"capacityBytes\":4096,\"unknown\":0}",
            ),
        ] {
            let input = replace_once(OVERLAY, before, after);
            assert!(decode_bootstrap(&input).is_err(), "{after}");
        }
    }

    #[test]
    fn nested_device_numbers_reject_raw_duplicate_unknown_and_missing_members() {
        for after in [
            "{\"major\":254,\"major\":254,\"minor\":0}",
            "{\"major\":254,\"minor\":0,\"unknown\":0}",
            "{\"major\":254}",
            "{\"minor\":0}",
        ] {
            let input = replace_once(OBSERVATION, "{\"major\":254,\"minor\":0}", after);
            assert!(decode_observation(&input).is_err(), "{after}");
        }
    }

    #[test]
    fn device_integer_tokens_and_u32_boundaries_are_strict() {
        let input = replace_once(OBSERVATION, "\"major\":254", "\"major\":4294967295");
        assert_eq!(
            decode_observation(&input).unwrap().lower_device.major,
            u32::MAX
        );
        let input = replace_once(OBSERVATION, "\"major\":254", "\"major\":4294967296");
        assert_eq!(decode_observation(&input), Err(Error::Overflow));
        let input = replace_once(
            OVERLAY,
            "\"logicalSectorSize\":512",
            "\"logicalSectorSize\":4294967295",
        );
        assert_eq!(decode_bootstrap(&input), Err(Error::InvalidValue));
        let input = replace_once(
            OVERLAY,
            "\"logicalSectorSize\":512",
            "\"logicalSectorSize\":4294967296",
        );
        assert_eq!(decode_bootstrap(&input), Err(Error::Overflow));
        for token in [
            "-1", "+512", "512.0", "5.12e2", "0512", "null", "true", "\"512\"",
        ] {
            let replacement = std::format!("\"logicalSectorSize\":{token}");
            assert!(
                decode_bootstrap(&replace_once(
                    OVERLAY,
                    "\"logicalSectorSize\":512",
                    &replacement
                ))
                .is_err(),
                "{token}"
            );
        }
        for token in ["-1", "254.0", "2.54e2", "0254"] {
            let replacement = std::format!("\"major\":{token}");
            assert!(
                decode_observation(&replace_once(OBSERVATION, "\"major\":254", &replacement))
                    .is_err(),
                "{token}"
            );
        }
        let input = replace_once(
            OVERLAY,
            "\"lengthBytes\":268435456",
            "\"lengthBytes\":18446744073709551615",
        );
        assert_eq!(decode_bootstrap(&input), Err(Error::InvalidValue));
        let input = replace_once(
            OVERLAY,
            "\"lengthBytes\":268435456",
            "\"lengthBytes\":18446744073709551616",
        );
        assert_eq!(decode_bootstrap(&input), Err(Error::Overflow));
    }

    fn assert_output_guards(mut encode: impl FnMut(&mut [u8]) -> Result<usize, Error>) {
        let mut reference = [0; 4096];
        let length = encode(&mut reference).unwrap();
        let mut exact = vec![0xa5; length + 2];
        assert_eq!(encode(&mut exact[1..length + 1]).unwrap(), length);
        assert_eq!(&exact[1..length + 1], &reference[..length]);
        assert_eq!((exact[0], exact[length + 1]), (0xa5, 0xa5));
        let mut oversized = vec![0xa5; length + 20];
        assert_eq!(encode(&mut oversized).unwrap(), length);
        assert_eq!(&oversized[..length], &reference[..length]);
        assert!(oversized[length..].iter().all(|byte| *byte == 0xa5));
        let mut short = vec![0xa5; length + 1];
        assert_eq!(encode(&mut short[1..length]), Err(Error::BufferTooSmall));
        assert_eq!((short[0], short[length]), (0xa5, 0xa5));
        assert_eq!(encode(&mut []), Err(Error::BufferTooSmall));
        // The short buffer's interior is deliberately not required to remain
        // unchanged: encoding failure does not promise transactional writes.
    }

    #[test]
    fn both_encoders_respect_exact_fit_and_output_sentinels_in_every_branch() {
        let mut tmpfs = decode_bootstrap(OVERLAY).unwrap();
        let Root::FlatOverlay(root) = &mut tmpfs.root else {
            panic!("overlay");
        };
        root.temporary_directory = TemporaryDirectory::Tmpfs {
            capacity_bytes: 4096,
        };
        for value in [
            decode_bootstrap(RAW).unwrap(),
            decode_bootstrap(OVERLAY).unwrap(),
            tmpfs,
        ] {
            assert_output_guards(|output| encode_bootstrap(&value, output));
        }
        let mut observation = decode_observation(OBSERVATION).unwrap();
        assert_output_guards(|output| encode_observation(&observation, output));
        observation.root.temporary_directory = TemporaryDirectory::Tmpfs {
            capacity_bytes: 4096,
        };
        assert_output_guards(|output| encode_observation(&observation, output));
    }

    #[test]
    fn observation_input_limit_is_inclusive() {
        let mut input = vec![b' '; MAX_JSON_BYTES];
        input[..OBSERVATION.len()].copy_from_slice(OBSERVATION);
        assert!(decode_observation(&input).is_ok());
        input.push(b' ');
        assert_eq!(decode_observation(&input), Err(Error::TooLarge));
    }
}
