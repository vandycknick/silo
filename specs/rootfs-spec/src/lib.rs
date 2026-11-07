//! Current, bounded root bootstrap and retained guest observation contract.
//! No allocator, host paths, external parser, or compatibility decoder is linked.
#![no_std]

pub mod kernel_cmdline;
pub mod rosetta;
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

/// Launch-only trusted-init contract. Every Silo direct boot carries one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bootstrap {
    pub root: Root,
    pub rosetta: RosettaMode,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Root {
    Raw(RawRoot),
    FlatOverlay(OverlayRoot),
}

/// Why init prepares the Rosetta capability. Both enabled modes fail boot when
/// the capability cannot be established; neither is a best-effort request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RosettaMode {
    Disabled,
    /// A native root explicitly or effectively requests foreign-binary support.
    Optional,
    /// The root userspace is foreign and cannot start without translation.
    Required,
}
impl RosettaMode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Disabled => "disabled",
            Self::Optional => "optional",
            Self::Required => "required",
        }
    }
    pub const fn enabled(self) -> bool {
        !matches!(self, Self::Disabled)
    }
}

/// One opaque root attachment; the concrete selector is resolved disk-locally.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RawRoot {
    pub device: RawDeviceExpectation,
    pub selector: RawSelector,
    pub filesystem: RootFilesystem,
}
/// The effective launch attachment, not import-time partition geometry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RawDeviceExpectation {
    pub serial: RawSerial,
    pub length_bytes: u64,
    pub logical_sector_size: u32,
    pub read_only: bool,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RawSerial {
    Root,
}
impl RawSerial {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Root => "silo-root",
        }
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RawSelector {
    /// The attachment itself; requires the absence of a partition table.
    WholeDisk,
    /// Unique partition GUID inside the named attachment's own GPT.
    GptPartition { guid: PartitionGuid },
    /// Original one-based primary MBR slot, never a compacted index.
    MbrPartition { number: MbrPartitionNumber },
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RootFilesystem {
    Ext4,
}
impl RootFilesystem {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Ext4 => "ext4",
        }
    }
}
/// One-based primary MBR slot, 1 through 4.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MbrPartitionNumber(u8);
impl MbrPartitionNumber {
    pub fn new(number: u8) -> Result<Self, Error> {
        if (1..=4).contains(&number) {
            Ok(Self(number))
        } else {
            Err(Error::InvalidValue)
        }
    }
    pub const fn get(self) -> u8 {
        self.0
    }
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
        nonzero(bytes).map(Self)
    }
    pub const fn bytes(self) -> [u8; 16] {
        self.0
    }
    pub fn parse(text: &str) -> Result<Self, Error> {
        Self::new(parse_uuid(text)?)
    }
    pub fn write(&self, output: &mut [u8]) -> Result<usize, Error> {
        let mut writer = Writer::new(output);
        writer.uuid(self)?;
        Ok(writer.length)
    }
}
impl fmt::Display for FilesystemUuid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        format_uuid(&self.0, f)
    }
}

/// Canonical nonzero GPT unique partition GUID. These are RFC 4122 textual
/// byte order (`uuid::Uuid::as_bytes`), not GPT's on-disk mixed-endian bytes;
/// the shared partition parser owns that disk encoding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PartitionGuid([u8; 16]);
impl PartitionGuid {
    pub fn new(bytes: [u8; 16]) -> Result<Self, Error> {
        nonzero(bytes).map(Self)
    }
    pub const fn bytes(self) -> [u8; 16] {
        self.0
    }
    pub fn parse(text: &str) -> Result<Self, Error> {
        Self::new(parse_uuid(text)?)
    }
}
impl fmt::Display for PartitionGuid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        format_uuid(&self.0, f)
    }
}

fn nonzero(bytes: [u8; 16]) -> Result<[u8; 16], Error> {
    if bytes == [0; 16] {
        Err(Error::InvalidValue)
    } else {
        Ok(bytes)
    }
}
/// Lowercase hyphenated canonical spelling only.
fn parse_uuid(text: &str) -> Result<[u8; 16], Error> {
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
    Ok(bytes)
}
fn format_uuid(bytes: &[u8; 16], f: &mut fmt::Formatter<'_>) -> fmt::Result {
    for (index, byte) in bytes.iter().enumerate() {
        if matches!(index, 4 | 6 | 8 | 10) {
            f.write_str("-")?;
        }
        write!(f, "{byte:02x}")?;
    }
    Ok(())
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
            Root::Raw(root) => root.validate(),
            Root::FlatOverlay(root) => root.validate(),
        }
    }
}
/// Shared attachment bound: 512-byte logical sectors, nonempty, at most 1 TiB.
fn validate_attachment(length_bytes: u64, logical_sector_size: u32) -> Result<(), Error> {
    if length_bytes == 0
        || length_bytes > 1 << 40
        || !length_bytes.is_multiple_of(512)
        || logical_sector_size != 512
    {
        return Err(Error::InvalidValue);
    }
    Ok(())
}
impl RawRoot {
    pub fn validate(&self) -> Result<(), Error> {
        validate_attachment(self.device.length_bytes, self.device.logical_sector_size)
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
            validate_attachment(device.length_bytes, device.logical_sector_size)?;
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
fn parse_raw_device(parser: &mut Parser<'_>) -> Result<RawDeviceExpectation, Error> {
    let (mut serial, mut length, mut sector, mut read_only) = (None, None, None, None);
    let seen = parser.object(
        &["serial", "lengthBytes", "logicalSectorSize", "readOnly"],
        |p, field| {
            match field {
                0 => {
                    serial = Some(match p.string()? {
                        "silo-root" => RawSerial::Root,
                        _ => return Err(Error::InvalidValue),
                    })
                }
                1 => length = Some(p.uint()?),
                2 => sector = Some(p.u32()?),
                3 => read_only = Some(p.boolean()?),
                _ => return Err(Error::UnknownField),
            }
            Ok(())
        },
    )?;
    if seen != 15 {
        return Err(Error::MissingField);
    }
    Ok(RawDeviceExpectation {
        serial: required(serial)?,
        length_bytes: required(length)?,
        logical_sector_size: required(sector)?,
        read_only: required(read_only)?,
    })
}
fn parse_selector(parser: &mut Parser<'_>) -> Result<RawSelector, Error> {
    let (mut kind, mut guid, mut number) = (None, None, None);
    let seen = parser.object(&["kind", "guid", "number"], |p, field| {
        match field {
            0 => kind = Some(p.string()?),
            1 => guid = Some(PartitionGuid::parse(p.string()?)?),
            2 => {
                let value = u8::try_from(p.uint()?).map_err(|_| Error::InvalidValue)?;
                number = Some(MbrPartitionNumber::new(value)?);
            }
            _ => return Err(Error::UnknownField),
        }
        Ok(())
    })?;
    match (required(kind)?, seen) {
        ("whole-disk", 1) => Ok(RawSelector::WholeDisk),
        ("gpt-partition", 3) => Ok(RawSelector::GptPartition {
            guid: required(guid)?,
        }),
        ("mbr-partition", 5) => Ok(RawSelector::MbrPartition {
            number: required(number)?,
        }),
        _ => Err(Error::InvalidValue),
    }
}
fn parse_root(parser: &mut Parser<'_>) -> Result<Root, Error> {
    let (mut kind, mut lower, mut upper, mut temporary) = (None, None, None, None);
    let (mut device, mut selector, mut filesystem) = (None, None, None);
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
            "device",
            "selector",
            "filesystem",
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
                8 => device = Some(parse_raw_device(p)?),
                9 => selector = Some(parse_selector(p)?),
                10 => {
                    p.literal(RootFilesystem::Ext4.as_str())?;
                    filesystem = Some(RootFilesystem::Ext4);
                }
                _ => return Err(Error::UnknownField),
            }
            Ok(())
        },
    )?;
    // kind, discovery, device, selector and filesystem; nothing overlay-only.
    const RAW_FIELDS: u16 = 0b111_0000_0011;
    // kind, discovery and the seven overlay members; nothing raw-only.
    const OVERLAY_FIELDS: u16 = 0b000_1111_1111;
    match (required(kind)?, seen) {
        ("opaque-raw-v1", RAW_FIELDS) => {
            let root = RawRoot {
                device: required(device)?,
                selector: required(selector)?,
                filesystem: required(filesystem)?,
            };
            root.validate()?;
            Ok(Root::Raw(root))
        }
        ("linux-flat-overlay-v1", OVERLAY_FIELDS) => {
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

fn parse_rosetta(parser: &mut Parser<'_>) -> Result<RosettaMode, Error> {
    match parser.string()? {
        "disabled" => Ok(RosettaMode::Disabled),
        "optional" => Ok(RosettaMode::Optional),
        "required" => Ok(RosettaMode::Required),
        _ => Err(Error::InvalidValue),
    }
}

/// The only accepted bootstrap schema. Older launch bytes are rejected, never
/// decoded through a compatibility path.
pub const BOOTSTRAP_SCHEMA_VERSION: u64 = 2;

pub fn decode_bootstrap(input: &[u8]) -> Result<Bootstrap, Error> {
    let mut parser = Parser::new(input)?;
    let (mut root, mut rosetta) = (None, None);
    let seen = parser.object(&["schemaVersion", "root", "rosetta"], |p, field| {
        match field {
            0 => {
                if p.uint()? != BOOTSTRAP_SCHEMA_VERSION {
                    return Err(Error::InvalidValue);
                }
            }
            1 => root = Some(parse_root(p)?),
            2 => rosetta = Some(parse_rosetta(p)?),
            _ => return Err(Error::UnknownField),
        }
        Ok(())
    })?;
    if seen != 7 {
        return Err(Error::MissingField);
    }
    parser.finish()?;
    let result = Bootstrap {
        root: required(root)?,
        rosetta: required(rosetta)?,
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
                        Root::Raw(_) => return Err(Error::InvalidValue),
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
    fn uuid(&mut self, value: &impl fmt::Display) -> Result<(), Error> {
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
            Root::Raw(root) => self.raw_root(root),
            Root::FlatOverlay(root) => self.overlay_root(root),
        }
    }
    fn raw_root(&mut self, root: &RawRoot) -> Result<(), Error> {
        self.text("{\"kind\":\"opaque-raw-v1\",\"discovery\":\"virtio-block-serial\",\"device\":{\"serial\":\"")?;
        self.text(root.device.serial.as_str())?;
        self.text("\",\"lengthBytes\":")?;
        self.uint(root.device.length_bytes)?;
        self.text(",\"logicalSectorSize\":")?;
        self.uint(u64::from(root.device.logical_sector_size))?;
        self.text(",\"readOnly\":")?;
        self.text(if root.device.read_only {
            "true"
        } else {
            "false"
        })?;
        self.text("},\"selector\":")?;
        match root.selector {
            RawSelector::WholeDisk => self.text("{\"kind\":\"whole-disk\"}")?,
            RawSelector::GptPartition { guid } => {
                self.text("{\"kind\":\"gpt-partition\",\"guid\":\"")?;
                self.uuid(&guid)?;
                self.text("\"}")?;
            }
            RawSelector::MbrPartition { number } => {
                self.text("{\"kind\":\"mbr-partition\",\"number\":")?;
                self.uint(u64::from(number.get()))?;
                self.text("}")?;
            }
        }
        self.text(",\"filesystem\":\"")?;
        self.text(root.filesystem.as_str())?;
        self.text("\"}")
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
    writer.text("{\"schemaVersion\":")?;
    writer.uint(BOOTSTRAP_SCHEMA_VERSION)?;
    writer.text(",\"root\":")?;
    writer.root(&value.root)?;
    writer.text(",\"rosetta\":\"")?;
    writer.text(value.rosetta.as_str())?;
    writer.text("\"}")?;
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
        Error, FilesystemUuid, MbrPartitionNumber, PartitionGuid, RawDeviceExpectation, RawRoot,
        RawSelector, RawSerial, Root, RootFilesystem, RosettaMode, TemporaryDirectory,
        MAX_JSON_BYTES,
    };
    use std::vec;
    const OVERLAY: &[u8] = include_bytes!("../fixtures/overlay.json");
    const OBSERVATION: &[u8] = include_bytes!("../fixtures/observation.json");
    const RAW: &[u8] = include_bytes!("../fixtures/raw.json");
    const RAW_GPT: &[u8] = include_bytes!("../fixtures/raw-gpt.json");
    const RAW_MBR: &[u8] = include_bytes!("../fixtures/raw-mbr.json");
    const RAW_ROOT: &str = "{\"kind\":\"opaque-raw-v1\",\"discovery\":\"virtio-block-serial\",\"device\":{\"serial\":\"silo-root\",\"lengthBytes\":8589934592,\"logicalSectorSize\":512,\"readOnly\":false},\"selector\":{\"kind\":\"whole-disk\"},\"filesystem\":\"ext4\"}";

    fn whole_disk() -> Bootstrap {
        Bootstrap {
            root: Root::Raw(RawRoot {
                device: RawDeviceExpectation {
                    serial: RawSerial::Root,
                    length_bytes: 8 << 30,
                    logical_sector_size: 512,
                    read_only: false,
                },
                selector: RawSelector::WholeDisk,
                filesystem: RootFilesystem::Ext4,
            }),
            rosetta: RosettaMode::Disabled,
        }
    }

    #[test]
    fn independent_json_fixtures_round_trip() {
        for input in [RAW, RAW_GPT, RAW_MBR, OVERLAY] {
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
    fn raw_fixtures_decode_to_exact_selectors_and_translation_modes() {
        assert_eq!(decode_bootstrap(RAW).unwrap(), whole_disk());
        let gpt = decode_bootstrap(RAW_GPT).unwrap();
        assert_eq!(gpt.rosetta, RosettaMode::Required);
        let Root::Raw(root) = gpt.root else {
            panic!("raw");
        };
        assert_eq!(
            root.selector,
            RawSelector::GptPartition {
                guid: PartitionGuid::new([
                    0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89,
                    0xab, 0xcd, 0xef
                ])
                .unwrap()
            }
        );
        let mbr = decode_bootstrap(RAW_MBR).unwrap();
        assert_eq!(mbr.rosetta, RosettaMode::Optional);
        let Root::Raw(root) = mbr.root else {
            panic!("raw");
        };
        assert_eq!(
            root.selector,
            RawSelector::MbrPartition {
                number: MbrPartitionNumber::new(4).unwrap()
            }
        );
        let overlay = decode_bootstrap(OVERLAY).unwrap();
        assert_eq!(overlay.rosetta, RosettaMode::Disabled);
        assert!(matches!(overlay.root, Root::FlatOverlay(_)));
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
            std::string::String::new(),
            "{}".into(),
            "[]".into(),
            "null".into(),
            std::format!("{{\"schemaVersion\":02,\"root\":{RAW_ROOT},\"rosetta\":\"disabled\"}}"),
            std::format!("{{\"schemaVersion\":2e0,\"root\":{RAW_ROOT},\"rosetta\":\"disabled\"}}"),
            std::format!("{{\"schemaVersion\":2,\"root\":{RAW_ROOT},\"rosetta\":\"disabled\",}}"),
            std::format!(
                "{{\"schemaVersion\":2,\"root\":{RAW_ROOT},\"rosetta\":\"disabled\"}}false"
            ),
        ] {
            assert!(decode_bootstrap(fixture.as_bytes()).is_err(), "{fixture}");
        }
    }

    #[test]
    fn only_schema_two_with_mandatory_translation_mode_is_accepted() {
        let bootstrap = |schema: &str, rosetta: &str| {
            decode_bootstrap(
                std::format!("{{\"schemaVersion\":{schema},\"root\":{RAW_ROOT}{rosetta}}}")
                    .as_bytes(),
            )
        };
        assert_eq!(
            bootstrap("2", ",\"rosetta\":\"disabled\""),
            Ok(whole_disk())
        );
        for schema in ["0", "1", "3"] {
            assert_eq!(
                bootstrap(schema, ",\"rosetta\":\"disabled\""),
                Err(Error::InvalidValue),
                "{schema}"
            );
        }
        assert_eq!(bootstrap("2", ""), Err(Error::MissingField));
        for mode in ["\"enabled\"", "\"Required\"", "true", "null", "\"\""] {
            assert!(
                bootstrap("2", &std::format!(",\"rosetta\":{mode}")).is_err(),
                "{mode}"
            );
        }
        assert_eq!(
            bootstrap("2", ",\"rosetta\":\"disabled\",\"rosetta\":\"disabled\""),
            Err(Error::DuplicateField)
        );
        // The exact schema-1 raw producer output is not a compatible input.
        assert!(
            decode_bootstrap(b"{\"schemaVersion\":1,\"root\":{\"kind\":\"opaque-raw-v1\"}}")
                .is_err()
        );
    }

    #[test]
    fn arbitrary_field_order_and_whitespace_are_valid() {
        assert_eq!(
            decode_bootstrap(
                b" \n{ \"rosetta\" : \"disabled\", \"root\" : { \"filesystem\" : \"ext4\", \"selector\" : { \"kind\" : \"whole-disk\" }, \"device\" : { \"readOnly\" : false, \"logicalSectorSize\" : 512, \"lengthBytes\" : 8589934592, \"serial\" : \"silo-root\" }, \"discovery\" : \"virtio-block-serial\", \"kind\" : \"opaque-raw-v1\" }, \"schemaVersion\" : 2 }\t"
            )
            .unwrap(),
            whole_disk()
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
        for fixture in [OVERLAY, RAW_GPT, RAW_MBR] {
            for length in 0..fixture.len() - 1 {
                assert!(decode_bootstrap(&fixture[..length]).is_err(), "{length}");
            }
        }
        assert_eq!(
            decode_bootstrap(
                std::format!(
                    "{{\"schemaVersion\":18446744073709551616,\"root\":{RAW_ROOT},\"rosetta\":\"disabled\"}}"
                )
                .as_bytes()
            ),
            Err(Error::Overflow)
        );
    }

    #[test]
    fn raw_attachment_selector_and_filesystem_are_closed_and_strict() {
        for (before, after) in [
            // Attachment identity and geometry.
            ("\"serial\":\"silo-root\"", "\"serial\":\"silo-root-lower\""),
            ("\"serial\":\"silo-root\"", "\"serial\":\"silo-root \""),
            ("\"serial\":\"silo-root\"", "\"serial\":\"vda\""),
            ("\"lengthBytes\":8589934592", "\"lengthBytes\":0"),
            ("\"lengthBytes\":8589934592", "\"lengthBytes\":8589934593"),
            ("\"lengthBytes\":8589934592", "\"lengthBytes\":1099511628288"),
            ("\"logicalSectorSize\":512", "\"logicalSectorSize\":4096"),
            ("\"readOnly\":false", "\"readOnly\":0"),
            // Closed device members.
            ("\"readOnly\":false", "\"readOnly\":false,\"readOnly\":false"),
            ("\"readOnly\":false", "\"readOnly\":false,\"filesystemUuid\":\"12345678-1234-4234-8234-123456789abc\""),
            (",\"readOnly\":false", ""),
            // Concrete selector only, never automatic or host-addressed.
            ("{\"kind\":\"whole-disk\"}", "{\"kind\":\"auto\"}"),
            ("{\"kind\":\"whole-disk\"}", "{\"kind\":\"whole-disk\",\"number\":1}"),
            ("{\"kind\":\"whole-disk\"}", "{\"kind\":\"whole-disk\",\"kind\":\"whole-disk\"}"),
            ("{\"kind\":\"whole-disk\"}", "{\"kind\":\"gpt-partition\"}"),
            ("{\"kind\":\"whole-disk\"}", "{\"kind\":\"mbr-partition\"}"),
            ("{\"kind\":\"whole-disk\"}", "{\"kind\":\"gpt-partition\",\"guid\":\"00000000-0000-0000-0000-000000000000\"}"),
            ("{\"kind\":\"whole-disk\"}", "{\"kind\":\"gpt-partition\",\"guid\":\"01234567-89AB-CDEF-0123-456789ABCDEF\"}"),
            ("{\"kind\":\"whole-disk\"}", "{\"kind\":\"gpt-partition\",\"guid\":\"0123456789abcdef0123456789abcdef\"}"),
            ("{\"kind\":\"whole-disk\"}", "{\"kind\":\"gpt-partition\",\"guid\":\"01234567-89ab-cdef-0123-456789abcdef\",\"number\":1}"),
            ("{\"kind\":\"whole-disk\"}", "{\"kind\":\"mbr-partition\",\"number\":0}"),
            ("{\"kind\":\"whole-disk\"}", "{\"kind\":\"mbr-partition\",\"number\":5}"),
            ("{\"kind\":\"whole-disk\"}", "{\"kind\":\"mbr-partition\",\"number\":257}"),
            ("{\"kind\":\"whole-disk\"}", "{\"kind\":\"mbr-partition\",\"number\":\"1\"}"),
            ("{\"kind\":\"whole-disk\"}", "{\"kind\":\"mbr-partition\",\"number\":1,\"guid\":\"01234567-89ab-cdef-0123-456789abcdef\"}"),
            ("{\"kind\":\"whole-disk\"}", "{\"path\":\"/dev/vda1\"}"),
            // Explicit filesystem contract, no auto-detection.
            ("\"filesystem\":\"ext4\"", "\"filesystem\":\"auto\""),
            ("\"filesystem\":\"ext4\"", "\"filesystem\":\"btrfs\""),
            (",\"filesystem\":\"ext4\"", ""),
            // Discovery is mandatory and fixed.
            ("\"discovery\":\"virtio-block-serial\",", ""),
            ("\"discovery\":\"virtio-block-serial\"", "\"discovery\":\"disk-order\""),
            // Raw roots cannot carry overlay members.
            ("\"filesystem\":\"ext4\"", "\"filesystem\":\"ext4\",\"temporaryDirectory\":{\"kind\":\"disk-backed\"}"),
        ] {
            let input = replace_once(RAW, before, after);
            assert!(
                decode_bootstrap(&input).is_err(),
                "{}",
                core::str::from_utf8(&input).unwrap()
            );
        }
        for number in 1..=4u8 {
            let input = replace_once(
                RAW,
                "{\"kind\":\"whole-disk\"}",
                &std::format!("{{\"kind\":\"mbr-partition\",\"number\":{number}}}"),
            );
            let Root::Raw(root) = decode_bootstrap(&input).unwrap().root else {
                panic!("raw");
            };
            assert_eq!(
                root.selector,
                RawSelector::MbrPartition {
                    number: MbrPartitionNumber::new(number).unwrap()
                }
            );
        }
        let read_only = replace_once(RAW, "\"readOnly\":false", "\"readOnly\":true");
        let Root::Raw(root) = decode_bootstrap(&read_only).unwrap().root else {
            panic!("raw");
        };
        assert!(root.device.read_only);
        let maximum = replace_once(
            RAW,
            "\"lengthBytes\":8589934592",
            "\"lengthBytes\":1099511627776",
        );
        assert!(decode_bootstrap(&maximum).is_ok());
    }

    #[test]
    fn overlay_roots_cannot_carry_raw_members() {
        for after in [
            "\"temporaryDirectory\": {\"kind\":\"disk-backed\"},\"filesystem\":\"ext4\"",
            "\"temporaryDirectory\": {\"kind\":\"disk-backed\"},\"selector\":{\"kind\":\"whole-disk\"}",
            "\"temporaryDirectory\": {\"kind\":\"disk-backed\"},\"device\":{\"serial\":\"silo-root\",\"lengthBytes\":512,\"logicalSectorSize\":512,\"readOnly\":false}",
        ] {
            let input = replace_once(
                OVERLAY,
                "\"temporaryDirectory\": {\"kind\":\"disk-backed\"}",
                after,
            );
            assert_eq!(decode_bootstrap(&input), Err(Error::InvalidValue), "{after}");
        }
    }

    #[test]
    fn typed_raw_values_validate_geometry_and_newtype_bounds() {
        assert!(MbrPartitionNumber::new(0).is_err());
        assert!(MbrPartitionNumber::new(5).is_err());
        assert_eq!(MbrPartitionNumber::new(1).unwrap().get(), 1);
        assert!(PartitionGuid::new([0; 16]).is_err());
        for (length, sector) in [(0, 512), (513, 512), ((1 << 40) + 512, 512), (4096, 4096)] {
            let mut value = whole_disk();
            let Root::Raw(root) = &mut value.root else {
                panic!("raw");
            };
            root.device.length_bytes = length;
            root.device.logical_sector_size = sector;
            assert_eq!(value.validate(), Err(Error::InvalidValue));
            assert_eq!(
                encode_bootstrap(&value, &mut [0; 4096]),
                Err(Error::InvalidValue)
            );
        }
    }

    #[test]
    fn partition_guid_text_is_canonical_byte_order() {
        let text = "01234567-89ab-cdef-0123-456789abcdef";
        let guid = PartitionGuid::parse(text).unwrap();
        assert_eq!(
            guid.bytes(),
            [
                0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab,
                0xcd, 0xef
            ]
        );
        assert_eq!(std::format!("{guid}"), text);
        for invalid in [
            "00000000-0000-0000-0000-000000000000",
            "01234567-89AB-cdef-0123-456789abcdef",
            "{01234567-89ab-cdef-0123-456789abcdef}",
            "01234567-89ab-cdef-0123-456789abcde",
        ] {
            assert!(PartitionGuid::parse(invalid).is_err(), "{invalid}");
        }
    }

    #[test]
    fn observation_never_describes_a_raw_root() {
        let raw_root = core::str::from_utf8(RAW).unwrap();
        let start = raw_root.find("{\"kind\"").unwrap();
        let end = raw_root.find(",\"rosetta\"").unwrap();
        let observation = core::str::from_utf8(OBSERVATION).unwrap();
        let root_start = observation.find("\"root\":").unwrap() + "\"root\":".len();
        let root_end = observation.find("\n  },").unwrap() + "\n  }".len();
        let mut mutated = std::string::String::from(&observation[..root_start]);
        mutated.push_str(&raw_root[start..end]);
        mutated.push_str(&observation[root_end..]);
        assert_eq!(
            decode_observation(mutated.as_bytes()),
            Err(Error::InvalidValue)
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
            decode_bootstrap(RAW_GPT).unwrap(),
            decode_bootstrap(RAW_MBR).unwrap(),
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
