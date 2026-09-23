use std::fmt;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

const VERSION: u64 = 1;
const MAX_HOST_ROOT_LEN: usize = 4_096;
const DIGEST_LEN: usize = 32;
const RESPONSE_LEN: usize = 1_024;
pub(crate) const ROSETTA_MOUNT_TAG: &str = "rosetta";

/// Wire shape of [`RosettaLaunchConfig`] inside the worker's `KrunConfig`.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RosettaWire {
    version: u64,
    host_root: String,
    translator_sha256: String,
    ioctl_result: i32,
    data_hex: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RosettaProfileId {
    CapturedCompatibilityV1,
}

#[derive(Clone, Eq, PartialEq)]
pub struct CapturedResponse([u8; RESPONSE_LEN]);

impl CapturedResponse {
    pub fn as_bytes(&self) -> &[u8; RESPONSE_LEN] {
        &self.0
    }
}

impl fmt::Debug for CapturedResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CapturedResponse")
            .field("len", &RESPONSE_LEN)
            .field("data", &"<redacted>")
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(try_from = "RosettaWire", into = "RosettaWire")]
pub struct RosettaLaunchConfig {
    profile: RosettaProfileId,
    host_root: PathBuf,
    translator_sha256: [u8; DIGEST_LEN],
    ioctl_result: i32,
    data: CapturedResponse,
}

impl RosettaLaunchConfig {
    pub fn new(
        host_root: PathBuf,
        translator_sha256: [u8; DIGEST_LEN],
        ioctl_result: i32,
        data: [u8; RESPONSE_LEN],
    ) -> Result<Self, RosettaConfigError> {
        validate_host_root(&host_root)?;
        if ioctl_result < 0 {
            return Err(RosettaConfigError::IoctlResult);
        }

        Ok(Self {
            profile: RosettaProfileId::CapturedCompatibilityV1,
            host_root,
            translator_sha256,
            ioctl_result,
            data: CapturedResponse(data),
        })
    }

    pub fn profile(&self) -> RosettaProfileId {
        self.profile
    }

    pub fn host_root(&self) -> &Path {
        &self.host_root
    }

    pub fn translator_sha256(&self) -> &[u8; DIGEST_LEN] {
        &self.translator_sha256
    }

    pub fn ioctl_result(&self) -> i32 {
        self.ioctl_result
    }

    pub fn data(&self) -> &CapturedResponse {
        &self.data
    }
}

impl From<RosettaLaunchConfig> for RosettaWire {
    fn from(config: RosettaLaunchConfig) -> Self {
        Self {
            version: VERSION,
            // Construction rejects non-UTF-8 roots, so nothing is replaced here.
            host_root: config.host_root.to_string_lossy().into_owned(),
            translator_sha256: encode_hex(&config.translator_sha256),
            ioctl_result: config.ioctl_result,
            data_hex: encode_hex(config.data.as_bytes()),
        }
    }
}

impl TryFrom<RosettaWire> for RosettaLaunchConfig {
    type Error = RosettaConfigError;

    fn try_from(wire: RosettaWire) -> Result<Self, Self::Error> {
        if wire.version != VERSION {
            return Err(RosettaConfigError::Version);
        }
        let digest = decode_hex::<DIGEST_LEN>(&wire.translator_sha256)
            .map_err(|_| RosettaConfigError::Digest)?;
        let data =
            decode_hex::<RESPONSE_LEN>(&wire.data_hex).map_err(|_| RosettaConfigError::Response)?;
        Self::new(
            PathBuf::from(wire.host_root),
            digest,
            wire.ioctl_result,
            data,
        )
    }
}

impl fmt::Debug for RosettaLaunchConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RosettaLaunchConfig")
            .field("profile", &self.profile)
            .field("host_root", &"<redacted>")
            .field("translator_sha256", &"<redacted>")
            .field("ioctl_result", &self.ioctl_result)
            .field("data", &self.data)
            .finish()
    }
}

#[derive(Debug, thiserror::Error, Eq, PartialEq)]
pub enum RosettaConfigError {
    #[error("Rosetta configuration has an unsupported version")]
    Version,
    #[error("Rosetta configuration has an invalid host root")]
    HostRoot,
    #[error("Rosetta configuration has an invalid translator digest")]
    Digest,
    #[error("Rosetta configuration has an invalid ioctl result")]
    IoctlResult,
    #[error("Rosetta configuration has an invalid captured response")]
    Response,
}

fn validate_host_root(host_root: &Path) -> Result<(), RosettaConfigError> {
    let host_root = host_root.to_str().ok_or(RosettaConfigError::HostRoot)?;
    if host_root.is_empty()
        || host_root.len() > MAX_HOST_ROOT_LEN
        || host_root.as_bytes().contains(&0)
        || !Path::new(host_root).is_absolute()
    {
        return Err(RosettaConfigError::HostRoot);
    }
    Ok(())
}

fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    encoded
}

fn decode_hex<const N: usize>(encoded: &str) -> Result<[u8; N], ()> {
    if !encoded.is_ascii() || encoded.len() != N * 2 {
        return Err(());
    }

    let mut decoded = [0; N];
    for (output, pair) in decoded.iter_mut().zip(encoded.as_bytes().chunks_exact(2)) {
        *output = (hex_nibble(pair[0]).ok_or(())? << 4) | hex_nibble(pair[1]).ok_or(())?;
    }
    Ok(decoded)
}

fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use crate::krun::rosetta::{
        RosettaConfigError, RosettaLaunchConfig, RosettaProfileId, DIGEST_LEN, MAX_HOST_ROOT_LEN,
        RESPONSE_LEN,
    };

    fn data_with_every_byte() -> [u8; RESPONSE_LEN] {
        std::array::from_fn(|index| index as u8)
    }

    fn config(ioctl_result: i32) -> RosettaLaunchConfig {
        RosettaLaunchConfig::new(
            PathBuf::from("/Library/Apple/RosettaLinux"),
            std::array::from_fn(|index| index as u8),
            ioctl_result,
            data_with_every_byte(),
        )
        .expect("valid config")
    }

    fn encoded_value() -> serde_json::Value {
        serde_json::to_value(config(1)).expect("encode config")
    }

    fn decode_value(value: &serde_json::Value) -> Result<RosettaLaunchConfig, String> {
        serde_json::from_value(value.clone()).map_err(|error| error.to_string())
    }

    fn rejected_with(value: &serde_json::Value, expected: RosettaConfigError) {
        let error = decode_value(value).expect_err("invalid Rosetta config");
        assert!(error.contains(&expected.to_string()), "{error}");
    }

    #[test]
    fn round_trips_all_bytes_and_statuses() {
        for status in [0, 1, i32::MAX] {
            let original = config(status);
            let value = serde_json::to_value(&original).expect("encode config");
            for (field, expected_len) in [
                ("translator_sha256", DIGEST_LEN * 2),
                ("data_hex", RESPONSE_LEN * 2),
            ] {
                let hex = value[field].as_str().expect("hex string");
                assert_eq!(hex.len(), expected_len);
                assert!(hex.bytes().all(|byte| !byte.is_ascii_uppercase()));
            }

            let decoded = decode_value(&value).expect("decode config");
            assert_eq!(decoded, original);
            assert_eq!(decoded.profile(), RosettaProfileId::CapturedCompatibilityV1);
            assert_eq!(decoded.ioctl_result(), status);
            assert_eq!(decoded.data().as_bytes(), &data_with_every_byte());
            assert_eq!(decoded.translator_sha256().len(), DIGEST_LEN);
        }
    }

    #[test]
    fn accepts_uppercase_hex() {
        let mut value = encoded_value();
        for field in ["translator_sha256", "data_hex"] {
            let uppercase = value[field].as_str().expect("hex string").to_uppercase();
            value[field] = serde_json::Value::String(uppercase);
        }
        assert_eq!(decode_value(&value).expect("uppercase config"), config(1));
    }

    #[test]
    fn rejects_invalid_digest_hex() {
        for invalid in [
            "0".repeat(63),
            "0".repeat(65),
            format!("{}g", "0".repeat(63)),
            format!("0x{}", "0".repeat(62)),
            format!("{} ", "0".repeat(63)),
            "é".repeat(32),
        ] {
            let mut value = encoded_value();
            value["translator_sha256"] = serde_json::Value::String(invalid);
            rejected_with(&value, RosettaConfigError::Digest);
        }
    }

    #[test]
    fn rejects_invalid_response_hex() {
        for invalid in [
            "0".repeat(2047),
            "0".repeat(2049),
            format!("{}z", "0".repeat(2047)),
            format!("0x{}", "0".repeat(2046)),
            format!("{}\n", "0".repeat(2047)),
            format!("{}-0", "0".repeat(2046)),
            "é".repeat(1024),
        ] {
            let mut value = encoded_value();
            value["data_hex"] = serde_json::Value::String(invalid);
            rejected_with(&value, RosettaConfigError::Response);
        }
    }

    #[test]
    fn validates_strict_schema_and_types() {
        for field in [
            "version",
            "host_root",
            "translator_sha256",
            "ioctl_result",
            "data_hex",
        ] {
            let mut value = encoded_value();
            value.as_object_mut().expect("object").remove(field);
            assert!(decode_value(&value).is_err());
            for invalid in [serde_json::Value::Null, serde_json::Value::Bool(true)] {
                let mut value = encoded_value();
                value[field] = invalid;
                assert!(decode_value(&value).is_err());
            }
        }

        let mut unknown = encoded_value();
        unknown["extra"] = serde_json::Value::Bool(true);
        assert!(decode_value(&unknown).is_err());

        let duplicate = serde_json::to_string(&config(1))
            .expect("encode config")
            .replacen('{', "{\"version\":1,", 1);
        assert!(serde_json::from_str::<RosettaLaunchConfig>(&duplicate).is_err());
    }

    #[test]
    fn validates_version_and_integer_result() {
        for version in [serde_json::json!(0), serde_json::json!(2)] {
            let mut value = encoded_value();
            value["version"] = version;
            rejected_with(&value, RosettaConfigError::Version);
        }
        let mut noninteger_version = encoded_value();
        noninteger_version["version"] = serde_json::json!(1.0);
        assert!(decode_value(&noninteger_version).is_err());

        let mut negative_result = encoded_value();
        negative_result["ioctl_result"] = serde_json::json!(-1);
        rejected_with(&negative_result, RosettaConfigError::IoctlResult);

        for result in [
            serde_json::json!(2_147_483_648_u64),
            serde_json::json!(1.0),
            serde_json::json!(1.5),
            serde_json::json!("1"),
        ] {
            let mut value = encoded_value();
            value["ioctl_result"] = result;
            assert!(decode_value(&value).is_err());
        }

        assert_eq!(
            RosettaLaunchConfig::new(PathBuf::from("/root"), [0; 32], -1, [0; 1024]),
            Err(RosettaConfigError::IoctlResult)
        );
    }

    #[test]
    fn validates_host_root() {
        for invalid in [
            String::new(),
            "relative".to_string(),
            "/with\0nul".to_string(),
            format!("/{}", "a".repeat(MAX_HOST_ROOT_LEN)),
        ] {
            assert_eq!(
                RosettaLaunchConfig::new(PathBuf::from(&invalid), [0; 32], 0, [0; 1024]),
                Err(RosettaConfigError::HostRoot)
            );
            let mut value = encoded_value();
            value["host_root"] = serde_json::Value::String(invalid);
            rejected_with(&value, RosettaConfigError::HostRoot);
        }

        let maximum = format!("/{}", "a".repeat(MAX_HOST_ROOT_LEN - 1));
        RosettaLaunchConfig::new(PathBuf::from(maximum), [0; 32], 0, [0; 1024])
            .expect("maximum-length host root");

        let path = "/quote\"/slash\\/café";
        let value = RosettaLaunchConfig::new(PathBuf::from(path), [0; 32], 0, [0; 1024])
            .expect("escaped path");
        let encoded = serde_json::to_string(&value).expect("encode escaped path");
        assert!(encoded.contains("quote\\\""));
        assert!(encoded.contains("slash\\\\"));
        assert_eq!(
            serde_json::from_str::<RosettaLaunchConfig>(&encoded)
                .expect("decode escaped path")
                .host_root(),
            PathBuf::from(path)
        );
    }

    #[cfg(unix)]
    #[test]
    fn rejects_non_utf8_host_root() {
        use std::ffi::OsString;
        use std::os::unix::ffi::OsStringExt;

        let path = PathBuf::from(OsString::from_vec(vec![b'/', 0xff]));
        assert_eq!(
            RosettaLaunchConfig::new(path, [0; 32], 0, [0; 1024]),
            Err(RosettaConfigError::HostRoot)
        );
    }

    #[test]
    fn decode_errors_do_not_leak_input() {
        let marker = "PAYLOAD_MUST_NOT_LEAK";
        let mut value = encoded_value();
        value["translator_sha256"] = serde_json::Value::String(marker.to_string());
        let error = decode_value(&value).expect_err("invalid digest");
        assert!(!error.contains(marker));
    }

    #[test]
    fn debug_redacts_digest_and_response() {
        let value = RosettaLaunchConfig::new(
            PathBuf::from("/root"),
            [0xcd; DIGEST_LEN],
            1,
            [0xab; RESPONSE_LEN],
        )
        .expect("valid config");
        let debug = format!("{value:?}");
        assert!(debug.contains("<redacted>"));
        assert!(!debug.contains("/root"));
        assert!(!debug.contains(&"ab".repeat(RESPONSE_LEN)));
        assert!(!debug.contains(&"cd".repeat(DIGEST_LEN)));
    }
}
