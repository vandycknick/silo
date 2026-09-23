use std::fmt;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

const VERSION: u64 = 1;
const MAX_ENCODED_LEN: usize = 16_384;
const MAX_HOST_ROOT_LEN: usize = 4_096;
const DIGEST_LEN: usize = 32;
const RESPONSE_LEN: usize = 1_024;
pub(crate) const ROSETTA_MOUNT_TAG: &str = "rosetta";

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

#[derive(Clone, Eq, PartialEq)]
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
            return Err(RosettaConfigError::InvalidIoctlResult);
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

    pub fn encode(&self) -> Result<String, RosettaConfigError> {
        let host_root = self
            .host_root
            .to_str()
            .ok_or(RosettaConfigError::InvalidHostRoot)?;
        let wire = RosettaWire {
            version: VERSION,
            host_root: host_root.to_owned(),
            translator_sha256: encode_hex(&self.translator_sha256),
            ioctl_result: self.ioctl_result,
            data_hex: encode_hex(self.data.as_bytes()),
        };
        let encoded = serde_json::to_string(&wire).map_err(|_| RosettaConfigError::Json)?;
        if encoded.len() > MAX_ENCODED_LEN {
            return Err(RosettaConfigError::EncodedTooLarge);
        }
        Ok(encoded)
    }

    pub fn decode(encoded: &[u8]) -> Result<Self, RosettaConfigError> {
        if encoded.is_empty() {
            return Err(RosettaConfigError::Empty);
        }
        if encoded.len() > MAX_ENCODED_LEN {
            return Err(RosettaConfigError::EncodedTooLarge);
        }
        let encoded_text =
            std::str::from_utf8(encoded).map_err(|_| RosettaConfigError::InvalidUtf8)?;
        if encoded_text
            .bytes()
            .find(|byte| !matches!(byte, b' ' | b'\n' | b'\r' | b'\t'))
            != Some(b'{')
        {
            return Err(RosettaConfigError::Json);
        }

        let wire: RosettaWire =
            serde_json::from_slice(encoded).map_err(|_| RosettaConfigError::Json)?;
        if wire.version != VERSION {
            return Err(RosettaConfigError::InvalidVersion);
        }

        let digest = decode_hex::<DIGEST_LEN>(&wire.translator_sha256)
            .map_err(|_| RosettaConfigError::InvalidDigest)?;
        let data = decode_hex::<RESPONSE_LEN>(&wire.data_hex)
            .map_err(|_| RosettaConfigError::InvalidResponse)?;
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
    #[error("Rosetta configuration is empty")]
    Empty,
    #[error("Rosetta configuration exceeds the encoded size limit")]
    EncodedTooLarge,
    #[error("Rosetta configuration is not UTF-8")]
    InvalidUtf8,
    #[error("Rosetta configuration is not valid JSON")]
    Json,
    #[error("Rosetta configuration has an unsupported version")]
    InvalidVersion,
    #[error("Rosetta configuration has an invalid host root")]
    InvalidHostRoot,
    #[error("Rosetta configuration has an invalid translator digest")]
    InvalidDigest,
    #[error("Rosetta configuration has an invalid ioctl result")]
    InvalidIoctlResult,
    #[error("Rosetta configuration has an invalid captured response")]
    InvalidResponse,
}

fn validate_host_root(host_root: &Path) -> Result<(), RosettaConfigError> {
    let host_root = host_root
        .to_str()
        .ok_or(RosettaConfigError::InvalidHostRoot)?;
    if host_root.is_empty()
        || host_root.len() > MAX_HOST_ROOT_LEN
        || host_root.as_bytes().contains(&0)
        || !Path::new(host_root).is_absolute()
    {
        return Err(RosettaConfigError::InvalidHostRoot);
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
        RosettaConfigError, RosettaLaunchConfig, RosettaProfileId, DIGEST_LEN, MAX_ENCODED_LEN,
        MAX_HOST_ROOT_LEN, RESPONSE_LEN,
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
        serde_json::from_str(&config(1).encode().expect("encode config")).expect("decode JSON")
    }

    fn decode_value(value: &serde_json::Value) -> Result<RosettaLaunchConfig, RosettaConfigError> {
        RosettaLaunchConfig::decode(
            serde_json::to_string(value)
                .expect("encode test JSON")
                .as_bytes(),
        )
    }

    #[test]
    fn round_trips_all_bytes_and_statuses() {
        for status in [0, 1, i32::MAX] {
            let original = config(status);
            let encoded = original.encode().expect("encode config");
            let value: serde_json::Value = serde_json::from_str(&encoded).expect("encoded JSON");
            for (field, expected_len) in [
                ("translator_sha256", DIGEST_LEN * 2),
                ("data_hex", RESPONSE_LEN * 2),
            ] {
                let hex = value[field].as_str().expect("hex string");
                assert_eq!(hex.len(), expected_len);
                assert!(hex.bytes().all(|byte| !byte.is_ascii_uppercase()));
            }

            let decoded = RosettaLaunchConfig::decode(encoded.as_bytes()).expect("decode config");
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
            assert_eq!(decode_value(&value), Err(RosettaConfigError::InvalidDigest));
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
            assert_eq!(
                decode_value(&value),
                Err(RosettaConfigError::InvalidResponse)
            );
        }
    }

    #[test]
    fn validates_strict_schema_and_types() {
        for missing in [
            "version",
            "host_root",
            "translator_sha256",
            "ioctl_result",
            "data_hex",
        ] {
            let mut value = encoded_value();
            value.as_object_mut().expect("object").remove(missing);
            assert_eq!(decode_value(&value), Err(RosettaConfigError::Json));
        }

        let mut unknown = encoded_value();
        unknown["extra"] = serde_json::Value::Bool(true);
        assert_eq!(decode_value(&unknown), Err(RosettaConfigError::Json));

        for field in [
            "version",
            "host_root",
            "translator_sha256",
            "ioctl_result",
            "data_hex",
        ] {
            for invalid in [serde_json::Value::Null, serde_json::Value::Bool(true)] {
                let mut value = encoded_value();
                value[field] = invalid;
                assert!(decode_value(&value).is_err());
            }
        }
    }

    #[test]
    fn rejects_duplicate_fields_and_trailing_values() {
        let encoded = config(1).encode().expect("encode config");
        let duplicate = encoded.replacen('{', "{\"version\":1,", 1);
        assert_eq!(
            RosettaLaunchConfig::decode(duplicate.as_bytes()),
            Err(RosettaConfigError::Json)
        );
        let escaped_duplicate = encoded.replacen('{', "{\"vers\\u0069on\":1,", 1);
        assert_eq!(
            RosettaLaunchConfig::decode(escaped_duplicate.as_bytes()),
            Err(RosettaConfigError::Json)
        );

        for suffix in ["{}", "null", "garbage"] {
            let trailing = format!("{encoded}{suffix}");
            assert_eq!(
                RosettaLaunchConfig::decode(trailing.as_bytes()),
                Err(RosettaConfigError::Json)
            );
        }
        let whitespace = format!("{encoded} \n\r\t");
        assert_eq!(
            RosettaLaunchConfig::decode(whitespace.as_bytes()).expect("trailing whitespace"),
            config(1)
        );
    }

    #[test]
    fn requires_a_top_level_object() {
        let value = encoded_value();
        let ordered_array = serde_json::json!([
            value["version"],
            value["host_root"],
            value["translator_sha256"],
            value["ioctl_result"],
            value["data_hex"],
        ]);
        for encoded in [
            serde_json::to_string(&ordered_array).expect("encode ordered array"),
            "1".to_string(),
            "null".to_string(),
        ] {
            assert_eq!(
                RosettaLaunchConfig::decode(encoded.as_bytes()),
                Err(RosettaConfigError::Json)
            );
        }

        let object = config(1).encode().expect("encode config");
        let leading_whitespace = format!(" \n\r\t{object}");
        assert_eq!(
            RosettaLaunchConfig::decode(leading_whitespace.as_bytes())
                .expect("leading JSON whitespace"),
            config(1)
        );
    }

    #[test]
    fn validates_version_and_integer_result() {
        for version in [serde_json::json!(0), serde_json::json!(2)] {
            let mut value = encoded_value();
            value["version"] = version;
            assert_eq!(
                decode_value(&value),
                Err(RosettaConfigError::InvalidVersion)
            );
        }
        let mut noninteger_version = encoded_value();
        noninteger_version["version"] = serde_json::json!(1.0);
        assert_eq!(
            decode_value(&noninteger_version),
            Err(RosettaConfigError::Json)
        );

        let mut negative_result = encoded_value();
        negative_result["ioctl_result"] = serde_json::json!(-1);
        assert_eq!(
            decode_value(&negative_result),
            Err(RosettaConfigError::InvalidIoctlResult)
        );

        for result in [
            serde_json::json!(2_147_483_648_u64),
            serde_json::json!(1.0),
            serde_json::json!(1.5),
            serde_json::json!("1"),
        ] {
            let mut value = encoded_value();
            value["ioctl_result"] = result;
            assert_eq!(decode_value(&value), Err(RosettaConfigError::Json));
        }

        assert_eq!(
            RosettaLaunchConfig::new(PathBuf::from("/root"), [0; 32], -1, [0; 1024]),
            Err(RosettaConfigError::InvalidIoctlResult)
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
                RosettaLaunchConfig::new(PathBuf::from(invalid), [0; 32], 0, [0; 1024]),
                Err(RosettaConfigError::InvalidHostRoot)
            );
        }

        let maximum = format!("/{}", "a".repeat(MAX_HOST_ROOT_LEN - 1));
        RosettaLaunchConfig::new(PathBuf::from(maximum), [0; 32], 0, [0; 1024])
            .expect("maximum-length host root");

        let path = "/quote\"/slash\\/café";
        let value = RosettaLaunchConfig::new(PathBuf::from(path), [0; 32], 0, [0; 1024])
            .expect("escaped path");
        let encoded = value.encode().expect("encode escaped path");
        assert!(encoded.contains("quote\\\""));
        assert!(encoded.contains("slash\\\\"));
        assert_eq!(
            RosettaLaunchConfig::decode(encoded.as_bytes())
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
            Err(RosettaConfigError::InvalidHostRoot)
        );
    }

    #[test]
    fn enforces_encoded_limit_before_parsing() {
        let encoded = config(1).encode().expect("encode config");
        let exact = format!("{encoded}{}", " ".repeat(MAX_ENCODED_LEN - encoded.len()));
        assert_eq!(exact.len(), MAX_ENCODED_LEN);
        assert_eq!(
            RosettaLaunchConfig::decode(exact.as_bytes()).expect("exact encoded limit"),
            config(1)
        );

        let oversized = format!("{exact} ");
        assert_eq!(
            RosettaLaunchConfig::decode(oversized.as_bytes()),
            Err(RosettaConfigError::EncodedTooLarge)
        );

        let malformed = vec![b'x'; MAX_ENCODED_LEN + 1];
        assert_eq!(
            RosettaLaunchConfig::decode(&malformed),
            Err(RosettaConfigError::EncodedTooLarge)
        );
    }

    #[test]
    fn rejects_writer_output_expanded_past_limit() {
        let path = format!("/{}", "\u{1}".repeat(MAX_HOST_ROOT_LEN - 1));
        let value = RosettaLaunchConfig::new(PathBuf::from(path), [0; 32], 0, [0; 1024])
            .expect("decoded path is within limit");
        assert_eq!(value.encode(), Err(RosettaConfigError::EncodedTooLarge));
    }

    #[test]
    fn rejects_empty_invalid_utf8_and_malformed_json_without_leaking_input() {
        assert_eq!(
            RosettaLaunchConfig::decode(b""),
            Err(RosettaConfigError::Empty)
        );
        assert_eq!(
            RosettaLaunchConfig::decode(&[0xff]),
            Err(RosettaConfigError::InvalidUtf8)
        );
        let encoded = config(1).encode().expect("encode config");
        let invalid_unicode = encoded.replacen("\"/Library/Apple/RosettaLinux\"", "\"\\uD800\"", 1);
        assert_eq!(
            RosettaLaunchConfig::decode(invalid_unicode.as_bytes()),
            Err(RosettaConfigError::Json)
        );
        let malformed_nested = br#"{"version":{"nested":[{"still":"open"}]}"#;
        assert!(malformed_nested.len() < MAX_ENCODED_LEN);
        assert_eq!(
            RosettaLaunchConfig::decode(malformed_nested),
            Err(RosettaConfigError::Json)
        );

        let marker = "PAYLOAD_MUST_NOT_LEAK";
        let error = RosettaLaunchConfig::decode(format!("{{\"{marker}\":").as_bytes())
            .expect_err("malformed JSON");
        assert!(!error.to_string().contains(marker));
        assert!(!format!("{error:?}").contains(marker));
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
