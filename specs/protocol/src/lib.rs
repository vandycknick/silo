pub mod negotiate;
pub mod services;

pub use prost_types;

use std::collections::BTreeMap;

use prost_types::value::Kind;
use prost_types::{ListValue, Struct, Value};

const JSON_MAX_SAFE_INTEGER: i64 = 9_007_199_254_740_991;
const JSON_MIN_SAFE_INTEGER: i64 = -JSON_MAX_SAFE_INTEGER;

pub mod v1 {
    tonic::include_proto!("silo.v1");

    impl StatusUpdate {
        pub fn new(
            source: StatusSource,
            state: LifecycleState,
            message: impl Into<String>,
        ) -> Self {
            Self {
                source: source as i32,
                state: state as i32,
                message: message.into(),
                timestamp_unix_ms: unix_time_ms(),
            }
        }
    }

    fn unix_time_ms() -> i64 {
        match std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
            Ok(duration) => duration.as_millis() as i64,
            Err(_) => 0,
        }
    }
}

pub const DEFAULT_GUEST_CONTROL_PORT: u32 = 1027;
pub const KERNEL_PARAM_GUEST_PORT: &str = "silo.guest.port";

pub fn guest_port_arg(port: u32) -> String {
    format!("{}={port}", KERNEL_PARAM_GUEST_PORT)
}

pub fn parse_guest_port_args<'a>(args: impl IntoIterator<Item = &'a str>) -> u32 {
    for arg in args {
        let Some(raw_port) = arg.strip_prefix(&format!("{}=", KERNEL_PARAM_GUEST_PORT)) else {
            continue;
        };

        let Ok(port) = raw_port.parse::<u32>() else {
            continue;
        };

        if (1..=u32::from(u16::MAX)).contains(&port) {
            return port;
        }
    }

    DEFAULT_GUEST_CONTROL_PORT
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MetadataConfigError {
    TopLevelMustBeObject,
    UnsupportedNumber(String),
    MissingProtobufValueKind,
}

impl std::fmt::Display for MetadataConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TopLevelMustBeObject => write!(f, "metadata config must be a JSON object"),
            Self::UnsupportedNumber(value) => {
                write!(
                    f,
                    "metadata config contains unsupported JSON number {value}"
                )
            }
            Self::MissingProtobufValueKind => {
                write!(f, "metadata config contains protobuf value without a kind")
            }
        }
    }
}

impl std::error::Error for MetadataConfigError {}

pub fn serde_json_to_protobuf_struct(
    value: serde_json::Value,
) -> Result<Struct, MetadataConfigError> {
    let serde_json::Value::Object(fields) = value else {
        return Err(MetadataConfigError::TopLevelMustBeObject);
    };

    fields
        .into_iter()
        .map(|(key, value)| Ok((key, serde_json_to_protobuf_value(value)?)))
        .collect::<Result<BTreeMap<_, _>, _>>()
        .map(|fields| Struct { fields })
}

pub fn protobuf_struct_to_serde_json(
    value: Struct,
) -> Result<serde_json::Value, MetadataConfigError> {
    value
        .fields
        .into_iter()
        .map(|(key, value)| Ok((key, protobuf_value_to_serde_json(value)?)))
        .collect::<Result<serde_json::Map<_, _>, _>>()
        .map(serde_json::Value::Object)
}

fn serde_json_to_protobuf_value(value: serde_json::Value) -> Result<Value, MetadataConfigError> {
    let kind = match value {
        serde_json::Value::Null => Kind::NullValue(0),
        serde_json::Value::Bool(value) => Kind::BoolValue(value),
        serde_json::Value::Number(value) => Kind::NumberValue(json_number_to_protobuf(value)?),
        serde_json::Value::String(value) => Kind::StringValue(value),
        serde_json::Value::Array(values) => Kind::ListValue(ListValue {
            values: values
                .into_iter()
                .map(serde_json_to_protobuf_value)
                .collect::<Result<_, _>>()?,
        }),
        serde_json::Value::Object(fields) => Kind::StructValue(Struct {
            fields: fields
                .into_iter()
                .map(|(key, value)| Ok((key, serde_json_to_protobuf_value(value)?)))
                .collect::<Result<_, _>>()?,
        }),
    };

    Ok(Value { kind: Some(kind) })
}

fn protobuf_value_to_serde_json(value: Value) -> Result<serde_json::Value, MetadataConfigError> {
    let Some(kind) = value.kind else {
        return Err(MetadataConfigError::MissingProtobufValueKind);
    };

    match kind {
        Kind::NullValue(_) => Ok(serde_json::Value::Null),
        Kind::BoolValue(value) => Ok(serde_json::Value::Bool(value)),
        Kind::NumberValue(value) => protobuf_number_to_json(value).map(serde_json::Value::Number),
        Kind::StringValue(value) => Ok(serde_json::Value::String(value)),
        Kind::ListValue(value) => value
            .values
            .into_iter()
            .map(protobuf_value_to_serde_json)
            .collect::<Result<Vec<_>, _>>()
            .map(serde_json::Value::Array),
        Kind::StructValue(value) => protobuf_struct_to_serde_json(value),
    }
}

fn json_number_to_protobuf(value: serde_json::Number) -> Result<f64, MetadataConfigError> {
    let Some(number) = value.as_f64() else {
        return Err(MetadataConfigError::UnsupportedNumber(value.to_string()));
    };
    if !number.is_finite() {
        return Err(MetadataConfigError::UnsupportedNumber(value.to_string()));
    }

    if let Some(integer) = value.as_i64() {
        if !(JSON_MIN_SAFE_INTEGER..=JSON_MAX_SAFE_INTEGER).contains(&integer) {
            return Err(MetadataConfigError::UnsupportedNumber(value.to_string()));
        }
    }
    if let Some(integer) = value.as_u64() {
        if integer > JSON_MAX_SAFE_INTEGER as u64 {
            return Err(MetadataConfigError::UnsupportedNumber(value.to_string()));
        }
    }

    Ok(number)
}

fn protobuf_number_to_json(value: f64) -> Result<serde_json::Number, MetadataConfigError> {
    if !value.is_finite() {
        return Err(MetadataConfigError::UnsupportedNumber(value.to_string()));
    }

    if value.fract() == 0.0
        && value >= JSON_MIN_SAFE_INTEGER as f64
        && value <= JSON_MAX_SAFE_INTEGER as f64
    {
        return Ok(serde_json::Number::from(value as i64));
    }

    serde_json::Number::from_f64(value)
        .ok_or_else(|| MetadataConfigError::UnsupportedNumber(value.to_string()))
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use crate::{
        parse_guest_port_args, protobuf_struct_to_serde_json, serde_json_to_protobuf_struct,
        DEFAULT_GUEST_CONTROL_PORT,
    };

    #[test]
    fn guest_port_args_parse_configured_port() {
        assert_eq!(
            parse_guest_port_args(["root=/dev/vda", "silo.guest.port=7001"]),
            7001
        );
    }

    #[test]
    fn guest_port_args_fall_back_on_missing_or_invalid_port() {
        assert_eq!(
            parse_guest_port_args(["root=/dev/vda"]),
            DEFAULT_GUEST_CONTROL_PORT
        );
        assert_eq!(
            parse_guest_port_args(["root=/dev/vda", "silo.guest.port=nope"]),
            DEFAULT_GUEST_CONTROL_PORT
        );
    }

    #[test]
    fn metadata_config_round_trips_json_struct() {
        let original = json!({
            "forward": {
                "enabled": true,
                "port": 4100,
                "uds": [{ "guest_path": "/var/run/docker.sock" }]
            },
            "provision": {
                "hostname": "demo",
                "resize_rootfs": { "enabled": true },
                "users": [{ "name": "silo", "uid": 1000 }],
                "float": 1.5,
                "nothing": null
            }
        });

        let encoded = serde_json_to_protobuf_struct(original.clone()).expect("encode struct");
        let decoded = protobuf_struct_to_serde_json(encoded).expect("decode struct");

        assert_eq!(decoded, original);
    }

    #[test]
    fn metadata_config_rejects_non_object_top_level() {
        let err = serde_json_to_protobuf_struct(json!(["nope"]))
            .expect_err("top-level array should fail");

        assert_eq!(err.to_string(), "metadata config must be a JSON object");
    }

    #[test]
    fn metadata_config_rejects_integers_outside_exact_f64_range() {
        let err = serde_json_to_protobuf_struct(json!({
            "too_big": 9_007_199_254_740_992_u64
        }))
        .expect_err("unsafe integer should fail");

        assert!(err.to_string().contains("9007199254740992"));
    }
}
