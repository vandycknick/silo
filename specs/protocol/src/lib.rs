pub mod negotiate;
pub mod services;

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

#[cfg(test)]
mod tests {
    use crate::{parse_guest_port_args, DEFAULT_GUEST_CONTROL_PORT};

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
}
