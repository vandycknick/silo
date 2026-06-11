use bento_protocol::parse_guest_port_args;

pub fn from_kernel_cmdline() -> u32 {
    let cmdline = std::fs::read_to_string("/proc/cmdline").unwrap_or_default();
    parse_guest_port_args(cmdline.split_whitespace())
}

#[cfg(test)]
fn parse_control_port(cmdline: &str) -> u32 {
    parse_guest_port_args(cmdline.split_whitespace())
}

#[cfg(test)]
mod tests {
    use super::parse_control_port;
    use bento_protocol::DEFAULT_GUEST_CONTROL_PORT;

    #[test]
    fn parses_control_port_from_kernel_cmdline() {
        assert_eq!(
            parse_control_port("root=/dev/vda bento.guest.port=7001"),
            7001
        );
    }

    #[test]
    fn falls_back_to_default_when_missing() {
        assert_eq!(
            parse_control_port("root=/dev/vda console=hvc0"),
            DEFAULT_GUEST_CONTROL_PORT
        );
    }

    #[test]
    fn falls_back_to_default_on_invalid_value() {
        assert_eq!(
            parse_control_port("root=/dev/vda bento.guest.port=nope"),
            DEFAULT_GUEST_CONTROL_PORT
        );
    }
}
