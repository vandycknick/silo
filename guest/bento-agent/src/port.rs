use bento_protocol::parse_agent_port_args;

pub fn from_kernel_cmdline() -> u32 {
    let cmdline = std::fs::read_to_string("/proc/cmdline").unwrap_or_default();
    parse_agent_port_args(cmdline.split_whitespace())
}

#[cfg(test)]
fn parse_control_port(cmdline: &str) -> u32 {
    parse_agent_port_args(cmdline.split_whitespace())
}

#[cfg(test)]
mod tests {
    use super::parse_control_port;
    use bento_protocol::DEFAULT_AGENT_CONTROL_PORT;

    #[test]
    fn parses_control_port_from_kernel_cmdline() {
        assert_eq!(
            parse_control_port("root=/dev/vda bento.agent.port=7001"),
            7001
        );
    }

    #[test]
    fn falls_back_to_default_when_missing() {
        assert_eq!(
            parse_control_port("root=/dev/vda console=hvc0"),
            DEFAULT_AGENT_CONTROL_PORT
        );
    }

    #[test]
    fn falls_back_to_default_on_invalid_value() {
        assert_eq!(
            parse_control_port("root=/dev/vda bento.agent.port=nope"),
            DEFAULT_AGENT_CONTROL_PORT
        );
    }
}
