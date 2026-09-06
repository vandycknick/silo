use std::ffi::OsString;
use std::net::IpAddr;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Config {
    pub(crate) protocol: String,
    pub(crate) host_ip: IpAddr,
    pub(crate) host_port: u16,
    pub(crate) container_ip: IpAddr,
    pub(crate) container_port: u16,
    pub(crate) use_listen_fd: bool,
    pub(crate) proxy_args: Vec<OsString>,
}

pub(crate) fn parse(arguments: impl IntoIterator<Item = OsString>) -> Result<Config, String> {
    let proxy_args = arguments.into_iter().collect::<Vec<_>>();
    let mut protocol = None;
    let mut host_ip = None;
    let mut host_port = None;
    let mut container_ip = None;
    let mut container_port = None;
    let mut use_listen_fd = false;
    let mut index = 0;
    while index < proxy_args.len() {
        let flag = proxy_args[index]
            .to_str()
            .ok_or_else(|| "arguments must be UTF-8".to_string())?;
        if flag == "-use-listen-fd" {
            if use_listen_fd {
                return Err("duplicate flag -use-listen-fd".to_string());
            }
            use_listen_fd = true;
            index += 1;
            continue;
        }
        let destination = match flag {
            "-proto" => &mut protocol,
            "-host-ip" => &mut host_ip,
            "-host-port" => &mut host_port,
            "-container-ip" => &mut container_ip,
            "-container-port" => &mut container_port,
            _ => return Err(format!("unknown flag {flag}")),
        };
        if destination.is_some() {
            return Err(format!("duplicate flag {flag}"));
        }
        let value = proxy_args
            .get(index + 1)
            .ok_or_else(|| format!("missing value for {flag}"))?
            .to_str()
            .ok_or_else(|| format!("value for {flag} must be UTF-8"))?;
        *destination = Some(value.to_string());
        index += 2;
    }

    Ok(Config {
        protocol: required(protocol, "-proto")?,
        host_ip: required(host_ip, "-host-ip")?
            .parse()
            .map_err(|error| format!("invalid -host-ip: {error}"))?,
        host_port: parse_port(required(host_port, "-host-port")?, "-host-port")?,
        container_ip: required(container_ip, "-container-ip")?
            .parse()
            .map_err(|error| format!("invalid -container-ip: {error}"))?,
        container_port: parse_port(
            required(container_port, "-container-port")?,
            "-container-port",
        )?,
        use_listen_fd,
        proxy_args,
    })
}

fn required(value: Option<String>, flag: &str) -> Result<String, String> {
    value.ok_or_else(|| format!("missing required flag {flag}"))
}

fn parse_port(value: String, flag: &str) -> Result<u16, String> {
    let port = value
        .parse::<u16>()
        .map_err(|error| format!("invalid {flag}: {error}"))?;
    if port == 0 {
        return Err(format!("invalid {flag}: port must be greater than zero"));
    }
    Ok(port)
}

#[cfg(test)]
mod tests {
    use std::ffi::OsString;
    use std::net::{IpAddr, Ipv6Addr};

    use crate::args::parse;

    fn arguments(values: &[&str]) -> Vec<OsString> {
        values.iter().map(OsString::from).collect()
    }

    #[test]
    fn parses_moby_arguments_with_and_without_listener_fd() {
        for extra in [Vec::new(), vec!["-use-listen-fd"]] {
            let mut values = vec![
                "-proto",
                "tcp",
                "-host-ip",
                "0.0.0.0",
                "-host-port",
                "8080",
                "-container-ip",
                "172.17.0.2",
                "-container-port",
                "80",
            ];
            values.extend(extra.iter().copied());
            let config = parse(arguments(&values)).expect("parse Moby arguments");
            assert_eq!(config.protocol, "tcp");
            assert_eq!(config.host_port, 8080);
            assert_eq!(config.container_port, 80);
            assert_eq!(config.use_listen_fd, !extra.is_empty());
        }
    }

    #[test]
    fn parses_ipv6_host_address() {
        let config = parse(arguments(&[
            "-proto",
            "tcp",
            "-host-ip",
            "::1",
            "-host-port",
            "8080",
            "-container-ip",
            "fd00::2",
            "-container-port",
            "80",
        ]))
        .expect("parse IPv6 arguments");

        assert_eq!(config.host_ip, IpAddr::V6(Ipv6Addr::LOCALHOST));
    }

    #[test]
    fn rejects_unknown_duplicate_missing_and_invalid_arguments() {
        let base = [
            "-proto",
            "tcp",
            "-host-ip",
            "0.0.0.0",
            "-host-port",
            "8080",
            "-container-ip",
            "172.17.0.2",
            "-container-port",
            "80",
        ];
        for values in [
            vec!["-unknown", "value"],
            vec!["-proto", "tcp", "-proto", "udp"],
            vec!["-proto"],
            vec!["-host-port", "0"],
        ] {
            assert!(parse(arguments(&values)).is_err(), "accepted {values:?}");
        }
        let mut duplicate = base.to_vec();
        duplicate.extend(["-host-port", "8081"]);
        assert!(parse(arguments(&duplicate)).is_err());
    }
}
