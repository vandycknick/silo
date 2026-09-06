use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::Path;

use clap::Args;
use libvm::{
    Forward, ForwardAddress, ForwardDirection, ForwardEndpoint, MachineAgentStatus,
    MachineForwardScope, MachineForwardState, MachineForwardStatus,
};

use crate::context::Context;
use crate::guest;
use crate::ui::Table;

#[derive(Debug, Args)]
#[command(
    about = "Open or list forwards for a running VM",
    long_about = "Open a session-scoped forward for a running VM. Use two full endpoints, or HOST-PORT:GUEST-PORT as shorthand for loopback TCP forwarding.",
    after_help = "Examples:\n  silo forward dev 8080:80\n  silo forward dev host:tcp:8080 guest:tcp:80\n  silo forward dev --list"
)]
pub struct Cmd {
    /// Name or ID of the running VM.
    #[arg(value_name = "VM")]
    vm: String,

    /// LISTEN and CONNECT endpoints, or one HOST-PORT:GUEST-PORT shorthand.
    #[arg(
        value_name = "ENDPOINT",
        num_args = 0..=2,
        required_unless_present = "list",
        conflicts_with = "list"
    )]
    endpoints: Vec<String>,

    /// Optional forward name.
    #[arg(long, value_name = "NAME", conflicts_with = "list")]
    name: Option<String>,

    /// List machine- and session-scoped forwards instead of opening one.
    #[arg(long)]
    list: bool,
}

impl Cmd {
    pub async fn run(self, context: &mut Context) -> eyre::Result<()> {
        let forward = if self.list {
            None
        } else {
            let cwd = std::env::current_dir()?;
            Some(parse_forward(&self.endpoints, self.name, &cwd)?)
        };
        let (_reference, machine) = context.machine(Some(&self.vm)).await?;
        let inspect = machine.inspect().await?;
        guest::ensure_running(&inspect)?;
        if self.list {
            return print_forwards(&machine.list_forwards().await?);
        }

        let forward = forward.ok_or_else(|| eyre::eyre!("forward endpoints are required"))?;
        let mut session = machine.open_forward(forward).await?;
        let mut signals = guest::HostSignals::termination()?;
        let mut previous = None;
        loop {
            tokio::select! {
                signal = signals.recv() => match signal {
                    Some(_) => return Ok(()),
                    None => eyre::bail!("host termination signal listeners ended"),
                },
                status = session.next_status() => match status? {
                    Some(status) => {
                        if previous != Some(status.state) {
                            report_status(&machine, &status).await?;
                            previous = Some(status.state);
                        }
                    }
                    None => eyre::bail!("forward ended because the machine monitor stopped"),
                }
            }
        }
    }
}

fn parse_forward(values: &[String], name: Option<String>, cwd: &Path) -> eyre::Result<Forward> {
    let (listen, connect) = match values {
        [shorthand] => parse_shorthand(shorthand)?,
        [listen, connect] => (
            absolutize_host_unix(listen.parse()?, cwd),
            absolutize_host_unix(connect.parse()?, cwd),
        ),
        _ => eyre::bail!(
            "forward requires one HOST-PORT:GUEST-PORT shorthand or exactly two endpoints"
        ),
    };
    let mut forward = Forward::new(listen, connect);
    forward.name = name;
    forward.validate()?;
    Ok(forward)
}

fn parse_shorthand(value: &str) -> eyre::Result<(ForwardEndpoint, ForwardEndpoint)> {
    let Some((host, guest)) = value.split_once(':') else {
        eyre::bail!("forward shorthand must be HOST-PORT:GUEST-PORT");
    };
    let host = parse_bare_port(host)?;
    let guest = parse_bare_port(guest)?;
    let loopback = IpAddr::V4(Ipv4Addr::LOCALHOST);
    Ok((
        ForwardEndpoint::Host(ForwardAddress::Tcp(SocketAddr::new(loopback, host))),
        ForwardEndpoint::Guest(ForwardAddress::Tcp(SocketAddr::new(loopback, guest))),
    ))
}

fn parse_bare_port(value: &str) -> eyre::Result<u16> {
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        eyre::bail!("forward shorthand ports must be bare decimal ports");
    }
    let port = value
        .parse::<u16>()
        .map_err(|_| eyre::eyre!("forward shorthand port {value:?} is outside 0..=65535"))?;
    if port.to_string() != value {
        eyre::bail!("forward shorthand port {value:?} is not canonical decimal");
    }
    Ok(port)
}

fn absolutize_host_unix(endpoint: ForwardEndpoint, cwd: &Path) -> ForwardEndpoint {
    match endpoint {
        ForwardEndpoint::Host(ForwardAddress::Unix(path)) if path.is_relative() => {
            ForwardEndpoint::Host(ForwardAddress::Unix(cwd.join(path)))
        }
        endpoint => endpoint,
    }
}

async fn report_status(
    machine: &libvm::Machine,
    status: &MachineForwardStatus,
) -> eyre::Result<()> {
    match status.state {
        MachineForwardState::Active => {
            let bound = status
                .bound
                .as_ref()
                .ok_or_else(|| eyre::eyre!("active forward did not report its bound endpoint"))?;
            println!(
                "Forwarding {bound} -> {} ({})",
                status.forward.connect,
                direction(status.direction)
            );
            Ok(())
        }
        MachineForwardState::Pending => {
            println!("Forward state: pending");
            Ok(())
        }
        MachineForwardState::Unsupported => {
            let version = machine
                .monitor_status()
                .await
                .ok()
                .and_then(|status| match status.agent {
                    MachineAgentStatus::Enabled(agent) => {
                        agent.identity.map(|identity| identity.version)
                    }
                    MachineAgentStatus::Disabled => None,
                })
                .unwrap_or_else(|| "unknown".to_string());
            eyre::bail!("guest agent {version} does not support forwarding")
        }
        MachineForwardState::Closed => {
            eyre::bail!("forward closed because the machine monitor stopped")
        }
    }
}

fn print_forwards(forwards: &[MachineForwardStatus]) -> eyre::Result<()> {
    let mut table = Table::new([
        "NAME",
        "DIRECTION",
        "SCOPE",
        "STATE",
        "LISTEN",
        "CONNECT",
        "ACTIVE",
        "REFUSED",
    ]);
    for status in forwards {
        table.add_row([
            status
                .forward
                .name
                .clone()
                .unwrap_or_else(|| "-".to_string()),
            direction(status.direction).to_string(),
            scope(status.scope).to_string(),
            state(status.state).to_string(),
            status
                .bound
                .as_ref()
                .unwrap_or(&status.forward.listen)
                .to_string(),
            status.forward.connect.to_string(),
            status.active_connections.to_string(),
            status.refused_connections.to_string(),
        ]);
    }
    table.print()
}

fn direction(value: ForwardDirection) -> &'static str {
    match value {
        ForwardDirection::Inbound => "inbound",
        ForwardDirection::Outbound => "outbound",
    }
}

fn scope(value: MachineForwardScope) -> &'static str {
    match value {
        MachineForwardScope::Machine => "machine",
        MachineForwardScope::Session => "session",
    }
}

fn state(value: MachineForwardState) -> &'static str {
    match value {
        MachineForwardState::Pending => "pending",
        MachineForwardState::Active => "active",
        MachineForwardState::Unsupported => "unsupported",
        MachineForwardState::Closed => "closed",
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use clap::Parser;
    use libvm::{ForwardAddress, ForwardEndpoint};

    use crate::app::Cli;
    use crate::commands::forward::parse_forward;
    use crate::commands::Command;

    #[test]
    fn parses_shorthand_and_full_endpoint_forms() {
        let shorthand = parse_forward(&["8080:80".to_string()], None, Path::new("/work"))
            .expect("parse shorthand");
        assert_eq!(shorthand.listen.to_string(), "host:tcp:127.0.0.1:8080");
        assert_eq!(shorthand.connect.to_string(), "guest:tcp:127.0.0.1:80");

        for (listen, connect) in [
            ("host:tcp:8080", "guest:tcp:80"),
            ("guest:tcp:5432", "host:tcp:5432"),
            ("host:tcp:2222", "vsock:22"),
        ] {
            let forward = parse_forward(
                &[listen.to_string(), connect.to_string()],
                Some("named".to_string()),
                Path::new("/work"),
            )
            .expect("parse endpoint pair");
            assert_eq!(forward.name.as_deref(), Some("named"));
        }
    }

    #[test]
    fn relative_host_unix_paths_are_absolutized() {
        let forward = parse_forward(
            &[
                "host:unix:./x.sock".to_string(),
                "guest:unix:/run/x.sock".to_string(),
            ],
            None,
            Path::new("/workspace"),
        )
        .expect("parse Unix endpoints");
        assert_eq!(
            forward.listen,
            ForwardEndpoint::Host(ForwardAddress::Unix(
                Path::new("/workspace/./x.sock").into()
            ))
        );
    }

    #[test]
    fn rejects_mixed_or_wrong_arity_forms() {
        for values in [
            vec!["8080:guest:tcp:80".to_string()],
            vec!["host:tcp:8080".to_string()],
            vec![
                "host:tcp:1".to_string(),
                "guest:tcp:2".to_string(),
                "guest:tcp:3".to_string(),
            ],
        ] {
            assert!(parse_forward(&values, None, Path::new("/work")).is_err());
        }
    }

    #[test]
    fn clap_requires_an_explicit_vm_and_supports_list() {
        let cli =
            Cli::try_parse_from(["silo", "forward", "dev", "--list"]).expect("parse list command");
        assert!(matches!(cli.command, Command::Forward(_)));
        assert!(Cli::try_parse_from(["silo", "forward", "--list"]).is_err());
        assert!(Cli::try_parse_from(["silo", "forward", "dev"]).is_err());
        assert!(Cli::try_parse_from([
            "silo",
            "forward",
            "dev",
            "host:tcp:1",
            "guest:tcp:2",
            "guest:tcp:3",
        ])
        .is_err());
    }
}
