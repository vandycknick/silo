use std::fmt::{Display, Write};

use chrono::{DateTime, Utc};

use crate::lobby::jobs::Operation;
use crate::lobby::views::{DocumentView, VersionView, VmView, WhoAmIView};

/// Tabwriter-style columns, counting Unicode scalar values as Go does.
pub(crate) fn table(rows: &[Vec<String>]) -> String {
    let columns = rows.iter().map(Vec::len).max().unwrap_or(0);
    let mut widths = vec![0; columns];
    for row in rows {
        for (i, cell) in row.iter().enumerate().take(row.len().saturating_sub(1)) {
            widths[i] = widths[i].max(cell.chars().count() + 2);
        }
    }
    let mut text = String::new();
    for row in rows {
        for (i, cell) in row.iter().enumerate() {
            text.push_str(cell);
            if i + 1 < row.len() {
                for _ in cell.chars().count()..widths[i] {
                    text.push(' ');
                }
            }
        }
        text.push('\n');
    }
    text
}

pub(crate) fn human_memory(bytes: u64) -> String {
    let mib = bytes / (1024 * 1024);
    if mib.is_multiple_of(1024) {
        format!("{}G", mib / 1024)
    } else {
        format!("{mib}M")
    }
}

pub(crate) fn human_disk(bytes: u64) -> String {
    let (unit, suffix) = if bytes >= 1 << 30 {
        (1 << 30, "GiB")
    } else if bytes >= 1 << 20 {
        (1 << 20, "MiB")
    } else {
        return format!("{bytes}B");
    };
    let (whole, remainder) = (bytes / unit, bytes % unit);
    if remainder == 0 {
        return format!("{whole}{suffix}");
    }
    let hundredths = (remainder * 100 + unit / 2) / unit;
    if hundredths == 100 {
        format!("{}{suffix}", whole + 1)
    } else if hundredths % 10 == 0 {
        format!("{whole}.{}{suffix}", hundredths / 10)
    } else {
        format!("{whole}.{hundredths:02}{suffix}")
    }
}

fn is_zero_time(time: &DateTime<Utc>) -> bool {
    time.timestamp() == -62_135_596_800 && time.timestamp_subsec_nanos() == 0
}

pub(crate) fn absolute_time(time: &DateTime<Utc>) -> String {
    if is_zero_time(time) {
        "N/A".into()
    } else {
        time.format("%Y-%m-%d %H:%M:%S UTC").to_string()
    }
}

pub(crate) fn relative_time(created: &DateTime<Utc>, now: &DateTime<Utc>) -> String {
    if is_zero_time(created) || created.timestamp() == 0 {
        return "N/A".into();
    }
    let seconds = now.timestamp() - created.timestamp();
    if seconds < 5 {
        return "Less than a second ago".into();
    }
    if seconds < 60 {
        return format!("{seconds} seconds ago");
    }
    let minutes = seconds / 60;
    if minutes == 1 {
        return "About a minute ago".into();
    }
    if minutes < 60 {
        return format!("{minutes} minutes ago");
    }
    let hours = minutes / 60;
    if hours == 1 {
        return "About an hour ago".into();
    }
    if hours < 48 {
        return format!("{hours} hours ago");
    }
    let days = hours / 24;
    if days < 14 {
        return format!("{days} days ago");
    }
    let weeks = days / 7;
    if weeks < 8 {
        return format!("{weeks} weeks ago");
    }
    let months = days / 30;
    if months < 12 {
        return format!("{months} months ago");
    }
    format!("{} years ago", days / 365)
}

pub(crate) fn render_list(vms: &[VmView]) -> String {
    render_list_at(vms, &Utc::now())
}

pub(crate) fn render_list_at(vms: &[VmView], now: &DateTime<Utc>) -> String {
    let mut rows = Vec::with_capacity(vms.len() + 1);
    rows.push(
        ["NAME", "STATE", "NODE", "CPUS", "MEMORY", "CREATED"]
            .map(String::from)
            .to_vec(),
    );
    for vm in vms {
        rows.push(vec![
            vm.name.clone(),
            vm.state.clone(),
            if vm.node.is_empty() {
                vm.node_state.clone()
            } else {
                vm.node.clone()
            },
            vm.cpus.to_string(),
            human_memory(vm.memory),
            relative_time(&vm.created, now),
        ]);
    }
    let mut text = table(&rows);
    for vm in vms {
        if !vm.approval_url.is_empty() {
            let _ = writeln!(text, "Approve {}: {}", vm.name, vm.approval_url);
        }
    }
    text
}

pub(crate) fn safe_text(text: &str) -> String {
    text.chars()
        .map(|c| {
            if c.is_control()
                || matches!(c,
        '\u{ad}' | '\u{600}'..='\u{605}' | '\u{61c}' | '\u{6dd}' | '\u{70f}' |
        '\u{890}'..='\u{891}' | '\u{8e2}' | '\u{180e}' | '\u{200b}'..='\u{200f}' |
        '\u{202a}'..='\u{202e}' | '\u{2060}'..='\u{2064}' | '\u{2066}'..='\u{206f}' |
        '\u{feff}' | '\u{fff9}'..='\u{fffb}' | '\u{110bd}' | '\u{110cd}' |
        '\u{13430}'..='\u{1343f}' | '\u{1bca0}'..='\u{1bca3}' |
        '\u{1d173}'..='\u{1d17a}' | '\u{e0001}' | '\u{e0020}'..='\u{e007f}')
            {
                '�'
            } else {
                c
            }
        })
        .collect()
}

pub(crate) fn expiry_text(vm: &VmView, now: &DateTime<Utc>) -> String {
    let mut text = if vm.key_expiry == "never" {
        "Never".into()
    } else if let Ok(expiry) = DateTime::parse_from_rfc3339(&vm.key_expiry) {
        let expiry = expiry.with_timezone(&Utc);
        if is_zero_time(&expiry) {
            "Unavailable".into()
        } else {
            let mut text = absolute_time(&expiry);
            if expiry <= *now {
                text += " (expired)";
            }
            text
        }
    } else {
        "Unavailable".into()
    };
    if text != "Unavailable" && vm.key_expiry_last_known {
        text += " (last known)";
    }
    text
}

pub(crate) fn render_show(vm: &VmView) -> String {
    render_show_at(vm, &Utc::now())
}

pub(crate) fn render_show_at(vm: &VmView, now: &DateTime<Utc>) -> String {
    let owner = if !vm.owner.is_tag() && !vm.owner_login.is_empty() {
        &vm.owner_login
    } else {
        vm.owner.as_str()
    };
    let user = if vm.default_user.is_empty() {
        "root"
    } else {
        &vm.default_user
    };
    let mut text = format!("Name: {}\nID: {}\nOwner: {}\nGuest user: {}\nState: {}\nCPUs: {}\nMemory: {}\nDisk: {}\nCreated: {}\nImage: {}\n",
        safe_text(&vm.name), safe_text(&vm.id), safe_text(owner), safe_text(user), vm.state, vm.cpus,
        human_memory(vm.memory), human_disk(vm.disk), absolute_time(&vm.created), safe_text(&vm.image));
    if !vm.labels.is_empty() {
        text += "Labels:\n";
        for (key, value) in &vm.labels {
            let _ = writeln!(text, "  {}: {}", safe_text(key), safe_text(value));
        }
    }
    if !vm.template.is_empty() {
        let _ = writeln!(text, "Template: {}", safe_text(&vm.template));
    }
    if !vm.tags.is_empty() {
        let _ = writeln!(text, "Tags: {}", safe_text(&vm.tags.join(", ")));
    }
    if !vm.policy.is_empty() {
        let _ = writeln!(text, "Policy: {}", safe_text(&vm.policy));
    }
    if !vm.forwards.is_empty() {
        text += "Forwards:\n";
        for forward in &vm.forwards {
            let target = if forward.url.is_empty() {
                format!(":{}", forward.listen_port)
            } else {
                safe_text(&forward.url)
            };
            let _ = writeln!(
                text,
                "  {}: {} -> guest {} ({})",
                safe_text(&forward.name),
                target,
                forward.target_port,
                forward.protocol
            );
        }
    }
    if !vm.guest_tcp_ports.is_empty() {
        let _ = writeln!(
            text,
            "Guest TCP hints (ACL controls access): {}",
            port_list(&vm.guest_tcp_ports)
        );
    }
    let _ = write!(
        text,
        "Node: {}\nNode state: {}\nKey expiry: {}\n",
        safe_text(&vm.node),
        safe_text(&vm.node_state),
        expiry_text(vm, now)
    );
    for diagnostic in &vm.node_diagnostics {
        let _ = writeln!(text, "Node diagnostic: {}", safe_text(diagnostic));
    }
    if !vm.approval_url.is_empty() {
        let _ = writeln!(text, "Login: {}", safe_text(&vm.approval_url));
    }
    text
}

fn port_list(ports: &[u16]) -> String {
    let mut text = String::from("[");
    for (i, port) in ports.iter().enumerate() {
        if i > 0 {
            text.push(' ');
        }
        let _ = write!(text, "{port}");
    }
    text.push(']');
    text
}

pub(crate) fn render_version(version: &VersionView) -> String {
    format!(
        "lobby {} · silod {} · tailscale {}\n",
        version.lobby, version.silod, version.tailscale
    )
}

pub(crate) fn render_who_am_i(who: &WhoAmIView) -> String {
    let peer = &who.peer;
    let user = if peer.principals.iter().any(|p| p.is_tag()) {
        "tagged device"
    } else if peer.login.is_empty() {
        "unknown"
    } else {
        &peer.login
    };
    format!(
        "User: {user}\nNode: {}\n",
        peer.node_name.strip_suffix('.').unwrap_or(&peer.node_name)
    )
}

pub(crate) fn render_ops(ops: &[Operation]) -> String {
    let mut text = String::new();
    for op in ops {
        let _ = writeln!(text, "{} {} {} {}", op.id, op.kind, op.vm, op.state);
    }
    text
}

pub(crate) fn render_documents(verb: &str, docs: &[DocumentView]) -> String {
    if verb == "show" {
        return docs.first().map(|d| d.content.clone()).unwrap_or_default();
    }
    let mut text = String::new();
    for doc in docs {
        let _ = writeln!(text, "{} {} {}", doc.kind, doc.name, doc.tier);
        if let Some(template) = &doc.template {
            optional(&mut text, "Description", template.description.as_ref());
            optional(&mut text, "Image", template.image.as_ref());
            if let Some(resources) = &template.resources {
                optional(&mut text, "CPUs", resources.cpus.as_ref());
                optional(&mut text, "Memory", resources.memory.as_ref());
            }
            optional(&mut text, "Disk", template.disk_size.as_ref());
            if let Some(network) = &template.network {
                optional(&mut text, "Policy", network.policy_ref.as_ref());
                if !network.publish.is_empty() {
                    let _ = writeln!(
                        text,
                        "Guest TCP hints (ACL controls access): {}",
                        port_list(&network.publish)
                    );
                }
            }
        }
        if let Some(secrets) = &doc.secrets {
            for slot in &secrets.slots {
                let _ = writeln!(
                    text,
                    "Secret: {} (key {}, required {})",
                    slot.name, slot.source.key, slot.required
                );
            }
        }
        for vm in &doc.bound_vms {
            if verb == "rm" {
                let _ = writeln!(
                    text,
                    "{} still references policy {}",
                    safe_text(&vm.name),
                    safe_text(&doc.name)
                );
            } else if vm.state == "running" {
                let _ = writeln!(
                    text,
                    "{} ({}): restart to apply",
                    safe_text(&vm.name),
                    vm.state
                );
            } else {
                let _ = writeln!(
                    text,
                    "{} ({}): run 'set {} policy={}' to apply",
                    safe_text(&vm.name),
                    vm.state,
                    safe_text(&vm.name),
                    safe_text(&doc.name)
                );
            }
        }
    }
    text
}

fn optional(text: &mut String, label: &str, value: Option<&impl Display>) {
    if let Some(value) = value {
        let _ = writeln!(text, "{label}: {value}");
    }
}

pub(crate) const SPINNER_FRAMES: &[char] = &['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏'];

pub(crate) struct ProgressDisplay {
    pub(crate) animated: bool,
    pub(crate) width: usize,
    pub(crate) message: String,
    frame: usize,
    visible: bool,
}

impl ProgressDisplay {
    pub(crate) fn new(animated: bool, width: usize) -> Self {
        Self {
            animated,
            width,
            message: String::new(),
            frame: 0,
            visible: false,
        }
    }
    pub(crate) fn tick(&mut self) -> String {
        if !self.animated {
            return String::new();
        }
        let frame = SPINNER_FRAMES[self.frame];
        self.frame = (self.frame + 1) % SPINNER_FRAMES.len();
        let width = if self.width == 0 { 80 } else { self.width };
        let line = format!("   {frame} {}", self.message);
        let line: String = line
            .chars()
            .filter(|c| !c.is_control())
            .take(width.saturating_sub(1).max(1))
            .collect();
        self.visible = true;
        format!("\r\x1b[2K{line}")
    }
    pub(crate) fn clear(&mut self) -> &'static str {
        if !self.visible {
            return "";
        }
        self.visible = false;
        "\r\x1b[2K"
    }
}

pub(crate) fn phase(line: &str, target: &str) -> String {
    for (prefix, label) in [
        ("pulling ", "Pulling"),
        ("creating ", "Creating"),
        ("materializing ", "Creating"),
        ("starting ", "Starting"),
        ("start ", "Starting"),
        ("stopping ", "Stopping"),
        ("stop ", "Stopping"),
        ("restart ", "Restarting"),
        ("remove ", "Removing"),
        ("set ", "Updating"),
        ("preparing ", "Preparing"),
    ] {
        if let Some(rest) = line.strip_prefix(prefix) {
            return format!(
                "{label:<12} {}",
                if matches!(rest, "VM" | "stopped VM") {
                    target
                } else {
                    rest
                }
            );
        }
    }
    if line.starts_with("waiting for guest") {
        return format!("{:<12} {target}", "Preparing");
    }
    if line.starts_with("checking Tailscale") {
        return format!("{:<12} onboarding link", "Tailscale");
    }
    if line == "guest ready" {
        return format!("{:<12} {target}", "Ready");
    }
    if line.starts_with("approve: ") {
        return "Waiting for Tailscale approval".into();
    }
    line.into()
}

fn lobby_name(configured: &str) -> &str {
    if configured.is_empty() {
        "silo"
    } else {
        configured
    }
}

pub(crate) fn connection_hints(
    lobby: &str,
    name: &str,
    user: &str,
    node: &str,
    enrolled: bool,
) -> String {
    let mut text = format!("\nShell\n  ssh -t {} shell {name}\n", lobby_name(lobby));
    if enrolled && !node.is_empty() {
        let _ = write!(text, "\nSSH\n  ssh {user}@{node}\n");
    }
    text
}

pub(crate) fn completion_text(op: &Operation, lobby: &str) -> String {
    let mut label = match op.kind.as_str() {
        "create" => "Created",
        "start" => "Started",
        "restart" => "Restarted",
        "stop" => "Stopped",
        "remove" => "Removed",
        "set" => "Updated",
        _ => "Completed",
    };
    let mut name = op.vm.as_str();
    if let Some(completion) = &op.completion {
        name = &completion.name;
        if op.kind == "create" && completion.running {
            label = "Ready";
        }
    }
    let elapsed = op
        .finished
        .and_then(|end| (end - op.started).to_std().ok())
        .map(|duration| duration.as_secs_f64())
        .unwrap_or(0.0);
    let mut text = format!("   ✓ {label:<12} {name} ({elapsed:.1}s)\n");
    let Some(completion) = &op.completion else {
        return text;
    };
    if !matches!(op.kind.as_str(), "create" | "start" | "restart") {
        return text;
    }
    if !completion.running {
        let _ = write!(text, "\nStart\n  ssh {} start {name}\n", lobby_name(lobby));
        return text;
    }
    text += &connection_hints(
        lobby,
        name,
        &completion.user,
        &completion.node,
        completion.node_state == "enrolled",
    );
    if !completion.node.is_empty() && completion.node_state == "enrolled" {
        return text;
    }
    if !completion.approval_url.is_empty() {
        let _ = write!(
            text,
            "\nTailscale · approval required\n  {}\n",
            completion.approval_url
        );
    } else if !matches!(completion.node_state.as_str(), "none" | "") {
        let _ = write!(
            text,
            "\nTailscale · {}\n  Check with: show {name}\n",
            completion.node_state
        );
    }
    text
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use chrono::{DateTime, TimeDelta, Utc};

    use crate::lobby::grammar::render::{
        absolute_time, completion_text, connection_hints, expiry_text, human_disk, human_memory,
        phase, relative_time, render_documents, render_list_at, render_ops, render_show,
        render_version, render_who_am_i, safe_text, ProgressDisplay, SPINNER_FRAMES,
    };
    use crate::lobby::identity::{Peer, Principal};
    use crate::lobby::jobs::{Completion, Operation, OperationState};
    use crate::lobby::service::documents::{
        parse_template, SecretField, SecretKind, SecretMetadata, SecretSlot, SecretSource,
    };
    use crate::lobby::views::{
        BoundVmView, DocumentView, ForwardView, VersionView, VmView, WhoAmIView,
    };

    fn time(value: &str) -> DateTime<Utc> {
        DateTime::parse_from_rfc3339(value)
            .unwrap()
            .with_timezone(&Utc)
    }

    #[test]
    fn human_sizes_match_cli() {
        for (bytes, want) in [
            (0, "0G"),
            (4 << 30, "4G"),
            (1536 << 20, "1536M"),
            (512 << 20, "512M"),
        ] {
            assert_eq!(human_memory(bytes), want);
        }
        for (bytes, want) in [
            (0, "0B"),
            (123, "123B"),
            ((1 << 20) - 1, "1048575B"),
            (512 << 20, "512MiB"),
            (64 << 30, "64GiB"),
            (200_000_000_000, "186.26GiB"),
            (1536 << 20, "1.5GiB"),
            ((1 << 20) + 10486, "1.01MiB"),
            ((2 << 20) - 1, "2MiB"),
            (u64::MAX, "17179869184GiB"),
        ] {
            assert_eq!(human_disk(bytes), want, "{bytes}");
        }
    }

    #[test]
    fn relative_time_cli_boundaries() {
        let now = time("2026-10-02T12:00:00Z");
        for (seconds, want) in [
            (-60, "Less than a second ago"),
            (0, "Less than a second ago"),
            (4, "Less than a second ago"),
            (5, "5 seconds ago"),
            (59, "59 seconds ago"),
            (60, "About a minute ago"),
            (119, "About a minute ago"),
            (120, "2 minutes ago"),
            (3599, "59 minutes ago"),
            (3600, "About an hour ago"),
            (7199, "About an hour ago"),
            (7200, "2 hours ago"),
            (48 * 3600 - 1, "47 hours ago"),
            (48 * 3600, "2 days ago"),
            (14 * 86400 - 1, "13 days ago"),
            (14 * 86400, "2 weeks ago"),
            (56 * 86400 - 1, "7 weeks ago"),
            (56 * 86400, "1 months ago"),
            (360 * 86400 - 1, "11 months ago"),
            (360 * 86400, "0 years ago"),
            (365 * 86400, "1 years ago"),
            (730 * 86400, "2 years ago"),
        ] {
            assert_eq!(
                relative_time(&(now - TimeDelta::seconds(seconds)), &now),
                want,
                "{seconds}"
            );
        }
        for created in [time("0001-01-01T00:00:00Z"), DateTime::UNIX_EPOCH] {
            assert_eq!(relative_time(&created, &now), "N/A");
        }
        assert_eq!(
            absolute_time(&time("2026-10-02T14:00:00+02:00")),
            "2026-10-02 12:00:00 UTC"
        );
        assert_eq!(absolute_time(&time("0001-01-01T00:00:00Z")), "N/A");
    }

    fn snapshot_vm() -> VmView {
        VmView {
            id: "vm".into(),
            name: "dev".into(),
            owner: Principal::parse("user:1").unwrap(),
            owner_login: "owner@example.test".into(),
            default_user: "nickvd".into(),
            state: "stopped".into(),
            cpus: 2,
            memory: 4 << 30,
            disk: 8 << 30,
            created: time("2026-10-02T12:34:56Z"),
            node: "dev.example.ts.net".into(),
            address: "100.64.0.1".into(),
            image: "ghcr.io/ns/image:tag".into(),
            labels: BTreeMap::from([("team".into(), "alpha".into())]),
            ..VmView::default()
        }
    }

    #[test]
    fn rendering_snapshots() {
        let vm = snapshot_vm();
        assert_eq!(render_list_at(std::slice::from_ref(&vm), &(vm.created + TimeDelta::hours(1))),
            "NAME  STATE    NODE                CPUS  MEMORY  CREATED\ndev   stopped  dev.example.ts.net  2     4G      About an hour ago\n");
        assert_eq!(render_show(&vm), "Name: dev\nID: vm\nOwner: owner@example.test\nGuest user: nickvd\nState: stopped\nCPUs: 2\nMemory: 4G\nDisk: 8GiB\nCreated: 2026-10-02 12:34:56 UTC\nImage: ghcr.io/ns/image:tag\nLabels:\n  team: alpha\nNode: dev.example.ts.net\nNode state: \nKey expiry: Unavailable\n");
        assert_eq!(
            render_list_at(&[], &vm.created),
            "NAME  STATE  NODE  CPUS  MEMORY  CREATED\n"
        );
    }

    #[test]
    fn show_optional_fields_and_expiry() {
        let mut vm = VmView {
            owner: Principal::parse("tag:owner").unwrap(),
            owner_login: "creator@example.test".into(),
            tags: vec!["tag:dev".into()],
            default_user: "root".into(),
            key_expiry: "never".into(),
            key_expiry_last_known: true,
            ..VmView::default()
        };
        let text = render_show(&vm);
        for want in [
            "Owner: tag:owner\n",
            "Guest user: root\n",
            "Key expiry: Never (last known)\n",
        ] {
            assert!(text.contains(want), "{text}");
        }
        for absent in ["Labels:", "Last operation:", "creator@example"] {
            assert!(!text.contains(absent));
        }
        vm.labels = BTreeMap::from([
            ("z".into(), "last".into()),
            ("a".into(), "line\n\x1b[2K".into()),
        ]);
        let text = render_show(&vm);
        assert!(text.contains("Labels:\n  a: line��[2K\n  z: last\n"));
        assert!(!text.contains("map["));
        let now = time("2026-10-05T12:00:00Z");
        for (value, want) in [
            ("unknown", "Unavailable"),
            ("0001-01-01T00:00:00Z", "Unavailable"),
            (
                "2026-10-05T11:00:00Z",
                "2026-10-05 11:00:00 UTC (expired) (last known)",
            ),
            (
                "2026-10-06T12:00:00Z",
                "2026-10-06 12:00:00 UTC (last known)",
            ),
        ] {
            vm.key_expiry = value.into();
            assert_eq!(expiry_text(&vm, &now), want);
        }
        assert!(serde_json::to_value(&vm)
            .unwrap()
            .get("last_operation")
            .is_none());
        vm.template = "base".into();
        vm.policy = "web".into();
        vm.guest_tcp_ports = vec![22, 8080];
        vm.forwards = vec![
            ForwardView {
                name: "web".into(),
                protocol: "https".into(),
                listen_port: 443,
                target_port: 8080,
                url: "https://dev/".into(),
            },
            ForwardView {
                name: "ssh".into(),
                protocol: "tcp".into(),
                listen_port: 2222,
                target_port: 22,
                url: String::new(),
            },
        ];
        vm.node_diagnostics = vec!["pending\u{202e}".into()];
        vm.approval_url = "https://login.example/".into();
        let text = render_show(&vm);
        for want in [
            "Template: base\n",
            "Policy: web\n",
            "Tags: tag:dev\n",
            "  web: https://dev/ -> guest 8080 (https)\n",
            "  ssh: :2222 -> guest 22 (tcp)\n",
            "Guest TCP hints (ACL controls access): [22 8080]\n",
            "Node diagnostic: pending�\n",
            "Login: https://login.example/\n",
        ] {
            assert!(text.contains(want), "{want}: {text}");
        }
    }

    #[test]
    fn human_rendering_keeps_json_sizes_and_addresses() {
        let created = time("2026-10-02T12:00:00Z");
        let vm = VmView {
            name: "café".into(),
            memory: 1536 << 20,
            disk: 200_000_000_000,
            created,
            address: "100.64.0.1".into(),
            addresses: vec!["100.64.0.1".into()],
            ..VmView::default()
        };
        for text in [
            render_list_at(std::slice::from_ref(&vm), &created),
            render_show(&vm),
        ] {
            for absent in ["ADDRESS", "Address:", "100.64.0.1"] {
                assert!(!text.contains(absent));
            }
            assert!(text.contains("1536M"));
        }
        let json = serde_json::to_value(&vm).unwrap();
        assert_eq!(json["memory"], vm.memory);
        assert_eq!(json["disk"], vm.disk);
        assert_eq!(json["address"], vm.address);
        assert_eq!(json["addresses"].as_array().unwrap().len(), 1);
        assert_eq!(json["created"], "2026-10-02T12:00:00Z");
        let text = render_list_at(
            &[
                vm,
                VmView {
                    name: "abcde".into(),
                    node: "pending".into(),
                    ..VmView::default()
                },
            ],
            &created,
        );
        let lines: Vec<_> = text.lines().collect();
        assert_eq!(
            lines[1].split("1536M").next().unwrap().chars().count(),
            lines[2].split("0G").next().unwrap().chars().count()
        );
        assert_eq!(safe_text("a\u{200b}\u{ad}\n\x1b"), "a����");
    }

    #[test]
    fn documents_policy_bindings_rendering() {
        let mut docs = vec![DocumentView {
            kind: "policy".into(),
            name: "preview".into(),
            tier: "yours".into(),
            bound_vms: vec![
                BoundVmView {
                    name: "web".into(),
                    state: "running".into(),
                },
                BoundVmView {
                    name: "web2".into(),
                    state: "stopped".into(),
                },
            ],
            ..DocumentView::default()
        }];
        assert_eq!(render_documents("edit", &docs), "policy preview yours\nweb (running): restart to apply\nweb2 (stopped): run 'set web2 policy=preview' to apply\n");
        assert_eq!(render_documents("rm", &docs), "policy preview yours\nweb still references policy preview\nweb2 still references policy preview\n");
        docs[0].bound_vms.clear();
        assert_eq!(render_documents("edit", &docs), "policy preview yours\n");
        docs[0].content = "raw\n".into();
        assert_eq!(render_documents("show", &docs), "raw\n");
        assert_eq!(render_documents("show", &[]), "");
        docs[0].template = Some(parse_template("version: '1'\ndescription: Hello\nimage: alpine\nresources:\n  cpus: 2\n  memory: 4GiB\ndisk_size: 8GiB\nnetwork:\n  kind: private\n  policy_ref: preview\n  publish: [22, 8080]\n").unwrap());
        assert!(render_documents("ls", &docs).contains("Description: Hello\nImage: alpine\nCPUs: 2\nMemory: 4GiB\nDisk: 8GiB\nPolicy: preview\nGuest TCP hints (ACL controls access): [22 8080]\n"));
        docs[0].secrets = Some(SecretMetadata {
            slots: vec![SecretSlot {
                name: "api".into(),
                required: true,
                kind: SecretKind::Plain,
                source: SecretSource {
                    key: "api.token".into(),
                    field: SecretField::Value,
                },
            }],
            requirements: Vec::new(),
        });
        assert!(
            render_documents("ls", &docs).contains("Secret: api (key api.token, required true)\n")
        );
    }

    fn operation() -> Operation {
        let started = time("2026-10-02T12:00:00Z");
        Operation {
            id: "op_01ARZ3NDEKTSV4RRFFQ69G5FAV".into(),
            kind: "create".into(),
            vm: "dev".into(),
            principal: Principal::parse("user:7").unwrap(),
            state: OperationState::Succeeded,
            started,
            finished: Some(started + TimeDelta::milliseconds(2400)),
            progress: Vec::new(),
            error: None,
            completion: Some(Completion {
                name: "dev".into(),
                running: true,
                user: "root".into(),
                node_state: "approval_required".into(),
                approval_url: "https://login.tailscale.com/a/example".into(),
                ..Completion::default()
            }),
        }
    }

    #[test]
    fn progress_animation_and_completion() {
        let mut p = ProgressDisplay::new(true, 20);
        p.message = phase("pulling ghcr.io/long/image:latest", "dev");
        let first = p.tick();
        assert!(first.contains("⠋ Pulling"));
        assert!(first.strip_prefix("\r\x1b[2K").unwrap().chars().count() < 20);
        p.width = 10;
        let second = p.tick();
        assert_eq!(second.strip_prefix("\r\x1b[2K").unwrap().chars().count(), 9);
        assert_eq!(p.clear(), "\r\x1b[2K");
        assert!(!p.visible);
        assert_eq!(p.clear(), "");
        p.animated = false;
        assert_eq!(p.tick(), "");
        p.animated = true;
        p.width = 0;
        p.message = "\n\x1b".into();
        assert!(!p.tick().strip_prefix("\r\x1b[2K").unwrap().contains('\n'));
        for _ in 0..SPINNER_FRAMES.len() * 2 {
            p.tick();
        }
        let mut op = operation();
        let text = completion_text(&op, "silo");
        for want in [
            "✓ Ready",
            "dev (2.4s)",
            "ssh -t silo shell dev",
            "https://login.tailscale.com/a/example",
        ] {
            assert!(text.contains(want), "{text}");
        }
        assert!(!text.contains("ssh root@"));
        let completion = op.completion.as_mut().unwrap();
        completion.approval_url.clear();
        completion.node_state = "enrolled".into();
        completion.node = "dev.tail.test".into();
        completion.user = "alice".into();
        assert!(completion_text(&op, "silo").contains("ssh alice@dev.tail.test"));
        op.completion.as_mut().unwrap().running = false;
        let text = completion_text(&op, "silo");
        assert!(!text.contains("Ready") && !text.contains("\nShell"));
        assert!(text.contains("ssh silo start dev"));
        op.finished = Some(op.started - TimeDelta::seconds(1));
        assert!(completion_text(&op, "").contains("(0.0s)"));
        op.completion = None;
        op.kind = "unknown".into();
        assert!(completion_text(&op, "").contains("✓ Completed"));
        assert_eq!(
            render_ops(std::slice::from_ref(&op)),
            format!("{} unknown dev succeeded\n", op.id)
        );
    }

    #[test]
    fn phase_labels_and_connection_hints() {
        for (line, want) in [
            ("pulling image", "Pulling      image"),
            ("creating VM", "Creating     dev"),
            ("materializing stopped VM", "Creating     dev"),
            ("starting VM", "Starting     dev"),
            ("start VM", "Starting     dev"),
            ("stopping VM", "Stopping     dev"),
            ("stop VM", "Stopping     dev"),
            ("restart VM", "Restarting   dev"),
            ("remove VM", "Removing     dev"),
            ("set VM", "Updating     dev"),
            ("preparing VM", "Preparing    dev"),
            ("waiting for guest agent", "Preparing    dev"),
            ("checking Tailscale node", "Tailscale    onboarding link"),
            ("guest ready", "Ready        dev"),
            (
                "approve: https://example/",
                "Waiting for Tailscale approval",
            ),
            ("other", "other"),
        ] {
            assert_eq!(phase(line, "dev"), want);
        }
        assert_eq!(
            connection_hints("", "dev", "root", "", false),
            "\nShell\n  ssh -t silo shell dev\n"
        );
        assert_eq!(
            connection_hints("custom", "dev", "alice", "dev.tail", true),
            "\nShell\n  ssh -t custom shell dev\n\nSSH\n  ssh alice@dev.tail\n"
        );
    }

    #[test]
    fn whoami_and_version() {
        let mut who = WhoAmIView {
            peer: Peer {
                principals: vec![Principal::parse("user:7").unwrap()],
                login: "verified@example.com".into(),
                node_name: "node.tail.test.".into(),
                ..Peer::default()
            },
            capability: "cap".into(),
            explanation: String::new(),
        };
        assert_eq!(
            render_who_am_i(&who),
            "User: verified@example.com\nNode: node.tail.test\n"
        );
        who.peer.principals = vec![Principal::parse("tag:ci").unwrap()];
        assert_eq!(
            render_who_am_i(&who),
            "User: tagged device\nNode: node.tail.test\n"
        );
        who.peer.principals.clear();
        who.peer.login.clear();
        assert_eq!(
            render_who_am_i(&who),
            "User: unknown\nNode: node.tail.test\n"
        );
        assert_eq!(
            render_version(&VersionView {
                lobby: "1".into(),
                silod: "1".into(),
                tailscale: "1.102.5".into()
            }),
            "lobby 1 · silod 1 · tailscale 1.102.5\n"
        );
    }
}
