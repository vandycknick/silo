use std::collections::BTreeMap;

use crate::lobby::grammar::render::table;

#[derive(Debug, Clone, Copy)]
pub(crate) struct OptionSpec {
    pub(crate) names: &'static [&'static str],
    pub(crate) placeholder: &'static str,
    pub(crate) help: &'static str,
    pub(crate) fallback: &'static str,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct CommandSpec {
    pub(crate) name: &'static str,
    pub(crate) summary: &'static str,
    pub(crate) usage: &'static str,
    pub(crate) arguments: &'static str,
    pub(crate) example: &'static str,
    pub(crate) aliases: &'static [&'static str],
    pub(crate) subcommands: &'static [&'static str],
    pub(crate) streaming: bool,
    pub(crate) options: &'static [OptionSpec],
}

#[derive(Debug, Clone)]
pub(crate) struct Topic {
    pub(crate) summary: String,
    pub(crate) usage: String,
    pub(crate) arguments: String,
    pub(crate) example: String,
}

pub(crate) const COMMANDS: &[CommandSpec] = &[
    CommandSpec {
        name: "whoami",
        summary: "Show your verified user and node.",
        usage: "whoami [OPTIONS]",
        arguments: "",
        example: "whoami --json",
        aliases: &[],
        subcommands: &[],
        streaming: false,
        options: &[
        ],
    },
    CommandSpec {
        name: "version",
        summary: "Show lobby, silod and Tailscale versions.",
        usage: "version [OPTIONS]",
        arguments: "",
        example: "version",
        aliases: &[],
        subcommands: &[],
        streaming: false,
        options: &[
        ],
    },
    CommandSpec {
        name: "help",
        summary: "Show command help.",
        usage: "help [COMMAND [SUBCOMMAND]] [OPTIONS]",
        arguments: "COMMAND [SUBCOMMAND]  Optional help topic.",
        example: "help template create",
        aliases: &[],
        subcommands: &[],
        streaming: false,
        options: &[
        ],
    },
    CommandSpec {
        name: "ls",
        summary: "List your VMs.",
        usage: "ls [OPTIONS]",
        arguments: "",
        example: "ls",
        aliases: &["list"],
        subcommands: &[],
        streaming: false,
        options: &[
        ],
    },
    CommandSpec {
        name: "show",
        summary: "Inspect a VM.",
        usage: "show VM [OPTIONS]",
        arguments: "VM  Exact name or VM ID.",
        example: "show devbox",
        aliases: &["status"],
        subcommands: &[],
        streaming: false,
        options: &[
        ],
    },
    CommandSpec {
        name: "ops",
        summary: "List operations or inspect one operation.",
        usage: "ops [COMMAND] [OPTIONS]",
        arguments: "COMMAND  Omit to list operations, or use show to inspect one.",
        example: "ops",
        aliases: &[],
        subcommands: &["show"],
        streaming: false,
        options: &[
        ],
    },
    CommandSpec {
        name: "create",
        summary: "Create and start a VM unless --no-start is supplied.",
        usage: "create [IMAGE] [-n/--name NAME] [OPTIONS]",
        arguments: "IMAGE  OCI reference, required unless the selected template provides one.",
        example: "create ghcr.io/example/dev:latest --name devbox --memory 4GiB",
        aliases: &["new"],
        subcommands: &[],
        streaming: false,
        options: &[
            OptionSpec { names: &["name", "n"], placeholder: "NAME", help: "Exact name; absent name is generated.", fallback: "generated" },
            OptionSpec { names: &["image"], placeholder: "OCI", help: "OCI reference; cannot be combined with IMAGE.", fallback: "template image" },
            OptionSpec { names: &["template"], placeholder: "NAME", help: "Apply a template; explicit options take precedence.", fallback: "none" },
            OptionSpec { names: &["policy"], placeholder: "NAME", help: "Named network policy.", fallback: "template/configured" },
            OptionSpec { names: &["cpus"], placeholder: "N", help: "Positive CPU count, 1..255, subject to grants.", fallback: "configured" },
            OptionSpec { names: &["memory"], placeholder: "SIZE", help: "Binary memory size, e.g. 4GiB or 8gb.", fallback: "template/configured" },
            OptionSpec { names: &["disk", "disk-size"], placeholder: "SIZE", help: "Binary root disk size, e.g. 16GiB.", fallback: "template/configured" },
            OptionSpec { names: &["provision-user"], placeholder: "NAME:UID:GID:HOME", help: "Provision the guest account.", fallback: "root" },
            OptionSpec { names: &["userdata"], placeholder: "INLINE|-", help: "Shebang script; - reads stdin after authorization.", fallback: "template/none" },
            OptionSpec { names: &["label"], placeholder: "K=V", help: "User label (repeatable).", fallback: "template/none" },
            OptionSpec { names: &["owner"], placeholder: "tag:NAME", help: "Select a verified owner tag.", fallback: "your principal" },
            OptionSpec { names: &["tailscale"], placeholder: "", help: "Add a VM tailnet node; interactive approval continues after boot.", fallback: "false" },
            OptionSpec { names: &["tag"], placeholder: "tag:NAME", help: "Request a Tailscale tag (repeatable); Tailscale authorizes assignment.", fallback: "none" },
            OptionSpec { names: &["no-start"], placeholder: "", help: "Leave the VM stopped.", fallback: "false" },
        ],
    },
    CommandSpec {
        name: "start",
        summary: "Start a stopped VM.",
        usage: "start VM [OPTIONS]",
        arguments: "VM  Exact name or VM ID.",
        example: "start devbox",
        aliases: &[],
        subcommands: &[],
        streaming: false,
        options: &[
        ],
    },
    CommandSpec {
        name: "restart",
        summary: "Restart a VM.",
        usage: "restart VM [OPTIONS]",
        arguments: "VM  Exact name or VM ID.",
        example: "restart devbox",
        aliases: &[],
        subcommands: &[],
        streaming: false,
        options: &[
        ],
    },
    CommandSpec {
        name: "stop",
        summary: "Stop a VM.",
        usage: "stop VM [OPTIONS]",
        arguments: "VM  Exact name or VM ID.",
        example: "stop devbox --timeout 30s",
        aliases: &[],
        subcommands: &[],
        streaming: false,
        options: &[
            OptionSpec { names: &["force"], placeholder: "", help: "Force shutdown.", fallback: "false" },
            OptionSpec { names: &["timeout"], placeholder: "DURATION", help: "Shutdown deadline.", fallback: "configured" },
        ],
    },
    CommandSpec {
        name: "rm",
        summary: "Remove a VM after confirmation.",
        usage: "rm VM [OPTIONS]",
        arguments: "VM  Exact name or VM ID.",
        example: "rm devbox --yes",
        aliases: &[],
        subcommands: &[],
        streaming: false,
        options: &[
            OptionSpec { names: &["force"], placeholder: "", help: "Stop a running VM first.", fallback: "false" },
            OptionSpec { names: &["yes"], placeholder: "", help: "Bypass [y/N] confirmation.", fallback: "false" },
        ],
    },
    CommandSpec {
        name: "set",
        summary: "Update a stopped VM.",
        usage: "set VM KEY=VALUE... [OPTIONS]",
        arguments: "VM  Exact name or VM ID.\nKEY=VALUE  name, cpus, memory, disk or policy. Sizes are binary; policy= clears the policy.",
        example: "set devbox memory=8gb disk=16GiB\nset devbox policy=web-preview",
        aliases: &[],
        subcommands: &[],
        streaming: false,
        options: &[
        ],
    },
    CommandSpec {
        name: "shell",
        summary: "Open a guest shell (requires SSH PTY).",
        usage: "shell VM [OPTIONS]",
        arguments: "VM  Exact name or VM ID.",
        example: "shell devbox -u root",
        aliases: &["ssh"],
        subcommands: &[],
        streaming: true,
        options: &[
            OptionSpec { names: &["u"], placeholder: "USER", help: "Guest user.", fallback: "VM default" },
        ],
    },
    CommandSpec {
        name: "exec",
        summary: "Run a guest command; arguments after -- are literal bytes (no shell).",
        usage: "exec VM [OPTIONS] -- CMD...",
        arguments: "VM  Exact name or VM ID.\nCMD...  Guest program and arguments after --. Without -t, stdin is streamed to the process and closed on EOF.",
        example: "exec devbox -- uname -a\nexec devbox -- python3 - < edit.py\nssh silo \"exec devbox -- python3 -c 'print(1, 2)'\"",
        aliases: &[],
        subcommands: &[],
        streaming: true,
        options: &[
            OptionSpec { names: &["u"], placeholder: "USER", help: "Guest user.", fallback: "VM default" },
            OptionSpec { names: &["w"], placeholder: "DIR", help: "Working directory.", fallback: "guest default" },
            OptionSpec { names: &["e"], placeholder: "K=V", help: "Environment (repeatable).", fallback: "none" },
            OptionSpec { names: &["t"], placeholder: "", help: "Guest PTY.", fallback: "false" },
        ],
    },
    CommandSpec {
        name: "cp",
        summary: "Copy a regular file between this session and a VM.",
        usage: "cp [OPTIONS] SRC DST",
        arguments: "SRC  - (stdin) or VM:/absolute/path.\nDST  - (stdout) or VM:/absolute/path.",
        example: "ssh silo cp - devbox:/root/patch.diff < patch.diff\nssh silo cp devbox:/root/shot.png - > shot.png\nssh silo cp -p --mode 0755 - devbox:/opt/bin/tool < tool",
        aliases: &[],
        subcommands: &[],
        streaming: true,
        options: &[
            OptionSpec { names: &["mode"], placeholder: "OCTAL", help: "File mode for uploads.", fallback: "0644 for new files; preserve on replace" },
            OptionSpec { names: &["owner"], placeholder: "UID[:GID]", help: "Numeric owner for uploads.", fallback: "unchanged" },
            OptionSpec { names: &["p", "parents"], placeholder: "", help: "Create missing parent directories.", fallback: "false" },
            OptionSpec { names: &["n", "no-clobber"], placeholder: "", help: "Fail if the destination exists (best effort, not atomic).", fallback: "false" },
        ],
    },
    CommandSpec {
        name: "logs",
        summary: "Read bounded VM logs.",
        usage: "logs VM [OPTIONS]",
        arguments: "VM  Exact name or VM ID.",
        example: "logs devbox --stream serial",
        aliases: &[],
        subcommands: &[],
        streaming: true,
        options: &[
            OptionSpec { names: &["follow"], placeholder: "", help: "Follow output.", fallback: "false" },
            OptionSpec { names: &["stream"], placeholder: "STREAM", help: "monitor, serial, exec, network or network-audit.", fallback: "serial" },
            OptionSpec { names: &["output"], placeholder: "OUTPUT", help: "stdout or stderr; omitted includes both.", fallback: "all" },
        ],
    },
    CommandSpec {
        name: "template",
        summary: "Manage YAML templates.",
        usage: "template COMMAND [OPTIONS]",
        arguments: "COMMAND  Document operation; see Commands below.",
        example: "help template create",
        aliases: &[],
        subcommands: &["ls", "show", "create", "edit", "rm", "validate"],
        streaming: false,
        options: &[
            OptionSpec { names: &["owner"], placeholder: "tag:NAME", help: "Verified owner namespace.", fallback: "your principal" },
        ],
    },
    CommandSpec {
        name: "policy",
        summary: "Manage HCL network policies.",
        usage: "policy COMMAND [OPTIONS]",
        arguments: "COMMAND  Document operation; see Commands below.",
        example: "help policy validate",
        aliases: &[],
        subcommands: &["ls", "show", "create", "edit", "rm", "validate"],
        streaming: false,
        options: &[
            OptionSpec { names: &["owner"], placeholder: "tag:NAME", help: "Verified owner namespace.", fallback: "your principal" },
        ],
    },
];

pub(crate) fn lookup(name: &str) -> Option<&'static CommandSpec> {
    COMMANDS
        .iter()
        .find(|cmd| cmd.name == name || cmd.aliases.contains(&name))
}

pub(crate) fn document_topic(kind: &str, verb: &str) -> Option<Topic> {
    if !matches!(kind, "template" | "policy") {
        return None;
    }
    let summary = match verb {
        "ls" => "List available documents.",
        "show" => "Show a document.",
        "create" => "Create a document from stdin.",
        "edit" => "Replace a document from stdin.",
        "rm" => "Remove a document.",
        "validate" => "Validate a document from stdin.",
        _ => return None,
    };
    let named = matches!(verb, "show" | "create" | "edit" | "rm");
    let mut topic = Topic {
        summary: summary.into(),
        usage: format!(
            "{kind} {verb}{} [OPTIONS]",
            if named { " NAME" } else { "" }
        ),
        arguments: if named {
            "NAME  Document name in your namespace.".into()
        } else {
            String::new()
        },
        example: format!("{kind} {verb}{}", if named { " dev" } else { "" }),
    };
    if matches!(verb, "create" | "edit" | "validate") {
        let (format, file) = if kind == "policy" {
            ("HCL", "policy.hcl")
        } else {
            ("YAML", "template.yaml")
        };
        topic.summary += &format!(" Reads one {format} document (up to 64KiB).");
        topic.example = format!("ssh silo {} < {file}", topic.example);
    }
    Some(topic)
}

impl CommandSpec {
    pub(crate) fn topic(&self, name: &str) -> Option<Topic> {
        if self.name == "ops" && name == "show" {
            return Some(Topic {
                summary: "Inspect an operation owned by your principal.".into(),
                usage: "ops show OPERATION_ID [OPTIONS]".into(),
                arguments: "OPERATION_ID  The op_ULID returned by a command.".into(),
                example: "ops show op_01ARZ3NDEKTSV4RRFFQ69G5FAV --json".into(),
            });
        }
        document_topic(self.name, name)
    }
}

pub(crate) fn help() -> String {
    let mut commands: Vec<_> = COMMANDS.iter().collect();
    commands.sort_by_key(|cmd| cmd.name);
    let rows: Vec<_> = commands
        .iter()
        .map(|cmd| vec![format!("  {}", cmd.name), cmd.summary.into()])
        .collect();
    format!("silo · manage your VMs\n\nUsage:\n  COMMAND [ARGUMENTS] [OPTIONS]\n\nCommands:\n{}\nOptions:\n  -h, --help  Show help.\n  --json      Structured output for supported queries/mutations.\n\nExamples:\n  help create\n  create --name devbox --memory 4GiB\n", table(&rows))
}

/// Defaults are descriptive text only, supplied by the live service when available.
pub(crate) fn detailed_help(path: &[&str], defaults: &BTreeMap<String, String>) -> Option<String> {
    let (name, tail) = path.split_first()?;
    let cmd = lookup(name)?;
    let topic = match tail {
        [] => Topic {
            summary: cmd.summary.into(),
            usage: cmd.usage.into(),
            arguments: cmd.arguments.into(),
            example: cmd.example.into(),
        },
        [sub] => cmd.topic(sub)?,
        _ => return None,
    };
    let mut text = format!("{}\n\nUsage:\n  {}\n", topic.summary, topic.usage);
    if !cmd.aliases.is_empty() {
        let mut aliases = cmd.aliases.to_vec();
        aliases.sort_unstable();
        text += &format!("\nAliases:\n  {}\n", aliases.join(", "));
    }
    if !topic.arguments.is_empty() {
        let rows: Vec<_> = topic
            .arguments
            .lines()
            .map(|line| {
                let (label, description) = line.split_once("  ").unwrap_or((line, ""));
                vec![format!("  {label}"), description.into()]
            })
            .collect();
        text += &format!("\nArguments:\n{}", table(&rows));
    }
    if tail.is_empty() && !cmd.subcommands.is_empty() {
        let rows: Vec<_> = cmd
            .subcommands
            .iter()
            .filter_map(|name| {
                cmd.topic(name)
                    .map(|topic| vec![format!("  {name}"), topic.summary])
            })
            .collect();
        text += &format!("\nCommands:\n{}", table(&rows));
    }
    let mut rows = Vec::new();
    for option in cmd.options {
        let mut names = Vec::new();
        for short in [true, false] {
            names.extend(
                option
                    .names
                    .iter()
                    .filter(|name| (name.len() == 1) == short)
                    .map(|name| format!("{}{name}", if short { "-" } else { "--" })),
            );
        }
        let mut label = format!("  {}", names.join(", "));
        if !option.placeholder.is_empty() {
            label += &format!(" {}", option.placeholder);
        }
        let fallback = option
            .names
            .first()
            .and_then(|name| defaults.get(*name))
            .map(String::as_str)
            .unwrap_or(option.fallback);
        let mut description = option.help.to_owned();
        if !fallback.is_empty() {
            description += &format!(" (default: {fallback})");
        }
        rows.push(vec![label, description]);
    }
    rows.push(vec!["  -h, --help".into(), "Show help.".into()]);
    if !cmd.streaming {
        rows.push(vec![
            "  --json".into(),
            format!(
                "{} (default: false)",
                if cmd.name == "rm" {
                    "Structured output; does not confirm removal."
                } else {
                    "Structured output."
                }
            ),
        ]);
    }
    text += &format!(
        "\nOptions:\n{}\nExamples:\n  {}\n",
        table(&rows),
        topic.example.replace('\n', "\n  ")
    );
    Some(text)
}

#[cfg(test)]
mod tests {
    use crate::lobby::grammar::help::{detailed_help, document_topic, help, lookup, COMMANDS};
    use std::collections::BTreeMap;

    #[test]
    fn all_help_topics_use_shared_layout() {
        for cmd in COMMANDS {
            let mut paths = vec![vec![cmd.name]];
            paths.extend(cmd.subcommands.iter().map(|sub| vec![cmd.name, *sub]));
            for path in paths {
                let text = detailed_help(&path, &BTreeMap::new()).unwrap();
                for heading in ["\n\nUsage:\n  ", "\nOptions:\n  ", "\nExamples:\n  "] {
                    assert!(text.contains(heading), "{path:?}: {text}");
                }
                let usage = text
                    .split("Usage:\n")
                    .nth(1)
                    .unwrap()
                    .lines()
                    .next()
                    .unwrap();
                assert!(
                    !usage.contains(';')
                        && !usage.contains("(requires")
                        && !usage.contains("ls|show")
                );
                assert_eq!(text.contains("  --json"), !cmd.streaming);
            }
            if !cmd.subcommands.is_empty() {
                assert!(detailed_help(&[cmd.name], &BTreeMap::new())
                    .unwrap()
                    .contains("\nCommands:\n"));
            }
            for alias in cmd.aliases {
                assert_eq!(lookup(alias).unwrap().name, cmd.name);
                assert_eq!(
                    detailed_help(&[alias], &BTreeMap::new()),
                    detailed_help(&[cmd.name], &BTreeMap::new())
                );
            }
        }
        assert!(detailed_help(&[], &BTreeMap::new()).is_none());
        for path in [
            vec!["unknown"],
            vec!["ls", "unknown"],
            vec!["ops", "unknown"],
            vec!["template", "show", "extra"],
        ] {
            assert!(detailed_help(&path, &BTreeMap::new()).is_none());
        }
    }

    #[test]
    fn document_topics_and_configured_defaults() {
        for kind in ["template", "policy"] {
            for verb in ["ls", "show", "create", "edit", "rm", "validate"] {
                let topic = document_topic(kind, verb).unwrap();
                assert!(topic.usage.starts_with(&format!("{kind} {verb}")));
                if matches!(verb, "create" | "edit" | "validate") {
                    assert!(topic.summary.ends_with("document (up to 64KiB)."));
                    assert!(topic.example.starts_with("ssh silo "));
                }
            }
        }
        assert!(document_topic("other", "ls").is_none());
        assert!(document_topic("template", "unknown").is_none());
        let defaults = BTreeMap::from([(
            "cpus".into(),
            "3; template takes precedence, explicit option overrides both".into(),
        )]);
        let text = detailed_help(&["create"], &defaults).unwrap();
        assert!(
            text.contains("default: 3; template takes precedence, explicit option overrides both")
        );
        assert!(text.contains("-n, --name NAME"));
        let names: Vec<_> = help()
            .lines()
            .filter_map(|line| line.strip_prefix("  "))
            .filter_map(|line| line.split_once("  "))
            .map(|(name, _)| name.to_owned())
            .take(COMMANDS.len())
            .collect();
        let mut sorted = names.clone();
        sorted.sort();
        assert_eq!(names, sorted);
    }
}
