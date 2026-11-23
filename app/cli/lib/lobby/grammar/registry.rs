use crate::lobby::failure::Outcome;
use crate::lobby::grammar::cmdline::{self, Args, FlagSet};
use crate::lobby::grammar::commands::{self, usage, Context, Handler, Result};
use crate::lobby::grammar::help::{self, CommandSpec};

fn handler(command: &CommandSpec) -> Outcome<Box<dyn Handler>> {
    Ok(match command.name {
        "whoami" => Box::new(commands::whoami::Whoami),
        "version" => Box::new(commands::version::Version),
        "help" => Box::new(commands::help::Help),
        "ls" => Box::new(commands::ls::Ls),
        "show" => Box::new(commands::show::Show),
        "ops" => Box::new(commands::ops::Ops),
        "create" => Box::new(commands::create::Create::default()),
        "start" => Box::new(commands::start::Start),
        "restart" => Box::new(commands::restart::Restart),
        "stop" => Box::new(commands::stop::Stop::default()),
        "rm" => Box::new(commands::rm::Remove::default()),
        "set" => Box::new(commands::set::Set),
        "shell" => Box::new(commands::shell::Shell::default()),
        "exec" => Box::new(commands::exec::Exec::default()),
        "cp" => Box::new(commands::cp::Copy::default()),
        "logs" => Box::new(commands::logs::Logs::default()),
        "template" => Box::new(commands::template::Template::default()),
        "policy" => Box::new(commands::policy::Policy::default()),
        _ => return Err(usage("unknown command")),
    })
}

enum Prepared {
    Help(Vec<String>),
    Command(Box<dyn Handler>, Args),
}

/// Strip only lobby flags, never option values or the guest's literal tail.
fn session_flags(
    tokens: Vec<String>,
    declared: Option<&FlagSet<'_>>,
    json: &mut bool,
) -> Outcome<(Vec<String>, bool)> {
    let mut kept = Vec::with_capacity(tokens.len());
    let mut help = false;
    let mut tokens = tokens.into_iter();
    while let Some(token) = tokens.next() {
        match token.as_str() {
            "--" => {
                kept.push(token);
                kept.extend(tokens);
                break;
            }
            "--json" => {
                if *json {
                    return Err(usage("duplicate --json"));
                }
                *json = true;
            }
            "-h" | "--help" => help = true,
            _ => {
                let takes_value = cmdline::is_flag(&token)
                    && !token.contains('=')
                    && declared
                        .is_some_and(|flags| flags.takes_value(token.trim_start_matches('-')));
                kept.push(token);
                if takes_value {
                    if let Some(value) = tokens.next() {
                        kept.push(value);
                    }
                }
            }
        }
    }
    Ok((kept, help))
}

fn prepare(mut tokens: Vec<String>, json: &mut bool) -> Outcome<Prepared> {
    let mut declaration = None;
    if let Some(index) = tokens.iter().position(|token| !cmdline::is_flag(token)) {
        declaration = help::lookup(&tokens[index]).map(handler).transpose()?;
        if index > 0 {
            tokens[..=index].rotate_right(1);
        }
    }
    let mut declared = FlagSet::new();
    if let Some(handler) = &mut declaration {
        handler.flags(&mut declared);
    }
    let (tokens, want_help) = session_flags(tokens, Some(&declared), json)?;
    drop(declared);
    let Some((name, tokens)) = tokens.split_first() else {
        return if want_help {
            Ok(Prepared::Help(Vec::new()))
        } else {
            Err(usage("command required"))
        };
    };
    let command = help::lookup(name).ok_or_else(|| usage("invalid command arguments; see help"))?;
    let mut handler = match declaration {
        Some(handler) => handler,
        None => handler(command)?,
    };
    let mut flags = FlagSet::new();
    handler.flags(&mut flags);
    if want_help {
        let args = flags
            .parse_help(tokens)
            .map_err(|error| usage(error.to_string()))?;
        let mut path = vec![command.name.into()];
        if !command.subcommands.is_empty() {
            if let Some(topic) = args.positional.first() {
                path.push(topic.clone());
            }
        }
        return Ok(Prepared::Help(path));
    }
    if *json && command.streaming {
        return Err(usage("--json is not supported by this command"));
    }
    let args = flags
        .parse(tokens)
        .map_err(|error| usage(error.to_string()))?;
    drop(flags);
    Ok(Prepared::Command(handler, args))
}

/// Execute one tokenized command after transport identity validation.
pub(crate) async fn execute(context: &mut Context<'_>, tokens: Vec<String>) -> Outcome<Result> {
    match prepare(tokens, &mut context.json)? {
        Prepared::Help(path) => commands::help::help_for(context, &path),
        Prepared::Command(handler, args) => handler.run(context, args).await,
    }
}

#[cfg(test)]
mod tests {
    use crate::lobby::grammar::cmdline::FlagSet;
    use crate::lobby::grammar::help;
    use crate::lobby::grammar::registry::{handler, prepare, session_flags, Prepared};

    fn tokens(line: &[&str]) -> Vec<String> {
        line.iter().map(|token| (*token).into()).collect()
    }

    #[test]
    fn declarations_match_help_and_option_arity() {
        for command in help::COMMANDS {
            let mut handler = handler(command).unwrap();
            let mut flags = FlagSet::new();
            handler.flags(&mut flags);
            assert_eq!(
                flags.options().len(),
                command.options.len(),
                "{}",
                command.name
            );
            for (flag, option) in flags.options().iter().zip(command.options) {
                assert_eq!(flag.names, option.names, "{}", command.name);
                assert_eq!(flag.placeholder, option.placeholder, "{}", command.name);
                for name in option.names {
                    assert_eq!(flags.takes_value(name), !option.placeholder.is_empty());
                }
            }
        }
    }

    #[test]
    fn session_grammar_preserves_option_values_and_guest_tail() {
        for command in help::COMMANDS {
            for option in command.options {
                for name in option.names {
                    for value in ["--help", "--json", "--yes", "--"] {
                        let mut h = handler(command).unwrap();
                        let mut flags = FlagSet::new();
                        h.flags(&mut flags);
                        let mut line = vec![command.name.to_owned(), format!("--{name}")];
                        if !option.placeholder.is_empty() {
                            line.push(value.into());
                        }
                        line.push("--unknown=SECRET".into());
                        let mut json = false;
                        let (kept, want_help) =
                            session_flags(line.clone(), Some(&flags), &mut json).unwrap();
                        assert_eq!(kept, line);
                        assert!(!want_help && !json);
                        let failure = match prepare(line, &mut false) {
                            Err(error) => error,
                            Ok(_) => panic!("accepted unknown option"),
                        };
                        assert_eq!(failure.exit, 2);
                        assert!(!failure.message.contains("SECRET"));
                    }
                }
            }
        }
        let line = tokens(&[
            "exec", "vm", "--", "program", "--", "--json", "--help", "--yes", "SECRET",
        ]);
        let (kept, help) = session_flags(line.clone(), None, &mut false).unwrap();
        assert_eq!(kept, line);
        assert!(!help);
    }

    #[test]
    fn help_and_aliases_resolve_everywhere() {
        for command in help::COMMANDS {
            for name in std::iter::once(command.name).chain(command.aliases.iter().copied()) {
                for line in [vec!["--help", name], vec![name, "--help"], vec!["-h", name]] {
                    match prepare(tokens(&line), &mut false).unwrap() {
                        Prepared::Help(path) => assert_eq!(path, [command.name]),
                        Prepared::Command(_, _) => panic!("help executed a handler"),
                    }
                }
            }
        }
        assert!(
            matches!(prepare(tokens(&["--help"]), &mut false), Ok(Prepared::Help(path)) if path.is_empty())
        );
    }

    #[test]
    fn streaming_json_is_rejected_but_help_is_allowed() {
        for command in help::COMMANDS.iter().filter(|command| command.streaming) {
            let error = match prepare(tokens(&[command.name, "--json"]), &mut false) {
                Err(error) => error,
                Ok(_) => panic!("streaming JSON accepted"),
            };
            assert_eq!(error.message, "--json is not supported by this command");
            assert!(matches!(
                prepare(tokens(&[command.name, "--json", "--help"]), &mut false),
                Ok(Prepared::Help(_))
            ));
        }
    }

    #[test]
    fn yes_has_one_occurrence_budget_across_leading_options() {
        for first in ["--yes", "--yes=true", "--yes=false", "-yes", "-yes=false"] {
            for second in ["--yes", "--yes=true", "--yes=false", "-yes=false"] {
                for line in [
                    vec!["rm", "dev", first, second],
                    vec![first, "rm", "dev", second],
                    vec![first, second, "rm", "dev"],
                ] {
                    let error = match prepare(tokens(&line), &mut false) {
                        Err(error) => error,
                        Ok(_) => panic!("duplicate yes accepted"),
                    };
                    assert!(
                        error.message.contains("duplicate option"),
                        "{line:?}: {error}"
                    );
                }
            }
        }
        let mut json = false;
        assert!(prepare(tokens(&["--json", "version", "--json"]), &mut json).is_err());
        assert!(json);
    }

    #[test]
    fn help_does_not_validate_values_or_consume_literal_flags() {
        for line in [
            vec!["create", "--cpus", "not-a-number", "--help"],
            vec!["create", "--provision-user", "invalid", "--help"],
            vec!["create", "--userdata", "--", "--help"],
            vec!["exec", "vm", "-h", "--", "ls"],
            vec!["template", "--owner", "tag:ci", "create", "--help"],
        ] {
            assert!(
                matches!(prepare(tokens(&line), &mut false), Ok(Prepared::Help(_))),
                "{line:?}"
            );
        }
        match prepare(
            tokens(&["create", "--name", "x", "--userdata", "-h"]),
            &mut false,
        )
        .unwrap()
        {
            Prepared::Command(_, args) => assert!(args.positional.is_empty()),
            Prepared::Help(_) => panic!("option value interpreted as help"),
        }
        let mut json = false;
        match prepare(tokens(&["exec", "vm", "--", "cmd", "--json"]), &mut json).unwrap() {
            Prepared::Command(_, args) => assert_eq!(args.literal, ["cmd", "--json"]),
            Prepared::Help(_) => panic!("literal tail interpreted"),
        }
        assert!(!json);
    }

    #[test]
    fn every_boolean_accepts_explicit_true_and_false() {
        for command in help::COMMANDS {
            for option in command
                .options
                .iter()
                .filter(|option| option.placeholder.is_empty())
            {
                for name in option.names {
                    for suffix in ["", "=true", "=false", "=0", "=1"] {
                        let line = vec![
                            command.name.to_owned(),
                            format!("--{name}{suffix}"),
                            "--help".into(),
                        ];
                        assert!(matches!(prepare(line, &mut false), Ok(Prepared::Help(_))));
                    }
                }
            }
        }
    }

    #[test]
    fn malformed_owner_is_a_typed_usage_error() {
        for command in ["create", "template", "policy"] {
            let failure = match prepare(tokens(&[command, "--owner", "SECRET"]), &mut false) {
                Err(failure) => failure,
                Ok(_) => panic!("malformed owner accepted"),
            };
            assert_eq!(failure.exit, 2);
            assert_eq!(failure.message, "invalid value for --owner");
        }
    }
}
