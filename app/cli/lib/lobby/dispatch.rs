use serde::Serialize;
use serde_json::Value;
use tokio::io::AsyncWriteExt;

use crate::lobby::caller::Caller;
use crate::lobby::failure::{Code, Failure};
use crate::lobby::grammar::commands::{Context, Result};
use crate::lobby::grammar::{registry, tokenizer};
use crate::lobby::service::Service;
use crate::lobby::session::{SessionExtras, SessionIo};

#[derive(Serialize)]
struct Response<'a> {
    ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    data: Option<&'a Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<ResponseError<'a>>,
}

#[derive(Serialize)]
struct ResponseError<'a> {
    code: Code,
    message: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    operation: Option<&'a str>,
}

/// Identity outranks syntax: an unverified peer learns nothing about parsing.
pub(crate) async fn dispatch_session(
    service: &Service,
    caller: &Caller,
    line: &str,
    streams: &mut SessionIo,
    extras: &SessionExtras,
) -> i32 {
    let mut context = Context {
        service,
        caller: caller.clone(),
        streams,
        extras,
        json: false,
        failure_data: None,
    };
    let outcome = match service.check_identity(&caller.peer) {
        Err(error) => Err(error),
        Ok(()) => match tokenizer::tokenize(line) {
            Err(error) => Err(Failure::new(Code::Usage, error.to_string())),
            Ok(tokens) => registry::execute(&mut context, tokens).await,
        },
    };
    let (result, failure) = match outcome {
        Ok(result) => (result, None),
        Err(error) => (
            Result {
                data: context.failure_data.take(),
                ..Result::default()
            },
            Some(error),
        ),
    };
    respond(context.streams, context.json, result, failure).await
}

async fn respond(
    streams: &mut SessionIo,
    json: bool,
    result: Result,
    failure: Option<Failure>,
) -> i32 {
    if json {
        let error = failure.as_ref().map(|failure| ResponseError {
            code: failure.code,
            message: &failure.message,
            operation: result
                .data
                .as_ref()
                .and_then(|data| data.get("id"))
                .and_then(Value::as_str)
                .filter(|id| id.starts_with("op_")),
        });
        let response = Response {
            ok: failure.is_none(),
            data: result.data.as_ref(),
            error,
        };
        let mut bytes = match serde_json::to_vec(&response) {
            Ok(bytes) => bytes,
            Err(_) => return 255,
        };
        bytes.push(b'\n');
        if streams.stdout.write_all(&bytes).await.is_err() {
            return 255;
        }
    }
    if let Some(failure) = failure {
        if streams
            .stderr
            .write_all(format!("Error: {}\n", failure.message).as_bytes())
            .await
            .is_err()
        {
            return 255;
        }
        return i32::from(failure.exit);
    }
    if !json
        && streams
            .stderr
            .write_all(result.human.as_bytes())
            .await
            .is_err()
    {
        return 255;
    }
    result.exit
}

#[cfg(test)]
mod tests {
    use serde_json::json;
    use tokio::io::AsyncReadExt;
    use tokio_util::sync::CancellationToken;

    use crate::lobby::dispatch::{dispatch_session, respond};
    use crate::lobby::failure::{Code, Failure};
    use crate::lobby::grammar::commands::Result;
    use crate::lobby::service::testing::{caller, fixture};
    use crate::lobby::session::{SessionExtras, SessionIo, Terminal, Window};

    fn streams() -> (SessionIo, tokio::io::DuplexStream, tokio::io::DuplexStream) {
        let (stdout, stdout_read) = tokio::io::duplex(8192);
        let (stderr, stderr_read) = tokio::io::duplex(8192);
        let (_, signals) = tokio::sync::mpsc::channel(1);
        (
            SessionIo {
                stdin: Box::new(tokio::io::empty()),
                stdout: Box::new(stdout),
                stderr: Box::new(stderr),
                terminal: None,
                signals,
                cancel: CancellationToken::new(),
            },
            stdout_read,
            stderr_read,
        )
    }

    #[tokio::test]
    async fn success_and_failure_envelopes_are_exact() {
        for (data, failure, expected, exit) in [
            (Some(json!([])), None, json!({"ok":true,"data":[]}), 0),
            (None, None, json!({"ok":true}), 0),
            (
                None,
                Some(Failure::new(Code::Usage, "bad arguments")),
                json!({"ok":false,"error":{"code":"usage","message":"bad arguments"}}),
                2,
            ),
            (
                Some(json!({"id":"op_123","state":"failed"})),
                Some(Failure::new(Code::Conflict, "stopped")),
                json!({"ok":false,"data":{"id":"op_123","state":"failed"},"error":{"code":"conflict","message":"stopped","operation":"op_123"}}),
                5,
            ),
        ] {
            let (mut streams, mut stdout, mut stderr) = streams();
            assert_eq!(
                respond(
                    &mut streams,
                    true,
                    Result {
                        data,
                        human: "not on stdout\n".into(),
                        exit: 0
                    },
                    failure.clone()
                )
                .await,
                exit
            );
            drop(streams);
            let mut out = String::new();
            stdout.read_to_string(&mut out).await.unwrap();
            assert_eq!(out.lines().count(), 1);
            assert_eq!(
                serde_json::from_str::<serde_json::Value>(&out).unwrap(),
                expected
            );
            let mut human = String::new();
            stderr.read_to_string(&mut human).await.unwrap();
            assert_eq!(
                human,
                failure.map_or(String::new(), |error| format!("Error: {}\n", error.message))
            );
        }
    }

    #[tokio::test]
    async fn human_output_is_stderr_and_guest_exit_is_preserved() {
        let (mut streams, mut stdout, mut stderr) = streams();
        assert_eq!(
            respond(
                &mut streams,
                false,
                Result {
                    human: "hello\n".into(),
                    exit: 127,
                    ..Result::default()
                },
                None
            )
            .await,
            127
        );
        drop(streams);
        let mut out = String::new();
        stdout.read_to_string(&mut out).await.unwrap();
        assert!(out.is_empty());
        stderr.read_to_string(&mut out).await.unwrap();
        assert_eq!(out, "hello\n");
    }

    #[tokio::test]
    async fn transport_failures_exit_255() {
        for json in [false, true] {
            let (mut streams, stdout, stderr) = streams();
            drop(stdout);
            drop(stderr);
            assert_eq!(
                respond(
                    &mut streams,
                    json,
                    Result {
                        human: "test".into(),
                        ..Result::default()
                    },
                    None
                )
                .await,
                255
            );
        }
    }

    #[tokio::test]
    async fn identity_precedes_syntax_and_capability_is_not_identity() {
        let fixture = fixture().await;
        let caller = caller("user:123", &[]);
        let extras = SessionExtras {
            prompt: None,
            approval_shown: None,
        };
        for line in [
            "whoami --json",
            "version --json",
            "help --json",
            "unknown --json",
            "whoami --bad --json",
        ] {
            let (mut streams, mut stdout, mut stderr) = streams();
            let exit =
                dispatch_session(&fixture.service, &caller, line, &mut streams, &extras).await;
            assert_eq!(
                exit,
                if line.starts_with("unknown") || line.contains("--bad") {
                    2
                } else {
                    0
                },
                "{line}"
            );
            drop(streams);
            let mut out = String::new();
            stdout.read_to_string(&mut out).await.unwrap();
            assert_eq!(out.lines().count(), 1);
            let wire: serde_json::Value = serde_json::from_str(&out).unwrap();
            assert_eq!(wire["ok"], exit == 0);
            let mut human = String::new();
            stderr.read_to_string(&mut human).await.unwrap();
            if exit == 0 {
                assert!(human.is_empty());
            }
        }
        let mut invalid = caller.clone();
        invalid.peer = Default::default();
        for line in [
            "whoami",
            "unknown",
            "'unterminated",
            "ls | cat",
            "--json --json ls",
        ] {
            let (mut streams, mut stdout, mut stderr) = streams();
            assert_eq!(
                dispatch_session(&fixture.service, &invalid, line, &mut streams, &extras).await,
                4
            );
            drop(streams);
            let mut out = String::new();
            stdout.read_to_string(&mut out).await.unwrap();
            assert!(out.is_empty());
            stderr.read_to_string(&mut out).await.unwrap();
            assert_eq!(out, "Error: verified identity required\n");
        }
    }

    #[tokio::test]
    async fn tokenize_execute_grammar_table() {
        let fixture = fixture().await;
        let caller = caller("tag:ci", &[]);
        let extras = SessionExtras {
            prompt: None,
            approval_shown: None,
        };
        let mut mismatches = Vec::new();
        for (line, expected) in [
            ("", 2), ("unknown", 2), ("ls | cat", 2), ("--json --json ls", 2), ("--yes ls", 2), ("ls --json", 4),
            ("rm vm --yes --yes", 2), ("stop vm -- x", 2), ("ls -- x", 2),
            ("rm vm --yes --yes=false", 2), ("rm vm --yes=false --yes", 2), ("--yes rm vm --yes=false", 2), ("--yes=false rm vm --yes", 2),
            ("--yes=false rm vm", 4), ("--yes=true rm vm", 4), ("rm vm --yes=false --json", 4),
            ("-h", 0), ("--help", 0), ("-h bogus", 2), ("stop vm --help", 0), ("exec vm -h -- ls", 0), ("template -h", 0), ("template create -h", 0),
            ("create --name x -h", 0), ("create --name x --userdata -h", 4), ("exec vm -- -h", 4),
            ("template --owner tag:ci create --help", 0), ("policy --owner tag:ci create --help", 0),
            ("template --owner tag:ci bogus --help", 2), ("policy --owner --help bogus --help", 2),
            ("template --owner tag:ci --help", 0), ("create --userdata -- --help", 0),
            ("list", 4), ("new dev", 4), ("status", 2), ("ssh", 2), ("help list", 0),
            ("help", 0), ("help create", 0), ("help nope", 2), ("help a b", 2), ("version", 0), ("version extra", 2), ("whoami", 0), ("whoami x", 2),
            ("ls extra", 2), ("ls", 4), ("show", 2), ("show a b", 2), ("ops", 4), ("ops show", 2), ("ops list", 2), ("ops show op_1", 4),
            ("create", 4), ("create --cpus 2 dev", 4), ("create dev img --image other", 2), ("create dev img extra", 2),
            ("create dev --cpus", 2), ("create dev --cpus 0", 2), ("create dev --cpus x", 2), ("create dev --cpus 2 --cpus 2", 2),
            ("create dev --memory 1GiB --memory 1GiB", 2), ("create dev --memory 0", 4), ("create dev --disk 1GiB --disk-size 2GiB", 2),
            ("create dev --template ''", 2), ("create dev --image ''", 2), ("create dev --policy ''", 2), ("create dev --bogus", 2),
            ("create dev --label a", 2), ("create dev --label a=1 --label a=2", 2), ("create dev --provision-user nope", 2),
            ("create dev --no-start --no-start", 2), ("create dev --timeout 1s", 2),
            ("create dev", 4), ("create --name dev img", 4),
            ("create --name dev --image img --cpus 2 --memory 512MiB --disk-size 1GiB --tailscale --no-start", 4), ("create --no-tailnet", 2),
            ("create dev --label a=1 --label b=2 --owner tag:ci --template t --policy p --userdata '#!/bin/sh'", 4), ("create dev --userdata -", 4),
            ("start", 2), ("start a b", 2), ("restart", 2), ("reauth a --force", 2),
            ("stop", 2), ("stop vm --timeout", 2), ("stop vm --timeout soon", 2), ("stop vm --force --force", 2), ("stop vm --bogus", 2),
            ("rm", 2), ("rm vm extra", 2), ("rm vm --force --force", 2),
            ("set vm", 2), ("set vm cpus", 2), ("set vm cpus=0", 2), ("set vm cpus=300", 2), ("set vm cpus=2 cpus=3", 2), ("set vm bogus=1", 2),
            ("shell", 2), ("shell vm --json", 2), ("shell vm -w /", 2), ("shell vm -u", 2), ("shell vm -u root", 4), ("shell vm", 4),
            ("exec vm", 2), ("exec vm --", 2), ("exec vm -u -- cmd", 2), ("exec vm -e NOEQ -- cmd", 2), ("exec vm -x 1 -- cmd", 2), ("exec vm cmd", 2), ("exec vm --json -- cmd", 2),
            ("exec vm -- cmd --json", 4), ("exec vm -t -u root -w / -e A=1 -e B=2 -- /bin/sh -c 'printf x'", 4),
            ("logs", 2), ("logs vm --json", 2), ("logs vm --stream", 2), ("logs vm --output stdout --output stderr", 2), ("logs vm extra", 2),
            ("logs vm --follow --stream network-audit --output stderr", 4),
            ("template", 2), ("template bogus", 2), ("template show", 2), ("template ls extra", 2), ("template ls --owner", 2), ("template ls --owner tag:ci --owner tag:ci", 2),
            ("template ls", 4), ("template show name --owner tag:ci", 4), ("template create name", 4), ("template validate", 4), ("policy rm name", 4), ("policy validate --owner tag:ci", 4),
        ] {
            let (mut streams, mut stdout, mut stderr) = streams();
            let (_, window) = tokio::sync::watch::channel(Window::default());
            streams.terminal = Some(Terminal { term: "dumb".into(), window });
            let exit = dispatch_session(&fixture.service, &caller, line, &mut streams, &extras).await;
            drop(streams);
            let mut out = String::new();
            let mut human = String::new();
            stdout.read_to_string(&mut out).await.unwrap();
            stderr.read_to_string(&mut human).await.unwrap();
            if exit != expected { mismatches.push(format!("{line}: got {exit}, expected {expected}: {out}{human}")); }
        }
        assert!(mismatches.is_empty(), "{}", mismatches.join("\n"));
        assert!(fixture.service.jobs().list(&caller.peer).is_empty());
    }

    #[tokio::test]
    async fn safe_positional_diagnostics_and_copy_grammar() {
        let fixture = fixture().await;
        let caller = caller("user:123", &[]);
        let extras = SessionExtras {
            prompt: None,
            approval_shown: None,
        };
        for (line, command, reason) in [
            ("rm", "rm", "missing VM argument"),
            ("status", "show", "missing VM argument"),
            ("start", "start", "missing VM argument"),
            ("restart", "restart", "missing VM argument"),
            ("stop", "stop", "missing VM argument"),
            ("ssh", "shell", "missing VM argument"),
            ("logs", "logs", "missing VM argument"),
            ("exec vm", "exec", "missing CMD (after --) argument"),
            ("exec -- SECRET", "exec", "missing VM argument"),
            ("template create", "template", "missing NAME argument"),
            ("policy show", "policy", "missing NAME argument"),
            ("ops show", "ops", "missing OPERATION_ID argument"),
            ("set", "set", "missing VM argument"),
            ("set vm", "set", "missing KEY=VALUE argument"),
            ("whoami SECRET", "whoami", "unexpected positional argument"),
            (
                "version SECRET",
                "version",
                "unexpected positional argument",
            ),
            ("ls SECRET", "ls", "unexpected positional argument"),
            ("rm vm SECRET", "rm", "unexpected VM argument"),
            (
                "rm vm -- SECRET",
                "rm",
                "unexpected literal arguments after --",
            ),
            ("create image SECRET", "create", "unexpected IMAGE argument"),
            (
                "help rm vm SECRET",
                "help",
                "unexpected help topic argument",
            ),
        ] {
            let (mut streams, stdout, mut stderr) = streams();
            assert_eq!(
                dispatch_session(&fixture.service, &caller, line, &mut streams, &extras).await,
                2
            );
            drop(streams);
            drop(stdout);
            let mut human = String::new();
            stderr.read_to_string(&mut human).await.unwrap();
            assert_eq!(
                human,
                format!("Error: {command}: {reason}. See '{command} --help'.\n"),
                "{line}"
            );
            assert!(!human.contains("SECRET"));
        }
        for (line, reason) in [
            ("cp - -", "cp requires a VM endpoint (VM:/path)"),
            (
                "cp ./in.bin vm:/root/x",
                "the lobby has no access to your files",
            ),
            ("cp - vm:relative", "guest paths must be absolute"),
            ("cp --mode 8 - vm:/x", "invalid value for --mode"),
            ("cp --owner 1000: - vm:/x", "invalid value for --owner"),
            ("cp vm:/x other:/x", "cp copies between the host and one VM"),
            ("cp vm:/x - --parents", "upload-only"),
            ("cp --json vm:/x -", "--json is not supported"),
            (
                "cp - vm:/x --",
                "cp does not accept literal arguments after --",
            ),
        ] {
            let (mut streams, stdout, mut stderr) = streams();
            assert_eq!(
                dispatch_session(&fixture.service, &caller, line, &mut streams, &extras).await,
                2
            );
            drop(streams);
            drop(stdout);
            let mut human = String::new();
            stderr.read_to_string(&mut human).await.unwrap();
            assert!(human.contains(reason), "{line}: {human}");
        }
    }

    #[tokio::test]
    async fn all_help_forms_match_without_jobs_or_domain_access() {
        let fixture = fixture().await;
        let caller = caller("user:123", &[]);
        let extras = SessionExtras {
            prompt: None,
            approval_shown: None,
        };
        for command in crate::lobby::grammar::help::COMMANDS {
            for topic in std::iter::once(None).chain(command.subcommands.iter().copied().map(Some))
            {
                let path = topic.map_or_else(
                    || command.name.to_owned(),
                    |topic| format!("{} {topic}", command.name),
                );
                let mut rendered = Vec::new();
                for line in [format!("help {path}"), format!("{path} --help")] {
                    let (mut streams, stdout, mut stderr) = streams();
                    assert_eq!(
                        dispatch_session(&fixture.service, &caller, &line, &mut streams, &extras)
                            .await,
                        0,
                        "{line}"
                    );
                    drop(streams);
                    drop(stdout);
                    let mut human = String::new();
                    stderr.read_to_string(&mut human).await.unwrap();
                    for heading in ["\n\nUsage:\n  ", "\nOptions:\n  ", "\nExamples:\n  "] {
                        assert!(human.contains(heading), "{path}: {human}");
                    }
                    rendered.push(human);
                }
                assert_eq!(rendered[0], rendered[1], "{path}");
            }
        }
        assert!(fixture.service.jobs().list(&caller.peer).is_empty());
    }

    #[tokio::test]
    async fn removal_json_never_confirms_and_explicit_yes_removes_real_stopped_vm() {
        use crate::lobby::identity::Action;
        use crate::lobby::service::testing::stopped_vm;

        let fixture = fixture().await;
        stopped_vm(&fixture, "devbox", "user:7").await;
        let caller = caller("user:7", &[Action::Read, Action::Delete]);
        let extras = SessionExtras {
            prompt: None,
            approval_shown: None,
        };
        for line in [
            "rm devbox --json",
            "--yes=false rm devbox --json",
            "rm devbox --yes=0 --json",
        ] {
            let (mut streams, mut stdout, mut stderr) = streams();
            assert_eq!(
                dispatch_session(&fixture.service, &caller, line, &mut streams, &extras).await,
                2,
                "{line}"
            );
            drop(streams);
            let mut output = String::new();
            stdout.read_to_string(&mut output).await.unwrap();
            assert_eq!(
                serde_json::from_str::<serde_json::Value>(&output).unwrap(),
                json!({"ok":false,"error":{"code":"cancelled","message":"removal cancelled"}})
            );
            let mut human = String::new();
            stderr.read_to_string(&mut human).await.unwrap();
            assert_eq!(human, "Error: removal cancelled\n");
            assert!(fixture.service.show(&caller.peer, "devbox").await.is_ok());
            assert!(fixture.service.jobs().list(&caller.peer).is_empty());
        }
        let (mut streams, mut stdout, mut stderr) = streams();
        assert_eq!(
            dispatch_session(
                &fixture.service,
                &caller,
                "--yes=true rm devbox --json",
                &mut streams,
                &extras
            )
            .await,
            0
        );
        drop(streams);
        let mut output = String::new();
        stdout.read_to_string(&mut output).await.unwrap();
        let response: serde_json::Value = serde_json::from_str(&output).unwrap();
        assert_eq!(response["ok"], true);
        assert_eq!(response["data"]["kind"], "remove");
        assert_eq!(response["data"]["state"], "succeeded");
        assert!(response["data"]["id"].as_str().unwrap().starts_with("op_"));
        let mut human = String::new();
        stderr.read_to_string(&mut human).await.unwrap();
        assert!(human.is_empty());
        assert_eq!(
            fixture
                .service
                .show(&caller.peer, "devbox")
                .await
                .unwrap_err()
                .code,
            Code::NotFound
        );
    }
}
