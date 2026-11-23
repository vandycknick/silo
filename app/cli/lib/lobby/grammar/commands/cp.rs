use futures::future::BoxFuture;

use crate::lobby::failure::Outcome;
use crate::lobby::grammar::cmdline::{Args, FlagSet, ValueError};
use crate::lobby::grammar::commands::{usage, Context, Handler, Result};
use crate::lobby::service::files::{parse_endpoint, CopyRequest};

#[derive(Default)]
pub(crate) struct Copy {
    request: CopyRequest,
}

#[derive(Debug, PartialEq, Eq)]
enum Endpoint {
    Stdio,
    Local,
    Guest { vm: String, path: String },
}

fn endpoint(text: &str) -> Outcome<Endpoint> {
    if text == "-" {
        return Ok(Endpoint::Stdio);
    }
    if text.starts_with("./") || text.starts_with('/') || !text.contains(':') {
        return Ok(Endpoint::Local);
    }
    let (vm, path) = text
        .split_once(':')
        .ok_or_else(|| usage("expected VM:/absolute/path"))?;
    if vm.is_empty() || path.contains(':') {
        return Err(usage(
            "ambiguous endpoint; use VM:/absolute/path or prefix a local path with ./",
        ));
    }
    if !path.starts_with('/') {
        return Err(usage("guest paths must be absolute (VM:/path)"));
    }
    let (vm, path) = parse_endpoint(text)?;
    Ok(Endpoint::Guest { vm, path })
}

fn mode(text: &str) -> std::result::Result<u32, ValueError> {
    if text.is_empty() || !text.bytes().all(|byte| matches!(byte, b'0'..=b'7')) {
        return Err(ValueError::Invalid);
    }
    u32::from_str_radix(text, 8)
        .ok()
        .filter(|mode| *mode <= 0o7777)
        .ok_or(ValueError::Invalid)
}

fn owner(text: &str) -> std::result::Result<(u32, Option<u32>), ValueError> {
    fn numeric(text: &str) -> std::result::Result<u32, ValueError> {
        if text.is_empty() || !text.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err(ValueError::Invalid);
        }
        text.parse().map_err(|_| ValueError::Invalid)
    }
    match text.split_once(':') {
        Some((uid, gid)) => Ok((numeric(uid)?, Some(numeric(gid)?))),
        None => Ok((numeric(text)?, None)),
    }
}

impl Handler for Copy {
    fn flags<'a>(&'a mut self, flags: &mut FlagSet<'a>) {
        flags.value("mode", "OCTAL", |text| {
            self.request.mode = Some(mode(text)?);
            Ok(())
        });
        flags.value("owner", "UID[:GID]", |text| {
            let (uid, gid) = owner(text)?;
            self.request.uid = Some(uid);
            self.request.gid = gid;
            Ok(())
        });
        let parents = flags.bool("p", &mut self.request.parents);
        flags.alias("parents", parents);
        let no_clobber = flags.bool("n", &mut self.request.no_clobber);
        flags.alias("no-clobber", no_clobber);
    }

    fn run<'a>(
        mut self: Box<Self>,
        c: &'a mut Context<'_>,
        args: Args,
    ) -> BoxFuture<'a, Outcome<Result>> {
        Box::pin(async move {
            if args.delimited {
                return Err(usage("cp does not accept literal arguments after --"));
            }
            let [source, destination] = args.positional.as_slice() else {
                return Err(usage("cp requires SRC and DST"));
            };
            let source = endpoint(source)?;
            let destination = endpoint(destination)?;
            if source == Endpoint::Local || destination == Endpoint::Local {
                return Err(usage(
                    "the lobby has no access to your files; use - and redirect stdin/stdout",
                ));
            }
            match (source, destination) {
                (Endpoint::Stdio, Endpoint::Guest { vm, path }) => {
                    self.request.vm = vm;
                    self.request.path = path;
                    self.request.upload = true;
                    c.service
                        .copy_to_vm(&c.caller, self.request, c.streams)
                        .await?;
                }
                (Endpoint::Guest { vm, path }, Endpoint::Stdio) => {
                    if self.request.mode.is_some()
                        || self.request.uid.is_some()
                        || self.request.parents
                        || self.request.no_clobber
                    {
                        return Err(usage(
                            "--mode, --owner, --parents and --no-clobber are upload-only",
                        ));
                    }
                    self.request.vm = vm;
                    self.request.path = path;
                    c.service
                        .copy_from_vm(&c.caller, self.request, c.streams)
                        .await?;
                }
                (Endpoint::Guest { .. }, Endpoint::Guest { .. }) => {
                    return Err(usage("cp copies between the host and one VM"))
                }
                _ => return Err(usage("cp requires a VM endpoint (VM:/path)")),
            }
            Ok(Result::default())
        })
    }
}

#[cfg(test)]
mod tests {
    use crate::lobby::grammar::cmdline::FlagSet;
    use crate::lobby::grammar::commands::{
        cp::{endpoint, mode, owner, Copy, Endpoint},
        Handler,
    };

    #[test]
    fn copy_endpoints_and_numeric_options() {
        for text in ["./file:part", "/file:part", "file"] {
            assert_eq!(endpoint(text).unwrap(), Endpoint::Local);
        }
        assert_eq!(endpoint("-").unwrap(), Endpoint::Stdio);
        assert_eq!(
            endpoint("vm:/root/x").unwrap(),
            Endpoint::Guest {
                vm: "vm".into(),
                path: "/root/x".into()
            }
        );
        for text in [":/x", "vm:/x:y", "vm:relative"] {
            assert!(endpoint(text).is_err(), "{text}");
        }
        assert_eq!(mode("0755").unwrap(), 0o755);
        assert_eq!(mode("0000").unwrap(), 0);
        assert_eq!(mode("7777").unwrap(), 0o7777);
        for text in ["", "8", "10000", "-1", "+755", "4294967296"] {
            assert!(mode(text).is_err(), "{text}");
        }
        assert_eq!(owner("1000").unwrap(), (1000, None));
        assert_eq!(owner("1000:1001").unwrap(), (1000, Some(1001)));
        for text in ["", "-1", "+1", "4294967296", "1:2:3", "1000:"] {
            assert!(owner(text).is_err(), "{text}");
        }
        let mut handler = Copy::default();
        let mut flags = FlagSet::new();
        handler.flags(&mut flags);
        assert!(flags.parse(&["-p".into(), "--parents".into()]).is_err());
    }
}
