use futures::future::BoxFuture;
use silod_spec::daemon::v1::User;

use crate::lobby::failure::Outcome;
use crate::lobby::grammar::cmdline::{self, Args, FlagSet, ValueError};
use crate::lobby::grammar::commands::{positional, usage, Context, Handler, Result};
use crate::lobby::identity::{Action, Principal};
use crate::lobby::service::create::CreateRequest;
use crate::lobby::service::documents::valid_document_name;

#[derive(Default)]
pub(crate) struct Create {
    request: CreateRequest,
    image_set: bool,
}

impl Handler for Create {
    fn flags<'a>(&'a mut self, flags: &mut FlagSet<'a>) {
        let name = flags.value("name", "NAME", |text| {
            if !valid_document_name(text) {
                return Err(ValueError::Invalid);
            }
            self.request.name = text.into();
            Ok(())
        });
        flags.alias("n", name);
        flags.value("image", "OCI", |text| {
            if text.is_empty() {
                return Err(ValueError::Invalid);
            }
            self.request.image = text.into();
            self.image_set = true;
            Ok(())
        });
        flags.value(
            "template",
            "NAME",
            cmdline::non_empty(&mut self.request.template),
        );
        flags.value(
            "policy",
            "NAME",
            cmdline::non_empty(&mut self.request.policy_ref),
        );
        flags.value("cpus", "N", cmdline::count(&mut self.request.cpus));
        flags.value(
            "memory",
            "SIZE",
            cmdline::non_empty(&mut self.request.memory_text),
        );
        let disk = flags.value(
            "disk",
            "SIZE",
            cmdline::non_empty(&mut self.request.disk_text),
        );
        flags.alias("disk-size", disk);
        flags.value("provision-user", "NAME:UID:GID:HOME", |text| {
            let user = crate::commands::create::parse_explicit_user(text)
                .map_err(|_| ValueError::Invalid)?;
            self.request.guest_user = Some(User {
                name: user.name,
                uid: user.uid,
                gid: user.gid,
                home: user.home,
            });
            Ok(())
        });
        flags.value("userdata", "INLINE|-", |text| {
            self.request.userdata = text.into();
            self.request.userdata_set = true;
            Ok(())
        });
        flags.repeat("label", "K=V", |text| {
            let (key, value) = text.split_once('=').ok_or(ValueError::Invalid)?;
            if self.request.labels.contains_key(key) {
                return Err(ValueError::Invalid);
            }
            self.request.labels.insert(key.into(), value.into());
            Ok(())
        });
        flags.value("owner", "tag:NAME", |text| {
            self.request.owner = Some(Principal::parse(text).map_err(|_| ValueError::Invalid)?);
            Ok(())
        });
        flags.bool("tailscale", &mut self.request.tailscale);
        flags.repeat("tag", "tag:NAME", |text| {
            let principal =
                Principal::parse(&text.to_lowercase()).map_err(|_| ValueError::Invalid)?;
            if !principal.is_tag() {
                return Err(ValueError::Invalid);
            }
            self.request.tags.push(principal.to_string());
            Ok(())
        });
        flags.bool("no-start", &mut self.request.no_start);
    }

    fn run<'a>(
        mut self: Box<Self>,
        c: &'a mut Context<'_>,
        args: Args,
    ) -> BoxFuture<'a, Outcome<Result>> {
        Box::pin(async move {
            positional("create", args.no_literal())?;
            if args.positional.len() > 1 {
                return positional("create", Err(cmdline::unexpected("IMAGE")));
            }
            if let Some(image) = args.positional.into_iter().next() {
                if self.image_set {
                    return Err(usage("IMAGE and --image cannot be supplied together"));
                }
                if image.is_empty() {
                    return Err(usage("invalid IMAGE"));
                }
                self.request.image = image;
            }
            if self.request.userdata_set && self.request.userdata == "-" {
                self.request.userdata = String::from_utf8(c.document(Action::Create, 16384).await?)
                    .map_err(|_| usage("userdata must be UTF-8"))?;
            }
            let operation = c.service.create(&c.caller, self.request).await?;
            c.await_operation(operation).await
        })
    }
}

#[cfg(test)]
mod tests {
    use crate::lobby::grammar::cmdline::FlagSet;
    use crate::lobby::grammar::commands::{create::Create, Handler};

    #[test]
    fn options_remain_pure_and_defaults_are_not_applied() {
        let mut handler = Create::default();
        let mut flags = FlagSet::new();
        handler.flags(&mut flags);
        flags
            .parse(&["--userdata".into(), "--".into(), "image".into()])
            .unwrap();
        drop(flags);
        assert!(handler.request.userdata_set);
        assert_eq!(handler.request.userdata, "--");
        assert_eq!(handler.request.cpus, 0);
        assert!(handler.request.memory_text.is_empty());
        assert!(!handler.request.tailscale);
    }

    #[test]
    fn invalid_options_do_not_disclose_values() {
        for args in [
            vec!["--cpus", "SECRET"],
            vec!["--provision-user", "SECRET"],
            vec!["--tag", "SECRET"],
            vec!["--label", "SECRET"],
        ] {
            let mut handler = Create::default();
            let mut flags = FlagSet::new();
            handler.flags(&mut flags);
            let args: Vec<String> = args.into_iter().map(str::to_owned).collect();
            let error = flags.parse(&args).unwrap_err();
            assert!(!error.to_string().contains("SECRET"));
        }
    }
}
