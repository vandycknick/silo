use std::collections::BTreeSet;

use futures::future::BoxFuture;

use crate::lobby::failure::Outcome;
use crate::lobby::grammar::cmdline::{self, Args};
use crate::lobby::grammar::commands::{positional, usage, Context, Handler, Result};
use crate::lobby::service::lifecycle::SetRequest;

pub(crate) struct Set;

impl Handler for Set {
    fn run<'a>(
        self: Box<Self>,
        c: &'a mut Context<'_>,
        args: Args,
    ) -> BoxFuture<'a, Outcome<Result>> {
        Box::pin(async move {
            positional("set", args.no_literal())?;
            let Some((reference, settings)) = args.positional.split_first() else {
                return positional("set", Err(cmdline::missing("VM")));
            };
            if settings.is_empty() {
                return positional("set", Err(cmdline::missing("KEY=VALUE")));
            }
            let mut request = SetRequest::default();
            let mut seen = BTreeSet::new();
            for setting in settings {
                let (key, value) = setting
                    .split_once('=')
                    .ok_or_else(|| usage("set expects KEY=VALUE"))?;
                if !seen.insert(key) {
                    return Err(usage("duplicate setting"));
                }
                match key {
                    "name" => request.name = Some(value.into()),
                    "policy" if value.is_empty() => request.clear_policy = true,
                    "policy" => request.policy_ref = Some(value.into()),
                    "cpus" => {
                        let mut count = 0;
                        cmdline::count(&mut count)(value)
                            .map_err(|error| usage(format!("invalid cpus setting: {error}")))?;
                        request.cpus =
                            Some(u8::try_from(count).map_err(|_| usage("invalid cpus setting"))?);
                    }
                    "memory" => request.memory = Some(c.service.parse_resource(key, value).await?),
                    "disk" => request.disk = Some(c.service.parse_resource(key, value).await?),
                    _ => {
                        return Err(usage(
                            "unknown setting; expected name, cpus, memory, disk or policy",
                        ))
                    }
                }
            }
            let operation = c.service.set(&c.caller, reference, request).await?;
            c.await_operation(operation).await
        })
    }
}
