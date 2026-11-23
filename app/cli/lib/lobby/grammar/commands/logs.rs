use futures::future::BoxFuture;

use crate::lobby::failure::Outcome;
use crate::lobby::grammar::cmdline::{Args, FlagSet};
use crate::lobby::grammar::commands::{positional, Context, Handler, Result};
use crate::lobby::service::streams::LogsRequest;

#[derive(Default)]
pub(crate) struct Logs {
    request: LogsRequest,
}

impl Handler for Logs {
    fn flags<'a>(&'a mut self, flags: &mut FlagSet<'a>) {
        flags.bool("follow", &mut self.request.follow);
        flags.value("stream", "STREAM", |value| {
            self.request.source = if value == "network-audit" {
                "network_audit".into()
            } else {
                value.into()
            };
            Ok(())
        });
        flags.string("output", "OUTPUT", &mut self.request.output);
    }
    fn run<'a>(
        self: Box<Self>,
        c: &'a mut Context<'_>,
        args: Args,
    ) -> BoxFuture<'a, Outcome<Result>> {
        Box::pin(async move {
            let reference = positional("logs", args.one("VM"))?;
            c.service
                .logs(&c.caller, reference, self.request, c.streams)
                .await?;
            Ok(Result::default())
        })
    }
}

#[cfg(test)]
mod tests {
    use crate::lobby::grammar::cmdline::FlagSet;
    use crate::lobby::grammar::commands::{logs::Logs, Handler};

    #[test]
    fn declarations_leave_domain_defaults_untouched() {
        let mut handler = Logs::default();
        let mut flags = FlagSet::new();
        handler.flags(&mut flags);
        flags.parse(&[]).unwrap();
        drop(flags);
        assert!(!handler.request.follow);
        assert!(handler.request.source.is_empty());
        assert!(handler.request.output.is_empty());
    }

    #[test]
    fn cli_network_audit_spelling_maps_to_wire_source() {
        let mut handler = Logs::default();
        let mut flags = FlagSet::new();
        handler.flags(&mut flags);
        flags
            .parse(&["--stream".into(), "network-audit".into()])
            .unwrap();
        drop(flags);
        assert_eq!(handler.request.source, "network_audit");
    }
}
