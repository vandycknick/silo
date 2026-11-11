use futures::future::BoxFuture;

use crate::lobby::failure::Outcome;
use crate::lobby::grammar::cmdline::{self, Args, FlagSet};
use crate::lobby::grammar::commands::{positional, Context, Handler, Result};
use crate::lobby::service::lifecycle::StopRequest;

#[derive(Default)]
pub(crate) struct Stop {
    request: StopRequest,
}

impl Handler for Stop {
    fn flags<'a>(&'a mut self, flags: &mut FlagSet<'a>) {
        flags.bool("force", &mut self.request.force);
        flags.value(
            "timeout",
            "DURATION",
            cmdline::duration(&mut self.request.timeout),
        );
    }
    fn run<'a>(
        self: Box<Self>,
        c: &'a mut Context<'_>,
        args: Args,
    ) -> BoxFuture<'a, Outcome<Result>> {
        Box::pin(async move {
            let reference = positional("stop", args.one("VM"))?;
            let operation = c.service.stop(&c.caller, reference, self.request).await?;
            c.await_operation(operation).await
        })
    }
}
