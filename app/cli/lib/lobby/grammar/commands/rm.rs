use futures::future::BoxFuture;

use crate::lobby::failure::{Code, Failure, Outcome};
use crate::lobby::grammar::cmdline::{Args, FlagSet};
use crate::lobby::grammar::commands::{positional, Context, Handler, Result};
use crate::lobby::service::lifecycle::RemoveRequest;

#[derive(Default)]
pub(crate) struct Remove {
    request: RemoveRequest,
    yes: bool,
}

impl Handler for Remove {
    fn flags<'a>(&'a mut self, flags: &mut FlagSet<'a>) {
        flags.bool("force", &mut self.request.force);
        flags.bool("yes", &mut self.yes);
    }
    fn run<'a>(
        self: Box<Self>,
        c: &'a mut Context<'_>,
        args: Args,
    ) -> BoxFuture<'a, Outcome<Result>> {
        Box::pin(async move {
            let reference = positional("rm", args.one("VM"))?;
            let target = c
                .service
                .preflight_remove(&c.caller, reference, self.request.force)
                .await?;
            if !(self.yes || c.confirm(&target).await) || c.streams.cancel.is_cancelled() {
                return Err(Failure::new(Code::Cancelled, "removal cancelled"));
            }
            let operation = c
                .service
                .remove(&c.caller, &target.id, self.request)
                .await?;
            c.await_operation(operation).await
        })
    }
}
