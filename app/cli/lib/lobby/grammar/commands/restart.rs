use futures::future::BoxFuture;

use crate::lobby::failure::Outcome;
use crate::lobby::grammar::cmdline::Args;
use crate::lobby::grammar::commands::{positional, Context, Handler, Result};

pub(crate) struct Restart;

impl Handler for Restart {
    fn run<'a>(
        self: Box<Self>,
        c: &'a mut Context<'_>,
        args: Args,
    ) -> BoxFuture<'a, Outcome<Result>> {
        Box::pin(async move {
            let reference = positional("restart", args.one("VM"))?;
            let operation = c.service.restart(&c.caller, reference).await?;
            c.await_operation(operation).await
        })
    }
}
