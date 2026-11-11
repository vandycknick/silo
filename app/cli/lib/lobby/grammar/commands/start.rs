use futures::future::BoxFuture;

use crate::lobby::failure::Outcome;
use crate::lobby::grammar::cmdline::Args;
use crate::lobby::grammar::commands::{positional, Context, Handler, Result};

pub(crate) struct Start;

impl Handler for Start {
    fn run<'a>(
        self: Box<Self>,
        c: &'a mut Context<'_>,
        args: Args,
    ) -> BoxFuture<'a, Outcome<Result>> {
        Box::pin(async move {
            let reference = positional("start", args.one("VM"))?;
            let operation = c.service.start(&c.caller, reference).await?;
            c.await_operation(operation).await
        })
    }
}
