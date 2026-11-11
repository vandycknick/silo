use futures::future::BoxFuture;

use crate::lobby::failure::Outcome;
use crate::lobby::grammar::cmdline::Args;
use crate::lobby::grammar::commands::{positional, result, Context, Handler, Result};
use crate::lobby::grammar::render;

pub(crate) struct Ls;

impl Handler for Ls {
    fn run<'a>(
        self: Box<Self>,
        c: &'a mut Context<'_>,
        args: Args,
    ) -> BoxFuture<'a, Outcome<Result>> {
        Box::pin(async move {
            positional("ls", args.none())?;
            let vms = c.service.list(&c.caller.peer).await?;
            let human = render::render_list(&vms);
            result(vms, human)
        })
    }
}
