use futures::future::BoxFuture;

use crate::lobby::failure::Outcome;
use crate::lobby::grammar::cmdline::Args;
use crate::lobby::grammar::commands::{positional, result, Context, Handler, Result};
use crate::lobby::grammar::render;

pub(crate) struct Whoami;

impl Handler for Whoami {
    fn run<'a>(
        self: Box<Self>,
        c: &'a mut Context<'_>,
        args: Args,
    ) -> BoxFuture<'a, Outcome<Result>> {
        Box::pin(async move {
            positional("whoami", args.none())?;
            let who = c.service.whoami(&c.caller.peer)?;
            let human = render::render_who_am_i(&who);
            result(who, human)
        })
    }
}
