use futures::future::BoxFuture;

use crate::lobby::failure::Outcome;
use crate::lobby::grammar::cmdline::{Args, FlagSet};
use crate::lobby::grammar::commands::{positional, Context, Handler, Result};

#[derive(Default)]
pub(crate) struct Shell {
    user: String,
}

impl Handler for Shell {
    fn flags<'a>(&'a mut self, flags: &mut FlagSet<'a>) {
        flags.string("u", "USER", &mut self.user);
    }
    fn run<'a>(
        self: Box<Self>,
        c: &'a mut Context<'_>,
        args: Args,
    ) -> BoxFuture<'a, Outcome<Result>> {
        Box::pin(async move {
            let reference = positional("shell", args.one("VM"))?;
            let exit = c
                .service
                .shell(&c.caller, reference, &self.user, c.streams, c.extras)
                .await?;
            Ok(Result {
                exit,
                ..Result::default()
            })
        })
    }
}
