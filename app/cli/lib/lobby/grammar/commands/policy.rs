use futures::future::BoxFuture;

use crate::lobby::failure::Outcome;
use crate::lobby::grammar::cmdline::{Args, FlagSet};
use crate::lobby::grammar::commands::{template, Context, Handler, Result};
use crate::lobby::identity::Principal;

#[derive(Default)]
pub(crate) struct Policy {
    owner: Option<Principal>,
}

impl Handler for Policy {
    fn flags<'a>(&'a mut self, flags: &mut FlagSet<'a>) {
        template::owner_flag(&mut self.owner, flags);
    }
    fn run<'a>(
        self: Box<Self>,
        c: &'a mut Context<'_>,
        args: Args,
    ) -> BoxFuture<'a, Outcome<Result>> {
        Box::pin(template::run(c, args, "policy", self.owner))
    }
}
