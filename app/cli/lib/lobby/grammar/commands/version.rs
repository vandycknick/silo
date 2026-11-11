use futures::future::BoxFuture;

use crate::lobby::failure::Outcome;
use crate::lobby::grammar::cmdline::Args;
use crate::lobby::grammar::commands::{positional, result, Context, Handler, Result};
use crate::lobby::grammar::render;

pub(crate) struct Version;

impl Handler for Version {
    fn run<'a>(
        self: Box<Self>,
        c: &'a mut Context<'_>,
        args: Args,
    ) -> BoxFuture<'a, Outcome<Result>> {
        Box::pin(async move {
            positional("version", args.none())?;
            let version = c.service.versions();
            let human = render::render_version(&version);
            result(version, human)
        })
    }
}
