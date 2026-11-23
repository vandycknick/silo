use futures::future::BoxFuture;

use crate::lobby::failure::Outcome;
use crate::lobby::grammar::cmdline::{self, Args, FlagSet};
use crate::lobby::grammar::commands::{positional, Context, Handler, Result};
use crate::lobby::service::streams::ExecRequest;

#[derive(Default)]
pub(crate) struct Exec {
    request: ExecRequest,
}

impl Handler for Exec {
    fn flags<'a>(&'a mut self, flags: &mut FlagSet<'a>) {
        flags.string("u", "USER", &mut self.request.user);
        flags.string("w", "DIR", &mut self.request.directory);
        flags.repeat("e", "K=V", cmdline::key_value(&mut self.request.env));
        flags.bool("t", &mut self.request.tty);
    }
    fn run<'a>(
        mut self: Box<Self>,
        c: &'a mut Context<'_>,
        mut args: Args,
    ) -> BoxFuture<'a, Outcome<Result>> {
        Box::pin(async move {
            let positionals = Args {
                positional: args.positional,
                ..Args::default()
            };
            let reference = positional("exec", positionals.one("VM"))?;
            if !args.delimited || args.literal.is_empty() {
                return positional("exec", Err(cmdline::missing("CMD (after --)")));
            }
            let mut literal = args.literal.drain(..);
            self.request.program = literal.next().ok_or_else(|| {
                crate::lobby::grammar::commands::usage("missing CMD (after --) argument")
            })?;
            self.request.args = literal.collect();
            let exit = c
                .service
                .exec(&c.caller, reference, self.request, c.streams)
                .await?;
            Ok(Result {
                exit,
                ..Result::default()
            })
        })
    }
}
