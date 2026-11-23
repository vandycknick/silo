use futures::future::BoxFuture;

use crate::lobby::failure::Outcome;
use crate::lobby::grammar::cmdline::Args;
use crate::lobby::grammar::commands::{positional, result, usage, Context, Handler, Result};
use crate::lobby::grammar::render;

pub(crate) struct Ops;

impl Handler for Ops {
    fn run<'a>(
        self: Box<Self>,
        c: &'a mut Context<'_>,
        args: Args,
    ) -> BoxFuture<'a, Outcome<Result>> {
        Box::pin(async move {
            positional("ops", args.no_literal())?;
            let id = match args.positional.split_first() {
                None => String::new(),
                Some((verb, tail)) if verb == "show" => positional(
                    "ops",
                    Args {
                        positional: tail.to_vec(),
                        ..Args::default()
                    }
                    .one("OPERATION_ID"),
                )?
                .to_owned(),
                _ => return Err(usage("ops: unknown SUBCOMMAND. See 'ops --help'.")),
            };
            let operations = c.service.ops(&c.caller.peer, &id)?;
            let mut human = render::render_ops(&operations);
            if !id.is_empty() {
                for operation in &operations {
                    if let Some(error) = &operation.error {
                        human += &format!("\nError: {}\n", error.message);
                    }
                    if operation.finished.is_none() {
                        for line in &operation.progress {
                            if let Some(url) = line.strip_prefix("approve: ") {
                                human += &format!("\nLogin\n  {url}\n");
                            }
                        }
                    }
                }
            }
            result(operations, human)
        })
    }
}
