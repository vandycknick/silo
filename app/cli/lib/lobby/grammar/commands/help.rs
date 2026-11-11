use std::collections::BTreeMap;

use futures::future::BoxFuture;

use crate::lobby::failure::Outcome;
use crate::lobby::grammar::cmdline::{self, Args};
use crate::lobby::grammar::commands::{positional, result, usage, Context, Handler, Result};
use crate::lobby::grammar::help;

pub(crate) struct Help;

impl Handler for Help {
    fn run<'a>(
        self: Box<Self>,
        c: &'a mut Context<'_>,
        args: Args,
    ) -> BoxFuture<'a, Outcome<Result>> {
        Box::pin(async move {
            positional("help", args.no_literal())?;
            if args.positional.len() > 2 {
                return positional("help", Err(cmdline::unexpected("help topic")));
            }
            help_for(c, &args.positional)
        })
    }
}

pub(crate) fn help_for(c: &Context<'_>, path: &[String]) -> Outcome<Result> {
    let text = if path.is_empty() {
        help::help()
    } else {
        let path: Vec<_> = path.iter().map(String::as_str).collect();
        let defaults: BTreeMap<String, String> = c.service.help_defaults();
        help::detailed_help(&path, &defaults).ok_or_else(|| usage("unknown command"))?
    };
    result(serde_json::json!({"help": text}), text)
}
