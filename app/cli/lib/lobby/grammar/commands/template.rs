use futures::future::BoxFuture;

use crate::lobby::failure::Outcome;
use crate::lobby::grammar::cmdline::{self, Args, FlagSet, ValueError};
use crate::lobby::grammar::commands::{positional, result, usage, Context, Handler, Result};
use crate::lobby::grammar::render;
use crate::lobby::identity::{Action, Principal};
use crate::lobby::service::documents::DOCUMENT_LIMIT;

#[derive(Default)]
pub(crate) struct Template {
    owner: Option<Principal>,
}

pub(crate) fn owner_flag<'a>(owner: &'a mut Option<Principal>, flags: &mut FlagSet<'a>) {
    flags.value("owner", "tag:NAME", move |text| {
        *owner = Some(Principal::parse(text).map_err(|_| ValueError::Invalid)?);
        Ok(())
    });
}

impl Handler for Template {
    fn flags<'a>(&'a mut self, flags: &mut FlagSet<'a>) {
        owner_flag(&mut self.owner, flags);
    }
    fn run<'a>(
        self: Box<Self>,
        c: &'a mut Context<'_>,
        args: Args,
    ) -> BoxFuture<'a, Outcome<Result>> {
        Box::pin(run(c, args, "template", self.owner))
    }
}

pub(crate) async fn run(
    c: &mut Context<'_>,
    args: Args,
    kind: &str,
    owner: Option<Principal>,
) -> Outcome<Result> {
    positional(kind, args.no_literal())?;
    let Some((verb, tail)) = args.positional.split_first() else {
        return positional(kind, Err(cmdline::missing("SUBCOMMAND")));
    };
    let tail = Args {
        positional: tail.to_vec(),
        ..Args::default()
    };
    let name = match verb.as_str() {
        "ls" | "validate" => {
            positional(kind, tail.none())?;
            ""
        }
        "show" | "create" | "edit" | "rm" => positional(kind, tail.one("NAME"))?,
        _ => {
            return Err(usage(format!(
                "{kind}: unknown SUBCOMMAND. See '{kind} --help'."
            )))
        }
    };
    let raw = if matches!(verb.as_str(), "create" | "edit" | "validate") {
        let action = if verb == "validate" {
            Action::Read
        } else {
            Action::TemplateManage
        };
        String::from_utf8(c.document(action, DOCUMENT_LIMIT).await?)
            .map_err(|_| usage("document input must be UTF-8"))?
    } else {
        String::new()
    };
    let documents: Vec<crate::lobby::views::DocumentView> = c
        .service
        .documents(&c.caller, kind, verb, name, owner.as_ref(), &raw)
        .await?
        .into_iter()
        .map(Into::into)
        .collect();
    let human = render::render_documents(verb, &documents);
    result(documents, human)
}
