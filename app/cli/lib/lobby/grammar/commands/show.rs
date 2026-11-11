use futures::future::BoxFuture;

use crate::lobby::failure::Outcome;
use crate::lobby::grammar::cmdline::Args;
use crate::lobby::grammar::commands::{positional, result, Context, Handler, Result};
use crate::lobby::grammar::render;

pub(crate) struct Show;

impl Handler for Show {
    fn run<'a>(
        self: Box<Self>,
        c: &'a mut Context<'_>,
        args: Args,
    ) -> BoxFuture<'a, Outcome<Result>> {
        Box::pin(async move {
            let reference = positional("show", args.one("VM"))?;
            let vm = c.service.show(&c.caller.peer, reference).await?;
            if !vm.approval_url.is_empty() {
                if let Some(shown) = &c.extras.approval_shown {
                    shown(&vm.id, &vm.approval_url);
                }
            }
            let mut human = render::render_show(&vm);
            if vm.state == "running" {
                human += &render::connection_hints(
                    &render::safe_text(&c.service.config().lobby_hostname),
                    &render::safe_text(&vm.name),
                    &render::safe_text(&vm.default_user),
                    &render::safe_text(&vm.node),
                    vm.node_state == "enrolled",
                );
            }
            result(vm, human)
        })
    }
}
