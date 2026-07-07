use crate::provision::{write_file, ProvisionContext, ProvisionOutcome};

pub(crate) fn apply(
    context: &ProvisionContext,
    locale: Option<&str>,
) -> eyre::Result<ProvisionOutcome> {
    let Some(locale) = locale.map(str::trim).filter(|locale| !locale.is_empty()) else {
        return Ok(ProvisionOutcome::skipped("no locale configured"));
    };

    write_file(
        &context.guest_path("/etc/default/locale"),
        format!("LANG={locale}\n"),
        0o644,
    )?;
    tracing::info!(locale, "reconciled locale");
    Ok(ProvisionOutcome::succeeded(false))
}
