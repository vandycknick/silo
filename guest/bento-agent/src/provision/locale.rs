use crate::provision::{write_file, ProvisionContext};

pub(crate) fn apply(context: &ProvisionContext, locale: Option<&str>) -> eyre::Result<()> {
    let Some(locale) = locale.map(str::trim).filter(|locale| !locale.is_empty()) else {
        return Ok(());
    };

    write_file(
        &context.guest_path("/etc/default/locale"),
        format!("LANG={locale}\n"),
        0o644,
    )?;
    tracing::info!(locale, "reconciled locale");
    Ok(())
}
