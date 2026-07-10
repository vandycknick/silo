use crate::provision::{
    write_file, ProvisionContext, ProvisionOutcome, Provisioner, ProvisionerId,
};

pub(crate) struct Locale<'a> {
    locale: Option<&'a str>,
}

impl<'a> Provisioner<'a> for Locale<'a> {
    type Config = Option<String>;

    fn init(config: &'a Self::Config) -> Self {
        Self {
            locale: config
                .as_deref()
                .map(str::trim)
                .filter(|locale| !locale.is_empty()),
        }
    }

    fn id(&self) -> ProvisionerId {
        ProvisionerId::LOCALE
    }

    fn apply(&self, context: &ProvisionContext) -> eyre::Result<ProvisionOutcome> {
        let Some(locale) = self.locale else {
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
}
