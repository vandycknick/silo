use std::path::Path;

use crate::constants::{
    DEFAULT_HOST_LOCALE, DEFAULT_HOST_TIMEZONE, HOST_LOCALTIME_PATH, HOST_TIMEZONE_PATH,
};

pub(crate) fn current_timezone() -> String {
    if let Some(timezone) = std::env::var("TZ")
        .ok()
        .and_then(|value| timezone_from_tz_env(&value))
    {
        return timezone;
    }

    if let Some(timezone) = std::fs::read_link(HOST_LOCALTIME_PATH)
        .ok()
        .and_then(|target| timezone_from_localtime_target(&target))
    {
        return timezone;
    }

    if let Some(timezone) = std::fs::read_to_string(HOST_TIMEZONE_PATH)
        .ok()
        .and_then(|contents| timezone_from_timezone_file(&contents))
    {
        return timezone;
    }

    DEFAULT_HOST_TIMEZONE.to_string()
}

pub(crate) fn current_locale() -> String {
    locale_from_env(
        std::env::var("LC_ALL").ok().as_deref(),
        std::env::var("LANG").ok().as_deref(),
    )
    .unwrap_or_else(|| DEFAULT_HOST_LOCALE.to_string())
}

fn timezone_from_tz_env(value: &str) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.trim_start_matches(':').to_string())
    }
}

fn timezone_from_localtime_target(path: &Path) -> Option<String> {
    let rendered = path.to_string_lossy();
    let (_, timezone) = rendered.split_once("zoneinfo/")?;
    let timezone = timezone.trim_matches('/');
    if timezone.is_empty() {
        None
    } else {
        Some(timezone.to_string())
    }
}

fn timezone_from_timezone_file(contents: &str) -> Option<String> {
    let timezone = contents.lines().next()?.trim();
    if timezone.is_empty() {
        None
    } else {
        Some(timezone.to_string())
    }
}

fn locale_from_env(lc_all: Option<&str>, lang: Option<&str>) -> Option<String> {
    [lc_all, lang]
        .into_iter()
        .flatten()
        .map(str::trim)
        .find(|value| !value.is_empty())
        .map(str::to_string)
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::{
        locale_from_env, timezone_from_localtime_target, timezone_from_timezone_file,
        timezone_from_tz_env,
    };

    #[test]
    fn timezone_from_tz_env_trims_leading_colon() {
        assert_eq!(
            timezone_from_tz_env(":America/New_York").as_deref(),
            Some("America/New_York")
        );
    }

    #[test]
    fn timezone_from_tz_env_ignores_empty_values() {
        assert!(timezone_from_tz_env("   ").is_none());
    }

    #[test]
    fn timezone_from_localtime_target_extracts_zoneinfo_suffix() {
        let path = Path::new("/usr/share/zoneinfo/Europe/Amsterdam");

        assert_eq!(
            timezone_from_localtime_target(path).as_deref(),
            Some("Europe/Amsterdam")
        );
    }

    #[test]
    fn timezone_from_timezone_file_uses_first_non_empty_line() {
        assert_eq!(
            timezone_from_timezone_file("Europe/Amsterdam\nignored").as_deref(),
            Some("Europe/Amsterdam")
        );
    }

    #[test]
    fn locale_from_env_prefers_lc_all_over_lang() {
        assert_eq!(
            locale_from_env(Some("nl_NL.UTF-8"), Some("en_US.UTF-8")).as_deref(),
            Some("nl_NL.UTF-8")
        );
    }

    #[test]
    fn locale_from_env_uses_lang_when_lc_all_is_empty() {
        assert_eq!(
            locale_from_env(Some(" "), Some("en_US.UTF-8")).as_deref(),
            Some("en_US.UTF-8")
        );
    }
}
