use std::collections::BTreeMap;
use std::fmt;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Args {
    pub(crate) positional: Vec<String>,
    pub(crate) literal: Vec<String>,
    pub(crate) delimited: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PositionalError(pub(crate) String);
impl fmt::Display for PositionalError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}
impl std::error::Error for PositionalError {}

pub(crate) fn missing(label: &str) -> PositionalError {
    PositionalError(format!("missing {label} argument"))
}
pub(crate) fn unexpected(label: &str) -> PositionalError {
    PositionalError(format!("unexpected {label} argument"))
}

impl Args {
    pub(crate) fn none(&self) -> Result<(), PositionalError> {
        if !self.positional.is_empty() {
            return Err(unexpected("positional"));
        }
        self.no_literal()
    }
    pub(crate) fn one(&self, label: &str) -> Result<&str, PositionalError> {
        self.no_literal()?;
        match self.positional.as_slice() {
            [] => Err(missing(label)),
            [value] => Ok(value),
            _ => Err(unexpected(label)),
        }
    }
    pub(crate) fn no_literal(&self) -> Result<(), PositionalError> {
        if self.delimited {
            return Err(PositionalError(
                "unexpected literal arguments after --".into(),
            ));
        }
        Ok(())
    }
}

/// Only explicit reasons are safe to include in a diagnostic.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ValueError {
    Invalid,
    Reason(String),
}
impl fmt::Display for ValueError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Invalid => f.write_str("invalid value"),
            Self::Reason(reason) => f.write_str(reason),
        }
    }
}
impl std::error::Error for ValueError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ParseError(pub(crate) String);
impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}
impl std::error::Error for ParseError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct OptionId(usize);

type ValueParser<'a> = Box<dyn FnMut(&str) -> Result<(), ValueError> + Send + 'a>;

pub(crate) struct Flag<'a> {
    pub(crate) names: Vec<String>,
    pub(crate) placeholder: String,
    parse: ValueParser<'a>,
    seen: bool,
    repeat: bool,
}
impl Flag<'_> {
    pub(crate) fn boolean(&self) -> bool {
        self.placeholder.is_empty()
    }
}

#[derive(Default)]
pub(crate) struct FlagSet<'a> {
    options: Vec<Flag<'a>>,
}
impl<'a> FlagSet<'a> {
    pub(crate) fn new() -> Self {
        Self {
            options: Vec::new(),
        }
    }
    fn add(
        &mut self,
        name: &str,
        placeholder: &str,
        parse: impl FnMut(&str) -> Result<(), ValueError> + Send + 'a,
        repeat: bool,
    ) -> OptionId {
        let id = OptionId(self.options.len());
        self.options.push(Flag {
            names: vec![name.into()],
            placeholder: placeholder.into(),
            parse: Box::new(parse),
            seen: false,
            repeat,
        });
        id
    }
    pub(crate) fn bool(&mut self, name: &str, dst: &'a mut bool) -> OptionId {
        self.add(
            name,
            "",
            move |value| {
                *dst = boolean(value)?;
                Ok(())
            },
            false,
        )
    }
    pub(crate) fn string(
        &mut self,
        name: &str,
        placeholder: &str,
        dst: &'a mut String,
    ) -> OptionId {
        self.add(
            name,
            placeholder,
            move |value| {
                *dst = value.into();
                Ok(())
            },
            false,
        )
    }
    pub(crate) fn value(
        &mut self,
        name: &str,
        placeholder: &str,
        parse: impl FnMut(&str) -> Result<(), ValueError> + Send + 'a,
    ) -> OptionId {
        self.add(name, placeholder, parse, false)
    }
    pub(crate) fn repeat(
        &mut self,
        name: &str,
        placeholder: &str,
        parse: impl FnMut(&str) -> Result<(), ValueError> + Send + 'a,
    ) -> OptionId {
        self.add(name, placeholder, parse, true)
    }
    pub(crate) fn alias(&mut self, name: &str, id: OptionId) {
        if let Some(option) = self.options.get_mut(id.0) {
            option.names.push(name.into());
        }
    }
    pub(crate) fn takes_value(&self, name: &str) -> bool {
        self.options()
            .iter()
            .any(|o| o.names.iter().any(|n| n == name) && !o.boolean())
    }
    pub(crate) fn options(&self) -> &[Flag<'a>] {
        &self.options
    }
    pub(crate) fn parse(&mut self, args: &[String]) -> Result<Args, ParseError> {
        self.parse_inner(args, true)
    }
    pub(crate) fn parse_help(&mut self, args: &[String]) -> Result<Args, ParseError> {
        self.parse_inner(args, false)
    }
    fn parse_inner(&mut self, args: &[String], apply: bool) -> Result<Args, ParseError> {
        let mut parsed = Args::default();
        let mut tokens = args.iter();
        while let Some(token) = tokens.next() {
            if token == "--" {
                parsed.delimited = true;
                parsed.literal.extend(tokens.cloned());
                break;
            }
            if !is_flag(token) || token == "-" {
                parsed.positional.push(token.clone());
                continue;
            }
            let flag = token.trim_start_matches('-');
            let (name, inline) = match flag.split_once('=') {
                Some((name, value)) => (name, Some(value)),
                None => (flag, None),
            };
            let Some(option) = self
                .options
                .iter_mut()
                .find(|o| o.names.iter().any(|n| n == name))
            else {
                return Err(ParseError("unknown option; see command help".into()));
            };
            if option.seen && !option.repeat {
                return Err(ParseError(format!("duplicate option --{name}")));
            }
            let value = match inline {
                Some(value) => value,
                None if option.boolean() => "true",
                None => tokens
                    .next()
                    .map(String::as_str)
                    .ok_or_else(|| ParseError(format!("option --{name} requires a value")))?,
            };
            option.seen = true;
            if apply {
                (option.parse)(value).map_err(|error| {
                    ParseError(match error {
                        ValueError::Reason(reason) => {
                            format!("invalid value for --{name}: {reason}")
                        }
                        ValueError::Invalid => format!("invalid value for --{name}"),
                    })
                })?;
            }
        }
        Ok(parsed)
    }
}

pub(crate) fn is_flag(token: &str) -> bool {
    token.starts_with('-')
}
pub(crate) fn boolean(value: &str) -> Result<bool, ValueError> {
    match value {
        "1" | "t" | "T" | "TRUE" | "true" | "True" => Ok(true),
        "0" | "f" | "F" | "FALSE" | "false" | "False" => Ok(false),
        _ => Err(ValueError::Invalid),
    }
}
pub(crate) fn non_empty(
    dst: &mut String,
) -> impl FnMut(&str) -> Result<(), ValueError> + Send + '_ {
    move |value| {
        if value.is_empty() {
            return Err(ValueError::Invalid);
        }
        *dst = value.into();
        Ok(())
    }
}
pub(crate) fn count(dst: &mut u64) -> impl FnMut(&str) -> Result<(), ValueError> + Send + '_ {
    move |value| {
        if let Ok(n @ 1..=255) = value.parse::<u64>() {
            if !value.starts_with('+') {
                *dst = n;
                return Ok(());
            }
        }
        Err(ValueError::Reason(
            "expected a positive integer (1..255)".into(),
        ))
    }
}
pub(crate) fn key_value(
    dst: &mut BTreeMap<String, String>,
) -> impl FnMut(&str) -> Result<(), ValueError> + Send + '_ {
    move |value| {
        let (key, value) = value.split_once('=').ok_or(ValueError::Invalid)?;
        dst.insert(key.into(), value.into());
        Ok(())
    }
}
pub(crate) fn duration(
    dst: &mut chrono::TimeDelta,
) -> impl FnMut(&str) -> Result<(), ValueError> + Send + '_ {
    move |value| {
        *dst = parse_duration(value)?;
        Ok(())
    }
}

/// Go duration syntax, bounded to a signed 64-bit count of nanoseconds.
pub(crate) fn parse_duration(value: &str) -> Result<chrono::TimeDelta, ValueError> {
    let (negative, mut value) = if let Some(rest) = value.strip_prefix('-') {
        (true, rest)
    } else {
        (false, value.strip_prefix('+').unwrap_or(value))
    };
    if value == "0" {
        return Ok(chrono::TimeDelta::zero());
    }
    if value.is_empty() {
        return Err(ValueError::Invalid);
    }
    let mut total = 0i128;
    while !value.is_empty() {
        let number_end = value
            .find(|c: char| !c.is_ascii_digit() && c != '.')
            .ok_or(ValueError::Invalid)?;
        let (number, rest) = value.split_at(number_end);
        let unit_end = rest
            .find(|c: char| c.is_ascii_digit() || c == '.')
            .unwrap_or(rest.len());
        let (unit, rest) = rest.split_at(unit_end);
        let scale = match unit {
            "ns" => 1i128,
            "us" | "µs" | "μs" => 1_000,
            "ms" => 1_000_000,
            "s" => 1_000_000_000,
            "m" => 60_000_000_000,
            "h" => 3_600_000_000_000,
            _ => return Err(ValueError::Invalid),
        };
        let (whole, fraction) = number.split_once('.').unwrap_or((number, ""));
        if whole.is_empty() && fraction.is_empty() {
            return Err(ValueError::Invalid);
        }
        let whole = if whole.is_empty() {
            0
        } else {
            whole.parse::<i128>().map_err(|_| ValueError::Invalid)?
        };
        let mut part = whole.checked_mul(scale).ok_or(ValueError::Invalid)?;
        if !fraction.is_empty() {
            if !fraction.bytes().all(|c| c.is_ascii_digit()) {
                return Err(ValueError::Invalid);
            }
            let mut denominator = 1i128;
            let mut numerator = 0i128;
            for digit in fraction.bytes().take(18) {
                numerator = numerator * 10 + i128::from(digit - b'0');
                denominator *= 10;
            }
            part = part
                .checked_add(numerator * scale / denominator)
                .ok_or(ValueError::Invalid)?;
        }
        total = total.checked_add(part).ok_or(ValueError::Invalid)?;
        value = rest;
    }
    if negative {
        total = -total;
    }
    let nanos = i64::try_from(total).map_err(|_| ValueError::Invalid)?;
    Ok(chrono::TimeDelta::nanoseconds(nanos))
}

#[cfg(test)]
mod tests {
    use crate::lobby::grammar::cmdline::{
        boolean, count, duration, is_flag, key_value, non_empty, parse_duration, Args, FlagSet,
    };
    use std::collections::BTreeMap;

    fn strings(values: &[&str]) -> Vec<String> {
        values.iter().map(|v| (*v).into()).collect()
    }
    fn parse(values: &[&str]) -> Result<Args, String> {
        let (mut force, mut start, mut cpus, mut owner, mut name, mut timeout, mut labels) = (
            false,
            false,
            0,
            String::new(),
            String::new(),
            chrono::TimeDelta::zero(),
            BTreeMap::new(),
        );
        let mut f = FlagSet::new();
        f.bool("force", &mut force);
        f.bool("no-start", &mut start);
        let id = f.value("cpus", "N", count(&mut cpus));
        f.alias("c", id);
        f.string("owner", "tag:NAME", &mut owner);
        let id = f.value("name", "NAME", non_empty(&mut name));
        f.alias("n", id);
        f.value("timeout", "DURATION", duration(&mut timeout));
        f.repeat("label", "K=V", key_value(&mut labels));
        f.parse(&strings(values)).map_err(|e| e.to_string())
    }
    #[test]
    fn strictness_and_redacted_diagnostics() {
        assert!(parse(&[
            "--force",
            "--cpus",
            "2",
            "--label",
            "a=1",
            "--label",
            "b=2",
            "--owner",
            "tag:x",
            "--timeout",
            "5s"
        ])
        .unwrap()
        .none()
        .is_ok());
        assert_eq!(
            parse(&["--no-start=false", "-c=3", "--name", "-", "x", "y"])
                .unwrap()
                .positional,
            strings(&["x", "y"])
        );
        let args = parse(&["vm", "--force", "--", "--force", "literal"]).unwrap();
        assert_eq!(args.positional, strings(&["vm"]));
        assert_eq!(args.literal, strings(&["--force", "literal"]));
        assert!(args.one("VM").is_err());
        for (args, want) in [
            (vec!["--force", "--force"], "duplicate option --force"),
            (vec!["--cpus", "2", "-c", "2"], "duplicate option --c"),
            (vec!["--cpus"], "option --cpus requires a value"),
            (
                vec!["--cpus", "lots"],
                "invalid value for --cpus: expected a positive integer (1..255)",
            ),
            (
                vec!["--cpus", "0"],
                "invalid value for --cpus: expected a positive integer (1..255)",
            ),
            (vec!["--timeout", "soon"], "invalid value for --timeout"),
            (vec!["--name", ""], "invalid value for --name"),
            (vec!["--label", "novalue"], "invalid value for --label"),
            (vec!["--unknown"], "unknown option; see command help"),
            (vec!["-h"], "unknown option; see command help"),
        ] {
            assert_eq!(parse(&args).unwrap_err(), want);
        }
        for (args, reason) in [
            (vec!["--cpus"], "requires a value"),
            (vec!["--cpus", "-1"], "positive integer"),
            (vec!["--cpus", "18446744073709551616"], "positive integer"),
            (vec!["--name", "one", "-n", "two"], "duplicate option"),
            (vec!["--name", ""], "--name"),
            (vec!["--unknown=SECRET"], "unknown option"),
            (vec!["--label", "SECRET"], "--label"),
            (vec!["--no-start=SECRET"], "--no-start"),
            (vec!["--cpus", "SECRET/token"], "positive integer"),
            (vec!["--cpus", "1SECRET"], "positive integer"),
            (vec!["--timeout", "tskey-secret"], "--timeout"),
        ] {
            let error = parse(&args).unwrap_err();
            assert!(error.contains(reason));
            assert!(!error.contains("SECRET") && !error.contains("tskey"));
        }
    }
    #[test]
    fn positional_shapes() {
        assert_eq!(
            Args {
                positional: strings(&["vm"]),
                ..Args::default()
            }
            .one("VM")
            .unwrap(),
            "vm"
        );
        assert_eq!(
            Args::default().one("VM").unwrap_err().to_string(),
            "missing VM argument"
        );
        assert_eq!(
            Args {
                positional: strings(&["a", "b"]),
                ..Args::default()
            }
            .one("VM")
            .unwrap_err()
            .to_string(),
            "unexpected VM argument"
        );
        assert!(Args {
            positional: strings(&["a"]),
            ..Args::default()
        }
        .none()
        .is_err());
        assert!(Args {
            delimited: true,
            ..Args::default()
        }
        .none()
        .is_err());
        assert!(is_flag("--x") && is_flag("-x") && !is_flag("x"));
    }
    #[test]
    fn declaration_drives_arity_and_aliases() {
        let (mut b, mut s) = (false, String::new());
        let mut f = FlagSet::new();
        f.bool("force", &mut b);
        let id = f.string("dir", "DIR", &mut s);
        f.alias("d", id);
        assert!(
            !f.takes_value("force")
                && f.takes_value("dir")
                && f.takes_value("d")
                && !f.takes_value("nope")
        );
        assert_eq!(f.options()[1].names, strings(&["dir", "d"]));
        f.parse(&strings(&["-d", "/tmp"])).unwrap();
        drop(f);
        assert_eq!(s, "/tmp");
    }
    #[test]
    fn parsers_apply_values_but_help_does_not() {
        let (mut b, mut n, mut s, mut labels, mut time) = (
            false,
            0,
            String::new(),
            BTreeMap::new(),
            chrono::TimeDelta::zero(),
        );
        {
            let mut f = FlagSet::new();
            f.bool("b", &mut b);
            f.value("n", "N", count(&mut n));
            f.value("s", "S", non_empty(&mut s));
            f.repeat("label", "K=V", key_value(&mut labels));
            f.value("time", "DURATION", duration(&mut time));
            f.parse(&strings(&[
                "--b", "--n", "2", "--s", "hi", "--label", "a=1", "--label", "a=2", "--time", "5s",
            ]))
            .unwrap();
        }
        assert!(b);
        assert_eq!(n, 2);
        assert_eq!(s, "hi");
        assert_eq!(labels["a"], "2");
        assert_eq!(time.num_seconds(), 5);
        {
            let mut f = FlagSet::new();
            f.value("n", "N", count(&mut n));
            f.parse_help(&strings(&["--n", "SECRET"])).unwrap();
        }
        assert_eq!(n, 2);
        for v in [
            "false", "0", "f", "F", "FALSE", "False", "true", "1", "t", "T", "TRUE", "True",
        ] {
            assert!(boolean(v).is_ok());
        }
        for (s, nanos) in [
            ("0", 0),
            ("5s", 5_000_000_000),
            ("-1.5s", -1_500_000_000),
            ("1h2m3s", 3_723_000_000_000),
            (".5µs", 500),
            ("1ns", 1),
        ] {
            assert_eq!(parse_duration(s).unwrap().num_nanoseconds(), Some(nanos));
        }
        for s in ["", "soon", "1", ".s", "1..2s", "9223372036854775808ns"] {
            assert!(parse_duration(s).is_err(), "{s}");
        }
    }
}
