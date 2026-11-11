use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use crate::coverage::CoverageError;

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct FileCoverage {
    pub functions: BTreeMap<String, u64>,
    pub lines: (u64, u64),
}

pub type CoverageFiles = BTreeMap<String, FileCoverage>;

fn add_count(value: &mut u64, count: u64, line: usize) -> Result<(), CoverageError> {
    *value = value
        .checked_add(count)
        .ok_or_else(|| CoverageError::parse(line, "coverage count overflow"))?;
    Ok(())
}

fn parse_number(value: &str, line: usize) -> Result<u64, CoverageError> {
    value
        .parse()
        .map_err(|error: std::num::ParseIntError| CoverageError::parse(line, error.to_string()))
}

pub fn parse_lcov(input: &str) -> Result<CoverageFiles, CoverageError> {
    let mut files = CoverageFiles::new();
    let mut lines: BTreeMap<String, BTreeMap<u64, u64>> = BTreeMap::new();
    // Rust unit tests live at the bottom of the file they test (`mod tests`), so
    // the first `::tests::` function start marks where test code begins; counting
    // those lines would let a folded or deleted test move the file's percentage.
    let mut test_start: BTreeMap<String, u64> = BTreeMap::new();
    let mut current = None;
    for (index, record) in input.lines().map(str::trim).enumerate() {
        let row = index + 1;
        if let Some(file) = record.strip_prefix("SF:") {
            if file.is_empty() {
                return Err(CoverageError::parse(row, "empty LCOV source file"));
            }
            files.entry(file.to_owned()).or_default();
            current = Some(file);
        } else if record == "end_of_record" {
            current = None;
        } else if let Some(value) = record.strip_prefix("FN:") {
            let file = current
                .ok_or_else(|| CoverageError::parse(row, "LCOV FN outside source record"))?;
            let (line, name) = value
                .split_once(',')
                .ok_or_else(|| CoverageError::parse(row, format!("invalid LCOV FN: {record}")))?;
            if format!("{:#}", rustc_demangle::demangle(name)).contains("::tests::") {
                let line = parse_number(line, row)?;
                let start = test_start.entry(file.to_owned()).or_insert(line);
                *start = (*start).min(line);
            }
        } else if let Some(value) = record.strip_prefix("FNDA:") {
            let file = current
                .ok_or_else(|| CoverageError::parse(row, "LCOV FNDA outside source record"))?;
            let (hits, name) = value
                .split_once(',')
                .ok_or_else(|| CoverageError::parse(row, format!("invalid LCOV FNDA: {record}")))?;
            if name.is_empty() {
                return Err(CoverageError::parse(row, "empty LCOV function name"));
            }
            // Merge compiled instances under their stable Rust name; other languages pass through.
            let name = format!("{:#}", rustc_demangle::demangle(name));
            add_count(
                files
                    .entry(file.to_owned())
                    .or_default()
                    .functions
                    .entry(name)
                    .or_default(),
                parse_number(hits, row)?,
                row,
            )?;
        } else if let Some(value) = record.strip_prefix("DA:") {
            let file = current
                .ok_or_else(|| CoverageError::parse(row, "LCOV DA outside source record"))?;
            let mut fields = value.split(',');
            let line = parse_number(
                fields
                    .next()
                    .ok_or_else(|| CoverageError::parse(row, "missing LCOV line"))?,
                row,
            )?;
            let hits = parse_number(
                fields
                    .next()
                    .ok_or_else(|| CoverageError::parse(row, "missing LCOV hits"))?,
                row,
            )?;
            add_count(
                lines
                    .entry(file.to_owned())
                    .or_default()
                    .entry(line)
                    .or_default(),
                hits,
                row,
            )?;
        }
    }
    for (file, counts) in lines {
        let limit = test_start.get(&file).copied().unwrap_or(u64::MAX);
        let production = counts.iter().filter(|(line, _)| **line < limit);
        files.entry(file).or_default().lines = (
            production.clone().filter(|(_, hits)| **hits > 0).count() as u64,
            production.count() as u64,
        );
    }
    Ok(files)
}

fn go_fields(record: &str, line: usize) -> Result<[&str; 3], CoverageError> {
    let mut fields = record.split_whitespace();
    match (fields.next(), fields.next(), fields.next(), fields.next()) {
        (Some(first), Some(second), Some(third), None) => Ok([first, second, third]),
        _ => Err(CoverageError::parse(
            line,
            format!("invalid Go coverage row: {record}"),
        )),
    }
}

pub fn parse_go_cover(input: &str) -> Result<CoverageFiles, CoverageError> {
    let mut records = input
        .lines()
        .enumerate()
        .filter(|(_, line)| !line.trim().is_empty());
    match records.next() {
        Some((_, record))
            if matches!(record.trim(), "mode: set" | "mode: count" | "mode: atomic") => {}
        record => {
            return Err(CoverageError::parse(
                record.map_or(1, |(index, _)| index + 1),
                "missing or invalid Go coverage mode",
            ))
        }
    }
    let mut files = CoverageFiles::new();
    for (index, record) in records {
        let row = index + 1;
        let fields = go_fields(record, row)?;
        let (file, position) = fields[0].rsplit_once(':').ok_or_else(|| {
            CoverageError::parse(row, format!("missing Go coverage position: {record}"))
        })?;
        let (start, end) = position.split_once(',').ok_or_else(|| {
            CoverageError::parse(row, format!("invalid Go coverage position: {record}"))
        })?;
        for point in [start, end] {
            let (line, column) = point.split_once('.').ok_or_else(|| {
                CoverageError::parse(row, format!("invalid Go coverage position: {record}"))
            })?;
            parse_number(line, row)?;
            parse_number(column, row)?;
        }
        if file.is_empty() {
            return Err(CoverageError::parse(row, "empty Go coverage source file"));
        }
        let statements = parse_number(fields[1], row)?;
        let hits = parse_number(fields[2], row)?;
        let coverage = files.entry(file.to_owned()).or_default();
        add_count(&mut coverage.lines.1, statements, row)?;
        if hits > 0 {
            add_count(&mut coverage.lines.0, statements, row)?;
        }
    }
    Ok(files)
}

fn parse_percentage(value: &str, line: usize) -> Result<f64, CoverageError> {
    let percent: f64 = value
        .strip_suffix('%')
        .ok_or_else(|| CoverageError::parse(line, "missing coverage percent suffix"))?
        .parse()
        .map_err(|error: std::num::ParseFloatError| {
            CoverageError::parse(line, error.to_string())
        })?;
    if !percent.is_finite() || !(0.0..=100.0).contains(&percent) {
        return Err(CoverageError::parse(
            line,
            format!("invalid coverage percentage: {value}"),
        ));
    }
    Ok(percent)
}

pub fn parse_go_functions(
    input: &str,
) -> Result<BTreeMap<String, BTreeMap<String, u64>>, CoverageError> {
    let mut files: BTreeMap<String, BTreeMap<String, u64>> = BTreeMap::new();
    for (index, record) in input
        .lines()
        .enumerate()
        .filter(|(_, line)| !line.trim().is_empty())
    {
        let row = index + 1;
        let fields = go_fields(record, row)?;
        let percent = parse_percentage(fields[2], row)?;
        if fields[0] == "total:" {
            if fields[1] != "(statements)" {
                return Err(CoverageError::parse(
                    row,
                    format!("invalid Go coverage total: {record}"),
                ));
            }
            continue;
        }
        let position = fields[0].strip_suffix(':').ok_or_else(|| {
            CoverageError::parse(
                row,
                format!("missing Go function position suffix: {record}"),
            )
        })?;
        let (file, line) = position.rsplit_once(':').ok_or_else(|| {
            CoverageError::parse(row, format!("missing Go function position: {record}"))
        })?;
        parse_number(line, row)?;
        if file.is_empty() {
            return Err(CoverageError::parse(row, "empty Go function source file"));
        }
        let hits = files
            .entry(file.to_owned())
            .or_default()
            .entry(fields[1].to_owned())
            .or_default();
        *hits = (*hits).max(u64::from(percent > 0.0));
    }
    Ok(files)
}

pub fn parse_go_total(input: &str) -> Result<f64, CoverageError> {
    for (index, record) in input.lines().enumerate() {
        if record.split_whitespace().next() == Some("total:") {
            let row = index + 1;
            let fields = go_fields(record, row)?;
            if fields[1] != "(statements)" {
                return Err(CoverageError::parse(
                    row,
                    format!("invalid Go coverage total: {record}"),
                ));
            }
            return parse_percentage(fields[2], row);
        }
    }
    Err(CoverageError::parse(
        input.lines().count() + 1,
        "missing Go coverage total",
    ))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Lane {
    Rust,
    Netd,
}

impl Lane {
    fn name(self) -> &'static str {
        match self {
            Self::Rust => "rust",
            Self::Netd => "netd",
        }
    }

    fn excludes_function(self, file: &str, symbol: &str) -> bool {
        match self {
            Self::Rust => symbol.contains("::tests::"),
            Self::Netd => file.ends_with("_test.go"),
        }
    }

    fn load(self, directory: &Path) -> Result<Option<CoverageFiles>, CoverageError> {
        let lcov = match self {
            Self::Rust => Some("rust.lcov"),
            Self::Netd => None,
        };
        if let Some(relative) = lcov {
            let path = directory.join(relative);
            return match fs::read_to_string(&path) {
                Ok(input) => parse_lcov(&input)
                    .map_err(|error| error.with_path(&path))
                    .map(Some),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
                Err(error) => Err(CoverageError::io(&path, error)),
            };
        }
        let profile = directory.join(format!("{}.cover", self.name()));
        let functions = directory.join(format!("{}.func.txt", self.name()));
        if !profile
            .try_exists()
            .map_err(|error| CoverageError::io(&profile, error))?
            && !functions
                .try_exists()
                .map_err(|error| CoverageError::io(&functions, error))?
        {
            return Ok(None);
        }
        let input =
            fs::read_to_string(&profile).map_err(|error| CoverageError::io(&profile, error))?;
        let mut files = parse_go_cover(&input).map_err(|error| error.with_path(&profile))?;
        let input =
            fs::read_to_string(&functions).map_err(|error| CoverageError::io(&functions, error))?;
        for (file, functions) in
            parse_go_functions(&input).map_err(|error| error.with_path(&functions))?
        {
            files.entry(file).or_default().functions = functions;
        }
        Ok(Some(files))
    }
}

#[derive(Debug, PartialEq, Eq)]
struct Row {
    fail: bool,
    kind: &'static str,
    lane: Lane,
    file: String,
    symbol: String,
    baseline: String,
    current: String,
}

fn percentage((covered, total): (u64, u64)) -> String {
    if total == 0 {
        "0.00%".to_owned()
    } else {
        format!("{:.2}%", covered as f64 * 100.0 / total as f64)
    }
}

fn file_dropped(baseline: (u64, u64), current: (u64, u64)) -> bool {
    if baseline.1 == 0 {
        return false;
    }
    if current.1 == 0 {
        return baseline.0 as u128 * 200 > baseline.1 as u128;
    }
    let old = baseline.0 as u128 * current.1 as u128;
    let new = current.0 as u128 * baseline.1 as u128;
    old > new && old - new > (baseline.1 as u128 * current.1 as u128) / 200
}

fn compare_lane(
    lane: Lane,
    baseline: &CoverageFiles,
    current: Option<&CoverageFiles>,
    allow_missing_lanes: &[String],
) -> Vec<Row> {
    let mut rows = Vec::new();
    let Some(current) = current else {
        if !allow_missing_lanes.iter().any(|name| name == lane.name()) {
            rows.push(Row {
                fail: true,
                kind: "lane-missing",
                lane,
                file: "-".to_owned(),
                symbol: "-".to_owned(),
                baseline: "present".to_owned(),
                current: "missing".to_owned(),
            });
        }
        return rows;
    };
    for (file, old) in baseline {
        let new = current.get(file);
        if let Some(new) = new {
            if file_dropped(old.lines, new.lines) {
                rows.push(Row {
                    fail: true,
                    kind: "file-drop",
                    lane,
                    file: file.clone(),
                    symbol: "-".to_owned(),
                    baseline: percentage(old.lines),
                    current: percentage(new.lines),
                });
            }
        }
        for (symbol, old_hits) in &old.functions {
            if lane.excludes_function(file, symbol) {
                continue;
            }
            let new_hits = new.and_then(|coverage| coverage.functions.get(symbol));
            let (fail, kind, hits) = match new_hits {
                Some(0) if *old_hits > 0 => (true, "function-lost", "0".to_owned()),
                None => (false, "function-removed", "-".to_owned()),
                _ => continue,
            };
            rows.push(Row {
                fail,
                kind,
                lane,
                file: file.clone(),
                symbol: symbol.clone(),
                baseline: old_hits.to_string(),
                current: hits,
            });
        }
    }
    rows
}

pub fn coverage_diff(
    baseline: &Path,
    current: &Path,
    allow_missing_lanes: &[String],
) -> Result<(), CoverageError> {
    for path in [baseline, current] {
        if !path.is_dir() {
            return Err(CoverageError::InvalidDirectory {
                path: path.to_owned(),
            });
        }
    }
    let mut rows = Vec::new();
    for lane in [Lane::Rust, Lane::Netd] {
        let old = lane.load(baseline)?;
        let new = lane.load(current)?;
        if let Some(old) = old {
            rows.extend(compare_lane(lane, &old, new.as_ref(), allow_missing_lanes));
        }
    }
    println!("kind | lane | file | symbol | baseline | current");
    for row in &rows {
        println!(
            "{} {} | {} | {} | {} | {} | {}",
            if row.fail { "FAIL" } else { "INFO" },
            row.kind,
            row.lane.name(),
            row.file,
            row.symbol,
            row.baseline,
            row.current
        );
    }
    let failures = rows.iter().filter(|row| row.fail).count();
    println!(
        "coverage-diff: {failures} FAIL, {} INFO",
        rows.len() - failures
    );
    if failures > 0 {
        return Err(CoverageError::Regressions { failures });
    }
    Ok(())
}
