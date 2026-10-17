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
    Node,
    Netd,
    Taild,
    SdkGo,
}

impl Lane {
    fn name(self) -> &'static str {
        match self {
            Self::Rust => "rust",
            Self::Node => "node",
            Self::Netd => "netd",
            Self::Taild => "taild",
            Self::SdkGo => "sdk-go",
        }
    }

    fn excludes_function(self, file: &str, symbol: &str) -> bool {
        match self {
            Self::Rust => symbol.contains("::tests::"),
            Self::Node => file.split(['/', '\\']).any(|part| part == "tests"),
            Self::Netd | Self::Taild | Self::SdkGo => file.ends_with("_test.go"),
        }
    }

    fn load(self, directory: &Path) -> Result<Option<CoverageFiles>, CoverageError> {
        let lcov = match self {
            Self::Rust => Some("rust.lcov"),
            Self::Node => Some("node/lcov.info"),
            _ => None,
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
    for lane in [Lane::Rust, Lane::Node, Lane::Netd, Lane::Taild, Lane::SdkGo] {
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

#[cfg(test)]
mod tests {
    use crate::coverage::diff::{
        compare_lane, coverage_diff, file_dropped, parse_go_cover, parse_go_functions,
        parse_go_total, parse_lcov, Lane,
    };

    #[test]
    fn lcov_parses_files_functions_and_unique_lines() {
        let files = parse_lcov("TN:\nSF:a.rs\nFN:1,func\nFNDA:2,func,with,commas\nFNDA:0,unused\nDA:1,2\nDA:2,0,checksum\nend_of_record\nSF:a.rs\nFNDA:3,func,with,commas\nDA:1,3\nend_of_record\nSF:b.rs\nDA:9,0\nend_of_record\n").unwrap();
        assert_eq!(files["a.rs"].lines, (1, 2));
        assert_eq!(files["a.rs"].functions["func,with,commas"], 5);
        assert_eq!(files["a.rs"].functions["unused"], 0);
        assert_eq!(files["b.rs"].lines, (0, 1));
        assert!(parse_lcov("DA:1,0").is_err());
        assert!(matches!(
            parse_lcov("SF:a\nFNDA:not-a-number,f"),
            Err(crate::coverage::CoverageError::Parse { line: 2, .. })
        ));
        assert!(parse_lcov("SF:").is_err());
        assert!(parse_lcov("").unwrap().is_empty());
    }

    #[test]
    fn lcov_line_totals_stop_at_the_first_rust_test_function() {
        // Production lines 1-4 (3 of 4 hit); the tests module starts at line 5.
        let files = parse_lcov(
            "SF:a.rs\nFN:1,_RNvCs7ssUw5X5CQd_5utils10format_mac\nFN:8,_RNvNtCs7ssUw5X5CQd_5utils5tests12formats_mac\nFN:5,_RNvNtCs7ssUw5X5CQd_5utils5tests6helper\nDA:1,1\nDA:2,0\nDA:3,1\nDA:4,1\nDA:5,1\nDA:6,1\nDA:8,1\nend_of_record\nSF:b.rs\nFN:1,f\nDA:1,1\nDA:2,0\nend_of_record\n",
        )
        .unwrap();
        assert_eq!(files["a.rs"].lines, (3, 4));
        assert_eq!(files["b.rs"].lines, (1, 2));
    }

    #[test]
    fn lcov_aggregates_mangled_instances_without_false_losses() {
        let old = parse_lcov(
            "SF:utils.rs\nFNDA:11,_RNvCs7ssUw5X5CQd_5utils10format_mac\nFNDA:0,_RNvCs5UL6qYxlKki_5utils10format_mac\n",
        )
        .unwrap();
        let new = parse_lcov(
            "SF:utils.rs\nFNDA:0,_RNvCs7ssUw5X5CQd_5utils10format_mac\nFNDA:11,_RNvCs5UL6qYxlKki_5utils10format_mac\n",
        )
        .unwrap();
        for files in [&old, &new] {
            assert_eq!(files["utils.rs"].functions.len(), 1);
            assert_eq!(files["utils.rs"].functions["utils::format_mac"], 11);
        }
        assert!(compare_lane(Lane::Rust, &old, Some(&new), &[]).is_empty());
    }

    #[test]
    fn lcov_normalises_legacy_and_v0_names_across_baselines() {
        let old =
            parse_lcov("SF:utils.rs\nFNDA:11,_ZN5utils10format_mac17h0123456789abcdefE\n").unwrap();
        let new =
            parse_lcov("SF:utils.rs\nFNDA:11,_RNvCs7ssUw5X5CQd_5utils10format_mac\n").unwrap();
        assert_eq!(old["utils.rs"].functions["utils::format_mac"], 11);
        assert_eq!(old, new);
        assert!(compare_lane(Lane::Rust, &old, Some(&new), &[]).is_empty());
    }

    #[test]
    fn lcov_preserves_node_function_names() {
        let files = parse_lcov("SF:src/runtime.ts\nFNDA:3,runtimeOptionsToNative\n").unwrap();
        assert_eq!(files["src/runtime.ts"].functions.len(), 1);
        assert_eq!(
            files["src/runtime.ts"].functions["runtimeOptionsToNative"],
            3
        );
    }

    #[test]
    fn lcov_rejects_overflow_when_aggregating_mangled_instances() {
        let input = format!(
            "SF:utils.rs\nFNDA:{},_ZN5utils10format_mac17h0123456789abcdefE\nFNDA:1,_RNvCs7ssUw5X5CQd_5utils10format_mac\n",
            u64::MAX
        );
        assert!(matches!(
            parse_lcov(&input),
            Err(crate::coverage::CoverageError::Parse { line: 3, .. })
        ));
    }

    #[test]
    fn go_profiles_weight_statements_and_functions() {
        let files = parse_go_cover("mode: atomic\nexample/a.go:1.2,3.4 4 2\nexample/a.go:4.1,5.2 6 0\nexample/b.go:1.1,2.1 1 1\n").unwrap();
        assert_eq!(files["example/a.go"].lines, (4, 10));
        assert_eq!(files["example/b.go"].lines, (1, 1));
        let input =
            "example/a.go:1:\tf\t25.0%\nexample/a.go:4:\tg\t0.0%\ntotal:\t(statements)\t40.0%\n";
        let functions = parse_go_functions(input).unwrap();
        assert_eq!(functions["example/a.go"]["f"], 1);
        assert_eq!(functions["example/a.go"]["g"], 0);
        assert_eq!(parse_go_total(input).unwrap(), 40.0);
        assert!(parse_go_cover("file:1.1,2.1 1 0").is_err());
        assert!(parse_go_cover("mode: atomic\nfile:bad 1 0").is_err());
        assert!(parse_go_functions("a.go:1: f NaN%").is_err());
        assert!(parse_go_functions("a.go:1: f 101%").is_err());
        assert!(parse_go_total("a.go:1: f 0%").is_err());
    }

    #[test]
    fn function_lost_and_removed_rules() {
        let old = parse_lcov(
            "SF:a.rs\nFNDA:2,lost\nFNDA:0,uncovered\nFNDA:1,kept\nFNDA:0,removed\nDA:1,1\n",
        )
        .unwrap();
        let new =
            parse_lcov("SF:a.rs\nFNDA:0,lost\nFNDA:0,uncovered\nFNDA:3,kept\nDA:1,1\n").unwrap();
        let rows = compare_lane(Lane::Rust, &old, Some(&new), &[]);
        assert_eq!(rows.len(), 2);
        assert!(rows
            .iter()
            .any(|row| row.kind == "function-lost" && row.fail && row.symbol == "lost"));
        assert!(rows
            .iter()
            .any(|row| row.kind == "function-removed" && !row.fail && row.symbol == "removed"));
        assert!(compare_lane(Lane::Rust, &old, Some(&old), &[]).is_empty());
        let empty = Default::default();
        let rows = compare_lane(Lane::Rust, &old, Some(&empty), &[]);
        assert_eq!(rows.len(), 4);
        assert!(rows
            .iter()
            .all(|row| row.kind == "function-removed" && !row.fail));
    }

    #[test]
    fn test_function_exclusions_apply_to_lost_and_removed() {
        for (lane, file, symbol) in [
            (Lane::Rust, "a.rs", "crate::tests::helper"),
            (Lane::Rust, "utils.rs", "utils::tests::formats_mac"),
            (
                Lane::Rust,
                "utils.rs",
                "_ZN5utils5tests11formats_mac17h0123456789abcdefE",
            ),
            (
                Lane::Rust,
                "utils.rs",
                "_ZN5utils5tests11formats_mac28_$u7b$$u7b$closure$u7d$$u7d$17h0123456789abcdefE",
            ),
            (Lane::Node, "sdk/node/tests/test.ts", "helper"),
            (Lane::Node, "tests/test.ts", "helper"),
            (Lane::Netd, "a_test.go", "helper"),
            (Lane::Taild, "a_test.go", "helper"),
            (Lane::SdkGo, "a_test.go", "helper"),
        ] {
            let old = parse_lcov(&format!("SF:{file}\nFNDA:1,{symbol}\n")).unwrap();
            let new = parse_lcov(&format!("SF:{file}\nFNDA:0,{symbol}\n")).unwrap();
            assert!(compare_lane(lane, &old, Some(&new), &[]).is_empty());
            assert!(compare_lane(lane, &old, Some(&Default::default()), &[]).is_empty());
        }
        assert!(!Lane::Node.excludes_function("src/tests-helper.ts", "f"));
        assert!(!Lane::Rust.excludes_function("a.rs", "crate::test_helper"));
        assert!(!Lane::Netd.excludes_function("test.go", "f"));
    }

    #[test]
    fn file_drop_threshold_is_strict_and_exact() {
        assert!(!file_dropped((10000, 10000), (9950, 10000)));
        assert!(file_dropped((10000, 10000), (9949, 10000)));
        assert!(!file_dropped((1, 2), (99, 200)));
        assert!(!file_dropped((1, 2), (2, 3)));
        assert!(!file_dropped((0, 0), (0, 10)));
        assert!(!file_dropped((0, 10), (0, 0)));
        assert!(file_dropped((1, 10), (0, 0)));
        let mut old = parse_lcov("SF:a.rs\nDA:1,1\nDA:2,1\n").unwrap();
        let mut new = old.clone();
        new.get_mut("a.rs").unwrap().lines = (1, 2);
        let rows = compare_lane(Lane::Rust, &old, Some(&new), &[]);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].kind, "file-drop");
        assert!(rows[0].fail);
        old.get_mut("a.rs").unwrap().lines = (10000, 10000);
        new.get_mut("a.rs").unwrap().lines = (9950, 10000);
        assert!(compare_lane(Lane::Rust, &old, Some(&new), &[]).is_empty());
    }

    #[test]
    fn missing_lanes_can_be_explicitly_allowed() {
        let old = parse_lcov("SF:a.rs\nDA:1,1\n").unwrap();
        let rows = compare_lane(Lane::Node, &old, None, &[]);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].kind, "lane-missing");
        assert!(rows[0].fail);
        assert!(compare_lane(Lane::Node, &old, None, &["node".to_owned()]).is_empty());
        assert_eq!(
            compare_lane(Lane::Node, &old, None, &["rust".to_owned()]).len(),
            1
        );
    }

    #[test]
    fn directory_gate_loads_all_lanes_and_returns_failures() {
        let old = tempfile::tempdir().unwrap();
        let new = tempfile::tempdir().unwrap();
        for dir in [old.path(), new.path()] {
            std::fs::write(dir.join("rust.lcov"), "SF:a.rs\nFNDA:1,f\nDA:1,1\n").unwrap();
            std::fs::create_dir(dir.join("node")).unwrap();
            std::fs::write(dir.join("node/lcov.info"), "SF:a.ts\nFNDA:1,f\nDA:1,1\n").unwrap();
            for lane in ["netd", "taild", "sdk-go"] {
                std::fs::write(
                    dir.join(format!("{lane}.cover")),
                    "mode: atomic\na.go:1.1,2.1 1 1\n",
                )
                .unwrap();
                std::fs::write(
                    dir.join(format!("{lane}.func.txt")),
                    "a.go:1:\tf\t100.0%\ntotal:\t(statements)\t100.0%\n",
                )
                .unwrap();
            }
        }
        coverage_diff(old.path(), new.path(), &[]).unwrap();
        std::fs::write(new.path().join("rust.lcov"), "SF:a.rs\nFNDA:0,f\nDA:1,0\n").unwrap();
        let error = coverage_diff(old.path(), new.path(), &[]).unwrap_err();
        assert!(error.to_string().contains("2 FAIL"));
        assert!(matches!(
            error,
            crate::coverage::CoverageError::Regressions { failures: 2 }
        ));
        std::fs::remove_file(new.path().join("rust.lcov")).unwrap();
        assert!(coverage_diff(old.path(), new.path(), &[]).is_err());
        coverage_diff(old.path(), new.path(), &["rust".to_owned()]).unwrap();
        std::fs::remove_file(new.path().join("netd.func.txt")).unwrap();
        let error = coverage_diff(old.path(), new.path(), &["rust".to_owned()]).unwrap_err();
        assert!(matches!(
            error,
            crate::coverage::CoverageError::Io { path, .. }
                if path == new.path().join("netd.func.txt")
        ));
    }
}
