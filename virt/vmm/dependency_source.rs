//! Explicit Cargo resolution shared by native build binding and release staging.

/// Cargo's declared baseline is distinct from the dependency selected by its lockfile.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DependencySource<'a> {
    Git { revision: &'a str },
    Path { crate_path: &'a str },
}

pub fn quoted_field<'a>(line: &'a str, key: &str) -> Option<&'a str> {
    let (name, value) = line.trim().split_once('=')?;
    if name.trim() != key {
        return None;
    }
    value
        .trim()
        .trim_end_matches('}')
        .trim()
        .strip_prefix('"')?
        .strip_suffix('"')
}

fn section<'a>(manifest: &'a str, header: &'a str) -> impl Iterator<Item = &'a str> {
    manifest
        .lines()
        .skip_while(move |line| line.trim() != header)
        .skip(1)
        .take_while(|line| !line.trim().starts_with('['))
}

fn inline_field<'a>(line: &'a str, field: &str) -> Option<&'a str> {
    line.split_once('{')?
        .1
        .split(',')
        .find_map(|part| quoted_field(part, field))
}

pub fn resolve_dependency<'a>(
    workspace: &'a str,
    lock: &'a str,
) -> Result<DependencySource<'a>, &'static str> {
    let dependency = section(workspace, "[workspace.dependencies]")
        .find(|line| line.starts_with("libkrun = "))
        .ok_or("workspace libkrun dependency is absent")?;
    let declared = inline_field(dependency, "rev")
        .ok_or("workspace libkrun dependency must pin its revision")?;
    let patch = section(
        workspace,
        "[patch.\"https://github.com/vandycknick/libkrun.git\"]",
    )
    .find(|line| line.starts_with("libkrun = "));
    let mut packages = lock.split("[[package]]").filter(|package| {
        package
            .lines()
            .any(|line| quoted_field(line, "name") == Some("libkrun"))
    });
    let package = packages.next().ok_or("libkrun lock identity is absent")?;
    if packages.next().is_some() {
        return Err("multiple libkrun package identities are unsupported");
    }
    let source = package
        .lines()
        .find_map(|line| quoted_field(line, "source"));
    if source.is_none()
        && package.lines().any(|line| {
            line.trim()
                .split_once('=')
                .is_some_and(|(name, _)| name.trim() == "source")
        })
    {
        return Err("libkrun lock source is malformed");
    }
    match (source, patch) {
        (None, Some(patch)) => {
            let crate_path = inline_field(patch, "path")
                .filter(|path| !path.is_empty())
                .ok_or("libkrun patch must name an explicit source path")?;
            Ok(DependencySource::Path { crate_path })
        }
        (Some(source), None) => {
            let (repository, revision) = source
                .rsplit_once('#')
                .ok_or("libkrun lock source lacks revision")?;
            if !repository.starts_with("git+https://github.com/vandycknick/libkrun.git?")
                || revision.len() != 40
                || !revision
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            {
                return Err("libkrun source must identify the actual full Git revision");
            }
            if declared != revision {
                return Err("libkrun Cargo.toml pin and resolved Cargo.lock revision disagree");
            }
            Ok(DependencySource::Git { revision })
        }
        (None, None) => Err("path-resolved libkrun requires its explicit workspace patch"),
        (Some(_), Some(_)) => Err("libkrun patch and lock disagree; run cargo update -p libkrun"),
    }
}

#[cfg(test)]
mod tests {
    use crate::dependency_source::{resolve_dependency, DependencySource};

    #[test]
    fn capabilities_dependency_source_distinguishes_patch_bytes_from_declared_baseline() {
        const REVISION: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let manifest = format!(
            "[workspace.dependencies]\nlibkrun = {{ git = \"https://github.com/vandycknick/libkrun.git\", rev = \"{REVISION}\" }}\n"
        );
        let git_lock = format!(
            "[[package]]\nname = \"libkrun\"\nversion = \"1\"\nsource = \"git+https://github.com/vandycknick/libkrun.git?rev={REVISION}#{REVISION}\"\n"
        );
        let path_lock = "[[package]]\nname = \"libkrun\"\nversion = \"1\"\n";
        let patched = format!(
            "{manifest}\n[patch.\"https://github.com/vandycknick/libkrun.git\"]\nlibkrun = {{ path = \"/production/src/libkrun\" }}\n"
        );
        assert_eq!(
            resolve_dependency(&manifest, &git_lock),
            Ok(DependencySource::Git { revision: REVISION })
        );
        assert_eq!(
            resolve_dependency(&patched, path_lock),
            Ok(DependencySource::Path {
                crate_path: "/production/src/libkrun"
            })
        );
        assert!(resolve_dependency(&manifest, path_lock).is_err());
        assert!(resolve_dependency(&patched, &git_lock).is_err());
        assert!(resolve_dependency(&manifest, "").is_err());
        assert!(resolve_dependency(&manifest, &format!("{git_lock}{path_lock}")).is_err());
        assert!(resolve_dependency(
            &manifest.replace(REVISION, "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"),
            &git_lock
        )
        .is_err());
        assert!(resolve_dependency(&manifest, &git_lock.replace("#aaaa", "#short-")).is_err());
        assert!(
            resolve_dependency(&patched.replace("/production/src/libkrun", ""), path_lock).is_err()
        );
        assert!(resolve_dependency(&patched, &format!("{path_lock}source = malformed\n")).is_err());
    }
}
