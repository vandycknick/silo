#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PackageRepository {
    Npm,
    PyPi,
}

impl PackageRepository {
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "npm" => Some(Self::Npm),
            "pypi" => Some(Self::PyPi),
            _ => None,
        }
    }

    fn hosts(self) -> &'static [&'static str] {
        match self {
            Self::Npm => &[
                "registry.npmjs.org",
                "registry.yarnpkg.com",
                "registry.npmjs.com",
            ],
            Self::PyPi => &[
                "pypi.org",
                "files.pythonhosted.org",
                "pypi.python.org",
                "pythonhosted.org",
            ],
        }
    }
}

pub(crate) fn registry_hosts(repositories: &[String]) -> Vec<String> {
    let mut hosts = Vec::new();
    for repository in repositories {
        let Some(repository) = PackageRepository::parse(repository) else {
            continue;
        };
        for host in repository.hosts() {
            if !hosts.iter().any(|existing| existing == host) {
                hosts.push((*host).to_owned());
            }
        }
    }
    hosts
}

#[cfg(test)]
mod tests {
    use crate::registry::{registry_hosts, PackageRepository};

    #[test]
    fn repositories_are_closed_and_expose_stable_host_order() {
        assert_eq!(
            PackageRepository::parse("npm"),
            Some(PackageRepository::Npm)
        );
        assert_eq!(
            PackageRepository::parse("pypi"),
            Some(PackageRepository::PyPi)
        );
        assert_eq!(PackageRepository::parse("rubygems"), None);
        assert_eq!(
            registry_hosts(&["npm".to_owned(), "pypi".to_owned()]),
            vec![
                "registry.npmjs.org",
                "registry.yarnpkg.com",
                "registry.npmjs.com",
                "pypi.org",
                "files.pythonhosted.org",
                "pypi.python.org",
                "pythonhosted.org",
            ]
        );
    }
}
