//! The package manager of a Node project, decided by its lockfile.
//!
//! `package-lock.json` is npm, `pnpm-lock.yaml` is pnpm and `yarn.lock` is
//! Yarn (classic, v1). Exactly one lockfile must exist: two of them mean the
//! project does not say which tool owns its dependencies, and the engine does
//! not guess. The tool is the native one, started without a shell and with a
//! fixed argument list; pnpm runs through the `corepack` that ships with the
//! Node image (`corepack pnpm`, no global install, nothing written outside
//! `/tmp`). Yarn Berry (a `yarn.lock` with a `__metadata` header) is refused:
//! its Plug'n'Play layout has no `node_modules` for a plain `node` entry.
//! Everything here is fixed text: a script name is the only caller value, and
//! the caller validates it.

use crate::{filesystem::ManagedRoot, site::SiteRelativePath};
use std::io::Read;

/// How much of `yarn.lock` is read to tell classic from Berry.
const LOCK_PEEK: u64 = 4096;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PackageManager {
    Npm,
    Pnpm,
    Yarn,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DetectError {
    Missing,
    Ambiguous,
    YarnBerry,
}

impl DetectError {
    pub(crate) fn message(self) -> &'static str {
        match self {
            Self::Missing => {
                "a lockfile is required (package-lock.json, pnpm-lock.yaml or yarn.lock)"
            }
            Self::Ambiguous => {
                "more than one lockfile exists; keep only the one of the project's package manager"
            }
            Self::YarnBerry => {
                "Yarn Berry (yarn.lock with a __metadata header) is not supported; use Yarn classic, pnpm or npm"
            }
        }
    }
}

fn rel(name: &str) -> SiteRelativePath {
    SiteRelativePath::parse(name).expect("fixed name")
}

fn words(list: &[&str]) -> Vec<String> {
    list.iter().map(|word| (*word).to_owned()).collect()
}

impl PackageManager {
    pub(crate) const ALL: [Self; 3] = [Self::Npm, Self::Pnpm, Self::Yarn];

    pub(crate) fn lockfile(self) -> &'static str {
        match self {
            Self::Npm => "package-lock.json",
            Self::Pnpm => "pnpm-lock.yaml",
            Self::Yarn => "yarn.lock",
        }
    }

    /// The tool of the one lockfile `root` holds.
    pub(crate) fn detect(root: &ManagedRoot) -> Result<Self, DetectError> {
        let found: Vec<Self> = Self::ALL
            .into_iter()
            .filter(|pm| root.exists(&rel(pm.lockfile())))
            .collect();
        match found[..] {
            [] => Err(DetectError::Missing),
            [Self::Yarn] => {
                let mut head = Vec::new();
                if let Ok(file) = root.open_regular_read(&rel("yarn.lock")) {
                    let _ = file.take(LOCK_PEEK).read_to_end(&mut head);
                }
                if is_yarn_berry(&head) {
                    Err(DetectError::YarnBerry)
                } else {
                    Ok(Self::Yarn)
                }
            }
            [one] => Ok(one),
            _ => Err(DetectError::Ambiguous),
        }
    }

    /// The phase name shown in errors and the log (`npm ci failed ...`).
    pub(crate) fn install_phase(self) -> &'static str {
        match self {
            Self::Npm => "npm ci",
            Self::Pnpm => "pnpm install",
            Self::Yarn => "yarn install",
        }
    }

    /// The install of a build: every dependency, from the lockfile only.
    pub(crate) fn install(self, ignore_scripts: bool) -> Vec<String> {
        let mut argv = match self {
            Self::Npm => words(&["npm", "ci", "--no-audit", "--no-fund"]),
            Self::Pnpm => words(&["corepack", "pnpm", "install", "--frozen-lockfile"]),
            Self::Yarn => words(&["yarn", "install", "--frozen-lockfile", "--non-interactive"]),
        };
        if ignore_scripts {
            argv.push("--ignore-scripts".into());
        }
        argv
    }

    /// The install of a release: production dependencies, from the lockfile.
    pub(crate) fn install_production(self) -> Vec<String> {
        match self {
            Self::Npm => words(&["npm", "ci", "--omit=dev", "--no-audit", "--no-fund"]),
            Self::Pnpm => words(&["corepack", "pnpm", "install", "--frozen-lockfile", "--prod"]),
            Self::Yarn => words(&[
                "yarn",
                "install",
                "--frozen-lockfile",
                "--non-interactive",
                "--production",
            ]),
        }
    }

    /// Runs a package script (the caller has validated `script`).
    pub(crate) fn run_script(self, script: &str) -> Vec<String> {
        let mut argv = match self {
            Self::Npm => words(&["npm", "run"]),
            Self::Pnpm => words(&["corepack", "pnpm", "run"]),
            Self::Yarn => words(&["yarn", "run"]),
        };
        argv.push(script.to_owned());
        argv
    }
}

/// Berry writes a `__metadata:` block at the top; classic never does.
fn is_yarn_berry(head: &[u8]) -> bool {
    String::from_utf8_lossy(head)
        .lines()
        .any(|line| line.trim_end() == "__metadata:")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::site::TrustedRoot;
    use std::fs;

    fn root_with(files: &[(&str, &str)]) -> (tempfile::TempDir, ManagedRoot) {
        let dir = tempfile::tempdir().unwrap();
        for (name, text) in files {
            fs::write(dir.path().join(name), text).unwrap();
        }
        let root = ManagedRoot::open(&TrustedRoot::parse(dir.path()).unwrap()).unwrap();
        (dir, root)
    }

    #[test]
    fn the_lockfile_decides_and_ambiguity_is_refused() {
        let classic = "# yarn lockfile v1\n\nleft-pad@^1:\n  version \"1.0.0\"\n";
        let berry = "# generated by yarn\n\n__metadata:\n  version: 8\n";
        let cases: Vec<(Vec<(&str, &str)>, Result<PackageManager, DetectError>)> = vec![
            (vec![("package-lock.json", "{}")], Ok(PackageManager::Npm)),
            (
                vec![("pnpm-lock.yaml", "lockfileVersion: 9")],
                Ok(PackageManager::Pnpm),
            ),
            (vec![("yarn.lock", classic)], Ok(PackageManager::Yarn)),
            (vec![("yarn.lock", berry)], Err(DetectError::YarnBerry)),
            (vec![], Err(DetectError::Missing)),
            (vec![("package.json", "{}")], Err(DetectError::Missing)),
            (
                vec![("package-lock.json", "{}"), ("yarn.lock", classic)],
                Err(DetectError::Ambiguous),
            ),
            (
                vec![
                    ("pnpm-lock.yaml", "x"),
                    ("yarn.lock", classic),
                    ("package-lock.json", "{}"),
                ],
                Err(DetectError::Ambiguous),
            ),
        ];
        for (files, expected) in cases {
            let (_dir, root) = root_with(&files);
            assert_eq!(PackageManager::detect(&root), expected, "{files:?}");
        }
    }

    #[test]
    fn every_tool_gets_a_fixed_native_argument_list() {
        let flat = |argv: Vec<String>| argv.join(" ");
        assert_eq!(
            flat(PackageManager::Npm.install(true)),
            "npm ci --no-audit --no-fund --ignore-scripts"
        );
        assert_eq!(
            flat(PackageManager::Pnpm.install(false)),
            "corepack pnpm install --frozen-lockfile"
        );
        assert_eq!(
            flat(PackageManager::Yarn.install(true)),
            "yarn install --frozen-lockfile --non-interactive --ignore-scripts"
        );
        assert_eq!(
            flat(PackageManager::Npm.install_production()),
            "npm ci --omit=dev --no-audit --no-fund"
        );
        assert_eq!(
            flat(PackageManager::Pnpm.install_production()),
            "corepack pnpm install --frozen-lockfile --prod"
        );
        assert_eq!(
            flat(PackageManager::Yarn.install_production()),
            "yarn install --frozen-lockfile --non-interactive --production"
        );
        assert_eq!(
            flat(PackageManager::Npm.run_script("build")),
            "npm run build"
        );
        assert_eq!(
            flat(PackageManager::Pnpm.run_script("build:ssr")),
            "corepack pnpm run build:ssr"
        );
        assert_eq!(
            flat(PackageManager::Yarn.run_script("build")),
            "yarn run build"
        );
    }
}
