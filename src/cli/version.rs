//! Little Snitch version detection and compatibility gate.
//!
//! Every feature the MCP depends on (especially `restore-model -t`) was
//! added in LS 6.3.3. [`check`] returns a [`VersionResult`] that the
//! startup path converts into a hard refusal if the installed version
//! is too old.

use std::path::Path;

use thiserror::Error;

/// Minimum supported Little Snitch version.
pub const MIN_VERSION: Version = Version {
    major: 6,
    minor: 3,
    patch: 3,
};

/// A parsed `major.minor.patch` version.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Version {
    pub major: u32,
    pub minor: u32,
    pub patch: u32,
}

impl std::fmt::Display for Version {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

/// Outcome of a version check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VersionResult {
    /// Installed version meets the minimum requirement.
    Compatible(Version),
    /// Installed version is below the minimum.
    TooOld(Version),
    /// The `--version` output could not be parsed.
    Unparseable(String),
}

/// Error produced when the startup gate refuses to continue.
#[derive(Debug, Error)]
pub enum VersionGateError {
    #[error(
        "Little Snitch {found} is below the minimum required version {min}. \
         Upgrade to {min}+ before using this MCP server."
    )]
    TooOld { found: Version, min: Version },

    #[error(
        "Could not parse the Little Snitch version from output {output:?}. \
         Install Little Snitch {min}+ before using this MCP server."
    )]
    Unparseable { output: String, min: Version },
}

/// Run `littlesnitch --version` via `bin` and return the parsed result.
pub fn check(bin: &Path) -> VersionResult {
    match std::process::Command::new(bin).arg("--version").output() {
        Err(_) => VersionResult::Unparseable("<subprocess failed>".into()),
        Ok(out) => {
            let stdout = String::from_utf8_lossy(&out.stdout);
            parse(stdout.trim())
        }
    }
}

/// Enforce the version gate: return `Ok(Version)` if compatible,
/// else a [`VersionGateError`].
pub fn require_compatible(bin: &Path) -> Result<Version, VersionGateError> {
    match check(bin) {
        VersionResult::Compatible(v) => Ok(v),
        VersionResult::TooOld(v) => Err(VersionGateError::TooOld {
            found: v,
            min: MIN_VERSION,
        }),
        VersionResult::Unparseable(s) => Err(VersionGateError::Unparseable {
            output: s,
            min: MIN_VERSION,
        }),
    }
}

/// Parse a version string like `"Version 6.3.3"` or `"6.3.3"` or
/// `"littlesnitch 6.3.3"`.
pub fn parse(s: &str) -> VersionResult {
    // Take the last whitespace-delimited token, then parse major.minor.patch.
    let token = s.rsplit_once(' ').map(|(_, v)| v).unwrap_or(s);
    // Strip a leading "v" if present.
    let token = token.strip_prefix('v').unwrap_or(token);
    // Split on '.', ignore build metadata after '-'.
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() < 3 {
        return VersionResult::Unparseable(s.to_string());
    }
    let parse_part = |p: &str| p.split('-').next().unwrap_or("").parse::<u32>().ok();
    match (
        parse_part(parts[0]),
        parse_part(parts[1]),
        parse_part(parts[2]),
    ) {
        (Some(major), Some(minor), Some(patch)) => {
            let v = Version {
                major,
                minor,
                patch,
            };
            if v >= MIN_VERSION {
                VersionResult::Compatible(v)
            } else {
                VersionResult::TooOld(v)
            }
        }
        _ => VersionResult::Unparseable(s.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_version_prefix() {
        assert_eq!(
            parse("Version 6.3.3"),
            VersionResult::Compatible(Version {
                major: 6,
                minor: 3,
                patch: 3
            })
        );
    }

    #[test]
    fn parses_bare_version() {
        assert_eq!(
            parse("6.3.3"),
            VersionResult::Compatible(Version {
                major: 6,
                minor: 3,
                patch: 3
            })
        );
    }

    #[test]
    fn parses_with_build_suffix() {
        assert_eq!(
            parse("Version 6.3.3-beta.1"),
            VersionResult::Compatible(Version {
                major: 6,
                minor: 3,
                patch: 3
            })
        );
    }

    #[test]
    fn too_old_version() {
        assert_eq!(
            parse("Version 6.2.0"),
            VersionResult::TooOld(Version {
                major: 6,
                minor: 2,
                patch: 0
            })
        );
    }

    #[test]
    fn too_old_patch() {
        assert_eq!(
            parse("Version 6.3.2"),
            VersionResult::TooOld(Version {
                major: 6,
                minor: 3,
                patch: 2
            })
        );
    }

    #[test]
    fn newer_version_is_compatible() {
        assert_eq!(
            parse("Version 7.0.0"),
            VersionResult::Compatible(Version {
                major: 7,
                minor: 0,
                patch: 0
            })
        );
    }

    #[test]
    fn unparseable_returns_unparseable() {
        assert!(matches!(
            parse("not-a-version"),
            VersionResult::Unparseable(_)
        ));
        assert!(matches!(parse(""), VersionResult::Unparseable(_)));
        assert!(matches!(parse("6.3"), VersionResult::Unparseable(_)));
    }

    #[test]
    fn version_ord_works() {
        let v633 = Version {
            major: 6,
            minor: 3,
            patch: 3,
        };
        let v632 = Version {
            major: 6,
            minor: 3,
            patch: 2,
        };
        let v700 = Version {
            major: 7,
            minor: 0,
            patch: 0,
        };
        assert!(v633 > v632);
        assert!(v700 > v633);
        assert_eq!(v633, v633);
    }
}
