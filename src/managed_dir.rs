use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use thiserror::Error;

/// Env-var override for the managed directory root.
pub const ENV_MANAGED_DIR: &str = "LSMCP_MANAGED_DIR";

/// Subdirectory for `.lsrules` Track-A files.
pub const RULES_SUBDIR: &str = "rules";

/// Subdirectory for live-model export backups.
pub const BACKUPS_SUBDIR: &str = "backups";

/// Subdirectory for capture-traffic output files.
pub const CAPTURES_SUBDIR: &str = "captures";

#[derive(Debug, Error)]
pub enum ManagedDirError {
    #[error("cannot determine home directory")]
    NoHomeDir,
    #[error("failed to create managed directory {path}: {source}")]
    CreateDir {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to set permissions on {path}: {source}")]
    SetPerms {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
}

/// Resolved managed-directory paths.
#[derive(Debug, Clone)]
pub struct ManagedDir {
    /// Root: `~/Library/Application Support/little-snitch-mcp/` (or override).
    pub root: PathBuf,
    /// `<root>/rules/` — Track-A .lsrules files.
    pub rules: PathBuf,
    /// `<root>/backups/` — live-model export backups.
    pub backups: PathBuf,
    /// `<root>/captures/` — capture-traffic output files.
    pub captures: PathBuf,
}

impl ManagedDir {
    /// Bootstrap the managed directory tree.
    ///
    /// Idempotent: safe to call on every startup.
    /// Respects `LSMCP_MANAGED_DIR` env var; falls back to
    /// `~/Library/Application Support/little-snitch-mcp/`.
    pub fn bootstrap() -> Result<Self, ManagedDirError> {
        let root = resolve_root()?;
        let rules = root.join(RULES_SUBDIR);
        let backups = root.join(BACKUPS_SUBDIR);
        let captures = root.join(CAPTURES_SUBDIR);

        for dir in [&root, &rules, &backups, &captures] {
            ensure_dir_700(dir)?;
        }

        Ok(Self {
            root,
            rules,
            backups,
            captures,
        })
    }

    /// Path to the named `.lsrules` file inside `rules/`.
    pub fn lsrules_file(&self, name: &str) -> PathBuf {
        self.rules.join(format!("{name}.lsrules"))
    }
}

fn resolve_root() -> Result<PathBuf, ManagedDirError> {
    if let Ok(override_path) = std::env::var(ENV_MANAGED_DIR) {
        return Ok(PathBuf::from(override_path));
    }

    let home = home_dir().ok_or(ManagedDirError::NoHomeDir)?;
    Ok(home.join("Library/Application Support/little-snitch-mcp"))
}

fn home_dir() -> Option<PathBuf> {
    std::env::var_os("HOME").map(PathBuf::from)
}

fn ensure_dir_700(path: &Path) -> Result<(), ManagedDirError> {
    if !path.exists() {
        std::fs::create_dir_all(path).map_err(|e| ManagedDirError::CreateDir {
            path: path.to_owned(),
            source: e,
        })?;
    }
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).map_err(|e| {
        ManagedDirError::SetPerms {
            path: path.to_owned(),
            source: e,
        }
    })?;
    Ok(())
}

/// Serializes all tests that mutate `LSMCP_MANAGED_DIR` across the crate.
/// Available in both unit tests (`#[cfg(test)]`) and integration tests (`tests/`).
pub static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn with_temp_managed<F: FnOnce(ManagedDir)>(f: F) {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let td = tempfile::tempdir().unwrap();
        // SAFETY: protected by ENV_LOCK; no concurrent env mutation across the crate.
        unsafe {
            std::env::set_var(ENV_MANAGED_DIR, td.path().join("mcp"));
        }
        let dir = ManagedDir::bootstrap().unwrap();
        f(dir);
        unsafe {
            std::env::remove_var(ENV_MANAGED_DIR);
        }
    }

    #[test]
    fn bootstrap_creates_subdirs() {
        with_temp_managed(|dir| {
            assert!(dir.root.is_dir());
            assert!(dir.rules.is_dir());
            assert!(dir.backups.is_dir());
        });
    }

    #[test]
    fn bootstrap_sets_mode_700() {
        with_temp_managed(|dir| {
            for d in [&dir.root, &dir.rules, &dir.backups] {
                let mode = fs::metadata(d).unwrap().permissions().mode() & 0o777;
                assert_eq!(mode, 0o700, "expected 700 on {d:?}, got {mode:o}");
            }
        });
    }

    #[test]
    fn bootstrap_is_idempotent() {
        with_temp_managed(|_| {
            assert!(ManagedDir::bootstrap().is_ok());
        });
    }

    #[test]
    fn lsrules_file_path_has_extension() {
        with_temp_managed(|dir| {
            let path = dir.lsrules_file("my-rules");
            assert_eq!(path.file_name().unwrap(), "my-rules.lsrules");
            assert_eq!(path.parent().unwrap(), dir.rules);
        });
    }
}
