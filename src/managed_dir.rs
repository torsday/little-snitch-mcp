use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use thiserror::Error;

/// Env-var override for the managed directory root.
pub const ENV_MANAGED_DIR: &str = "LSMCP_MANAGED_DIR";

/// Subdirectory for `.lsrules` Track-A files.
pub const RULES_SUBDIR: &str = "rules";

/// Subdirectory for live-model export backups.
pub const BACKUPS_SUBDIR: &str = "backups";

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

        for dir in [&root, &rules, &backups] {
            ensure_dir_700(dir)?;
        }

        Ok(Self { root, rules, backups })
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn temp_root() -> tempfile::TempDir {
        tempfile::tempdir().expect("tempdir")
    }

    #[test]
    fn bootstrap_creates_subdirs() {
        let td = temp_root();
        let root = td.path().join("mcp");
        // SAFETY: single-threaded test; no other threads read this env var concurrently.
        unsafe {
            std::env::set_var(ENV_MANAGED_DIR, &root);
        }
        let dir = ManagedDir::bootstrap().unwrap();
        assert!(dir.root.is_dir());
        assert!(dir.rules.is_dir());
        assert!(dir.backups.is_dir());
        unsafe {
            std::env::remove_var(ENV_MANAGED_DIR);
        }
    }

    #[test]
    fn bootstrap_sets_mode_700() {
        let td = temp_root();
        let root = td.path().join("mcp2");
        unsafe {
            std::env::set_var(ENV_MANAGED_DIR, &root);
        }
        let dir = ManagedDir::bootstrap().unwrap();
        for d in [&dir.root, &dir.rules, &dir.backups] {
            let mode = fs::metadata(d).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o700, "expected 700 on {d:?}, got {mode:o}");
        }
        unsafe {
            std::env::remove_var(ENV_MANAGED_DIR);
        }
    }

    #[test]
    fn bootstrap_is_idempotent() {
        let td = temp_root();
        let root = td.path().join("mcp3");
        unsafe {
            std::env::set_var(ENV_MANAGED_DIR, &root);
        }
        assert!(ManagedDir::bootstrap().is_ok());
        assert!(ManagedDir::bootstrap().is_ok()); // second call must not error
        unsafe {
            std::env::remove_var(ENV_MANAGED_DIR);
        }
    }

    #[test]
    fn lsrules_file_path_has_extension() {
        let td = temp_root();
        let root = td.path().join("mcp4");
        unsafe {
            std::env::set_var(ENV_MANAGED_DIR, &root);
        }
        let dir = ManagedDir::bootstrap().unwrap();
        let path = dir.lsrules_file("my-rules");
        assert_eq!(path.file_name().unwrap(), "my-rules.lsrules");
        assert_eq!(path.parent().unwrap(), dir.rules);
        unsafe {
            std::env::remove_var(ENV_MANAGED_DIR);
        }
    }
}
