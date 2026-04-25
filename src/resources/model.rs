//! `littlesnitch://model` resource — returns the full live model JSON.
//!
//! The model JSON is cached with a short TTL so that repeated reads within
//! the same few seconds do not each shell out to `littlesnitch export-model`.

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

pub const URI: &str = "littlesnitch://model";
pub const DESCRIPTION: &str = "Full Little Snitch model JSON (rules, groups, profiles, preferences). \
     Cached for 5 seconds.";

const TTL: Duration = Duration::from_secs(5);

/// Shared, briefly-cached model JSON string.
///
/// Stored as an `Arc<Mutex<...>>` so `LittleSnitchServer` clones (one per MCP
/// connection) all share the same cache entry without locking across
/// connections longer than a single read.
#[derive(Clone, Default)]
pub struct ModelCache(Arc<Mutex<Option<(Instant, String)>>>);

impl ModelCache {
    pub fn new() -> Self {
        Self(Arc::new(Mutex::new(None)))
    }

    /// Return cached JSON if fresh, or call `fetch` to refresh.
    pub fn get_or_fetch<F>(&self, fetch: F) -> Result<String, String>
    where
        F: FnOnce() -> Result<String, String>,
    {
        let mut guard = self.0.lock().unwrap_or_else(|e| e.into_inner());

        if let Some((ts, json)) = &*guard
            && ts.elapsed() < TTL
        {
            return Ok(json.clone());
        }

        let json = fetch()?;
        *guard = Some((Instant::now(), json.clone()));
        Ok(json)
    }

    /// Invalidate the cache (called after a write so the next read is fresh).
    pub fn invalidate(&self) {
        let mut guard = self.0.lock().unwrap_or_else(|e| e.into_inner());
        *guard = None;
    }
}

/// Fetch the live model JSON by running `littlesnitch export-model`.
pub fn fetch_model_json() -> Result<String, String> {
    let cli = crate::cli::adapter::LsCli::resolve()
        .map_err(|e| format!("littlesnitch binary not found: {e}"))?;
    let output = cli
        .run(&["export-model"])
        .map_err(|e| format!("export-model failed: {e}"))?;
    String::from_utf8(output.stdout).map_err(|e| format!("export-model output not UTF-8: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cache_returns_same_value_within_ttl() {
        let cache = ModelCache::new();
        let mut call_count = 0usize;
        let json1 = cache
            .get_or_fetch(|| {
                call_count += 1;
                Ok(r#"{"bundleVersion":1}"#.to_string())
            })
            .unwrap();
        let json2 = cache
            .get_or_fetch(|| {
                call_count += 1;
                Ok(r#"{"bundleVersion":2}"#.to_string())
            })
            .unwrap();
        assert_eq!(json1, json2, "second call must return cached value");
        assert_eq!(call_count, 1, "fetch must be called only once");
    }

    #[test]
    fn invalidate_forces_refetch() {
        let cache = ModelCache::new();
        cache
            .get_or_fetch(|| Ok(r#"{"bundleVersion":1}"#.to_string()))
            .unwrap();
        cache.invalidate();
        let json = cache
            .get_or_fetch(|| Ok(r#"{"bundleVersion":2}"#.to_string()))
            .unwrap();
        assert_eq!(json, r#"{"bundleVersion":2}"#);
    }

    #[test]
    fn fetch_error_propagates() {
        let cache = ModelCache::new();
        let err = cache.get_or_fetch(|| Err("oops".to_string())).unwrap_err();
        assert_eq!(err, "oops");
    }

    #[test]
    fn stale_cache_refetches() {
        let cache = ModelCache::new();
        // Prime with a value that has an artificially old timestamp.
        {
            let mut guard = cache.0.lock().unwrap();
            *guard = Some((
                Instant::now() - Duration::from_secs(10),
                r#"{"bundleVersion":0}"#.to_string(),
            ));
        }
        let json = cache
            .get_or_fetch(|| Ok(r#"{"bundleVersion":99}"#.to_string()))
            .unwrap();
        assert_eq!(json, r#"{"bundleVersion":99}"#);
    }
}
