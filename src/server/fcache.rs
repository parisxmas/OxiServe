//! The open-file cache behind `open_file_cache`.
//!
//! Profiling on Linux showed 3 of the ~5.5 syscalls per static request were
//! filesystem metadata: `statx` + `openat` + `close`, and 88% of request CPU
//! was kernel time dominated by path lookup. This cache keeps the opened
//! descriptor and its `fstat` result per worker thread, so a hit serves a
//! request with **zero** filesystem syscalls.
//!
//! Per-worker (thread-local) by design — the same choice nginx makes. No
//! locks, no cross-core traffic; the cost is that each worker warms its own
//! copy.
//!
//! Semantics follow nginx's documented behaviour: within
//! `open_file_cache_valid` a cached result is trusted, so file changes are
//! not observed until the entry re-validates. Sharing the descriptor is safe
//! because every consumer reads with an explicit offset (`pread`,
//! `sendfile(off)`) — nothing ever touches the shared file position.

use std::cell::RefCell;
use std::collections::HashMap;
use std::fs::File;
use std::sync::Arc;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use crate::config::model::OpenFileCache;

/// What a path resolved to.
#[derive(Clone)]
pub enum Cached {
    File {
        file: Arc<File>,
        size: u64,
        mtime: SystemTime,
    },
    Dir,
    /// The HTTP status the failure maps to (404, 403, …).
    Error(u16),
}

struct Entry {
    val: Cached,
    /// When the entry was created or last re-validated.
    checked: Instant,
    last_used: Instant,
    uses: u32,
}

thread_local! {
    static CACHE: RefCell<HashMap<Box<str>, Entry>> = RefCell::new(HashMap::new());
}

/// Resolves `path`, through the worker's cache when the directive enables it.
pub fn lookup(path: &str, p: &OpenFileCache) -> Cached {
    if !p.enabled {
        return open_direct(path);
    }
    let now = Instant::now();

    let hit = CACHE.with(|c| {
        let mut m = c.borrow_mut();
        match m.get_mut(path) {
            Some(e)
                if now.duration_since(e.checked) <= p.valid
                    && now.duration_since(e.last_used) <= p.inactive =>
            {
                e.last_used = now;
                e.uses = e.uses.saturating_add(1);
                Some(e.val.clone())
            }
            Some(_) => {
                // Past `valid` (or idle past `inactive`): drop and re-resolve.
                m.remove(path);
                None
            }
            None => None,
        }
    });
    if let Some(v) = hit {
        return v;
    }

    let v = open_direct(path);
    let cacheable = match &v {
        Cached::Error(_) => p.errors,
        _ => true,
    };
    if cacheable {
        CACHE.with(|c| {
            let mut m = c.borrow_mut();
            if m.len() >= p.max {
                evict(&mut m, p);
            }
            m.insert(
                path.into(),
                Entry { val: v.clone(), checked: now, last_used: now, uses: 1 },
            );
        });
    }
    v
}

/// One `open` + one `fstat`.
///
/// Even with the cache disabled this is cheaper than the old flow: `stat(path)`
/// followed by `open(path)` walked the path **twice**; `fstat(fd)` is a
/// descriptor operation with no path resolution at all.
fn open_direct(path: &str) -> Cached {
    let f = match File::open(path) {
        Ok(f) => f,
        Err(e) => return Cached::Error(super::files::io_status(&e)),
    };
    match f.metadata() {
        Ok(md) if md.is_dir() => Cached::Dir,
        Ok(md) => Cached::File {
            size: md.len(),
            mtime: md.modified().unwrap_or(UNIX_EPOCH),
            file: Arc::new(f),
        },
        Err(e) => Cached::Error(super::files::io_status(&e)),
    }
}

/// Frees roughly 10% of `max`, preferring entries that never reached
/// `min_uses`, then the least recently used. Runs only when the cache is full,
/// so the O(n log n) sort is off the hot path.
fn evict(m: &mut HashMap<Box<str>, Entry>, p: &OpenFileCache) {
    let mut victims: Vec<(Box<str>, bool, Instant)> = m
        .iter()
        .map(|(k, e)| (k.clone(), e.uses < p.min_uses, e.last_used))
        .collect();
    // Under-used entries first, then oldest.
    victims.sort_by(|a, b| b.1.cmp(&a.1).then(a.2.cmp(&b.2)));
    let drop_n = (p.max / 10).max(1);
    for (k, _, _) in victims.into_iter().take(drop_n) {
        m.remove(&k);
    }
}

/// Test hook: number of entries in this worker's cache.
#[cfg(test)]
fn len() -> usize {
    CACHE.with(|c| c.borrow().len())
}

#[cfg(test)]
fn clear() {
    CACHE.with(|c| c.borrow_mut().clear());
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::time::Duration;

    fn tmp(name: &str, content: &[u8]) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("oxiserve-fcache-{}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        let p = d.join(name);
        let mut f = std::fs::File::create(&p).unwrap();
        f.write_all(content).unwrap();
        p
    }

    fn params(max: usize, valid_ms: u64) -> OpenFileCache {
        OpenFileCache {
            enabled: true,
            max,
            inactive: Duration::from_secs(60),
            valid: Duration::from_millis(valid_ms),
            min_uses: 1,
            errors: false,
        }
    }

    #[test]
    fn hit_serves_the_cached_metadata() {
        clear();
        let p = tmp("hit.txt", b"12345");
        let path = p.to_str().unwrap();
        let ofc = params(16, 60_000);

        let Cached::File { size, .. } = lookup(path, &ofc) else { panic!("expected file") };
        assert_eq!(size, 5);

        // Grow the file; within `valid` the cache must still report old size.
        std::fs::write(&p, b"1234567890").unwrap();
        let Cached::File { size, .. } = lookup(path, &ofc) else { panic!("expected file") };
        assert_eq!(size, 5, "size change must not be visible within valid window");
    }

    #[test]
    fn expiry_revalidates() {
        clear();
        let p = tmp("expire.txt", b"old");
        let path = p.to_str().unwrap();
        let ofc = params(16, 50); // 50ms validity

        let Cached::File { size, .. } = lookup(path, &ofc) else { panic!() };
        assert_eq!(size, 3);
        std::fs::write(&p, b"newer!").unwrap();
        std::thread::sleep(Duration::from_millis(80));
        let Cached::File { size, .. } = lookup(path, &ofc) else { panic!() };
        assert_eq!(size, 6, "entry must re-validate after valid expires");
    }

    #[test]
    fn disabled_cache_sees_changes_immediately() {
        clear();
        let p = tmp("nocache.txt", b"a");
        let path = p.to_str().unwrap();
        let ofc = OpenFileCache::default(); // disabled

        let Cached::File { size, .. } = lookup(path, &ofc) else { panic!() };
        assert_eq!(size, 1);
        std::fs::write(&p, b"ab").unwrap();
        let Cached::File { size, .. } = lookup(path, &ofc) else { panic!() };
        assert_eq!(size, 2);
        assert_eq!(len(), 0, "disabled cache must not store entries");
    }

    #[test]
    fn errors_cached_only_when_asked() {
        clear();
        let d = std::env::temp_dir().join(format!("oxiserve-fcache-{}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        let missing = d.join("appears-later.txt");
        let path = missing.to_str().unwrap().to_string();

        // errors off: the miss is not cached, so the file is found once created.
        let off = params(16, 60_000);
        assert!(matches!(lookup(&path, &off), Cached::Error(404)));
        std::fs::write(&missing, b"here").unwrap();
        assert!(matches!(lookup(&path, &off), Cached::File { .. }));

        // errors on: the 404 sticks until validity expires.
        std::fs::remove_file(&missing).unwrap();
        clear();
        let mut on = params(16, 60_000);
        on.errors = true;
        assert!(matches!(lookup(&path, &on), Cached::Error(404)));
        std::fs::write(&missing, b"here").unwrap();
        assert!(
            matches!(lookup(&path, &on), Cached::Error(404)),
            "with errors on, the cached 404 must persist within valid"
        );
    }

    #[test]
    fn eviction_bounds_the_cache() {
        clear();
        let ofc = params(4, 60_000);
        for i in 0..12 {
            let p = tmp(&format!("evict-{i}.txt"), b"x");
            lookup(p.to_str().unwrap(), &ofc);
        }
        assert!(len() <= 4, "cache exceeded max: {}", len());
    }

    #[test]
    fn directories_are_classified() {
        clear();
        let d = std::env::temp_dir().join(format!("oxiserve-fcache-{}/subdir", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        let ofc = params(16, 60_000);
        assert!(matches!(lookup(d.to_str().unwrap(), &ofc), Cached::Dir));
    }
}
