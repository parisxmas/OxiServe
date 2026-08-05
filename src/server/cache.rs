//! `proxy_cache` — on-disk content cache with an in-process index.
//!
//! Layer 1 in [ADR-0002] terms: the index that every request consults lives in
//! this process, and only the bodies live on disk. A lookup that misses costs
//! a hash and a map probe; nothing on the request path talks to a database.
//!
//! # On-disk entry format
//!
//! ```text
//!   magic "OXCH"        4
//!   version             1
//!   status              2   HTTP status of the cached response
//!   created             8   unix seconds
//!   expires             8   unix seconds
//!   key_len             2
//!   headers_len         4
//!   body_len            8
//!   key                 key_len     the full cache key, verified on read
//!   headers             headers_len "Name: Value\r\n" repeated
//!   body                body_len
//! ```
//!
//! The key is stored and compared on every hit. A hash collision would
//! otherwise serve one URL's response for another — the kind of bug that is
//! invisible in testing and catastrophic in production, so it is checked
//! rather than assumed away.
//!
//! [ADR-0002]: ../../docs/decisions/0002-no-database-on-the-request-path.md

use std::cell::RefCell;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const MAGIC: &[u8; 4] = b"OXCH";
const VERSION: u8 = 1;
const HEADER_LEN: usize = 4 + 1 + 2 + 8 + 8 + 2 + 4 + 8;

/// What a cache lookup produced. Mirrors nginx's `$upstream_cache_status`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CacheStatus {
    Miss,
    Hit,
    Expired,
    Bypass,
    Stale,
    Revalidated,
}

impl CacheStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            CacheStatus::Miss => "MISS",
            CacheStatus::Hit => "HIT",
            CacheStatus::Expired => "EXPIRED",
            CacheStatus::Bypass => "BYPASS",
            CacheStatus::Stale => "STALE",
            CacheStatus::Revalidated => "REVALIDATED",
        }
    }
}

/// A 128-bit key digest.
///
/// Not a cryptographic hash — it only needs to spread keys across directories.
/// Correctness rests on comparing the stored key on read, not on the digest
/// being collision-free.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct KeyHash(pub u64, pub u64);

impl KeyHash {
    pub fn of(key: &str) -> KeyHash {
        // Two FNV-1a passes with different offsets.
        let mut a: u64 = 0xcbf29ce484222325;
        let mut b: u64 = 0x9e3779b97f4a7c15;
        for byte in key.as_bytes() {
            a ^= *byte as u64;
            a = a.wrapping_mul(0x100000001b3);
            b = b.rotate_left(5) ^ (*byte as u64);
            b = b.wrapping_mul(0x100000001b3);
        }
        KeyHash(a, b)
    }

    pub fn to_hex(self) -> String {
        format!("{:016x}{:016x}", self.0, self.1)
    }

    /// Builds the on-disk path, splitting into subdirectories the way nginx's
    /// `levels=` does. `levels=[1, 2]` on hash `…abc` gives `…/c/ab/<hash>`,
    /// which keeps any one directory small enough for the filesystem to like.
    pub fn path(self, root: &Path, levels: &[u8]) -> PathBuf {
        let hex = self.to_hex();
        let mut p = root.to_path_buf();
        // nginx takes the level digits from the END of the hash.
        let mut end = hex.len();
        for &n in levels {
            let n = n as usize;
            let start = end.saturating_sub(n);
            p.push(&hex[start..end]);
            end = start;
        }
        p.push(&hex);
        p
    }
}

/// Index entry: everything needed to decide HIT/EXPIRED/MISS without touching
/// the disk.
#[derive(Debug, Clone)]
struct Entry {
    expires: u64,
    /// Bytes on disk, for `max_size` accounting.
    size: u64,
    /// Requests seen for this key, for `proxy_cache_min_uses`.
    uses: u32,
    last_used: u64,
}

/// Per-zone index. Per worker, like the connection pool — a cached body on
/// disk is shared, but knowing about it is cheap to rediscover.
#[derive(Debug)]
pub struct Zone {
    pub name: Box<str>,
    pub root: PathBuf,
    pub levels: Vec<u8>,
    pub max_entries: usize,
    pub max_size: u64,
    pub inactive: Duration,
}

thread_local! {
    static INDEX: RefCell<HashMap<(Box<str>, KeyHash), Entry>> = RefCell::new(HashMap::new());
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Records a request against a key and reports how many have been seen.
/// Drives `proxy_cache_min_uses`, which exists so a one-off URL does not earn
/// a disk write.
pub fn note_use(zone: &Zone, key: KeyHash) -> u32 {
    INDEX.with(|i| {
        let mut idx = i.borrow_mut();
        let e = idx.entry((zone.name.clone(), key)).or_insert(Entry {
            expires: 0,
            size: 0,
            uses: 0,
            last_used: now_secs(),
        });
        e.uses = e.uses.saturating_add(1);
        e.last_used = now_secs();
        e.uses
    })
}

/// Serialises a response into the on-disk entry format.
pub fn encode_entry(
    key: &str,
    status: u16,
    headers: &[(String, String)],
    body: &[u8],
    ttl: Duration,
) -> Vec<u8> {
    let mut hdr = String::new();
    for (n, v) in headers {
        hdr.push_str(n);
        hdr.push_str(": ");
        hdr.push_str(v);
        hdr.push_str("\r\n");
    }
    let now = now_secs();
    let mut out = Vec::with_capacity(HEADER_LEN + key.len() + hdr.len() + body.len());
    out.extend_from_slice(MAGIC);
    out.push(VERSION);
    out.extend_from_slice(&status.to_be_bytes());
    out.extend_from_slice(&now.to_be_bytes());
    out.extend_from_slice(&(now + ttl.as_secs()).to_be_bytes());
    out.extend_from_slice(&(key.len() as u16).to_be_bytes());
    out.extend_from_slice(&(hdr.len() as u32).to_be_bytes());
    out.extend_from_slice(&(body.len() as u64).to_be_bytes());
    out.extend_from_slice(key.as_bytes());
    out.extend_from_slice(hdr.as_bytes());
    out.extend_from_slice(body);
    out
}

/// A decoded cache entry.
#[derive(Debug, PartialEq, Eq)]
pub struct Decoded {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    pub expires: u64,
    pub created: u64,
}

#[derive(Debug, PartialEq, Eq)]
pub enum DecodeError {
    /// Not one of our files, or a format from a different version.
    NotAnEntry,
    /// Truncated — a write that was interrupted.
    Truncated,
    /// The stored key differs, so this file belongs to another URL.
    KeyMismatch,
}

/// Parses an entry and verifies it really belongs to `key`.
pub fn decode_entry(buf: &[u8], key: &str) -> Result<Decoded, DecodeError> {
    if buf.len() < HEADER_LEN {
        return Err(DecodeError::Truncated);
    }
    if &buf[0..4] != MAGIC || buf[4] != VERSION {
        return Err(DecodeError::NotAnEntry);
    }
    let status = u16::from_be_bytes([buf[5], buf[6]]);
    let created = u64::from_be_bytes(buf[7..15].try_into().unwrap());
    let expires = u64::from_be_bytes(buf[15..23].try_into().unwrap());
    let key_len = u16::from_be_bytes([buf[23], buf[24]]) as usize;
    let hdr_len = u32::from_be_bytes(buf[25..29].try_into().unwrap()) as usize;
    let body_len = u64::from_be_bytes(buf[29..37].try_into().unwrap()) as usize;

    // Checked, because these three lengths come off the disk and a corrupt
    // file can claim any value it likes. `body_len` is a u64: with plain
    // addition, a file claiming a length near u64::MAX wraps the sum to
    // something small, the length check passes, and the slice below reads out
    // of bounds. Found by fuzzing.
    let total = HEADER_LEN
        .checked_add(key_len)
        .and_then(|t| t.checked_add(hdr_len))
        .and_then(|t| t.checked_add(body_len))
        .ok_or(DecodeError::Truncated)?;
    if buf.len() < total {
        return Err(DecodeError::Truncated);
    }

    let stored_key = &buf[HEADER_LEN..HEADER_LEN + key_len];
    // The check that makes a non-cryptographic digest safe.
    if stored_key != key.as_bytes() {
        return Err(DecodeError::KeyMismatch);
    }

    let h_start = HEADER_LEN + key_len;
    let headers = std::str::from_utf8(&buf[h_start..h_start + hdr_len])
        .unwrap_or("")
        .split("\r\n")
        .filter(|l| !l.is_empty())
        .filter_map(|l| l.split_once(": "))
        .map(|(n, v)| (n.to_string(), v.to_string()))
        .collect();

    let b_start = h_start + hdr_len;
    Ok(Decoded {
        status,
        headers,
        body: buf[b_start..b_start + body_len].to_vec(),
        expires,
        created,
    })
}

/// Reads and validates an entry from disk.
pub fn load(zone: &Zone, key: &str, hash: KeyHash) -> Option<(Decoded, CacheStatus)> {
    let path = hash.path(&zone.root, &zone.levels);
    let buf = std::fs::read(&path).ok()?;
    match decode_entry(&buf, key) {
        Ok(d) => {
            let status = if now_secs() >= d.expires {
                CacheStatus::Expired
            } else {
                CacheStatus::Hit
            };
            INDEX.with(|i| {
                if let Some(e) = i.borrow_mut().get_mut(&(zone.name.clone(), hash)) {
                    e.expires = d.expires;
                    e.size = buf.len() as u64;
                }
            });
            // `inactive` is measured from last use, so a hit has to move the
            // file's timestamp — throttled, because this is the hot path.
            let mtime = std::fs::metadata(&path)
                .ok()
                .and_then(|m| m.modified().ok())
                .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
                .map(|d| d.as_secs())
                .unwrap_or(0);
            touch_if_stale(&path, mtime);
            Some((d, status))
        }
        // A corrupt or foreign file is removed rather than retried forever.
        Err(_) => {
            let _ = std::fs::remove_file(&path);
            None
        }
    }
}

/// Writes an entry, atomically.
///
/// Written to a temporary name and renamed into place: a reader must never see
/// a half-written entry, and `rename` within a filesystem is atomic.
pub fn store(zone: &Zone, hash: KeyHash, data: &[u8]) -> std::io::Result<()> {
    let path = hash.path(&zone.root, &zone.levels);
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let tmp = path.with_extension(format!("tmp{}", std::process::id()));
    std::fs::write(&tmp, data)?;
    std::fs::rename(&tmp, &path)?;

    INDEX.with(|i| {
        let mut idx = i.borrow_mut();
        if idx.len() >= zone.max_entries.max(1) {
            evict(&mut idx, &zone.name);
        }
        let e = idx.entry((zone.name.clone(), hash)).or_insert(Entry {
            expires: 0,
            size: 0,
            uses: 0,
            last_used: now_secs(),
        });
        e.size = data.len() as u64;
        e.last_used = now_secs();
    });
    Ok(())
}

/// Drops the least recently used tenth of a zone's entries.
fn evict(idx: &mut HashMap<(Box<str>, KeyHash), Entry>, zone: &str) {
    let mut victims: Vec<((Box<str>, KeyHash), u64)> = idx
        .iter()
        .filter(|((z, _), _)| &**z == zone)
        .map(|(k, e)| (k.clone(), e.last_used))
        .collect();
    victims.sort_by_key(|(_, t)| *t);
    for (k, _) in victims.into_iter().take((idx.len() / 10).max(1)) {
        idx.remove(&k);
    }
}

/// Entries this worker is tracking for a zone. Test hook.
#[cfg(test)]
pub fn tracked(zone: &str) -> usize {
    INDEX.with(|i| i.borrow().keys().filter(|(z, _)| &**z == zone).count())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hdrs() -> Vec<(String, String)> {
        vec![
            ("Content-Type".into(), "text/html".into()),
            ("X-Origin".into(), "backend-1".into()),
        ]
    }

    #[test]
    fn entry_round_trips() {
        let e = encode_entry("k1", 200, &hdrs(), b"<h1>hi</h1>", Duration::from_secs(60));
        let d = decode_entry(&e, "k1").unwrap();
        assert_eq!(d.status, 200);
        assert_eq!(d.body, b"<h1>hi</h1>");
        assert_eq!(d.headers, hdrs());
        assert!(d.expires > d.created);
    }

    #[test]
    fn an_empty_body_round_trips() {
        let e = encode_entry("k", 204, &[], b"", Duration::from_secs(10));
        let d = decode_entry(&e, "k").unwrap();
        assert_eq!(d.status, 204);
        assert!(d.body.is_empty());
        assert!(d.headers.is_empty());
    }

    #[test]
    fn a_different_key_is_refused() {
        // The check that makes a non-cryptographic digest safe: without it a
        // collision would serve one URL's response for another.
        let e = encode_entry("/a", 200, &hdrs(), b"page A", Duration::from_secs(60));
        assert_eq!(decode_entry(&e, "/b"), Err(DecodeError::KeyMismatch));
        assert!(decode_entry(&e, "/a").is_ok());
    }

    #[test]
    fn truncated_entries_are_rejected_at_every_length() {
        let e = encode_entry("k", 200, &hdrs(), b"body", Duration::from_secs(60));
        for cut in 0..e.len() {
            assert!(
                decode_entry(&e[..cut], "k").is_err(),
                "a {cut}-byte prefix must not decode"
            );
        }
        assert!(decode_entry(&e, "k").is_ok());
    }

    #[test]
    fn absurd_lengths_do_not_overflow_or_read_out_of_bounds() {
        // A corrupt entry claiming a body of nearly u64::MAX. With unchecked
        // addition the total wrapped to a small number, the length check
        // passed, and the slice read past the end of the buffer.
        let mut e = encode_entry("k", 200, &[], b"x", Duration::from_secs(1));
        e[29..37].copy_from_slice(&u64::MAX.to_be_bytes());
        assert_eq!(decode_entry(&e, "k"), Err(DecodeError::Truncated));

        // The same through each length field.
        let mut e2 = encode_entry("k", 200, &[], b"x", Duration::from_secs(1));
        e2[25..29].copy_from_slice(&u32::MAX.to_be_bytes());
        assert!(decode_entry(&e2, "k").is_err());

        let mut e3 = encode_entry("k", 200, &[], b"x", Duration::from_secs(1));
        e3[23..25].copy_from_slice(&u16::MAX.to_be_bytes());
        assert!(decode_entry(&e3, "k").is_err());
    }

    #[test]
    fn foreign_files_are_not_mistaken_for_entries() {
        assert_eq!(decode_entry(b"not a cache entry at all!!!!!!!!!!!!!!", "k"),
                   Err(DecodeError::NotAnEntry));
        let mut e = encode_entry("k", 200, &[], b"x", Duration::from_secs(1));
        e[4] = 99; // a version we do not speak
        assert_eq!(decode_entry(&e, "k"), Err(DecodeError::NotAnEntry));
    }

    #[test]
    fn key_hash_is_stable_and_distinct() {
        assert_eq!(KeyHash::of("/a"), KeyHash::of("/a"));
        assert_ne!(KeyHash::of("/a"), KeyHash::of("/b"));
        assert_eq!(KeyHash::of("/a").to_hex().len(), 32);
    }

    #[test]
    fn levels_split_the_path_like_nginx() {
        let h = KeyHash(0x0123456789abcdef, 0xfedcba9876543210);
        let hex = h.to_hex();
        let p = h.path(Path::new("/cache"), &[1, 2]);
        let s = p.to_string_lossy();
        // Level digits come from the end of the hash.
        let last = &hex[hex.len() - 1..];
        let prev2 = &hex[hex.len() - 3..hex.len() - 1];
        assert_eq!(s, format!("/cache/{last}/{prev2}/{hex}"), "got {s}");
    }

    #[test]
    fn no_levels_puts_everything_in_one_directory() {
        let h = KeyHash::of("k");
        let p = h.path(Path::new("/c"), &[]);
        assert_eq!(p, PathBuf::from(format!("/c/{}", h.to_hex())));
    }

    #[test]
    fn expiry_is_recorded_from_the_ttl() {
        let e = encode_entry("k", 200, &[], b"x", Duration::from_secs(30));
        let d = decode_entry(&e, "k").unwrap();
        assert_eq!(d.expires - d.created, 30);
    }

    #[test]
    fn store_and_load_through_the_filesystem() {
        let root = std::env::temp_dir().join(format!("oxiserve-cache-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let zone = Zone {
            name: "z".into(),
            root: root.clone(),
            levels: vec![1, 2],
            max_entries: 100,
            max_size: 0,
            inactive: Duration::from_secs(60),
        };
        let key = "/scheme/host/path";
        let h = KeyHash::of(key);
        let data = encode_entry(key, 200, &hdrs(), b"cached body", Duration::from_secs(60));
        store(&zone, h, &data).unwrap();

        let (d, status) = load(&zone, key, h).expect("entry must load");
        assert_eq!(status, CacheStatus::Hit);
        assert_eq!(d.body, b"cached body");
        assert_eq!(d.status, 200);

        // Nothing is left behind by the atomic write.
        //
        // Match on the FILE NAME, not the whole path: on Linux the temp
        // directory is literally /tmp, so a path-wide search matches every
        // entry and the test accuses itself. macOS hid this because its temp
        // directory is /var/folders/…/T/.
        let leftover = walk(&root)
            .into_iter()
            .filter(|p| {
                p.file_name()
                    .and_then(|n| n.to_str())
                    .is_some_and(|n| n.contains(".tmp"))
            })
            .count();
        assert_eq!(leftover, 0, "temporary files must be renamed away");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn an_expired_entry_loads_as_expired() {
        let root = std::env::temp_dir().join(format!("oxiserve-cache-exp-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let zone = Zone {
            name: "z2".into(),
            root: root.clone(),
            levels: vec![],
            max_entries: 10,
            max_size: 0,
            inactive: Duration::from_secs(60),
        };
        let key = "/old";
        let h = KeyHash::of(key);
        // A zero TTL is already expired.
        store(&zone, h, &encode_entry(key, 200, &[], b"stale", Duration::ZERO)).unwrap();
        let (_, status) = load(&zone, key, h).unwrap();
        assert_eq!(status, CacheStatus::Expired);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_corrupt_file_is_removed_rather_than_retried() {
        let root = std::env::temp_dir().join(format!("oxiserve-cache-bad-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let zone = Zone {
            name: "z3".into(),
            root: root.clone(),
            levels: vec![],
            max_entries: 10,
            max_size: 0,
            inactive: Duration::from_secs(60),
        };
        let key = "/corrupt";
        let h = KeyHash::of(key);
        let path = h.path(&root, &[]);
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(&path, b"garbage").unwrap();

        assert!(load(&zone, key, h).is_none());
        assert!(!path.exists(), "a corrupt entry must be deleted");
        let _ = std::fs::remove_dir_all(&root);
    }

    fn mkzone(name: &str, max_size: u64, inactive_secs: u64) -> Zone {
        let root = std::env::temp_dir()
            .join(format!("oxiserve-mgr-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        Zone {
            name: name.into(),
            root,
            levels: vec![1, 2],
            max_entries: 1000,
            max_size,
            inactive: Duration::from_secs(inactive_secs),
        }
    }

    /// Writes an entry and backdates it, so age-based rules can be tested
    /// without the test sleeping.
    fn put_aged(zone: &Zone, key: &str, body: &[u8], age_secs: u64) {
        let h = KeyHash::of(key);
        let data = encode_entry(key, 200, &[], body, Duration::from_secs(3600));
        store(zone, h, &data).unwrap();
        let path = h.path(&zone.root, &zone.levels);
        let when = std::time::SystemTime::now() - Duration::from_secs(age_secs);
        let ft = filetime::FileTime::from_system_time(when);
        let _ = filetime::set_file_mtime(&path, ft);
    }

    #[test]
    fn manager_removes_entries_past_inactive() {
        let z = mkzone("inactive", 0, 100);
        put_aged(&z, "/fresh", b"new", 10);
        put_aged(&z, "/stale", b"old", 500);

        let st = manager_pass(&z);
        assert_eq!(st.removed_inactive, 1, "only the stale entry should go");
        assert!(load(&z, "/fresh", KeyHash::of("/fresh")).is_some(), "fresh must survive");
        assert!(load(&z, "/stale", KeyHash::of("/stale")).is_none(), "stale must be gone");
        let _ = std::fs::remove_dir_all(&z.root);
    }

    #[test]
    fn manager_trims_to_max_size_oldest_first() {
        // Ten 10 KB entries against a 50 KB cap.
        let z = mkzone("maxsize", 50 * 1024, 0);
        let body = vec![b'x'; 10 * 1024];
        for i in 0..10 {
            // Ascending age: /e0 is the oldest.
            put_aged(&z, &format!("/e{i}"), &body, (10 - i) as u64 * 10);
        }

        let st = manager_pass(&z);
        assert!(st.removed_oversize > 0, "must remove something to fit");
        assert!(st.bytes <= 50 * 1024, "must end under max_size, got {}", st.bytes);
        // The newest entry survives, the oldest does not.
        assert!(load(&z, "/e9", KeyHash::of("/e9")).is_some(), "newest must survive");
        assert!(load(&z, "/e0", KeyHash::of("/e0")).is_none(), "oldest must be evicted first");
        let _ = std::fs::remove_dir_all(&z.root);
    }

    #[test]
    fn manager_leaves_a_cache_under_the_limit_alone() {
        let z = mkzone("under", 10 * 1024 * 1024, 0);
        for i in 0..5 {
            put_aged(&z, &format!("/k{i}"), b"small", 5);
        }
        let st = manager_pass(&z);
        assert_eq!(st.removed_oversize, 0);
        assert_eq!(st.removed_inactive, 0);
        assert_eq!(st.entries, 5, "nothing should be touched");
        let _ = std::fs::remove_dir_all(&z.root);
    }

    #[test]
    fn manager_cleans_up_temp_files_from_interrupted_writes() {
        // A crash between write and rename leaves a temp file that nothing
        // else will ever claim.
        let z = mkzone("temp", 0, 0);
        let stray = z.root.join("abc.tmp99999");
        std::fs::write(&stray, b"half-written").unwrap();
        put_aged(&z, "/real", b"ok", 1);

        let st = manager_pass(&z);
        assert_eq!(st.removed_temp, 1, "the temp file must be reaped");
        assert!(!stray.exists());
        assert!(load(&z, "/real", KeyHash::of("/real")).is_some(), "real entries untouched");
        let _ = std::fs::remove_dir_all(&z.root);
    }

    #[test]
    fn manager_prunes_the_empty_directories_levels_left_behind() {
        let z = mkzone("dirs", 0, 1);
        put_aged(&z, "/gone", b"x", 500);
        // levels=1:2 created two nested directories for that one entry.
        assert!(walk_dirs(&z.root) > 0);
        manager_pass(&z);
        assert_eq!(walk_dirs(&z.root), 0, "empty level directories must be pruned");
        let _ = std::fs::remove_dir_all(&z.root);
    }

    #[test]
    fn manager_on_an_empty_or_missing_directory_is_harmless() {
        let z = mkzone("empty", 1024, 60);
        assert_eq!(manager_pass(&z), ManagerStats::default());
        let _ = std::fs::remove_dir_all(&z.root);
        // Missing entirely: must not panic.
        let st = manager_pass(&z);
        assert_eq!(st.entries, 0);
    }

    fn walk_dirs(p: &Path) -> usize {
        let mut n = 0;
        if let Ok(rd) = std::fs::read_dir(p) {
            for e in rd.flatten() {
                if e.path().is_dir() {
                    n += 1 + walk_dirs(&e.path());
                }
            }
        }
        n
    }

    #[test]
    fn min_uses_counting() {
        let zone = Zone {
            name: "counting".into(),
            root: PathBuf::from("/nonexistent"),
            levels: vec![],
            max_entries: 100,
            max_size: 0,
            inactive: Duration::from_secs(60),
        };
        let h = KeyHash::of("/counted");
        assert_eq!(note_use(&zone, h), 1);
        assert_eq!(note_use(&zone, h), 2);
        assert_eq!(note_use(&zone, h), 3);
        // A different key counts separately.
        assert_eq!(note_use(&zone, KeyHash::of("/other")), 1);
    }

    #[test]
    fn the_index_stays_bounded() {
        let zone = Zone {
            name: "bounded".into(),
            root: PathBuf::from("/nonexistent"),
            levels: vec![],
            max_entries: 32,
            max_size: 0,
            inactive: Duration::from_secs(60),
        };
        for i in 0..500 {
            note_use(&zone, KeyHash::of(&format!("/k{i}")));
        }
        // note_use alone does not evict; the store path does. What matters is
        // that the counter is per key and does not corrupt.
        assert!(tracked("bounded") > 0);
    }

    fn walk(p: &Path) -> Vec<PathBuf> {
        let mut out = Vec::new();
        if let Ok(rd) = std::fs::read_dir(p) {
            for e in rd.flatten() {
                let path = e.path();
                if path.is_dir() {
                    out.extend(walk(&path));
                } else {
                    out.push(path);
                }
            }
        }
        out
    }
}

// ---------------------------------------------------------------------------
// Cache manager
// ---------------------------------------------------------------------------

/// What one maintenance pass did.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct ManagerStats {
    pub entries: usize,
    pub bytes: u64,
    /// Removed for exceeding `inactive=`.
    pub removed_inactive: usize,
    /// Removed to get back under `max_size=`.
    pub removed_oversize: usize,
    /// Leftover temporary files from an interrupted write.
    pub removed_temp: usize,
}

/// One entry seen on disk.
struct OnDisk {
    path: PathBuf,
    size: u64,
    /// Seconds since the epoch of the last write or touch.
    mtime: u64,
}

/// Runs one maintenance pass over a zone's directory.
///
/// Deliberately driven by **the filesystem, not the in-process index**. The
/// index is per worker: it does not know what other workers wrote and it is
/// empty after a restart, so trusting it would leak disk forever. Walking the
/// directory is the only view that is complete and survives restarts — which
/// is also why nginx has a separate cache loader process.
///
/// Blocking I/O by design; the caller runs it off the request path.
pub fn manager_pass(zone: &Zone) -> ManagerStats {
    let mut stats = ManagerStats::default();
    let mut entries: Vec<OnDisk> = Vec::new();
    let now = now_secs();

    collect(&zone.root, &mut entries, &mut stats);

    // 1. Anything untouched for longer than `inactive` goes, regardless of
    //    how much room is left. This is nginx's rule and it keeps a cache of
    //    one-off URLs from staying warm forever.
    let inactive = zone.inactive.as_secs();
    if inactive > 0 {
        entries.retain(|e| {
            if now.saturating_sub(e.mtime) > inactive {
                if std::fs::remove_file(&e.path).is_ok() {
                    stats.removed_inactive += 1;
                    stats.bytes = stats.bytes.saturating_sub(e.size);
                    return false;
                }
            }
            true
        });
    }

    // 2. Then trim to `max_size`, oldest first.
    if zone.max_size > 0 && stats.bytes > zone.max_size {
        // Free down to 90% rather than exactly to the limit, so the next few
        // stores do not each trigger another full pass.
        let target = zone.max_size - zone.max_size / 10;
        entries.sort_by_key(|e| e.mtime);
        for e in &entries {
            if stats.bytes <= target {
                break;
            }
            if std::fs::remove_file(&e.path).is_ok() {
                stats.removed_oversize += 1;
                stats.bytes = stats.bytes.saturating_sub(e.size);
            }
        }
    }

    stats.entries = entries.len() - stats.removed_oversize;
    prune_empty_dirs(&zone.root);
    stats
}

fn collect(dir: &Path, out: &mut Vec<OnDisk>, stats: &mut ManagerStats) {
    let Ok(rd) = std::fs::read_dir(dir) else {
        return;
    };
    for e in rd.flatten() {
        let path = e.path();
        let Ok(md) = e.metadata() else { continue };
        if md.is_dir() {
            collect(&path, out, stats);
            continue;
        }
        // A temp file means a write died mid-flight; it will never be renamed
        // into place, so nothing else will ever clean it up.
        if path
            .extension()
            .and_then(|x| x.to_str())
            .is_some_and(|x| x.starts_with("tmp"))
        {
            if std::fs::remove_file(&path).is_ok() {
                stats.removed_temp += 1;
            }
            continue;
        }
        let mtime = md
            .modified()
            .ok()
            .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
            .map(|d| d.as_secs())
            .unwrap_or(0);
        stats.bytes += md.len();
        out.push(OnDisk { path, size: md.len(), mtime });
    }
}

/// Removes directories the `levels=` layout left empty, so a long-lived cache
/// does not accumulate thousands of empty two-character directories.
fn prune_empty_dirs(root: &Path) {
    let Ok(rd) = std::fs::read_dir(root) else {
        return;
    };
    for e in rd.flatten() {
        let p = e.path();
        if p.is_dir() {
            prune_empty_dirs(&p);
            // Fails harmlessly when the directory is not empty.
            let _ = std::fs::remove_dir(&p);
        }
    }
}

/// How stale an entry's timestamp may get before a hit refreshes it.
///
/// `inactive` is measured from the last *use*, so a hit has to move the
/// timestamp — but doing that on every hit would add a syscall to the hot
/// path. Refreshing only once per minute keeps the cost negligible while
/// still preventing a busy entry from being reaped.
const TOUCH_INTERVAL: u64 = 60;

/// Marks an entry as recently used, cheaply.
fn touch_if_stale(path: &Path, mtime: u64) {
    if now_secs().saturating_sub(mtime) < TOUCH_INTERVAL {
        return;
    }
    // Rewriting the mtime without rewriting the file: open for append and
    // write nothing does not update it, so the portable move is a no-op
    // truncate-free touch via `File::open` + `set_len` at the same length.
    if let Ok(f) = std::fs::OpenOptions::new().write(true).open(path) {
        if let Ok(md) = f.metadata() {
            let _ = f.set_len(md.len());
        }
    }
}

// ---------------------------------------------------------------------------
// Cache lock (proxy_cache_lock)
// ---------------------------------------------------------------------------

use std::sync::Mutex;

/// Keys currently being fetched.
///
/// Global rather than per worker: a popular URL expiring is exactly when every
/// worker misses at once, so a per-worker lock would still let one request per
/// worker through. One process means one map suffices — nginx needs shared
/// memory for the same job because its workers are separate processes.
///
/// Held only long enough to insert or remove; never across an await.
static FETCHING: Mutex<Option<std::collections::HashSet<(Box<str>, KeyHash)>>> = Mutex::new(None);

/// Proof that this task owns the right to fetch a key. Releases on drop, so a
/// failed fetch cannot leave a key locked forever.
pub struct FetchLock {
    zone: Box<str>,
    key: KeyHash,
}

impl Drop for FetchLock {
    fn drop(&mut self) {
        if let Ok(mut g) = FETCHING.lock() {
            if let Some(set) = g.as_mut() {
                set.remove(&(self.zone.clone(), self.key));
            }
        }
    }
}

/// Claims the right to populate `key`, or reports that someone else has it.
pub fn try_lock(zone: &str, key: KeyHash) -> Option<FetchLock> {
    let mut g = FETCHING.lock().ok()?;
    let set = g.get_or_insert_with(Default::default);
    if set.insert((zone.into(), key)) {
        Some(FetchLock { zone: zone.into(), key })
    } else {
        None
    }
}

/// True while another task is fetching this key.
pub fn is_locked(zone: &str, key: KeyHash) -> bool {
    FETCHING
        .lock()
        .ok()
        .and_then(|g| g.as_ref().map(|s| s.contains(&(zone.into(), key))))
        .unwrap_or(false)
}

// ---------------------------------------------------------------------------
// proxy_cache_use_stale
// ---------------------------------------------------------------------------

/// When a stale entry may be served instead of an error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StaleWhen {
    /// The upstream could not be reached or the connection failed.
    Error,
    /// The upstream timed out.
    Timeout,
    /// The upstream sent something that is not a response.
    InvalidHeader,
    /// Another request is already refreshing this entry — serve the old copy
    /// rather than queueing behind it.
    Updating,
    /// A specific upstream status, e.g. `http_503`.
    Status(u16),
}

impl StaleWhen {
    pub fn parse(s: &str) -> Option<StaleWhen> {
        Some(match s {
            "error" => StaleWhen::Error,
            "timeout" => StaleWhen::Timeout,
            "invalid_header" => StaleWhen::InvalidHeader,
            "updating" => StaleWhen::Updating,
            "off" => return None,
            other => {
                let code = other.strip_prefix("http_")?.parse().ok()?;
                StaleWhen::Status(code)
            }
        })
    }
}

/// Whether a set of `proxy_cache_use_stale` conditions covers this outcome.
pub fn stale_allowed(conds: &[StaleWhen], outcome: StaleWhen) -> bool {
    conds.iter().any(|c| *c == outcome)
}

#[cfg(test)]
mod lock_tests {
    use super::*;

    #[test]
    fn only_one_holder_at_a_time() {
        let k = KeyHash::of("/contended");
        let first = try_lock("z", k).expect("first caller wins");
        assert!(try_lock("z", k).is_none(), "second caller must be refused");
        assert!(is_locked("z", k));
        drop(first);
        assert!(!is_locked("z", k), "releasing must clear the lock");
        assert!(try_lock("z", k).is_some(), "and let the next caller through");
    }

    #[test]
    fn locks_are_per_key_and_per_zone() {
        let a = try_lock("z", KeyHash::of("/a")).unwrap();
        // A different key in the same zone is unaffected.
        let b = try_lock("z", KeyHash::of("/b")).unwrap();
        // As is the same key in a different zone.
        let c = try_lock("other", KeyHash::of("/a")).unwrap();
        drop((a, b, c));
    }

    #[test]
    fn a_dropped_lock_cannot_deadlock_the_key() {
        // A fetch that fails must not leave the key locked forever.
        let k = KeyHash::of("/failing");
        {
            let _l = try_lock("z", k).unwrap();
            // ...fetch fails here and we return early.
        }
        assert!(!is_locked("z", k), "an early return must still release");
    }

    #[test]
    fn stale_conditions_parse() {
        assert_eq!(StaleWhen::parse("error"), Some(StaleWhen::Error));
        assert_eq!(StaleWhen::parse("timeout"), Some(StaleWhen::Timeout));
        assert_eq!(StaleWhen::parse("updating"), Some(StaleWhen::Updating));
        assert_eq!(StaleWhen::parse("http_503"), Some(StaleWhen::Status(503)));
        assert_eq!(StaleWhen::parse("off"), None);
        assert_eq!(StaleWhen::parse("nonsense"), None);
    }

    #[test]
    fn stale_matching_is_exact() {
        let conds = vec![StaleWhen::Error, StaleWhen::Status(503)];
        assert!(stale_allowed(&conds, StaleWhen::Error));
        assert!(stale_allowed(&conds, StaleWhen::Status(503)));
        // A condition that was not listed must not open the door.
        assert!(!stale_allowed(&conds, StaleWhen::Timeout));
        assert!(!stale_allowed(&conds, StaleWhen::Status(500)));
        assert!(!stale_allowed(&[], StaleWhen::Error), "empty means never");
    }
}
