//! ModSecurity support, via libmodsecurity v3.
//!
//! # Why this and not `load_module`
//!
//! nginx runs ModSecurity through a binary module compiled against nginx's
//! internal C ABI. That ABI is not a plugin interface: a module carries a
//! signature encoding the host's compile-time options, and nginx refuses to
//! load one whose signature differs by a single bit. Hosting such a module
//! would mean being byte-compatible with one specific nginx build — its struct
//! layouts, its global filter chains — which is not something a different
//! server can be.
//!
//! libmodsecurity is the way through, because the rule engine was never the
//! nginx-coupled part. It is a standalone library with a plain C API, and
//! nginx's module is a thin shim over it. Calling it directly gets the real
//! engine and real OWASP CRS semantics with nginx nowhere in the picture.
//!
//! # Threading
//!
//! `ModSecurity` and `RulesSet` are built once at configuration load and are
//! read-only afterwards, so every worker shares one [`Engine`]. A
//! [`Transaction`] is per-request and never crosses threads — it is not `Send`,
//! which is what keeps that true rather than merely intended.

use std::ffi::{c_char, c_int, c_void, CStr, CString};
use std::os::raw::c_uchar;
use std::sync::{Arc, Mutex};

/// libmodsecurity parses rules with a flex scanner that is not reentrant —
/// two threads calling `msc_rules_add*` concurrently abort the process with
/// "fatal flex scanner internal error". Configuration load is single-threaded,
/// so production never reaches that, but relying on a caller's threading model
/// to avoid an abort is not a guarantee. This makes it one.
static RULE_PARSE_LOCK: Mutex<()> = Mutex::new(());

/// Opaque libmodsecurity handles. Only ever held as pointers.
#[repr(C)]
struct ModSecurityT {
    _private: [u8; 0],
}
#[repr(C)]
struct RulesSetT {
    _private: [u8; 0],
}
#[repr(C)]
struct TransactionT {
    _private: [u8; 0],
}

/// Mirrors `ModSecurityIntervention_t` from `modsecurity/intervention.h`.
/// Field order is load-bearing; libmodsecurity writes through this pointer.
#[repr(C)]
struct Intervention {
    status: c_int,
    pause: c_int,
    url: *mut c_char,
    log: *mut c_char,
    disruptive: c_int,
}

/// `ModSecLogCb` from `modsecurity/modsecurity.h`. The second argument is the
/// message; the first is the per-transaction data pointer, which is null here.
type LogCb = extern "C" fn(*mut c_void, *const c_void);

/// Routes a rule's log output to stderr, where the rest of the server's
/// warnings go. Without this libmodsecurity prints "Server log callback is not
/// set" and swallows the message — leaving an operator with a blocked request
/// and no way to learn which rule did it.
extern "C" fn log_cb(_data: *mut c_void, msg: *const c_void) {
    if msg.is_null() {
        return;
    }
    // Safety: libmodsecurity passes a nul-terminated string it owns for the
    // duration of the call; the copy below does not outlive it.
    let text = unsafe { CStr::from_ptr(msg as *const c_char) }.to_string_lossy();
    eprintln!("oxiserve: [warn] modsecurity: {text}");
}

extern "C" {
    fn msc_init() -> *mut ModSecurityT;
    fn msc_set_connector_info(msc: *mut ModSecurityT, connector: *const c_char);
    fn msc_set_log_cb(msc: *mut ModSecurityT, cb: LogCb);
    fn msc_cleanup(msc: *mut ModSecurityT);

    fn msc_create_rules_set() -> *mut RulesSetT;
    fn msc_rules_add_file(
        rules: *mut RulesSetT,
        file: *const c_char,
        error: *mut *const c_char,
    ) -> c_int;
    fn msc_rules_add(
        rules: *mut RulesSetT,
        plain_rules: *const c_char,
        error: *mut *const c_char,
    ) -> c_int;
    fn msc_rules_error_cleanup(error: *const c_char);
    fn msc_rules_cleanup(rules: *mut RulesSetT) -> c_int;

    fn msc_new_transaction(
        ms: *mut ModSecurityT,
        rules: *mut RulesSetT,
        log_cb_data: *mut c_void,
    ) -> *mut TransactionT;
    fn msc_process_connection(
        t: *mut TransactionT,
        client: *const c_char,
        c_port: c_int,
        server: *const c_char,
        s_port: c_int,
    ) -> c_int;
    fn msc_process_uri(
        t: *mut TransactionT,
        uri: *const c_char,
        protocol: *const c_char,
        http_version: *const c_char,
    ) -> c_int;
    fn msc_add_n_request_header(
        t: *mut TransactionT,
        key: *const c_uchar,
        len_key: usize,
        value: *const c_uchar,
        len_value: usize,
    ) -> c_int;
    fn msc_process_request_headers(t: *mut TransactionT) -> c_int;
    fn msc_append_request_body(t: *mut TransactionT, body: *const c_uchar, size: usize) -> c_int;
    fn msc_process_request_body(t: *mut TransactionT) -> c_int;
    fn msc_add_n_response_header(
        t: *mut TransactionT,
        key: *const c_uchar,
        len_key: usize,
        value: *const c_uchar,
        len_value: usize,
    ) -> c_int;
    fn msc_process_response_headers(t: *mut TransactionT, code: c_int, protocol: *const c_char)
        -> c_int;
    fn msc_append_response_body(t: *mut TransactionT, body: *const c_uchar, size: usize) -> c_int;
    fn msc_process_response_body(t: *mut TransactionT) -> c_int;
    fn msc_process_logging(t: *mut TransactionT) -> c_int;
    fn msc_intervention(t: *mut TransactionT, it: *mut Intervention) -> c_int;
    fn msc_transaction_cleanup(t: *mut TransactionT);
}

/// What the rules decided. `Allow` covers both "no rule matched" and "a rule
/// matched but only logged" — a CRS run in `DetectionOnly` produces the latter
/// constantly, and it must not affect the response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    Allow,
    Block { status: u16 },
    Redirect { status: u16, url: String },
}

/// The compiled rule set, shared by every worker.
pub struct Engine {
    msc: *mut ModSecurityT,
    rules: *mut RulesSetT,
}

// Safety: both pointers are created during configuration load and only read
// afterwards. libmodsecurity keeps per-transaction state in the transaction,
// which is why a shared rule set is the documented usage — it is what nginx's
// own connector does with a single set across all workers.
unsafe impl Send for Engine {}
unsafe impl Sync for Engine {}

impl Engine {
    pub fn new() -> Result<Engine, String> {
        // Safety: msc_init allocates and returns an owned handle, or null.
        let msc = unsafe { msc_init() };
        if msc.is_null() {
            return Err("msc_init() returned null".into());
        }
        let connector = CString::new(format!("OxiServe/{}", env!("CARGO_PKG_VERSION")))
            .expect("version string has no interior nul");
        // Rules can test the connector string, and it lands in audit logs, so
        // it is worth setting even though nothing here requires it.
        unsafe { msc_set_connector_info(msc, connector.as_ptr()) };
        unsafe { msc_set_log_cb(msc, log_cb) };

        let rules = unsafe { msc_create_rules_set() };
        if rules.is_null() {
            unsafe { msc_cleanup(msc) };
            return Err("msc_create_rules_set() returned null".into());
        }
        Ok(Engine { msc, rules })
    }

    /// Loads a rules file. The path is what `Include` directives inside it are
    /// resolved against, so CRS's own layout works unchanged.
    pub fn add_rules_file(&mut self, path: &str) -> Result<(), String> {
        let c_path = CString::new(path).map_err(|_| format!("path {path:?} contains a nul byte"))?;
        let mut err: *const c_char = std::ptr::null();
        let _guard = RULE_PARSE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        // Safety: `err` is only read when the call reports failure, which is
        // the contract libmodsecurity documents for it.
        let rc = unsafe { msc_rules_add_file(self.rules, c_path.as_ptr(), &mut err) };
        if rc < 0 {
            return Err(take_error(err, || format!("could not load rules from {path}")));
        }
        Ok(())
    }

    /// Loads rules written inline in the configuration.
    pub fn add_rules_inline(&mut self, rules: &str) -> Result<(), String> {
        let c_rules =
            CString::new(rules).map_err(|_| "inline rules contain a nul byte".to_string())?;
        let mut err: *const c_char = std::ptr::null();
        let _guard = RULE_PARSE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let rc = unsafe { msc_rules_add(self.rules, c_rules.as_ptr(), &mut err) };
        if rc < 0 {
            return Err(take_error(err, || "could not parse inline rules".to_string()));
        }
        Ok(())
    }

    /// Takes `&Arc<Self>` so the transaction can own a reference to the engine.
    /// A borrow would be simpler, but the transaction has to survive from the
    /// request phases to the response phases — stored in the request context in
    /// between — and a lifetime tied to a `&self` cannot cross that.
    pub fn transaction(self: &Arc<Self>) -> Option<Transaction> {
        // Safety: both handles live as long as the Arc the transaction holds.
        let t = unsafe { msc_new_transaction(self.msc, self.rules, std::ptr::null_mut()) };
        if t.is_null() {
            return None;
        }
        Some(Transaction { t, _engine: self.clone() })
    }
}

/// The rule set has no representation worth printing — libmodsecurity offers
/// no way to enumerate what it compiled — so this says only that one is here.
impl std::fmt::Debug for Engine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Engine(<modsecurity rules>)")
    }
}

impl Drop for Engine {
    fn drop(&mut self) {
        // Safety: called once, and no transaction can outlive the engine.
        unsafe {
            msc_rules_cleanup(self.rules);
            msc_cleanup(self.msc);
        }
    }
}

/// Copies an error string out of libmodsecurity and frees its copy.
fn take_error(err: *const c_char, fallback: impl FnOnce() -> String) -> String {
    if err.is_null() {
        return fallback();
    }
    // Safety: non-null means libmodsecurity allocated a nul-terminated string
    // that it expects to be handed back to msc_rules_error_cleanup.
    let msg = unsafe { CStr::from_ptr(err) }.to_string_lossy().into_owned();
    unsafe { msc_rules_error_cleanup(err) };
    msg
}

/// One request's worth of rule evaluation.
///
/// Deliberately not `Send`: libmodsecurity does not promise a transaction can
/// move between threads, and a request never needs it to.
pub struct Transaction {
    t: *mut TransactionT,
    /// Keeps the rule set alive; the transaction points into it.
    _engine: Arc<Engine>,
}

impl Transaction {
    pub fn connection(&mut self, client: &str, client_port: u16, server: &str, server_port: u16) {
        let (Ok(c), Ok(s)) = (CString::new(client), CString::new(server)) else {
            return;
        };
        unsafe {
            msc_process_connection(
                self.t,
                c.as_ptr(),
                client_port as c_int,
                s.as_ptr(),
                server_port as c_int,
            )
        };
    }

    /// `uri` must carry the query string: most CRS rules that matter read
    /// `ARGS`, and libmodsecurity parses those out of what it is given here.
    pub fn uri(&mut self, uri: &str, method: &str, http_version: &str) {
        let (Ok(u), Ok(m), Ok(v)) =
            (CString::new(uri), CString::new(method), CString::new(http_version))
        else {
            return;
        };
        unsafe { msc_process_uri(self.t, u.as_ptr(), m.as_ptr(), v.as_ptr()) };
    }

    pub fn request_header(&mut self, name: &[u8], value: &[u8]) {
        unsafe {
            msc_add_n_request_header(
                self.t,
                name.as_ptr(),
                name.len(),
                value.as_ptr(),
                value.len(),
            )
        };
    }

    pub fn process_request_headers(&mut self) -> Verdict {
        unsafe { msc_process_request_headers(self.t) };
        self.intervention()
    }

    pub fn request_body(&mut self, body: &[u8]) -> Verdict {
        if !body.is_empty() {
            unsafe { msc_append_request_body(self.t, body.as_ptr(), body.len()) };
        }
        unsafe { msc_process_request_body(self.t) };
        self.intervention()
    }

    pub fn response_header(&mut self, name: &[u8], value: &[u8]) {
        unsafe {
            msc_add_n_response_header(
                self.t,
                name.as_ptr(),
                name.len(),
                value.as_ptr(),
                value.len(),
            )
        };
    }

    pub fn process_response_headers(&mut self, status: u16, http_version: &str) -> Verdict {
        let Ok(v) = CString::new(http_version) else {
            return Verdict::Allow;
        };
        unsafe { msc_process_response_headers(self.t, status as c_int, v.as_ptr()) };
        self.intervention()
    }

    /// Phase 4. `body` is what the client is about to receive; a caller that
    /// cannot produce it should skip this rather than pass an empty slice,
    /// which would tell the rules the response was empty.
    pub fn response_body(&mut self, body: &[u8]) -> Verdict {
        if !body.is_empty() {
            unsafe { msc_append_response_body(self.t, body.as_ptr(), body.len()) };
        }
        unsafe { msc_process_response_body(self.t) };
        self.intervention()
    }

    /// Runs the logging phase. Rules with `nolog` produce nothing; the audit
    /// engine is configured by the rules themselves, not from here.
    pub fn logging(&mut self) {
        unsafe { msc_process_logging(self.t) };
    }

    /// Asks whether the rules want to interrupt the request.
    ///
    /// `disruptive == 0` is the case that matters most: a rule matched and
    /// chose only to log. Treating that as a block is how a `DetectionOnly`
    /// deployment turns into an outage.
    fn intervention(&mut self) -> Verdict {
        let mut it = Intervention {
            status: 200,
            pause: 0,
            url: std::ptr::null_mut(),
            log: std::ptr::null_mut(),
            disruptive: 0,
        };
        // Safety: libmodsecurity fills the struct and, when it sets `url` or
        // `log`, hands over strings it allocated with strdup for us to free.
        let acted = unsafe { msc_intervention(self.t, &mut it) };

        let url = take_owned_string(it.url);
        let log = take_owned_string(it.log);

        if acted == 0 || it.disruptive == 0 {
            return Verdict::Allow;
        }

        // A disruptive action reports itself here, in the intervention, not
        // through the log callback — that one only carries the non-blocking
        // warnings. Dropping it leaves an operator with a 403 and no way to
        // find out which rule produced it, which is the state this whole
        // integration exists to avoid.
        if let Some(log) = &log {
            eprintln!("oxiserve: [warn] modsecurity: {log}");
        }

        // A redirect is expressed as an intervention carrying a URL; anything
        // else is a status to answer with.
        let status = if (100..=599).contains(&it.status) { it.status as u16 } else { 403 };
        if let Some(url) = url {
            return Verdict::Redirect { status, url };
        }
        Verdict::Block { status }
    }
}

/// Takes ownership of a `strdup`ed string from an intervention and frees it.
fn take_owned_string(p: *mut c_char) -> Option<String> {
    if p.is_null() {
        return None;
    }
    // Safety: intervention strings are allocated with strdup by
    // libmodsecurity and documented as the caller's to free.
    let s = unsafe { CStr::from_ptr(p) }.to_string_lossy().into_owned();
    unsafe { libc::free(p as *mut c_void) };
    Some(s)
}

impl Drop for Transaction {
    fn drop(&mut self) {
        // Safety: the pointer came from msc_new_transaction and is freed once.
        unsafe { msc_transaction_cleanup(self.t) };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn engine_with(rules: &str) -> Arc<Engine> {
        let mut e = Engine::new().expect("engine");
        e.add_rules_inline(rules).expect("rules");
        Arc::new(e)
    }

    #[test]
    fn a_clean_request_is_allowed() {
        let e = engine_with(
            "SecRuleEngine On\n\
             SecRule ARGS \"@rx attack\" \"id:1,phase:2,deny,status:403\"\n",
        );
        let mut t = e.transaction().unwrap();
        t.connection("10.0.0.1", 1234, "10.0.0.2", 80);
        t.uri("/index.html?q=hello", "GET", "1.1");
        t.request_header(b"Host", b"example.com");
        assert_eq!(t.process_request_headers(), Verdict::Allow);
        assert_eq!(t.request_body(b""), Verdict::Allow);
    }

    #[test]
    fn a_matching_rule_blocks_with_its_status() {
        let e = engine_with(
            "SecRuleEngine On\n\
             SecRule ARGS \"@rx attack\" \"id:1,phase:2,deny,status:403\"\n",
        );
        let mut t = e.transaction().unwrap();
        t.connection("10.0.0.1", 1234, "10.0.0.2", 80);
        t.uri("/index.html?q=attack", "GET", "1.1");
        t.request_header(b"Host", b"example.com");
        // The verdict can land in either phase depending on the rule; what
        // matters is that the request does not come out allowed.
        let v = match t.process_request_headers() {
            Verdict::Allow => t.request_body(b""),
            other => other,
        };
        assert_eq!(v, Verdict::Block { status: 403 });
    }

    #[test]
    fn detection_only_logs_without_blocking() {
        // The failure this guards against is treating any rule match as a
        // block, which would take a site down the moment CRS is switched on
        // for observation.
        let e = engine_with(
            "SecRuleEngine DetectionOnly\n\
             SecRule ARGS \"@rx attack\" \"id:1,phase:2,deny,status:403\"\n",
        );
        let mut t = e.transaction().unwrap();
        t.connection("10.0.0.1", 1234, "10.0.0.2", 80);
        t.uri("/index.html?q=attack", "GET", "1.1");
        t.request_header(b"Host", b"example.com");
        assert_eq!(t.process_request_headers(), Verdict::Allow);
        assert_eq!(t.request_body(b""), Verdict::Allow);
    }

    #[test]
    fn a_body_rule_sees_the_request_body() {
        let e = engine_with(
            "SecRuleEngine On\n\
             SecRequestBodyAccess On\n\
             SecRule REQUEST_BODY \"@rx attack\" \"id:2,phase:2,deny,status:403\"\n",
        );
        let mut t = e.transaction().unwrap();
        t.connection("10.0.0.1", 1234, "10.0.0.2", 80);
        t.uri("/post", "POST", "1.1");
        t.request_header(b"Host", b"example.com");
        t.request_header(b"Content-Type", b"application/x-www-form-urlencoded");
        let _ = t.process_request_headers();
        assert_eq!(t.request_body(b"payload=attack"), Verdict::Block { status: 403 });
    }

    #[test]
    fn a_broken_rule_file_reports_why() {
        let mut e = Engine::new().unwrap();
        let err = e.add_rules_inline("ThisIsNotADirective foo bar\n").unwrap_err();
        assert!(!err.is_empty(), "an error message is the whole point");
        // Worth knowing: an unparseable *regex* is not in this category.
        // libmodsecurity accepts `@rx (` without complaint, so a config test
        // cannot promise every rule in a file is sound — only that the file
        // parses.
        assert!(e.add_rules_inline("SecRule ARGS \"@rx (\" \"id:9\"\n").is_ok());
    }

    #[test]
    fn a_response_header_rule_blocks_in_phase_3() {
        let e = engine_with(
            "SecRuleEngine On\n\
             SecRule RESPONSE_HEADERS:X-Powered-By \"@rx .\" \"id:20,phase:3,deny,status:500\"\n",
        );
        let mut t = e.transaction().unwrap();
        t.connection("10.0.0.1", 1234, "10.0.0.2", 80);
        t.uri("/", "GET", "1.1");
        let _ = t.process_request_headers();
        let _ = t.request_body(b"");
        t.response_header(b"Content-Type", b"text/html");
        t.response_header(b"X-Powered-By", b"PHP/8.1");
        assert_eq!(t.process_response_headers(200, "1.1"), Verdict::Block { status: 500 });
    }

    #[test]
    fn a_response_body_rule_blocks_in_phase_4() {
        // The leak case: the request was clean, so nothing before phase 4 has
        // any reason to object.
        let e = engine_with(
            "SecRuleEngine On\n\
             SecResponseBodyAccess On\n\
             SecResponseBodyMimeType text/plain text/html\n\
             SecRule RESPONSE_BODY \"@rx (?i)sql syntax error\" \"id:21,phase:4,deny,status:500\"\n",
        );
        let mut t = e.transaction().unwrap();
        t.connection("10.0.0.1", 1234, "10.0.0.2", 80);
        t.uri("/", "GET", "1.1");
        let _ = t.process_request_headers();
        let _ = t.request_body(b"");
        t.response_header(b"Content-Type", b"text/html");
        assert_eq!(t.process_response_headers(200, "1.1"), Verdict::Allow);
        assert_eq!(
            t.response_body(b"SQL syntax error near unexpected token"),
            Verdict::Block { status: 500 }
        );
    }

    #[test]
    fn a_clean_response_passes_every_phase() {
        let e = engine_with(
            "SecRuleEngine On\n\
             SecResponseBodyAccess On\n\
             SecResponseBodyMimeType text/plain text/html\n\
             SecRule RESPONSE_BODY \"@rx (?i)sql syntax error\" \"id:22,phase:4,deny,status:500\"\n",
        );
        let mut t = e.transaction().unwrap();
        t.connection("10.0.0.1", 1234, "10.0.0.2", 80);
        t.uri("/", "GET", "1.1");
        assert_eq!(t.process_request_headers(), Verdict::Allow);
        assert_eq!(t.request_body(b""), Verdict::Allow);
        t.response_header(b"Content-Type", b"text/html");
        assert_eq!(t.process_response_headers(200, "1.1"), Verdict::Allow);
        assert_eq!(t.response_body(b"an ordinary page"), Verdict::Allow);
        t.logging();
    }

    #[test]
    fn rules_parse_concurrently_without_aborting() {
        // libmodsecurity's rule parser is a non-reentrant flex scanner: before
        // RULE_PARSE_LOCK existed, two threads here killed the whole process
        // with "fatal flex scanner internal error", which no amount of caller
        // discipline can catch.
        let threads: Vec<_> = (0..8)
            .map(|i| {
                std::thread::spawn(move || {
                    let mut e = Engine::new().unwrap();
                    e.add_rules_inline(&format!(
                        "SecRuleEngine On\nSecRule ARGS \"@rx a{i}\" \"id:{},phase:2,deny\"\n",
                        100 + i
                    ))
                    .unwrap();
                })
            })
            .collect();
        for t in threads {
            t.join().expect("a worker aborted while parsing rules");
        }
    }
}
