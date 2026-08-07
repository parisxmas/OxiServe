//! A `MAP_SHARED | MAP_ANONYMOUS` region of atomics.
//!
//! Both limiters keep their counters here rather than in a `Vec<AtomicU64>`,
//! which would carry the same bits but in pages private to the process: after
//! `fork` each worker would write to its own copy and a zone would stop being
//! one zone. The mapping is created at config load — before any worker exists
//! — so threads see it through the shared address space and forked worker
//! processes inherit the very same pages.

use std::sync::atomic::AtomicU64;

pub struct Shared {
    ptr: *mut AtomicU64,
    words: usize,
}

// SAFETY: every access goes through &AtomicU64; the mapping outlives the zone
// that owns it and is unmapped exactly once, on drop.
unsafe impl Send for Shared {}
unsafe impl Sync for Shared {}

impl Shared {
    /// Maps `words` zeroed atomics. `what` names the caller in the panic
    /// message, which is the only way this can fail.
    pub fn new(words: usize, what: &str) -> Shared {
        let bytes = words * std::mem::size_of::<AtomicU64>();
        // SAFETY: an anonymous mapping with no file behind it; checked for
        // MAP_FAILED before use. Zero-filled by the kernel, and zero is the
        // "empty" state in both tables built on this.
        let ptr = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                bytes,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        assert!(
            !std::ptr::eq(ptr, libc::MAP_FAILED),
            "mmap for a {what} zone failed: {}",
            std::io::Error::last_os_error()
        );
        Shared { ptr: ptr.cast(), words }
    }

    #[inline]
    pub fn at(&self, i: usize) -> &AtomicU64 {
        debug_assert!(i < self.words);
        // SAFETY: `i` is always produced by masking with `slots - 1`, and the
        // mapping holds `words` atomics.
        unsafe { &*self.ptr.add(i) }
    }
}

impl Drop for Shared {
    fn drop(&mut self) {
        // SAFETY: exactly the region mapped in `new`.
        unsafe {
            libc::munmap(self.ptr.cast(), self.words * std::mem::size_of::<AtomicU64>());
        }
    }
}
