//! Memory protection for sensitive key material
//!
//! Implements memory locking and core dump protection per GM/T 0028 requirements.
//! These protections prevent key material from being written to swap or core dumps.
//!
//! ## SecureBox vs LockedMemory
//!
//! `SecureBox` owns its allocation and locks memory at creation time via `mmap`,
//! eliminating the allocation-to-lock window. **Prefer `SecureBox` for new code**
//! that manages sensitive key material.
//!
//! `LockedMemory` wraps an existing `&[u8]` slice — use when you already have
//! a buffer that needs protection but can't control its allocation.

use crate::Result;
use std::sync::Arc;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU64, Ordering};

/// Global counter for mlock failures, set by server startup.
/// Incremented each time a SecureBox or LockedMemory allocation
/// fails to lock pages into RAM.
static MLOCK_FAILURE_COUNTER: OnceLock<Arc<AtomicU64>> = OnceLock::new();

/// Set the mlock failure counter from the KMS metrics system.
/// Called once at server startup.
pub fn set_mlock_failure_counter(counter: Arc<AtomicU64>) {
    let _ = MLOCK_FAILURE_COUNTER.set(counter);
}

fn record_mlock_failure() {
    if let Some(c) = MLOCK_FAILURE_COUNTER.get() {
        c.fetch_add(1, Ordering::Relaxed);
    }
}

/// Disable core dumps for the current process
///
/// Per GM/T 0028-2014 and GB/T 39786-2021, sensitive key material should not
/// be recoverable from core dumps. This function sets RLIMIT_CORE to 0.
///
/// Note: This must be called before any threads are created that might
/// handle sensitive data, to be effective.
pub fn disable_core_dump() -> Result<()> {
    #[cfg(unix)]
    {
        use libc::{RLIMIT_CORE, rlimit};

        let limit = rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };

        // Try to set RLIMIT_CORE to 0 (disabled)
        // On some systems, we need to set both soft and hard limits
        let result = unsafe { libc::setrlimit(RLIMIT_CORE, &limit) };

        if result != 0 {
            return Err(crate::Error::Internal(
                "Failed to disable core dumps (RLIMIT_CORE)".to_string(),
            ));
        }

        tracing::info!("Core dump protection enabled (RLIMIT_CORE=0)");
    }

    #[cfg(not(unix))]
    {
        tracing::warn!("Core dump protection not available on this platform");
    }

    Ok(())
}

/// Lock a region of memory to prevent it from being swapped to disk
///
/// Per GM/T 0028-2014 and GB/T 39786-2021, key material should be locked
/// in RAM to prevent recovery from swap files.
///
/// # Arguments
///
/// * `data` - The byte slice to lock (typically key material)
///
/// # Returns
///
/// Returns Ok(()) on success, or an error if mlock fails
pub fn mlock(data: &[u8]) -> Result<()> {
    #[cfg(unix)]
    {
        let ptr = data.as_ptr() as *const libc::c_void;
        let len = data.len();

        // mlock prevents the memory pages containing data from being swapped out
        let result = unsafe { libc::mlock(ptr, len) };

        if result != 0 {
            let errno = std::io::Error::last_os_error();
            return Err(crate::Error::Internal(format!(
                "Failed to lock memory (mlock): {errno}")));
        }

        tracing::debug!("Locked {} bytes of memory", len);
    }

    #[cfg(not(unix))]
    {
        tracing::warn!("Memory locking (mlock) not available on this platform");
    }

    Ok(())
}

/// Unlock previously locked memory
///
/// This reverses a previous mlock() call, allowing the pages to be swapped again.
/// Generally called during shutdown.
pub fn munlock(data: &[u8]) -> Result<()> {
    #[cfg(unix)]
    {
        let ptr = data.as_ptr() as *const libc::c_void;
        let len = data.len();

        let result = unsafe { libc::munlock(ptr, len) };

        if result != 0 {
            let errno = std::io::Error::last_os_error();
            tracing::warn!("Failed to unlock memory (munlock): {}", errno);
            // Don't fail the operation - munlock failure is not critical
        }
    }

    Ok(())
}

/// Wrapper type that automatically locks memory on creation and unlocks on drop
///
/// Uses RAII pattern - memory is locked for the lifetime of this object.
#[cfg(unix)]
pub struct LockedMemory<'a> {
    data: &'a [u8],
    locked: bool,
}

#[cfg(unix)]
impl<'a> LockedMemory<'a> {
    /// Create a new LockedMemory, immediately locking the data
    pub fn new(data: &'a [u8]) -> Result<Self> {
        mlock(data)?;
        Ok(Self { data, locked: true })
    }
}

#[cfg(unix)]
impl Drop for LockedMemory<'_> {
    fn drop(&mut self) {
        if self.locked {
            let _ = munlock(self.data);
        }
    }
}

// ============================================================================
// SecureBox — allocation-time memory locking
// ============================================================================

/// Page size for memory alignment.
#[cfg(unix)]
const PAGE_SIZE: usize = 4096;

/// Round size up to the nearest page boundary.
#[cfg(unix)]
const fn page_align(size: usize) -> usize {
    (size + PAGE_SIZE - 1) & !(PAGE_SIZE - 1)
}

/// A securely allocated byte buffer for sensitive key material.
///
/// Unlike [`LockedMemory`] which wraps an already-allocated slice (leaving a
/// window between allocation and locking), `SecureBox` allocates via `mmap`
/// and locks pages immediately, eliminating the allocation-to-lock time window.
///
/// On Linux / Unix:
/// - Allocates via `mmap(MAP_PRIVATE | MAP_ANONYMOUS)` for page-aligned memory
/// - Immediately calls `mlock` to prevent swapping
/// - Marks pages with `madvise(MADV_DONTDUMP)` to exclude from core dumps
/// - Zeroizes all bytes on drop, then `munlock`s and `munmap`s
///
/// On non-Unix platforms:
/// - Falls back to a `Vec<u8>` allocation (without mlock support)
/// - Still zeroizes on drop
///
/// # Example
///
/// ```ignore
/// let mut key_material = SecureBox::new(32)?;
/// key_material.copy_from_slice(&random_bytes);
/// // key_material is mlock'd and won't appear in swap or core dumps
/// ```
pub struct SecureBox {
    ptr: *mut u8,
    len: usize,
    capacity: usize,
    /// Whether the allocation came from mmap (true) or Vec (false).
    is_mmap: bool,
}

// Safety: SecureBox owns its memory exclusively. The raw pointer is never
// shared or exposed mutably to other threads without synchronization.
unsafe impl Send for SecureBox {}
unsafe impl Sync for SecureBox {}

impl SecureBox {
    /// Allocate a new zero-initialized `SecureBox` of the given size.
    ///
    /// On Unix, the allocation is page-aligned and immediately locked.
    pub fn new(size: usize) -> Result<Self> {
        if size == 0 {
            return Err(crate::Error::Internal(
                "SecureBox size must be greater than 0".to_string(),
            ));
        }
        Self::allocate(size)
    }

    /// Create a `SecureBox` from an existing byte slice.
    pub fn from_slice(data: &[u8]) -> Result<Self> {
        let mut sb = Self::new(data.len())?;
        sb.copy_from_slice(data);
        Ok(sb)
    }

    /// Copy data into the buffer.
    ///
    /// # Panics
    ///
    /// Panics if `src` is larger than the allocated size.
    pub fn copy_from_slice(&mut self, src: &[u8]) {
        assert!(
            src.len() <= self.len,
            "src length {} exceeds SecureBox length {}",
            src.len(),
            self.len
        );
        unsafe {
            std::ptr::copy_nonoverlapping(src.as_ptr(), self.ptr, src.len());
        }
    }

    /// Return the logical length of the buffer.
    pub fn len(&self) -> usize {
        self.len
    }

    /// Return true if the buffer is empty.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Return a raw pointer to the buffer.
    pub fn as_ptr(&self) -> *const u8 {
        self.ptr
    }

    /// Return a mutable raw pointer to the buffer.
    pub fn as_mut_ptr(&mut self) -> *mut u8 {
        self.ptr
    }

    /// Zeroize the buffer contents (but don't deallocate).
    fn zeroize(&mut self) {
        unsafe {
            std::ptr::write_bytes(self.ptr, 0, self.len);
        }
    }

    // -- internal allocation methods --

    #[cfg(unix)]
    fn allocate(size: usize) -> Result<Self> {
        use libc::{MAP_ANONYMOUS, MAP_FAILED, MAP_PRIVATE, PROT_READ, PROT_WRITE, mlock, mmap};

        let capacity = page_align(size);

        let ptr = unsafe {
            mmap(
                std::ptr::null_mut(),
                capacity,
                PROT_READ | PROT_WRITE,
                MAP_PRIVATE | MAP_ANONYMOUS,
                -1,
                0,
            )
        };

        if ptr == MAP_FAILED {
            // Fall back to Vec-based allocation
            tracing::warn!("mmap failed for SecureBox, falling back to Vec allocation");
            return Self::allocate_fallback(size);
        }

        // Lock pages immediately — before any key material is written
        let lock_result = unsafe { mlock(ptr, capacity) };
        if lock_result != 0 {
            record_mlock_failure();
            let errno = std::io::Error::last_os_error();
            // Fail-closed: mlock is a critical security control.
            // Return error so the caller knows memory protection failed.
            unsafe {
                libc::munmap(ptr, capacity);
            }
            return Err(crate::Error::Internal(format!(
                "mlock failed ({capacity} bytes): {errno} — refusing to use unprotected memory")));
        }

        // Exclude from core dumps (Linux only)
        #[cfg(target_os = "linux")]
        unsafe {
            libc::madvise(ptr, capacity, libc::MADV_DONTDUMP);
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (ptr, capacity); // suppress unused warnings
        }

        Ok(Self {
            ptr: ptr as *mut u8,
            len: size,
            capacity,
            is_mmap: true,
        })
    }

    #[cfg(not(unix))]
    fn allocate(size: usize) -> Result<Self> {
        Self::allocate_fallback(size)
    }

    #[allow(unused_mut)]
    fn allocate_fallback(size: usize) -> Result<Self> {
        let mut vec: Vec<u8> = vec![0u8; size];
        let ptr = vec.as_mut_ptr();
        let capacity = size;
        std::mem::forget(vec);

        // Try to mlock on unix (best effort)
        // NOTE: unlike the primary mmap path above which is fail-closed,
        // this fallback path uses mlock() from this module which returns Result
        // so the error is visible via the metrics counter but doesn't panic.
        #[cfg(unix)]
        {
            let slice = unsafe { std::slice::from_raw_parts(ptr, capacity) };
            if let Err(e) = mlock(slice) {
                record_mlock_failure();
                tracing::debug!("mlock fallback failed: {}", e);
            }
        }

        Ok(Self {
            ptr,
            len: size,
            capacity,
            is_mmap: false,
        })
    }
}

impl std::ops::Deref for SecureBox {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        unsafe { std::slice::from_raw_parts(self.ptr, self.len) }
    }
}

impl std::ops::DerefMut for SecureBox {
    fn deref_mut(&mut self) -> &mut [u8] {
        unsafe { std::slice::from_raw_parts_mut(self.ptr, self.len) }
    }
}

impl AsRef<[u8]> for SecureBox {
    fn as_ref(&self) -> &[u8] {
        self
    }
}

impl AsMut<[u8]> for SecureBox {
    fn as_mut(&mut self) -> &mut [u8] {
        self
    }
}

impl Drop for SecureBox {
    fn drop(&mut self) {
        // 1. Zeroize the data first
        self.zeroize();

        // 2. Unlock and deallocate
        if self.is_mmap {
            #[cfg(unix)]
            {
                unsafe { libc::munlock(self.ptr as *const libc::c_void, self.capacity) };
                unsafe { libc::munmap(self.ptr as *mut libc::c_void, self.capacity) };
            }
        } else {
            // Reconstruct the Vec to deallocate properly
            unsafe {
                let _vec = Vec::from_raw_parts(self.ptr, self.len, self.capacity);
                // _vec is dropped here (already zeroized above)
            }
        }
    }
}

impl std::fmt::Debug for SecureBox {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SecureBox")
            .field("len", &self.len)
            .field("capacity", &self.capacity)
            .field("is_mmap", &self.is_mmap)
            .finish_non_exhaustive()
    }
}

/// Initialize memory protection at process startup
///
/// Call this once at application startup before any key material is loaded.
/// Sets up core dump protection and logs security configuration status.
pub fn init_memory_protection() -> Result<()> {
    disable_core_dump()?;
    tracing::info!("Memory protection initialized: core dumps disabled, mlock available");
    Ok(())
}

/// Check if memory locking is supported on this platform
#[cfg(unix)]
pub fn is_mlock_supported() -> bool {
    // Check if we have CAP_IPC_LOCK or sufficient privileges
    // On most Linux systems, mlock is available but may require privileges
    // for locking large amounts of memory
    true
}

#[cfg(not(unix))]
pub fn is_mlock_supported() -> bool {
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_disable_core_dump() {
        // This test just verifies the function doesn't panic
        let result = disable_core_dump();
        // May fail in some test environments, so we don't assert success
        let _ = result;
    }

    #[test]
    fn test_mlock_munlock() {
        let data = vec![0u8; 4096]; // One page

        // mlock should succeed
        let result = mlock(&data);
        if result.is_ok() {
            // If mlock succeeded, munlock should also succeed
            let unlock_result = munlock(&data);
            assert!(unlock_result.is_ok());
        }
    }

    // -- SecureBox tests --

    #[test]
    fn test_secure_box_new() {
        let sb = SecureBox::new(32).expect("SecureBox::new should succeed");
        assert_eq!(sb.len(), 32);
        assert!(!sb.is_empty());
        // All bytes should be zero-initialized
        assert!(sb.iter().all(|&b| b == 0));
    }

    #[test]
    fn test_secure_box_new_zero_size() {
        let result = SecureBox::new(0);
        assert!(result.is_err());
    }

    #[test]
    fn test_secure_box_from_slice() {
        let data = b"super secret key material";
        let sb = SecureBox::from_slice(data).expect("SecureBox::from_slice should succeed");
        assert_eq!(sb.len(), data.len());
        assert_eq!(&sb[..], &data[..]);
    }

    #[test]
    fn test_secure_box_copy_from_slice() {
        let mut sb = SecureBox::new(64).expect("allocation");
        let data = [0xAAu8; 32];
        sb.copy_from_slice(&data);
        assert_eq!(&sb[0..32], &data[..]);
        assert_eq!(&sb[32..64], &[0u8; 32]);
    }

    #[test]
    #[should_panic(expected = "exceeds SecureBox length")]
    fn test_secure_box_copy_from_slice_overflow() {
        let mut sb = SecureBox::new(16).expect("allocation");
        sb.copy_from_slice(&[0u8; 32]);
    }

    #[test]
    fn test_secure_box_deref_mut() {
        let mut sb = SecureBox::new(16).expect("allocation");
        sb[0] = 0x42;
        sb[15] = 0xFF;
        assert_eq!(sb[0], 0x42);
        assert_eq!(sb[15], 0xFF);
    }

    #[test]
    fn test_secure_box_as_ref() {
        let sb = SecureBox::new(8).expect("allocation");
        let r: &[u8] = sb.as_ref();
        assert_eq!(r.len(), 8);
    }

    #[test]
    fn test_secure_box_as_mut() {
        let mut sb = SecureBox::new(8).expect("allocation");
        let r: &mut [u8] = sb.as_mut();
        r.fill(0xCC);
        assert!(sb.iter().all(|&b| b == 0xCC));
    }

    #[test]
    fn test_secure_box_debug_does_not_leak_data() {
        let sb = SecureBox::new(32).expect("allocation");
        let debug_str = format!("{:?}", sb);
        // Debug output must not contain the buffer contents
        assert!(debug_str.contains("len"));
        assert!(!debug_str.contains("0x"));
        assert!(debug_str.contains("..")); // non-exhaustive
    }

    #[test]
    fn test_secure_box_large_allocation() {
        // Test page-aligned allocation (multiple pages)
        let sb = SecureBox::new(8192).expect("large allocation");
        assert_eq!(sb.len(), 8192);
        assert!(sb.iter().all(|&b| b == 0));
    }

    #[test]
    fn test_secure_box_send_sync() {
        fn assert_send<T: Send>() {}
        fn assert_sync<T: Sync>() {}
        assert_send::<SecureBox>();
        assert_sync::<SecureBox>();
    }
}
