//! Host-only shims for exercising qqrm-bpf-core programs outside the kernel.

pub mod prebuilt;

pub mod maps {
    use arrayvec::ArrayVec;
    use std::sync::{Mutex, MutexGuard};

    /// Simplified fixed-size array map used by tests and fuzzers.
    pub struct TestArray<T: Copy, const N: usize> {
        inner: TestHashMap<u32, T, N>,
    }

    unsafe impl<T: Copy, const N: usize> Sync for TestArray<T, N> {}

    impl<T: Copy, const N: usize> Default for TestArray<T, N> {
        fn default() -> Self {
            Self::new()
        }
    }

    impl<T: Copy, const N: usize> TestArray<T, N> {
        /// Creates an empty map instance.
        pub const fn new() -> Self {
            Self {
                inner: TestHashMap::new(),
            }
        }

        /// Retrieves an entry if the index is in range and populated.
        pub fn get(&self, index: u32) -> Option<T> {
            let idx = index as usize;
            if idx >= N {
                return None;
            }
            self.inner.get(index)
        }

        /// Writes an entry if the index is in range.
        pub fn set(&self, index: u32, value: T) {
            let idx = index as usize;
            if idx >= N {
                return;
            }
            self.inner.insert(index, value);
        }

        /// Clears all entries in place.
        pub fn clear(&self) {
            self.inner.clear();
        }
    }

    /// Zero-sized stand-in for the Aya ring buffer handle.
    #[derive(Copy, Clone)]
    pub struct DummyRingBuf;

    impl Default for DummyRingBuf {
        fn default() -> Self {
            Self::new()
        }
    }

    impl DummyRingBuf {
        /// Creates a new dummy ring buffer handle.
        pub const fn new() -> Self {
            Self
        }

        /// Clears the dummy ring buffer.
        #[allow(clippy::unused_self)]
        pub fn clear(&self) {}
    }

    /// Simplified hash map implementation for host-based tests.
    pub struct TestHashMap<K: Copy + PartialEq, V: Copy, const N: usize> {
        data: Mutex<ArrayVec<(K, V), N>>,
    }

    unsafe impl<K: Copy + PartialEq, V: Copy, const N: usize> Sync for TestHashMap<K, V, N> {}

    impl<K: Copy + PartialEq, V: Copy, const N: usize> Default for TestHashMap<K, V, N> {
        fn default() -> Self {
            Self::new()
        }
    }

    impl<K: Copy + PartialEq, V: Copy, const N: usize> TestHashMap<K, V, N> {
        /// Creates an empty hash map instance.
        pub const fn new() -> Self {
            Self {
                data: Mutex::new(ArrayVec::new_const()),
            }
        }

        /// Retrieves a value for the provided key when it exists.
        pub fn get(&self, key: K) -> Option<V> {
            let slots = self.lock();
            slots
                .iter()
                .find_map(|(stored, value)| if *stored == key { Some(*value) } else { None })
        }

        /// Inserts or updates the value for the provided key.
        pub fn insert(&self, key: K, value: V) {
            let mut slots = self.lock();
            if let Some(existing) = slots.iter_mut().find(|(stored, _)| *stored == key) {
                *existing = (key, value);
                return;
            }
            if slots.len() < N {
                slots.push((key, value));
            } else if let Some(slot) = slots.first_mut() {
                *slot = (key, value);
            }
        }

        /// Removes the value associated with the provided key.
        pub fn remove(&self, key: K) {
            let mut slots = self.lock();
            let mut i = 0;
            while i < slots.len() {
                if slots[i].0 == key {
                    slots.remove(i);
                } else {
                    i += 1;
                }
            }
        }

        /// Clears all entries from the hash map.
        pub fn clear(&self) {
            self.lock().clear();
        }

        fn lock(&self) -> MutexGuard<'_, ArrayVec<(K, V), N>> {
            match self.data.lock() {
                Ok(guard) => guard,
                Err(poisoned) => poisoned.into_inner(),
            }
        }
    }
}

pub mod fs {
    use core::ffi::c_void;

    /// Host representation of a kernel `file` pointer for tests.
    #[repr(C)]
    pub struct TestFile {
        pub path: *const u8,
        pub mode: u32,
    }

    /// Host representation of a kernel `dentry` pointer for tests.
    #[repr(C)]
    pub struct TestDentry {
        pub name: *const u8,
    }

    /// Extracts the backing path pointer from a simulated `file` handle.
    pub fn file_path_ptr(file: *mut c_void) -> Option<*const u8> {
        if file.is_null() {
            None
        } else {
            let file = unsafe { &*(file as *const TestFile) };
            Some(file.path)
        }
    }

    /// Extracts the mode bits from a simulated `file` handle.
    pub fn file_mode_bits(file: *mut c_void) -> Option<u32> {
        if file.is_null() {
            None
        } else {
            let file = unsafe { &*(file as *const TestFile) };
            Some(file.mode)
        }
    }

    /// Extracts the backing path pointer from a simulated `dentry`.
    pub fn dentry_path_ptr(dentry: *mut c_void) -> Option<*const u8> {
        if dentry.is_null() {
            None
        } else {
            let dentry = unsafe { &*(dentry as *const TestDentry) };
            if dentry.name.is_null() {
                None
            } else {
                Some(dentry.name)
            }
        }
    }

    /// Extracts both source and destination path pointers from simulated rename dentries.
    pub fn rename_path_ptrs(
        old_dentry: *mut c_void,
        new_dentry: *mut c_void,
    ) -> Option<(*const u8, *const u8)> {
        let old = dentry_path_ptr(old_dentry)?;
        let new = dentry_path_ptr(new_dentry)?;
        Some((old, new))
    }
}

pub mod prebuilt {
    use sha2::{Digest, Sha256};
    use std::env;
    use std::fmt;
    use std::fs;
    use std::io::{self, ErrorKind};
    use std::path::{Path, PathBuf};

    const OBJECT_NAME: &str = "qqrm-bpf-core.o";
    const MANIFEST: &str = include_str!("../../../prebuilt/CHECKSUMS");

    /// Errors produced when validating packaged BPF objects.
    #[derive(Debug, PartialEq, Eq)]
    pub enum VerificationError {
        /// The manifest does not contain a checksum for the detected architecture.
        MissingChecksum { arch: String },
        /// The packaged bytes do not match the recorded checksum.
        ChecksumMismatch {
            arch: String,
            expected: &'static str,
            actual: String,
        },
    }

    impl fmt::Display for VerificationError {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            match self {
                VerificationError::MissingChecksum { arch } => {
                    write!(f, "no checksum recorded for architecture {arch}")
                }
                VerificationError::ChecksumMismatch {
                    arch,
                    expected,
                    actual,
                } => {
                    write!(
                        f,
                        "checksum mismatch for {arch}: expected {expected}, computed {actual}"
                    )
                }
            }
        }
    }

    impl std::error::Error for VerificationError {}

    /// Returns the on-disk path to the packaged BPF object for the current architecture.
    pub fn packaged_object_path() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../prebuilt")
            .join(env::consts::ARCH)
            .join(OBJECT_NAME)
    }

    /// Reads the packaged object for the detected architecture and validates its checksum.
    pub fn packaged_object_bytes() -> io::Result<Vec<u8>> {
        let path = packaged_object_path();
        read_and_verify(&path)
    }

    /// Reads a specific file, validating it against the recorded checksum for this architecture.
    pub fn read_and_verify(path: &Path) -> io::Result<Vec<u8>> {
        let bytes = fs::read(path)?;
        verify_bytes(&bytes).map_err(|err| {
            io::Error::new(
                ErrorKind::InvalidData,
                format!("{} ({})", err, path.display()),
            )
        })?;
        Ok(bytes)
    }

    /// Verifies raw bytes against the checksum for the current architecture.
    pub fn verify_bytes(bytes: &[u8]) -> Result<(), VerificationError> {
        verify_bytes_for_arch(env::consts::ARCH, bytes)
    }

    /// Verifies raw bytes against the checksum recorded for `arch`.
    pub fn verify_bytes_for_arch(arch: &str, bytes: &[u8]) -> Result<(), VerificationError> {
        let expected =
            expected_checksum(arch).ok_or_else(|| VerificationError::MissingChecksum {
                arch: arch.to_owned(),
            })?;
        let actual = sha256_hex(bytes);
        if actual == expected {
            Ok(())
        } else {
            Err(VerificationError::ChecksumMismatch {
                arch: arch.to_owned(),
                expected,
                actual,
            })
        }
    }

    /// Exposes the raw checksum manifest for downstream tooling.
    pub fn checksum_manifest() -> &'static str {
        MANIFEST
    }

    fn expected_checksum(arch: &str) -> Option<&'static str> {
        for line in MANIFEST.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let mut parts = line.split_whitespace();
            let manifest_arch = parts.next()?;
            let checksum = parts.next()?;
            if manifest_arch == arch {
                return Some(checksum);
            }
        }
        None
    }

    fn sha256_hex(bytes: &[u8]) -> String {
        let digest = Sha256::digest(bytes);
        let mut out = String::with_capacity(digest.len() * 2);
        for byte in digest.as_slice() {
            out.push(nibble_to_hex(byte >> 4));
            out.push(nibble_to_hex(byte & 0x0f));
        }
        out
    }

    fn nibble_to_hex(nibble: u8) -> char {
        match nibble {
            0..=9 => (b'0' + nibble) as char,
            10..=15 => (b'a' + (nibble - 10)) as char,
            _ => unreachable!("nibble out of range"),
        }
    }
}

pub mod net {
    use std::io;
    use std::net::{IpAddr, ToSocketAddrs};

    /// Resolves a host name for unit tests and fuzz harnesses.
    pub fn resolve_host(host: &str) -> io::Result<Vec<IpAddr>> {
        (host, 0)
            .to_socket_addrs()
            .map(|iter| iter.map(|sock| sock.ip()).collect())
    }
}

pub use fs::{TestDentry, TestFile, rename_path_ptrs};
pub use maps::{DummyRingBuf, TestArray, TestHashMap};
pub use net::resolve_host;

#[cfg(test)]
mod tests {
    use super::fs::{
        TestDentry, TestFile, dentry_path_ptr, file_mode_bits, file_path_ptr, rename_path_ptrs,
    };
    use super::maps::TestArray;
    use core::ffi::c_void;
    use std::ffi::CString;
    use std::ptr;

    #[test]
    fn test_array_get_set_and_clear() {
        const CAPACITY: usize = 4;
        let map: TestArray<u32, CAPACITY> = TestArray::new();
        assert_eq!(map.get(0), None);
        map.set(0, 7);
        map.set(3, 42);
        assert_eq!(map.get(0), Some(7));
        assert_eq!(map.get(3), Some(42));
        assert_eq!(map.get(2), None);
        map.clear();
        assert_eq!(map.get(0), None);
        assert_eq!(map.get(3), None);
    }

    #[test]
    fn test_array_ignores_out_of_range_indices() {
        const CAPACITY: usize = 2;
        let map: TestArray<u8, CAPACITY> = TestArray::new();
        map.set(5, 1);
        assert_eq!(map.get(5), None);
        map.set(1, 9);
        assert_eq!(map.get(1), Some(9));
    }

    #[test]
    fn file_helpers_expose_pointer_and_mode() {
        let path = CString::new("/tmp/example").unwrap();
        let path_ptr = path.as_ptr() as *const u8;
        let mut file = TestFile {
            path: path_ptr,
            mode: 0o3,
        };
        let file_ptr = (&mut file) as *mut _ as *mut c_void;
        assert_eq!(file_path_ptr(file_ptr), Some(path_ptr));
        assert_eq!(file_mode_bits(file_ptr), Some(0o3));
    }

    #[test]
    fn rename_path_ptrs_return_both_entries() {
        let old = CString::new("/tmp/old").unwrap();
        let new = CString::new("/tmp/new").unwrap();
        let old_ptr_raw = old.as_ptr() as *const u8;
        let new_ptr_raw = new.as_ptr() as *const u8;
        let mut old_dentry = TestDentry { name: old_ptr_raw };
        let mut new_dentry = TestDentry { name: new_ptr_raw };
        let old_ptr = (&mut old_dentry) as *mut _ as *mut c_void;
        let new_ptr = (&mut new_dentry) as *mut _ as *mut c_void;
        let (resolved_old, resolved_new) =
            rename_path_ptrs(old_ptr, new_ptr).expect("rename pointers");
        assert_eq!(resolved_old, old_ptr_raw);
        assert_eq!(resolved_new, new_ptr_raw);
    }

    #[test]
    fn rename_path_ptrs_return_none_on_null() {
        let mut old_dentry = TestDentry { name: ptr::null() };
        let mut new_dentry = TestDentry { name: ptr::null() };
        let old_ptr = (&mut old_dentry) as *mut _ as *mut c_void;
        let new_ptr = (&mut new_dentry) as *mut _ as *mut c_void;
        assert!(rename_path_ptrs(old_ptr, new_ptr).is_none());
        assert!(dentry_path_ptr(old_ptr).is_none());
        assert!(dentry_path_ptr(new_ptr).is_none());
    }
}
