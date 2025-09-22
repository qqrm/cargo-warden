//! Host-only shims for exercising qqrm-bpf-core programs outside the kernel.

pub mod maps {
    use core::cell::UnsafeCell;

    /// Simplified fixed-size array map used by tests and fuzzers.
    pub struct TestArray<T: Copy, const N: usize> {
        data: UnsafeCell<[Option<T>; N]>,
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
                data: UnsafeCell::new([None; N]),
            }
        }

        /// Retrieves an entry if the index is in range and populated.
        pub fn get(&self, index: u32) -> Option<T> {
            let idx = index as usize;
            if idx >= N {
                return None;
            }
            unsafe { (*self.data.get())[idx] }
        }

        /// Writes an entry if the index is in range.
        pub fn set(&self, index: u32, value: T) {
            let idx = index as usize;
            if idx >= N {
                return;
            }
            unsafe {
                (*self.data.get())[idx] = Some(value);
            }
        }

        /// Clears all entries in place.
        pub fn clear(&self) {
            unsafe {
                for slot in (*self.data.get()).iter_mut() {
                    *slot = None;
                }
            }
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
    }

    /// Simplified hash map implementation for host-based tests.
    pub struct TestHashMap<K: Copy + PartialEq, V: Copy, const N: usize> {
        data: UnsafeCell<[Option<(K, V)>; N]>,
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
                data: UnsafeCell::new([None; N]),
            }
        }

        /// Retrieves a value for the provided key when it exists.
        pub fn get(&self, key: K) -> Option<V> {
            unsafe {
                (*self.data.get()).iter().find_map(|slot| {
                    slot.and_then(
                        |(stored, value)| {
                            if stored == key { Some(value) } else { None }
                        },
                    )
                })
            }
        }

        /// Inserts or updates the value for the provided key.
        pub fn insert(&self, key: K, value: V) {
            unsafe {
                let slots = &mut *self.data.get();
                for slot in slots.iter_mut() {
                    if let Some((stored, _)) = slot
                        && *stored == key
                    {
                        *slot = Some((key, value));
                        return;
                    }
                }
                if let Some(empty) = slots.iter_mut().find(|slot| slot.is_none()) {
                    *empty = Some((key, value));
                    return;
                }
                if let Some(slot) = slots.first_mut() {
                    *slot = Some((key, value));
                }
            }
        }

        /// Removes the value associated with the provided key.
        pub fn remove(&self, key: K) {
            unsafe {
                for slot in (*self.data.get()).iter_mut() {
                    if slot.map(|(stored, _)| stored == key).unwrap_or(false) {
                        *slot = None;
                    }
                }
            }
        }

        /// Clears all entries from the hash map.
        pub fn clear(&self) {
            unsafe {
                for slot in (*self.data.get()).iter_mut() {
                    *slot = None;
                }
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
            Some(dentry.name)
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

pub use fs::{TestDentry, TestFile};
pub use maps::{DummyRingBuf, TestArray, TestHashMap};
pub use net::resolve_host;
