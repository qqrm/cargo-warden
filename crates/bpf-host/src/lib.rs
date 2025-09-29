//! Host-only shims for exercising qqrm-bpf-core programs outside the kernel.

pub mod maps {
    use core::cell::{Ref, RefCell, RefMut};

    use heapless::LinearMap;

    /// Simplified fixed-capacity array map used by tests and fuzzers.
    pub struct TestArray<T: Copy, const N: usize> {
        data: RefCell<LinearMap<usize, T, N>>,
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
                data: RefCell::new(LinearMap::new()),
            }
        }

        /// Retrieves a shared reference to an entry when the index is valid.
        pub fn get(&self, index: u32) -> Option<Ref<'_, T>> {
            let idx = index as usize;
            if idx >= N {
                return None;
            }
            let borrow = self.data.borrow();
            if borrow.iter().any(|(key, _)| *key == idx) {
                Some(Ref::map(borrow, move |map| {
                    map.get(&idx)
                        .expect("entry presence validated before mapping")
                }))
            } else {
                None
            }
        }

        /// Retrieves a mutable reference to an entry when the index is valid.
        pub fn get_mut(&self, index: u32) -> Option<RefMut<'_, T>> {
            let idx = index as usize;
            if idx >= N {
                return None;
            }
            let borrow = self.data.borrow_mut();
            if borrow.iter().any(|(key, _)| *key == idx) {
                Some(RefMut::map(borrow, move |map| {
                    map.get_mut(&idx)
                        .expect("entry presence validated before mapping")
                }))
            } else {
                None
            }
        }

        /// Writes an entry if the index is in range.
        pub fn set(&self, index: u32, value: T) {
            let idx = index as usize;
            if idx >= N {
                return;
            }
            let mut map = self.data.borrow_mut();
            match map.insert(idx, value) {
                Ok(_) => {}
                Err((pending_idx, pending_value)) => {
                    if let Some(first_key) = map.iter().next().map(|(key, _)| *key) {
                        let _ = map.remove(&first_key);
                    }
                    let _ = map.insert(pending_idx, pending_value);
                }
            }
        }

        /// Clears all entries in place.
        pub fn clear(&self) {
            self.data.borrow_mut().clear();
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
    pub struct TestHashMap<K: Copy + Eq, V: Copy, const N: usize> {
        data: RefCell<LinearMap<K, V, N>>,
    }

    unsafe impl<K: Copy + Eq, V: Copy, const N: usize> Sync for TestHashMap<K, V, N> {}

    impl<K: Copy + Eq, V: Copy, const N: usize> Default for TestHashMap<K, V, N> {
        fn default() -> Self {
            Self::new()
        }
    }

    impl<K: Copy + Eq, V: Copy, const N: usize> TestHashMap<K, V, N> {
        /// Creates an empty hash map instance.
        pub const fn new() -> Self {
            Self {
                data: RefCell::new(LinearMap::new()),
            }
        }

        /// Retrieves a shared reference to the value associated with the provided key.
        pub fn get(&self, key: &K) -> Option<Ref<'_, V>> {
            let borrow = self.data.borrow();
            if borrow.iter().any(|(stored, _)| stored == key) {
                Some(Ref::map(borrow, |map| {
                    map.get(key)
                        .expect("entry presence validated before mapping")
                }))
            } else {
                None
            }
        }

        /// Retrieves a mutable reference to the value associated with the provided key.
        pub fn get_mut(&self, key: &K) -> Option<RefMut<'_, V>> {
            let borrow = self.data.borrow_mut();
            if borrow.iter().any(|(stored, _)| stored == key) {
                Some(RefMut::map(borrow, |map| {
                    map.get_mut(key)
                        .expect("entry presence validated before mapping")
                }))
            } else {
                None
            }
        }

        /// Inserts or updates the value for the provided key.
        pub fn insert(&self, key: K, value: V) {
            let mut map = self.data.borrow_mut();
            match map.insert(key, value) {
                Ok(_) => {}
                Err((pending_key, pending_value)) => {
                    if let Some(first_key) = map.iter().next().map(|(key, _)| *key) {
                        let _ = map.remove(&first_key);
                    }
                    let _ = map.insert(pending_key, pending_value);
                }
            }
        }

        /// Removes the value associated with the provided key.
        pub fn remove(&self, key: &K) {
            let _ = self.data.borrow_mut().remove(key);
        }

        /// Clears all entries from the hash map.
        pub fn clear(&self) {
            self.data.borrow_mut().clear();
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
    use core::ffi::c_void;
    use std::ffi::CString;
    use std::ptr;

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
