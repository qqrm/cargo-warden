pub mod maps {
    use arrayvec::ArrayVec;
    use std::sync::{Mutex, MutexGuard};

    pub struct TestArray<T: Copy, const N: usize> {
        inner: TestHashMap<u32, T, N>,
    }

    unsafe impl<T: Copy, const N: usize> Sync for TestArray<T, N> {}

    impl<T: Copy, const N: usize> TestArray<T, N> {
        pub const fn new() -> Self {
            Self {
                inner: TestHashMap::new(),
            }
        }

        pub fn get(&self, index: u32) -> Option<T> {
            let idx = index as usize;
            if idx >= N {
                return None;
            }
            self.inner.get(index)
        }

        pub fn set(&self, index: u32, value: T) {
            let idx = index as usize;
            if idx >= N {
                return;
            }
            self.inner.insert(index, value);
        }

        pub fn clear(&self) {
            self.inner.clear();
        }
    }

    #[derive(Copy, Clone)]
    pub struct DummyRingBuf;

    impl DummyRingBuf {
        pub const fn new() -> Self {
            Self
        }

        pub fn clear(&self) {}
    }

    pub struct TestHashMap<K: Copy + PartialEq, V: Copy, const N: usize> {
        data: Mutex<ArrayVec<(K, V), N>>,
    }

    unsafe impl<K: Copy + PartialEq, V: Copy, const N: usize> Sync for TestHashMap<K, V, N> {}

    impl<K: Copy + PartialEq, V: Copy, const N: usize> TestHashMap<K, V, N> {
        pub const fn new() -> Self {
            Self {
                data: Mutex::new(ArrayVec::new_const()),
            }
        }

        pub fn get(&self, key: K) -> Option<V> {
            let slots = self.lock();
            slots
                .iter()
                .find_map(|(stored, value)| if *stored == key { Some(*value) } else { None })
        }

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

    #[repr(C)]
    pub struct TestFile {
        pub path: *const u8,
        pub mode: u32,
    }

    #[repr(C)]
    pub struct TestDentry {
        pub name: *const u8,
    }

    pub fn file_path_ptr(file: *mut c_void) -> Option<*const u8> {
        if file.is_null() {
            None
        } else {
            let file = unsafe { &*(file as *const TestFile) };
            Some(file.path)
        }
    }

    pub fn file_mode_bits(file: *mut c_void) -> Option<u32> {
        if file.is_null() {
            None
        } else {
            let file = unsafe { &*(file as *const TestFile) };
            Some(file.mode)
        }
    }

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
}

pub mod net {
    use std::io;
    use std::net::{IpAddr, ToSocketAddrs};

    pub fn resolve_host(host: &str) -> io::Result<Vec<IpAddr>> {
        (host, 0)
            .to_socket_addrs()
            .map(|iter| iter.map(|sock| sock.ip()).collect())
    }
}
