use crate::policy::{ExecDefault, FsDefault, NetDefault};
use indexmap::set::IndexSet;
use std::path::PathBuf;

#[derive(Debug, Clone)]
pub(crate) struct FsRules {
    pub(crate) default: FsDefault,
    write: IndexSet<PathBuf>,
    read: IndexSet<PathBuf>,
    duplicate_write: Option<PathBuf>,
    duplicate_read: Option<PathBuf>,
}

impl Default for FsRules {
    fn default() -> Self {
        Self {
            default: FsDefault::Strict,
            write: IndexSet::new(),
            read: IndexSet::new(),
            duplicate_write: None,
            duplicate_read: None,
        }
    }
}

impl FsRules {
    pub(crate) fn with_default(default: FsDefault) -> Self {
        Self {
            default,
            ..Self::default()
        }
    }

    pub(crate) fn insert_write_raw(&mut self, path: PathBuf) {
        let (index, inserted) = self.write.insert_full(path);
        if !inserted
            && self.duplicate_write.is_none()
            && let Some(existing) = self.write.get_index(index)
        {
            self.duplicate_write = Some(existing.clone());
        }
    }

    pub(crate) fn insert_read_raw(&mut self, path: PathBuf) {
        let (index, inserted) = self.read.insert_full(path);
        if !inserted
            && self.duplicate_read.is_none()
            && let Some(existing) = self.read.get_index(index)
        {
            self.duplicate_read = Some(existing.clone());
        }
    }

    pub(crate) fn extend_writes<I>(&mut self, iter: I)
    where
        I: IntoIterator<Item = PathBuf>,
    {
        for path in iter {
            self.insert_write_raw(path);
        }
    }

    pub(crate) fn extend_reads<I>(&mut self, iter: I)
    where
        I: IntoIterator<Item = PathBuf>,
    {
        for path in iter {
            self.insert_read_raw(path);
        }
    }

    pub(crate) fn merge(&mut self, other: FsRules) {
        let FsRules {
            default,
            write,
            read,
            duplicate_write,
            duplicate_read,
        } = other;

        self.default = default;
        for path in write {
            self.insert_write_raw(path);
        }
        for path in read {
            self.insert_read_raw(path);
        }
        if self.duplicate_write.is_none() {
            self.duplicate_write = duplicate_write;
        }
        if self.duplicate_read.is_none() {
            self.duplicate_read = duplicate_read;
        }
    }

    pub(crate) fn write_iter(&self) -> impl Iterator<Item = &PathBuf> {
        self.write.iter()
    }

    pub(crate) fn read_iter(&self) -> impl Iterator<Item = &PathBuf> {
        self.read.iter()
    }

    pub(crate) fn first_duplicate_write(&self) -> Option<&PathBuf> {
        self.duplicate_write.as_ref()
    }

    pub(crate) fn first_duplicate_read(&self) -> Option<&PathBuf> {
        self.duplicate_read.as_ref()
    }

    pub(crate) fn conflicts(&self) -> impl Iterator<Item = &PathBuf> {
        self.write.intersection(&self.read)
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.write.is_empty() && self.read.is_empty()
    }
}

macro_rules! define_duplicate_rules {
    ($name:ident, $value_ty:ty, $field:ident, $default_ty:ty) => {
        #[derive(Debug, Clone)]
        pub(crate) struct $name {
            pub(crate) default: $default_ty,
            $field: IndexSet<$value_ty>,
            duplicate: Option<$value_ty>,
        }

        impl Default for $name {
            fn default() -> Self {
                Self {
                    default: <$default_ty>::default(),
                    $field: IndexSet::new(),
                    duplicate: None,
                }
            }
        }

        impl $name {
            pub(crate) fn with_default(default: $default_ty) -> Self {
                Self {
                    default,
                    ..Self::default()
                }
            }

            pub(crate) fn insert_raw(&mut self, value: $value_ty) {
                let (index, inserted) = self.$field.insert_full(value);
                if !inserted
                    && self.duplicate.is_none()
                    && let Some(existing) = self.$field.get_index(index)
                {
                    self.duplicate = Some(existing.clone());
                }
            }

            pub(crate) fn extend<I>(&mut self, iter: I)
            where
                I: IntoIterator<Item = $value_ty>,
            {
                for value in iter {
                    self.insert_raw(value);
                }
            }

            pub(crate) fn merge(&mut self, other: $name) {
                let $name {
                    default,
                    $field,
                    duplicate,
                } = other;

                self.default = default;
                for value in $field {
                    self.insert_raw(value);
                }
                if self.duplicate.is_none() {
                    self.duplicate = duplicate;
                }
            }

            pub(crate) fn iter(&self) -> impl Iterator<Item = &$value_ty> {
                self.$field.iter()
            }

            pub(crate) fn first_duplicate(&self) -> Option<&$value_ty> {
                self.duplicate.as_ref()
            }

            pub(crate) fn is_empty(&self) -> bool {
                self.$field.is_empty()
            }
        }
    };
    ($name:ident, $value_ty:ty, $field:ident) => {
        #[derive(Debug, Clone)]
        pub(crate) struct $name {
            $field: IndexSet<$value_ty>,
            duplicate: Option<$value_ty>,
        }

        impl Default for $name {
            fn default() -> Self {
                Self {
                    $field: IndexSet::new(),
                    duplicate: None,
                }
            }
        }

        impl $name {
            pub(crate) fn insert_raw(&mut self, value: $value_ty) {
                let (index, inserted) = self.$field.insert_full(value);
                if !inserted
                    && self.duplicate.is_none()
                    && let Some(existing) = self.$field.get_index(index)
                {
                    self.duplicate = Some(existing.clone());
                }
            }

            pub(crate) fn extend<I>(&mut self, iter: I)
            where
                I: IntoIterator<Item = $value_ty>,
            {
                for value in iter {
                    self.insert_raw(value);
                }
            }

            pub(crate) fn merge(&mut self, other: $name) {
                let $name { $field, duplicate } = other;

                for value in $field {
                    self.insert_raw(value);
                }
                if self.duplicate.is_none() {
                    self.duplicate = duplicate;
                }
            }

            pub(crate) fn iter(&self) -> impl Iterator<Item = &$value_ty> {
                self.$field.iter()
            }

            pub(crate) fn first_duplicate(&self) -> Option<&$value_ty> {
                self.duplicate.as_ref()
            }

            pub(crate) fn is_empty(&self) -> bool {
                self.$field.is_empty()
            }
        }
    };
}

define_duplicate_rules!(NetRules, String, hosts, NetDefault);
define_duplicate_rules!(ExecRules, String, allowed, ExecDefault);
define_duplicate_rules!(SyscallRules, String, deny);
define_duplicate_rules!(EnvRules, String, read);
