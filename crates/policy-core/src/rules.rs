use crate::policy::{ExecDefault, FsDefault, NetDefault};
use std::collections::BTreeSet;
use std::path::PathBuf;

#[derive(Debug, Clone)]
pub(crate) struct FsRules {
    pub(crate) default: FsDefault,
    write: BTreeSet<PathBuf>,
    read: BTreeSet<PathBuf>,
    duplicate_write: BTreeSet<PathBuf>,
    duplicate_read: BTreeSet<PathBuf>,
}

impl Default for FsRules {
    fn default() -> Self {
        Self {
            default: FsDefault::Strict,
            write: BTreeSet::new(),
            read: BTreeSet::new(),
            duplicate_write: BTreeSet::new(),
            duplicate_read: BTreeSet::new(),
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
        if !self.write.insert(path.clone()) {
            self.duplicate_write.insert(path);
        }
    }

    pub(crate) fn insert_read_raw(&mut self, path: PathBuf) {
        if !self.read.insert(path.clone()) {
            self.duplicate_read.insert(path);
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
        self.default = other.default;
        self.write.extend(other.write);
        self.read.extend(other.read);
        self.duplicate_write.extend(other.duplicate_write);
        self.duplicate_read.extend(other.duplicate_read);
    }

    pub(crate) fn write_iter(&self) -> impl Iterator<Item = &PathBuf> {
        self.write.iter()
    }

    pub(crate) fn read_iter(&self) -> impl Iterator<Item = &PathBuf> {
        self.read.iter()
    }

    pub(crate) fn first_duplicate_write(&self) -> Option<&PathBuf> {
        self.duplicate_write.iter().next()
    }

    pub(crate) fn first_duplicate_read(&self) -> Option<&PathBuf> {
        self.duplicate_read.iter().next()
    }

    pub(crate) fn conflicts(&self) -> impl Iterator<Item = &PathBuf> {
        self.write.intersection(&self.read)
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.write.is_empty() && self.read.is_empty()
    }
}

#[derive(Debug, Clone, Default)]
pub(crate) struct DuplicateAwareSet<T>
where
    T: Ord,
{
    values: BTreeSet<T>,
    duplicates: BTreeSet<T>,
}

impl<T> DuplicateAwareSet<T>
where
    T: Ord + Clone,
{
    pub(crate) fn insert(&mut self, value: T) {
        if !self.values.insert(value.clone()) {
            self.duplicates.insert(value);
        }
    }

    pub(crate) fn merge(&mut self, other: Self) {
        self.values.extend(other.values);
        self.duplicates.extend(other.duplicates);
    }

    pub(crate) fn iter(&self) -> impl Iterator<Item = &T> {
        self.values.iter()
    }

    pub(crate) fn first_duplicate(&self) -> Option<&T> {
        self.duplicates.iter().next()
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.values.is_empty()
    }
}

macro_rules! define_duplicate_rules {
    ($name:ident, $value_ty:ty, $field:ident, $default_ty:ty) => {
        #[derive(Debug, Clone)]
        pub(crate) struct $name {
            pub(crate) default: $default_ty,
            $field: DuplicateAwareSet<$value_ty>,
        }

        impl Default for $name {
            fn default() -> Self {
                Self {
                    default: <$default_ty>::default(),
                    $field: DuplicateAwareSet::default(),
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
                self.$field.insert(value);
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
                self.default = other.default;
                self.$field.merge(other.$field);
            }

            pub(crate) fn iter(&self) -> impl Iterator<Item = &$value_ty> {
                self.$field.iter()
            }

            pub(crate) fn first_duplicate(&self) -> Option<&$value_ty> {
                self.$field.first_duplicate()
            }

            pub(crate) fn is_empty(&self) -> bool {
                self.$field.is_empty()
            }
        }
    };
    ($name:ident, $value_ty:ty, $field:ident) => {
        #[derive(Debug, Clone)]
        pub(crate) struct $name {
            $field: DuplicateAwareSet<$value_ty>,
        }

        impl Default for $name {
            fn default() -> Self {
                Self {
                    $field: DuplicateAwareSet::default(),
                }
            }
        }

        impl $name {
            pub(crate) fn insert_raw(&mut self, value: $value_ty) {
                self.$field.insert(value);
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
                self.$field.merge(other.$field);
            }

            pub(crate) fn iter(&self) -> impl Iterator<Item = &$value_ty> {
                self.$field.iter()
            }

            pub(crate) fn first_duplicate(&self) -> Option<&$value_ty> {
                self.$field.first_duplicate()
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
