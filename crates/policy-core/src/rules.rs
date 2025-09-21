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

    pub(crate) fn extend<I>(&mut self, iter: I)
    where
        I: IntoIterator<Item = T>,
    {
        for value in iter {
            self.insert(value);
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

#[derive(Debug, Clone)]
pub(crate) struct NetRules {
    pub(crate) default: NetDefault,
    hosts: DuplicateAwareSet<String>,
}

impl Default for NetRules {
    fn default() -> Self {
        Self {
            default: NetDefault::Deny,
            hosts: DuplicateAwareSet::default(),
        }
    }
}

impl NetRules {
    pub(crate) fn with_default(default: NetDefault) -> Self {
        Self {
            default,
            ..Self::default()
        }
    }

    pub(crate) fn insert_raw(&mut self, host: String) {
        self.hosts.insert(host);
    }

    pub(crate) fn extend<I>(&mut self, iter: I)
    where
        I: IntoIterator<Item = String>,
    {
        self.hosts.extend(iter);
    }

    pub(crate) fn merge(&mut self, other: NetRules) {
        self.default = other.default;
        self.hosts.merge(other.hosts);
    }

    pub(crate) fn iter(&self) -> impl Iterator<Item = &String> {
        self.hosts.iter()
    }

    pub(crate) fn first_duplicate(&self) -> Option<&String> {
        self.hosts.first_duplicate()
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.hosts.is_empty()
    }
}

#[derive(Debug, Clone)]
pub(crate) struct ExecRules {
    pub(crate) default: ExecDefault,
    allowed: DuplicateAwareSet<String>,
}

impl Default for ExecRules {
    fn default() -> Self {
        Self {
            default: ExecDefault::Allowlist,
            allowed: DuplicateAwareSet::default(),
        }
    }
}

impl ExecRules {
    pub(crate) fn with_default(default: ExecDefault) -> Self {
        Self {
            default,
            ..Self::default()
        }
    }

    pub(crate) fn insert_raw(&mut self, value: String) {
        self.allowed.insert(value);
    }

    pub(crate) fn extend<I>(&mut self, iter: I)
    where
        I: IntoIterator<Item = String>,
    {
        self.allowed.extend(iter);
    }

    pub(crate) fn merge(&mut self, other: ExecRules) {
        self.default = other.default;
        self.allowed.merge(other.allowed);
    }

    pub(crate) fn iter(&self) -> impl Iterator<Item = &String> {
        self.allowed.iter()
    }

    pub(crate) fn first_duplicate(&self) -> Option<&String> {
        self.allowed.first_duplicate()
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.allowed.is_empty()
    }
}

#[derive(Debug, Clone, Default)]
pub(crate) struct SyscallRules {
    deny: DuplicateAwareSet<String>,
}

impl SyscallRules {
    pub(crate) fn insert_raw(&mut self, name: String) {
        self.deny.insert(name);
    }

    pub(crate) fn extend<I>(&mut self, iter: I)
    where
        I: IntoIterator<Item = String>,
    {
        self.deny.extend(iter);
    }

    pub(crate) fn merge(&mut self, other: SyscallRules) {
        self.deny.merge(other.deny);
    }

    pub(crate) fn iter(&self) -> impl Iterator<Item = &String> {
        self.deny.iter()
    }

    pub(crate) fn first_duplicate(&self) -> Option<&String> {
        self.deny.first_duplicate()
    }
}

#[derive(Debug, Clone, Default)]
pub(crate) struct EnvRules {
    read: BTreeSet<String>,
}

impl EnvRules {
    pub(crate) fn extend<I>(&mut self, iter: I)
    where
        I: IntoIterator<Item = String>,
    {
        self.read.extend(iter);
    }

    pub(crate) fn merge(&mut self, other: EnvRules) {
        self.read.extend(other.read);
    }

    pub(crate) fn iter(&self) -> impl Iterator<Item = &String> {
        self.read.iter()
    }
}
