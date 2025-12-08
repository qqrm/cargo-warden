pub use super::{MapDescriptor, MapKind};

pub const MAP_DESCRIPTORS: &[MapDescriptor] = super::HOST_MAP_DESCRIPTORS;

pub fn reset_all() {
    for descriptor in MAP_DESCRIPTORS {
        (descriptor.clear)();
    }
}

pub fn clear_by_name(name: &str) -> bool {
    if let Some(descriptor) = MAP_DESCRIPTORS.iter().find(|d| d.name == name) {
        (descriptor.clear)();
        true
    } else {
        false
    }
}

pub fn descriptor(name: &str) -> Option<&'static MapDescriptor> {
    MAP_DESCRIPTORS.iter().find(|d| d.name == name)
}
