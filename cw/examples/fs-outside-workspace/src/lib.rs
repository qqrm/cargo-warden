//! Dummy crate for demonstrating workspace write restrictions.

/// Returns a static string so the crate has at least one item.
pub fn marker() -> &'static str {
    "fs-outside-workspace"
}
