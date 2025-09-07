//! Integration test helpers.

/// Dummy helper to verify crate wiring.
pub fn init() -> bool {
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn init_returns_true() {
        assert!(init());
    }
}
