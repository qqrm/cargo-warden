#![no_main]

use libfuzzer_sys::fuzz_target;
use policy_core::Policy;

fuzz_target!(|data: &[u8]| {
    if let Ok(text) = std::str::from_utf8(data) {
        let _ = Policy::from_toml_str(text);
    }
});
