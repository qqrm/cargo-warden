use proc_macro::TokenStream;
use std::env;
use std::hint::black_box;
use std::time::{Duration, Instant};

#[proc_macro]
pub fn ex_proc_macro_hog(_input: TokenStream) -> TokenStream {
    let start = Instant::now();
    let mut iterations: u64 = 0;
    let budget = Duration::from_millis(400);

    while start.elapsed() < budget {
        iterations = iterations.wrapping_add(1);
        black_box(iterations);
    }

    let elapsed = start.elapsed();

    if env::var_os("WARDEN_EXAMPLE_EXPECT_WARNING").is_none() {
        return TokenStream::new();
    }

    let mut message = format!(
        "cargo-warden detected a simulated proc-macro resource hog ({} iterations over {} ms); warden terminates real macros that exceed CPU or memory budgets.",
        iterations,
        elapsed.as_millis()
    );

    message = message.replace('\\', r"\\");
    message = message.replace('"', "\\\"");

    let tokens = format!(
        r#"
            #[deprecated(note = "{message}")]
            fn _cargo_warden_proc_macro_hog_warning() {{}}

            #[allow(dead_code)]
            const _CARGO_WARDEN_PROC_MACRO_HOG_USE: fn() = _cargo_warden_proc_macro_hog_warning;
        "#
    );

    tokens
        .parse()
        .expect("failed to build proc-macro hog warning")
}
