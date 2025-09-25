# Proc Macro Hog Example

This binary crate depends on a companion procedural macro that intentionally burns CPU cycles during expansion.
The macro finishes by emitting a deprecated helper and calling it so the compiler prints a warning similar to:

```text
warning: use of deprecated function `_cargo_warden_proc_macro_hog_warning`
  --> src/main.rs:4:1
   |
4  | ex_proc_macro_hog!();
   | ^^^^^^^^^^^^^^^^^^^^^
   |
   = note: cargo-warden detected a simulated proc-macro resource hog (.. iterations over .. ms); warden terminates real macros that exceed CPU or memory budgets.
```

Set `WARDEN_EXAMPLE_EXPECT_WARNING=1` when building (for example, by running `bash ../../run_examples.sh ex_proc_macro_hog`) to surface the warning above.
When the sandbox is enabled, the macro will be terminated once it exceeds the configured CPU or memory budgets, demonstrating cargo-warden's protection against runaway procedural macros.
