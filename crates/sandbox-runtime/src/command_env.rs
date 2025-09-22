use std::collections::HashMap;
use std::ffi::OsString;
use std::process::Command;

/// Restrict the command environment to variables explicitly allowed by policy.
pub(crate) fn restrict_command_environment(cmd: &mut Command, allowed: &[String]) {
    let overrides: HashMap<OsString, Option<OsString>> = cmd
        .get_envs()
        .map(|(key, value)| (key.to_os_string(), value.map(|v| v.to_os_string())))
        .collect();

    cmd.env_clear();

    for allowed_key in allowed {
        let key_os = OsString::from(allowed_key);
        match overrides.get(&key_os) {
            Some(Some(value)) => {
                cmd.env(&key_os, value);
            }
            Some(None) => {}
            None => {
                if let Some(value) = std::env::var_os(&key_os) {
                    cmd.env(&key_os, value);
                }
            }
        }
    }
}
