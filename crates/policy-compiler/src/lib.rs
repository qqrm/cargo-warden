use policy_core::Policy;

/// Compile a [`Policy`] into a binary blob.
pub fn compile(policy: &Policy) -> Vec<u8> {
    policy.syscall.deny.join(",").into_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compiles_syscall_list() {
        let policy = Policy {
            mode: policy_core::Mode::Enforce,
            fs: Default::default(),
            net: Default::default(),
            exec: Default::default(),
            syscall: policy_core::SyscallPolicy {
                deny: vec!["clone".into(), "execve".into()],
            },
            allow: Default::default(),
        };
        let blob = compile(&policy);
        assert_eq!(blob, b"clone,execve".to_vec());
    }
}
