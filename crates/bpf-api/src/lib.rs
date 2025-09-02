#![no_std]

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct ExecAllowEntry {
    pub path: [u8; 256],
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct NetRule {
    pub addr: [u8; 16],
    pub port: u16,
    pub protocol: u8,
    pub reserved: u8,
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::mem::size_of;

    #[test]
    fn exec_allow_entry_size() {
        assert_eq!(size_of::<ExecAllowEntry>(), 256);
    }

    #[test]
    fn net_rule_size() {
        assert_eq!(size_of::<NetRule>(), 20);
    }
}
