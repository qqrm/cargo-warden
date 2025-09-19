use policy_core::Mode;
use std::io;

#[cfg(not(test))]
pub(crate) fn apply_seccomp(mode: Mode, deny: &[String]) -> io::Result<()> {
    if !matches!(mode, Mode::Enforce) {
        return Ok(());
    }
    use libseccomp::{ScmpAction, ScmpFilterContext, ScmpSyscall};
    let mut filter = ScmpFilterContext::new_filter(ScmpAction::Allow).map_err(io::Error::other)?;
    for name in deny {
        if let Ok(sys) = ScmpSyscall::from_name(name) {
            filter
                .add_rule(ScmpAction::Errno(libc::EPERM), sys)
                .map_err(io::Error::other)?;
        }
    }
    filter.load().map_err(io::Error::other)
}

#[cfg(test)]
pub(crate) fn apply_seccomp(_mode: Mode, _deny: &[String]) -> io::Result<()> {
    Ok(())
}
