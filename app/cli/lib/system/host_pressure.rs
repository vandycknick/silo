//! Host memory pressure as macOS reports it.
//!
//! `kern.memorystatus_vm_pressure_level` mirrors the level libdispatch's
//! memory-pressure source publishes: 1 normal, 2 warning, 4 critical. Polling
//! it from the supervisor's tick keeps the daemon free of a dispatch run loop.

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum HostMemoryPressure {
    Normal,
    Warning,
    Critical,
}

impl HostMemoryPressure {
    #[cfg_attr(not(target_os = "macos"), allow(dead_code))]
    fn from_level(level: i32) -> Option<Self> {
        match level {
            1 => Some(Self::Normal),
            2 => Some(Self::Warning),
            4 => Some(Self::Critical),
            _ => None,
        }
    }
}

/// The host's current memory pressure, or `None` where it cannot be read.
#[cfg(target_os = "macos")]
pub(crate) fn current() -> Option<HostMemoryPressure> {
    let name = c"kern.memorystatus_vm_pressure_level";
    let mut level: libc::c_int = 0;
    let mut len = std::mem::size_of::<libc::c_int>();
    // SAFETY: the buffer and length describe one c_int and the sysctl only
    // writes that many bytes; the name is a valid NUL-terminated string.
    let status = unsafe {
        libc::sysctlbyname(
            name.as_ptr(),
            (&mut level as *mut libc::c_int).cast(),
            &mut len,
            std::ptr::null_mut(),
            0,
        )
    };
    if status != 0 || len != std::mem::size_of::<libc::c_int>() {
        return None;
    }
    HostMemoryPressure::from_level(level)
}

#[cfg(not(target_os = "macos"))]
pub(crate) fn current() -> Option<HostMemoryPressure> {
    None
}

#[cfg(test)]
mod tests {
    use super::HostMemoryPressure;

    #[test]
    fn levels_map_to_dispatch_values_and_order() {
        assert_eq!(
            HostMemoryPressure::from_level(1),
            Some(HostMemoryPressure::Normal)
        );
        assert_eq!(
            HostMemoryPressure::from_level(2),
            Some(HostMemoryPressure::Warning)
        );
        assert_eq!(
            HostMemoryPressure::from_level(4),
            Some(HostMemoryPressure::Critical)
        );
        assert_eq!(HostMemoryPressure::from_level(3), None);
        assert!(HostMemoryPressure::Critical > HostMemoryPressure::Warning);
        assert!(HostMemoryPressure::Warning > HostMemoryPressure::Normal);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn host_pressure_is_readable_on_macos() {
        assert!(super::current().is_some());
    }
}
