use std::sync::Arc;

use tokio::sync::{OwnedSemaphorePermit, Semaphore};

use crate::virt::error::VirtError;

pub(crate) const MAX_ACTIVE_VSOCK_CONNECTIONS: usize = 1023;
pub(crate) const INTERNAL_HEADROOM: usize = 16;
pub(crate) const MAX_PUBLIC_VSOCK_CONNECTIONS: usize =
    MAX_ACTIVE_VSOCK_CONNECTIONS - INTERNAL_HEADROOM;

/// Admission shared by every vsock path for one virtual machine.
#[derive(Clone, Debug)]
pub(crate) struct VsockCapacity {
    machine: Arc<str>,
    total: Arc<Semaphore>,
    public: Arc<Semaphore>,
    limit: usize,
}

impl VsockCapacity {
    pub(crate) fn new(machine: impl Into<Arc<str>>) -> Self {
        Self::with_limit(machine, MAX_ACTIVE_VSOCK_CONNECTIONS)
    }

    fn with_limit(machine: impl Into<Arc<str>>, limit: usize) -> Self {
        Self {
            machine: machine.into(),
            total: Arc::new(Semaphore::new(limit)),
            public: Arc::new(Semaphore::new(limit.saturating_sub(INTERNAL_HEADROOM))),
            limit,
        }
    }

    pub(crate) fn reserve(&self) -> Result<VsockLease, VirtError> {
        let permit = self.total.clone().try_acquire_owned().map_err(|_| {
            VirtError::VsockCapacityExhausted {
                machine: self.machine.to_string(),
                limit: self.limit,
            }
        })?;
        Ok(VsockLease {
            total: self.total.clone(),
            _total_permit: permit,
            _public_permit: None,
        })
    }

    pub(crate) fn reserve_public(&self) -> Result<VsockLease, VirtError> {
        let public = self.public.clone().try_acquire_owned().map_err(|_| {
            VirtError::VsockCapacityExhausted {
                machine: self.machine.to_string(),
                limit: self.limit.saturating_sub(INTERNAL_HEADROOM),
            }
        })?;
        let total = self.total.clone().try_acquire_owned().map_err(|_| {
            VirtError::VsockCapacityExhausted {
                machine: self.machine.to_string(),
                limit: self.limit.saturating_sub(INTERNAL_HEADROOM),
            }
        })?;
        Ok(VsockLease {
            total: self.total.clone(),
            _total_permit: total,
            _public_permit: Some(public),
        })
    }

    pub(crate) fn owns(&self, lease: &VsockLease) -> bool {
        Arc::ptr_eq(&self.total, &lease.total)
    }

    pub(crate) fn shares_limit_with(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.total, &other.total)
    }

    #[cfg(test)]
    pub(crate) fn test_with_limit(machine: impl Into<Arc<str>>, limit: usize) -> Self {
        Self::with_limit(machine, limit)
    }

    #[cfg(test)]
    pub(crate) fn available_permits(&self) -> usize {
        self.total.available_permits()
    }
}

/// A move-only reservation for one pending or established vsock stream.
#[derive(Debug)]
pub(crate) struct VsockLease {
    total: Arc<Semaphore>,
    _total_permit: OwnedSemaphorePermit,
    _public_permit: Option<OwnedSemaphorePermit>,
}

#[cfg(test)]
mod tests {
    use crate::virt::capacity::{
        VsockCapacity, INTERNAL_HEADROOM, MAX_ACTIVE_VSOCK_CONNECTIONS,
        MAX_PUBLIC_VSOCK_CONNECTIONS,
    };
    use crate::virt::VirtError;

    #[test]
    fn exact_machine_limit_and_release() {
        let capacity = VsockCapacity::new("boundary");
        let leases = (0..MAX_ACTIVE_VSOCK_CONNECTIONS)
            .map(|_| capacity.reserve().expect("capacity through exact limit"))
            .collect::<Vec<_>>();

        assert!(matches!(
            capacity.reserve(),
            Err(VirtError::VsockCapacityExhausted { machine, limit })
                if machine == "boundary" && limit == MAX_ACTIVE_VSOCK_CONNECTIONS
        ));

        drop(leases);
        assert_eq!(capacity.available_permits(), MAX_ACTIVE_VSOCK_CONNECTIONS);
    }

    #[test]
    fn clones_share_capacity_and_lease_drop_releases_it() {
        let capacity = VsockCapacity::test_with_limit("clone", 1);
        let clone = capacity.clone();
        let lease = capacity.reserve().expect("first reservation");

        assert!(matches!(
            clone.reserve(),
            Err(VirtError::VsockCapacityExhausted { .. })
        ));
        drop(lease);
        assert!(clone.reserve().is_ok());
    }

    #[test]
    fn public_users_leave_internal_headroom() {
        let capacity = VsockCapacity::new("headroom");
        let public = (0..MAX_PUBLIC_VSOCK_CONNECTIONS)
            .map(|_| capacity.reserve_public().expect("public capacity"))
            .collect::<Vec<_>>();
        assert!(capacity.reserve_public().is_err());
        let internal = (0..INTERNAL_HEADROOM)
            .map(|_| capacity.reserve().expect("internal headroom"))
            .collect::<Vec<_>>();
        assert!(capacity.reserve().is_err());
        drop(internal);
        drop(public);
        assert_eq!(capacity.available_permits(), MAX_ACTIVE_VSOCK_CONNECTIONS);
    }

    #[test]
    fn public_failure_reports_the_public_limit_even_when_total_is_exhausted() {
        let capacity = VsockCapacity::new("diagnostic");
        let internal = (0..MAX_ACTIVE_VSOCK_CONNECTIONS)
            .map(|_| capacity.reserve().expect("internal capacity"))
            .collect::<Vec<_>>();

        assert!(matches!(
            capacity.reserve_public(),
            Err(VirtError::VsockCapacityExhausted { machine, limit })
                if machine == "diagnostic" && limit == MAX_PUBLIC_VSOCK_CONNECTIONS
        ));
        drop(internal);
    }
}
