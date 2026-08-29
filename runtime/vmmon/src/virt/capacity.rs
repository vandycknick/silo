use std::sync::Arc;

use tokio::sync::{OwnedSemaphorePermit, Semaphore};

use crate::virt::error::VirtError;

pub(crate) const MACHINE_VSOCK_CAPACITY: usize = 1024;

/// Admission shared by every vsock path for one virtual machine.
#[derive(Clone, Debug)]
pub(crate) struct VsockCapacity {
    machine: Arc<str>,
    semaphore: Arc<Semaphore>,
    limit: usize,
}

impl VsockCapacity {
    pub(crate) fn new(machine: impl Into<Arc<str>>) -> Self {
        Self::with_limit(machine, MACHINE_VSOCK_CAPACITY)
    }

    fn with_limit(machine: impl Into<Arc<str>>, limit: usize) -> Self {
        Self {
            machine: machine.into(),
            semaphore: Arc::new(Semaphore::new(limit)),
            limit,
        }
    }

    pub(crate) fn reserve(&self) -> Result<VsockLease, VirtError> {
        let permit = self.semaphore.clone().try_acquire_owned().map_err(|_| {
            VirtError::VsockCapacityExhausted {
                machine: self.machine.to_string(),
                limit: self.limit,
            }
        })?;
        Ok(VsockLease {
            semaphore: self.semaphore.clone(),
            _permit: permit,
        })
    }

    pub(crate) fn owns(&self, lease: &VsockLease) -> bool {
        Arc::ptr_eq(&self.semaphore, &lease.semaphore)
    }

    pub(crate) fn shares_limit_with(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.semaphore, &other.semaphore)
    }

    #[cfg(test)]
    pub(crate) fn test_with_limit(machine: impl Into<Arc<str>>, limit: usize) -> Self {
        Self::with_limit(machine, limit)
    }

    #[cfg(test)]
    pub(crate) fn available_permits(&self) -> usize {
        self.semaphore.available_permits()
    }
}

/// A move-only reservation for one pending or established vsock stream.
#[derive(Debug)]
pub(crate) struct VsockLease {
    semaphore: Arc<Semaphore>,
    _permit: OwnedSemaphorePermit,
}

#[cfg(test)]
mod tests {
    use crate::virt::capacity::{VsockCapacity, MACHINE_VSOCK_CAPACITY};
    use crate::virt::VirtError;

    #[test]
    fn exact_machine_limit_and_release() {
        let capacity = VsockCapacity::new("boundary");
        let leases = (0..MACHINE_VSOCK_CAPACITY)
            .map(|_| capacity.reserve().expect("capacity through exact limit"))
            .collect::<Vec<_>>();

        assert!(matches!(
            capacity.reserve(),
            Err(VirtError::VsockCapacityExhausted { machine, limit })
                if machine == "boundary" && limit == MACHINE_VSOCK_CAPACITY
        ));

        drop(leases);
        assert_eq!(capacity.available_permits(), MACHINE_VSOCK_CAPACITY);
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
}
