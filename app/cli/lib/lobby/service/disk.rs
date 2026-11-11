use crate::lobby::{
    failure::{Code, Failure, Outcome},
    service::{Admission, Service},
};
use std::sync::Arc;

pub(crate) struct Reservation {
    admission: Arc<parking_lot::Mutex<Admission>>,
    key: String,
}
impl Reservation {
    pub(crate) fn new(service: &Service, key: String) -> Self {
        Self {
            admission: service.admission.clone(),
            key,
        }
    }
    pub(crate) fn release(&self) {
        let mut admission = self.admission.lock();
        admission.names.remove(&self.key);
        admission.disks.remove(&self.key);
    }
}
impl Drop for Reservation {
    fn drop(&mut self) {
        self.release();
    }
}

pub(crate) fn admit(
    available: u64,
    reserve: u64,
    pending: impl IntoIterator<Item = u64>,
    add: u64,
) -> Outcome<()> {
    let needed = pending
        .into_iter()
        .try_fold(reserve, u64::checked_add)
        .and_then(|needed| needed.checked_add(add));
    if needed.is_none_or(|needed| needed > available) {
        Err(Failure::new(
            Code::Limit,
            "disk free-space floor or concurrent reservations exceeded",
        ))
    } else {
        Ok(())
    }
}
impl Service {
    pub(crate) fn disk_admission(&self, add: u64) -> Outcome<()> {
        let stat = nix::sys::statvfs::statvfs(&self.config.home)
            .map_err(|_| Failure::new(Code::Unavailable, "disk availability unavailable"))?;
        let block = stat.fragment_size();
        let available = stat
            .blocks_available()
            .checked_mul(block)
            .filter(|_| block > 0)
            .ok_or_else(|| Failure::new(Code::Unavailable, "disk availability invalid"))?;
        admit(
            available,
            self.config.settings.disk_reserve(),
            self.admission.lock().disks.values().copied(),
            add,
        )
    }
    pub(crate) async fn reserve_disk_growth(&self, id: &str, growth: u64) -> Outcome<Reservation> {
        let _guard = self.create_lock.lock().await;
        self.disk_admission(growth)?;
        let key = format!("resize:{id}");
        self.admission.lock().disks.insert(key.clone(), growth);
        Ok(Reservation::new(self, key))
    }
}

#[cfg(test)]
mod tests {
    use crate::lobby::service::disk::admit;
    #[test]
    fn disk_floor_and_concurrent_reservations() {
        for (available, floor, pending, add, allowed) in [
            (1024, 128, vec![], 512, true),
            (1024, 128, vec![512], 512, false),
            (1024, 128, vec![u64::MAX], 1, false),
            (u64::MAX, 0, vec![u64::MAX], 1, false),
            (1024, 128, vec![512], 384, true),
            (0, 0, vec![], 0, true),
        ] {
            let result = admit(available, floor, pending, add);
            assert_eq!(result.is_ok(), allowed);
            if let Err(error) = result {
                assert_eq!(error.exit, 6);
            }
        }
    }
    #[tokio::test]
    async fn real_filesystem_reservation_releases() {
        let fixture = crate::lobby::service::testing::fixture().await;
        fixture.service.disk_admission(512).unwrap();
        let reservation = fixture
            .service
            .reserve_disk_growth("id", 1024)
            .await
            .unwrap();
        assert_eq!(fixture.service.admission.lock().disks.len(), 1);
        drop(reservation);
        assert!(fixture.service.admission.lock().disks.is_empty());
        fixture
            .service
            .admission
            .lock()
            .disks
            .insert("overflow".into(), u64::MAX);
        assert_eq!(fixture.service.disk_admission(1).unwrap_err().exit, 6);
    }
}
