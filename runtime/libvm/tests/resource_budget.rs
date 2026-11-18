//! Public store APIs are linked as normal libvm dependencies in integration tests.

#[cfg(test)]
mod tests {
    #[tokio::test]
    async fn public_store_opens_use_only_their_fixture_home_resource_ledger() {
        let root = tempfile::tempdir().unwrap();
        let first = root.path().join("first-home");
        let second = root.path().join("second-home");
        let _layers = libvm::storage::LayerStore::open(&first).await.unwrap();
        let first_ledger = first.join("resource-budget");
        assert!(first_ledger.is_dir());
        // A poisoned fixture ledger cannot leak into independently opened homes.
        std::fs::write(first_ledger.join("unknown"), b"not a charge").unwrap();
        let _other = libvm::storage::LayerStore::open(&second).await.unwrap();
        let second_ledger = second.join("resource-budget");
        assert!(second_ledger.is_dir());
        assert_ne!(first_ledger, second_ledger);
        assert!(!second_ledger.join("unknown").exists());
        let anchors = std::fs::read_dir(&second_ledger)
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .filter(|name| name.to_string_lossy().ends_with("-home.json"))
            .count();
        assert_eq!(anchors, 1);
    }
    #[test]
    fn capture_budget_diagnostics_name_phase_device_and_components() {
        let error = libvm::storage::StorageError::CaptureDiskBudget {
            phase: "publication deferred",
            filesystem: "/capture-pool".into(),
            required: 104,
            available: 99,
            ram_staging: 0,
            disk_staging: 0,
            publication: 32,
            reserves: 64,
            other: 8,
        };
        let diagnostic = error.to_string();
        for expected in [
            "publication deferred",
            "/capture-pool",
            "requires 104 bytes",
            "available 99 bytes",
            "RAM staging 0",
            "disk staging 0",
            "publication 32",
            "reserves 64",
            "other reservations 8",
        ] {
            assert!(diagnostic.contains(expected), "{diagnostic}");
        }
    }
}
