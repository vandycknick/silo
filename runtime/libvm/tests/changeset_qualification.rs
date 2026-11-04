//! Cross-crate end-to-end publication proof, using independently authored bytes/IDs.
use std::path::Path;

use libvm::storage::LayerStore;
use oci::changeset::{ingest_layer, ChangesetLimits, ContentDigest, LayerInput};
use serde_json::Value;

#[cfg(test)]
mod tests {
    use crate::{
        ingest_layer, ChangesetLimits, ContentDigest, LayerInput, LayerStore, Path, Value,
    };

    #[tokio::test]
    async fn independent_fixture_ids_survive_real_publication_and_source_removal() {
        let root =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../oci/testdata/changesets/generated");
        let manifest: Value = serde_json::from_slice(
            &std::fs::read(root.join("manifest.json"))
                .expect("run make changeset-fixtures and retain its full-byte artifacts first"),
        )
        .unwrap();
        let home = tempfile::tempdir().unwrap();
        let source = tempfile::tempdir().unwrap();
        let store = LayerStore::open(home.path()).await.unwrap();
        let limits = ChangesetLimits::default();
        let mut counter = 0_u64;
        for fixture in manifest["cases"].as_array().unwrap() {
            let mut ids = Vec::new();
            let mut retained = Vec::new();
            for layer in fixture["layers"].as_array().unwrap() {
                counter += 1;
                let tar = std::fs::read(root.join(layer["tar"].as_str().unwrap())).unwrap();
                let input_path = source.path().join(format!("{counter}.tar"));
                std::fs::write(&input_path, &tar).unwrap();
                let input = LayerInput {
                    blob_digest: layer["diffId"]
                        .as_str()
                        .unwrap()
                        .parse::<ContentDigest>()
                        .unwrap(),
                    diff_id: layer["diffId"].as_str().unwrap().parse().unwrap(),
                    media_type: "application/vnd.oci.image.layer.v1.tar".into(),
                    size_bytes: tar.len() as u64,
                };
                let operation = format!("00000000-0000-0000-0000-{counter:012x}")
                    .try_into()
                    .unwrap();
                let stage =
                    ingest_layer(&input_path, &input, source.path(), &operation, &limits).unwrap();
                let expected_changeset = stage.changeset().clone();
                let result = store.publish(stage, &limits).await.unwrap();
                assert_eq!(result.id.to_string(), layer["result"].as_str().unwrap());
                assert_eq!(result.recipe.to_string(), layer["recipe"].as_str().unwrap());
                assert_eq!(
                    result.pack_stream.to_string(),
                    layer["packStream"].as_str().unwrap()
                );
                assert_eq!(result.pack_length, layer["packLength"].as_u64().unwrap());
                assert_eq!(
                    result.index_root.to_string(),
                    layer["indexRoot"].as_str().unwrap()
                );
                std::fs::remove_file(&input_path).unwrap();
                assert_eq!(
                    store.load(result.id, &limits).await.unwrap(),
                    expected_changeset
                );
                ids.push(result.id);
                retained.push(expected_changeset);
            }
            let owner = ContentDigest::of_bytes(fixture["name"].as_str().unwrap().as_bytes());
            store.retain_occurrences(owner, &ids).await.unwrap();
            assert_eq!(
                store.occurrences(owner).await.unwrap(),
                ids,
                "ordered duplicate occurrences retained"
            );
            let namespace = store.compose(&ids, &limits).await;
            assert_eq!(
                namespace.is_err(),
                fixture["expectedRejected"].as_bool().unwrap(),
                "{}",
                fixture["name"]
            );
            // Re-load, and re-compose after operation recovery, with no source
            // transport tar remaining. Results are immutable reusable inputs.
            store.recover().await.unwrap();
            for (id, expected) in ids.iter().zip(&retained) {
                assert_eq!(store.load(*id, &limits).await.unwrap(), *expected);
            }
            let recomposed = store.compose(&ids, &limits).await;
            assert_eq!(namespace.is_err(), recomposed.is_err());
            assert_eq!(namespace.ok(), recomposed.ok());
        }
        let cases = manifest["cases"].as_array().unwrap();
        let old = cases
            .iter()
            .find(|case| case["name"] == "link-before-replace")
            .unwrap();
        let other = cases
            .iter()
            .find(|case| case["name"] == "link-before-replace-other-parent")
            .unwrap();
        for field in [
            "diffId",
            "size",
            "packLength",
            "packStream",
            "recipe",
            "indexRoot",
            "result",
        ] {
            assert_eq!(
                old["layers"][1][field], other["layers"][1][field],
                "reusable upper {field} is parent-independent"
            );
        }
        let upper = old["layers"][1]["result"]
            .as_str()
            .unwrap()
            .parse()
            .unwrap();
        let lower_old = old["layers"][0]["result"]
            .as_str()
            .unwrap()
            .parse()
            .unwrap();
        let lower_other = other["layers"][0]["result"]
            .as_str()
            .unwrap()
            .parse()
            .unwrap();
        let immutable_upper = store.load(upper, &limits).await.unwrap();
        let first = store.compose(&[lower_old, upper], &limits).await.unwrap();
        let second = store.compose(&[lower_other, upper], &limits).await.unwrap();
        use oci::changeset::namespace::NamespaceKind;
        let NamespaceKind::Regular { body: first_body } = &first.inode_at(b"b").unwrap().kind
        else {
            panic!("old body regular");
        };
        let NamespaceKind::Regular { body: second_body } = &second.inode_at(b"b").unwrap().kind
        else {
            panic!("other body regular");
        };
        assert_eq!(first_body.entry.layer, 0);
        assert_eq!(second_body.entry.layer, 0);
        assert_eq!(first_body.length, 3);
        assert_eq!(second_body.length, 9);
        assert_eq!(store.load(upper, &limits).await.unwrap(), immutable_upper);
    }
}
