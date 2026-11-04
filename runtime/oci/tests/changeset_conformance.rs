mod support;

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use oci::changeset::index::{encode_index, LayerRecipe, LayerResult};
use oci::changeset::namespace::compose;
use oci::changeset::{ingest_layer, ChangesetLimits, ContentDigest, LayerInput, StagedChangeset};
use serde_json::{json, Value};

use crate::support::abi;
use crate::support::fixtures::{archive, corpus, Fixture};
use crate::support::oracle::{compare, hash, Tree};

fn operation(index: usize) -> oci::StagingOperation {
    format!("00000000-0000-0000-0000-{index:012x}")
        .try_into()
        .expect("canonical fixture operation")
}

fn ingest(tar: &[u8], root: &Path, index: usize) -> StagedChangeset {
    let source = root.join(format!("source-{index}.tar"));
    std::fs::write(&source, tar).expect("write fixture source");
    let digest = ContentDigest::of_bytes(tar);
    let input = LayerInput {
        blob_digest: digest,
        media_type: "application/vnd.oci.image.layer.v1.tar".into(),
        size_bytes: tar.len() as u64,
        diff_id: digest,
    };
    ingest_layer(
        &source,
        &input,
        root,
        &operation(index),
        &ChangesetLimits::default(),
    )
    .expect("fixture structurally valid")
}

fn check_fixture(fixture: &Fixture, output: Option<&Path>) -> Value {
    let staging = tempfile::tempdir().expect("fixture staging");
    let mut stages = Vec::new();
    let mut layers = Vec::new();
    let mut tree = Tree::default();
    let mut oracle_error = None;
    let fixture_out = output.map(|root| root.join(&fixture.name));
    if let Some(path) = &fixture_out {
        std::fs::create_dir_all(path).expect("fixture output");
    }
    for (index, operations) in fixture.layers.iter().enumerate() {
        let tar = archive(operations);
        let expected = abi::expected(operations, &tar);
        let stage = ingest(&tar, staging.path(), index);
        let actual_pack = std::fs::read(stage.pack_path()).expect("read pack");
        assert_eq!(
            actual_pack, expected.pack,
            "{} layer {index} full pack",
            fixture.name
        );
        let actual_index =
            encode_index(stage.changeset(), &ChangesetLimits::default()).expect("encode index");
        assert_eq!(
            actual_index.root.bytes, expected.root,
            "{} layer {index} exact root",
            fixture.name
        );
        let objects: BTreeMap<_, _> = actual_index
            .pages
            .into_iter()
            .map(|page| (page.digest.to_string(), page.bytes))
            .collect();
        assert_eq!(
            objects, expected.objects,
            "{} layer {index} exact pages",
            fixture.name
        );
        let recipe = LayerRecipe {
            diff_id: ContentDigest::of_bytes(&tar),
        };
        assert_eq!(
            recipe.canonical_bytes().expect("recipe record"),
            expected.recipe_record
        );
        assert_eq!(recipe.id().expect("recipe id").to_string(), expected.recipe);
        let result = LayerResult {
            recipe: recipe.id().expect("recipe id"),
            pack_stream: expected.stream.parse().expect("stream digest wire"),
            pack_length: expected.pack.len() as u64,
            index_root: actual_index.root.digest,
        };
        assert_eq!(
            result.canonical_bytes().expect("result record"),
            expected.result_record
        );
        assert_eq!(result.id().expect("result id").to_string(), expected.result);
        // A second complete ingest, in another private operation, compares bytes,
        // not merely self-reported identities.
        let repeated = ingest(&tar, staging.path(), index + 1024);
        assert_eq!(
            std::fs::read(repeated.pack_path()).expect("second pack"),
            actual_pack
        );
        assert_eq!(
            encode_index(repeated.changeset(), &ChangesetLimits::default()).expect("second index"),
            encode_index(stage.changeset(), &ChangesetLimits::default()).expect("first index")
        );
        if oracle_error.is_none() {
            oracle_error = tree.apply(operations).err();
        }
        if let Some(out) = &fixture_out {
            std::fs::write(out.join(format!("layer-{index}.tar")), &tar).expect("save tar");
            std::fs::write(out.join(format!("layer-{index}.pack")), &expected.pack)
                .expect("save pack");
            std::fs::write(
                out.join(format!("layer-{index}.index.json")),
                &expected.root,
            )
            .expect("save index");
            std::fs::write(
                out.join(format!("layer-{index}.stream.json")),
                &expected.stream_record,
            )
            .expect("save stream record");
            std::fs::write(
                out.join(format!("layer-{index}.recipe.json")),
                &expected.recipe_record,
            )
            .expect("save recipe");
            std::fs::write(
                out.join(format!("layer-{index}.result.json")),
                &expected.result_record,
            )
            .expect("save result");
            for (digest, bytes) in &expected.objects {
                std::fs::write(out.join(format!("{}.json", &digest[7..])), bytes)
                    .expect("save index page");
            }
        }
        layers.push(json!({"tar":format!("{}/layer-{index}.tar",fixture.name),"diffId":hash(&tar),"size":tar.len(),"packLength":expected.pack.len(),"packStream":expected.stream,"recipe":expected.recipe,"indexRoot":hash(&expected.root),"result":expected.result}));
        stages.push(stage);
    }
    let inputs: Vec<_> = stages.iter().map(StagedChangeset::changeset).collect();
    let actual = compose(&inputs, &ChangesetLimits::default());
    assert_eq!(
        oracle_error.is_some(),
        fixture.rejection,
        "{} independent rejection",
        fixture.name
    );
    assert_eq!(
        actual.is_err(),
        fixture.rejection,
        "{} production rejection: {actual:?}",
        fixture.name
    );
    let expected = if fixture.rejection {
        Vec::new()
    } else {
        let expected = tree.listing();
        let packs: Vec<_> = stages
            .iter()
            .map(|stage| stage.pack_path().to_path_buf())
            .collect();
        compare(
            &expected,
            &crate::support::production::listing(&actual.expect("accepted namespace"), &packs),
        )
        .unwrap_or_else(|error| panic!("{}: {error}", fixture.name));
        expected
    };
    json!({"name":fixture.name,"matrix":fixture.matrix,"layers":layers,"expected":expected,"expectedRejected":fixture.rejection})
}

fn generated_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("testdata/changesets/generated")
}

fn generate(root: &Path) {
    std::fs::create_dir_all(root).expect("golden directory");
    let cases: Vec<_> = corpus()
        .iter()
        .map(|fixture| check_fixture(fixture, Some(root)))
        .collect();
    let manifest = json!({"schema":1,"generator":"changeset_conformance::tests::generate_goldens","source":"declarative independent operations; no production expectations","cases":cases});
    std::fs::write(
        root.join("manifest.json"),
        serde_json::to_vec_pretty(&manifest).expect("manifest JSON"),
    )
    .expect("write golden manifest");
}

fn assert_same_file(left: &Path, right: &Path) {
    use std::io::Read;
    let mut left = std::fs::File::open(left).expect("first immutable pack");
    let mut right = std::fs::File::open(right).expect("second immutable pack");
    assert_eq!(
        left.metadata().unwrap().len(),
        right.metadata().unwrap().len()
    );
    let mut a = [0_u8; 16384];
    let mut b = [0_u8; 16384];
    let mut remaining = left.metadata().unwrap().len();
    while remaining != 0 {
        let count = remaining.min(a.len() as u64) as usize;
        left.read_exact(&mut a[..count]).unwrap();
        right.read_exact(&mut b[..count]).unwrap();
        assert_eq!(&a[..count], &b[..count], "complete pack byte comparison");
        remaining -= count as u64;
    }
}

fn retain_actual(stage: &StagedChangeset, directory: &Path) -> Value {
    std::fs::create_dir_all(directory).unwrap();
    let pack = directory.join("payload.pack");
    if pack.exists() {
        assert_same_file(stage.pack_path(), &pack);
    } else {
        std::fs::hard_link(stage.pack_path(), &pack)
            .expect("same-filesystem immutable artifact retention");
    }
    let encoded = encode_index(stage.changeset(), &ChangesetLimits::default()).unwrap();
    let retain = |name: &str, bytes: &[u8]| {
        let path = directory.join(name);
        if path.exists() {
            assert_eq!(std::fs::read(path).unwrap(), bytes);
        } else {
            std::fs::write(path, bytes).unwrap();
        }
    };
    retain("index.json", &encoded.root.bytes);
    for page in &encoded.pages {
        retain(
            &format!("{}.json", &page.digest.to_string()[7..]),
            &page.bytes,
        );
    }
    let (stream_record, stream) = crate::support::abi::stream_file_identity(&pack);
    retain("stream.json", &stream_record);
    let recipe = LayerRecipe {
        diff_id: stage.changeset().diff_id,
    };
    let recipe_record = serde_json::to_vec(&json!({"changesetAbi":"silo-changeset-v1","diffId":stage.changeset().diff_id,"kind":"layer-recipe","packProfile":"silo-payload-pack-v1","schema":1})).unwrap();
    assert_eq!(recipe.canonical_bytes().unwrap(), recipe_record);
    let independent_recipe = crate::support::abi::domain("layer-recipe", &recipe_record);
    assert_eq!(recipe.id().unwrap().to_string(), independent_recipe);
    retain("recipe.json", &recipe_record);
    let result = LayerResult {
        recipe: recipe.id().unwrap(),
        pack_stream: stream.parse().unwrap(),
        pack_length: stage.pack_length(),
        index_root: encoded.root.digest,
    };
    let result_record = serde_json::to_vec(&json!({"indexRoot":encoded.root.digest,"kind":"layer-result","packLength":stage.pack_length(),"packStream":stream,"recipe":independent_recipe,"schema":1})).unwrap();
    assert_eq!(result.canonical_bytes().unwrap(), result_record);
    let independent_result = crate::support::abi::domain("layer-result", &result_record);
    assert_eq!(result.id().unwrap().to_string(), independent_result);
    retain("result.json", &result_record);
    json!({"diffId":stage.changeset().diff_id,"packLength":stage.pack_length(),"packStream":stream,"recipe":independent_recipe,"indexRoot":encoded.root.digest,"result":independent_result})
}

#[cfg(test)]
mod tests {
    use crate::support::fixtures::{archive, corpus};
    use crate::support::oracle::{bytes, compare, hash, Object, Operation, Row, Tree};
    use crate::{check_fixture, generate, generated_root};

    #[test]
    fn declarative_oracle_matches_real_decoder_and_composer() {
        for fixture in corpus() {
            check_fixture(&fixture, None);
        }
    }

    #[test]
    fn exact_slash_directory_has_canonical_root_metadata_but_distinct_source_identity() {
        let fixtures = corpus();
        let dot = fixtures
            .iter()
            .find(|fixture| fixture.name == "root-metadata")
            .unwrap();
        let slash = fixtures
            .iter()
            .find(|fixture| fixture.name == "root-slash-metadata")
            .unwrap();
        let dot_tar = archive(&dot.layers[0]);
        let slash_tar = archive(&slash.layers[0]);
        // One local mtime PAX record precedes the independently written root
        // member. Prove the actual wire contains `/`, not a rewritten `.`.
        assert_eq!(&dot_tar[1024..1026], b".\0");
        assert_eq!(&slash_tar[1024..1026], b"/\0");
        assert_eq!(slash_tar[1024 + 156], b'5');
        assert_ne!(dot_tar, slash_tar);
        let dot_expected = crate::support::abi::expected(&dot.layers[0], &dot_tar);
        let slash_expected = crate::support::abi::expected(&slash.layers[0], &slash_tar);
        assert_eq!(dot_expected.pack, slash_expected.pack);
        assert_eq!(dot_expected.root, slash_expected.root);
        assert_eq!(dot_expected.objects, slash_expected.objects);
        assert_eq!(dot_expected.stream, slash_expected.stream);
        assert_ne!(dot_expected.recipe, slash_expected.recipe);
        assert_ne!(dot_expected.result, slash_expected.result);
        let root = Row {
            path: String::new(),
            kind: "directory".into(),
            mode: 0o1770,
            uid: 7,
            gid: 8,
            mtime_seconds: 9,
            mtime_nanos: 10,
            xattrs: vec![],
            length: None,
            content: None,
            target: None,
            device_major: None,
            device_minor: None,
            group: None,
            links: None,
        };
        let mut dot_tree = Tree::default();
        dot_tree.apply(&dot.layers[0]).unwrap();
        let mut slash_tree = Tree::default();
        slash_tree.apply(&slash.layers[0]).unwrap();
        assert_eq!(dot_tree.listing().first(), Some(&root));
        assert_eq!(slash_tree.listing(), dot_tree.listing());
        // Production is only observed after the independent byte and listing
        // expectations above have been authored.
        check_fixture(dot, None);
        check_fixture(slash, None);
    }

    #[test]
    fn slash_root_exception_does_not_admit_other_absolutes_or_duplicate_root_aliases() {
        let dot = Operation::put(b".", Object::Directory);
        let slash = Operation::put(b"/", Object::Directory);
        let mut controls = vec![
            (
                "empty-directory-name",
                vec![Operation::put(b"", Object::Directory)],
            ),
            (
                "double-slash-directory",
                vec![Operation::put(b"//", Object::Directory)],
            ),
            (
                "slash-dot-directory",
                vec![Operation::put(b"/./", Object::Directory)],
            ),
            (
                "absolute-child-directory",
                vec![Operation::put(b"/nix/", Object::Directory)],
            ),
            (
                "absolute-child-file",
                vec![Operation::file(b"/nix/store/file", b"body")],
            ),
            ("slash-regular-file", vec![Operation::file(b"/", b"body")]),
            (
                "slash-symlink",
                vec![Operation::put(b"/", Object::Symlink(b"target".to_vec()))],
            ),
            (
                "slash-character-device",
                vec![Operation::put(b"/", Object::Character(1, 3))],
            ),
            ("slash-fifo", vec![Operation::put(b"/", Object::Fifo)]),
            ("slash-socket", vec![Operation::put(b"/", Object::Socket)]),
            (
                "slash-hardlink-source",
                vec![
                    Operation::file(b"base", b"body"),
                    Operation::link(b"/", b"base"),
                ],
            ),
            (
                "slash-hardlink-target",
                vec![
                    Operation::file(b"base", b"body"),
                    Operation::link(b"alias", b"/"),
                ],
            ),
        ];
        controls.push(("dot-slash-duplicate", vec![dot.clone(), slash.clone()]));
        controls.push(("slash-dot-duplicate", vec![slash, dot]));
        for (name, operations) in controls {
            let mut tree = Tree::default();
            assert!(
                tree.apply(&operations).is_err(),
                "independent control {name}"
            );
            let staging = tempfile::tempdir().unwrap();
            let tar = archive(&operations);
            let source = staging.path().join("source.tar");
            std::fs::write(&source, &tar).unwrap();
            let digest = oci::changeset::ContentDigest::of_bytes(&tar);
            let input = oci::changeset::LayerInput {
                blob_digest: digest,
                diff_id: digest,
                size_bytes: tar.len() as u64,
                media_type: "application/vnd.oci.image.layer.v1.tar".into(),
            };
            let error = oci::changeset::ingest_layer(
                &source,
                &input,
                staging.path(),
                &crate::operation(0),
                &oci::changeset::ChangesetLimits::default(),
            )
            .expect_err(name);
            assert!(
                matches!(error, oci::changeset::ChangesetError::Invalid(_)),
                "{name}: {error}"
            );
            if name.ends_with("duplicate") {
                assert!(
                    error.to_string().contains("duplicate normalized tar path"),
                    "{name}: {error}"
                );
            }
        }
    }

    #[test]
    fn hand_written_link_and_whiteout_anchors() {
        let root = Row {
            path: String::new(),
            kind: "directory".into(),
            mode: 0o755,
            uid: 0,
            gid: 0,
            mtime_seconds: 0,
            mtime_nanos: 0,
            xattrs: vec![],
            length: None,
            content: None,
            target: None,
            device_major: None,
            device_minor: None,
            group: None,
            links: None,
        };
        let mut a = root.clone();
        a.path = "YQ".into();
        a.kind = "regular".into();
        a.length = Some(3);
        a.content = Some(hash(b"new"));
        a.group = Some("YQ".into());
        a.links = Some(1);
        let mut b = a.clone();
        b.path = "Yg".into();
        b.content = Some(hash(b"old"));
        b.group = Some("Yg".into());
        let mut tree = Tree::default();
        tree.apply(&[Operation::file(b"a", b"old")]).unwrap();
        tree.apply(&[Operation::link(b"b", b"a"), Operation::file(b"a", b"new")])
            .unwrap();
        assert_eq!(tree.listing(), vec![root.clone(), a.clone(), b]);
        tree.apply(&[Operation::remove(b".wh.b"), Operation::file(b"b", b"new")])
            .unwrap();
        let mut b = a.clone();
        b.path = "Yg".into();
        b.group = Some("Yg".into());
        assert_eq!(tree.listing(), vec![root.clone(), a.clone(), b]);
        let mut reverse = Tree::default();
        reverse.apply(&[Operation::file(b"a", b"old")]).unwrap();
        reverse
            .apply(&[Operation::file(b"a", b"new"), Operation::remove(b".wh.a")])
            .unwrap();
        assert_eq!(
            reverse.listing(),
            vec![root.clone(), a.clone()],
            "reverse whiteout cannot delete a same-layer addition"
        );
        let mut opaque = Tree::default();
        opaque
            .apply(&[Operation::file(b"a/b/c/bar", b"old")])
            .unwrap();
        opaque
            .apply(&[
                Operation::file(b"a/b/c/foo", b"new"),
                Operation::opaque(b"a/.wh..wh..opq"),
            ])
            .unwrap();
        let directories = [b"a".as_slice(), b"a/b", b"a/b/c"];
        let mut anchored = vec![root.clone()];
        for path in directories {
            let mut directory = root.clone();
            directory.path = bytes(path);
            anchored.push(directory);
        }
        let mut foo = a;
        foo.path = "YS9iL2MvZm9v".into();
        foo.group = Some("YS9iL2MvZm9v".into());
        anchored.push(foo);
        assert_eq!(
            opaque.listing(),
            anchored,
            "implicit upper ancestors survive a reverse opaque marker"
        );
        let mut dangling = Tree::default();
        dangling
            .apply(&[
                Operation::put(b"s", Object::Symlink(b"missing".to_vec())),
                Operation::link(b"t", b"s"),
            ])
            .unwrap();
        let rows = dangling.listing();
        assert_eq!(rows[1].target.as_deref(), Some("bWlzc2luZw"));
        assert_eq!(rows[1].group.as_deref(), Some("cw"));
        assert_eq!(rows[2].group.as_deref(), Some("cw"));
        assert_eq!(rows[1].links, Some(2));
    }

    #[test]
    fn comparator_negative_controls_preserve_every_difference() {
        let mut tree = Tree::default();
        tree.apply(&[Operation::file(b"d/old", b"old")]).unwrap();
        tree.apply(&[
            Operation::file(b"d/new", b"new"),
            Operation::opaque(b"d/.wh..wh..opq"),
        ])
        .unwrap();
        let expected = tree.listing();
        let mut wrong_whiteout = expected.clone();
        wrong_whiteout.retain(|row| row.path != bytes(b"d/new"));
        assert!(compare(&expected, &wrong_whiteout).is_err());
        let mut wrong_group = expected.clone();
        wrong_group.last_mut().unwrap().group = Some(bytes(b"unrelated"));
        assert!(compare(&expected, &wrong_group).is_err());
        let mut wrong_nanos = expected.clone();
        wrong_nanos.last_mut().unwrap().mtime_nanos = 1;
        assert!(compare(&expected, &wrong_nanos).is_err());
        let mut wrong_raw = expected.clone();
        wrong_raw.last_mut().unwrap().path = bytes(b"d/ne\xff");
        assert!(compare(&expected, &wrong_raw).is_err());
    }

    #[test]
    fn committed_goldens_are_full_byte_artifacts() {
        let root = generated_root();
        let manifest: serde_json::Value = serde_json::from_slice(
            &std::fs::read(root.join("manifest.json"))
                .expect("run make changeset-fixtures first, then retain generated bytes"),
        )
        .unwrap();
        let cases = manifest["cases"].as_array().unwrap();
        for (fixture, case) in corpus().iter().zip(cases) {
            assert_eq!(check_fixture(fixture, None), *case);
            for (index, operations) in fixture.layers.iter().enumerate() {
                let tar = archive(operations);
                let expected = crate::support::abi::expected(operations, &tar);
                let prefix = root.join(&fixture.name);
                assert_eq!(
                    std::fs::read(prefix.join(format!("layer-{index}.tar"))).unwrap(),
                    tar
                );
                assert_eq!(
                    std::fs::read(prefix.join(format!("layer-{index}.pack"))).unwrap(),
                    expected.pack
                );
                assert_eq!(
                    std::fs::read(prefix.join(format!("layer-{index}.index.json"))).unwrap(),
                    expected.root
                );
                assert_eq!(
                    std::fs::read(prefix.join(format!("layer-{index}.stream.json"))).unwrap(),
                    expected.stream_record
                );
                assert_eq!(
                    std::fs::read(prefix.join(format!("layer-{index}.recipe.json"))).unwrap(),
                    expected.recipe_record
                );
                assert_eq!(
                    std::fs::read(prefix.join(format!("layer-{index}.result.json"))).unwrap(),
                    expected.result_record
                );
                for (digest, bytes) in expected.objects {
                    assert_eq!(
                        std::fs::read(prefix.join(format!("{}.json", &digest[7..]))).unwrap(),
                        bytes
                    );
                }
            }
        }
        assert_eq!(cases.len(), corpus().len());
    }

    #[test]
    fn published_pins_and_actual_builder_evidence_are_retained_offline() {
        use serde_json::Value;
        use std::path::Path;
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("testdata/changesets");
        let corpus: Value =
            serde_json::from_slice(&std::fs::read(root.join("corpus.json")).unwrap()).unwrap();
        let mut builders = std::collections::BTreeSet::new();
        for pin in corpus["images"].as_array().unwrap() {
            let name = pin["name"].as_str().unwrap();
            builders.insert(pin["builder"].as_str().unwrap());
            let index = std::fs::read(root.join(format!("corpus/{name}/index.json"))).unwrap();
            let manifest =
                std::fs::read(root.join(format!("corpus/{name}/manifest.json"))).unwrap();
            let config = std::fs::read(root.join(format!("corpus/{name}/config.json"))).unwrap();
            assert_eq!(hash(&index), pin["index"]);
            assert_eq!(hash(&manifest), pin["manifest"]);
            assert_eq!(hash(&config), pin["config"]);
            let manifest: Value = serde_json::from_slice(&manifest).unwrap();
            let config: Value = serde_json::from_slice(&config).unwrap();
            assert_eq!(manifest["config"]["digest"], pin["config"]);
            assert_eq!(config["architecture"], "amd64");
            assert_eq!(config["os"], "linux");
            assert_eq!(
                manifest["layers"].as_array().unwrap().len(),
                config["rootfs"]["diff_ids"].as_array().unwrap().len()
            );
            if pin["index"] != pin["manifest"] {
                let index: Value = serde_json::from_slice(&index).unwrap();
                assert!(index["manifests"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|entry| entry["digest"] == pin["manifest"]
                        && entry["platform"]["architecture"] == "amd64"
                        && entry["platform"]["os"] == "linux"));
            }
            match name {
                "docker" => assert!(config["history"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|entry| entry["comment"] == "buildkit.dockerfile.v0")),
                "buildah" => assert_eq!(
                    config["config"]["Labels"]["built.by.commit"],
                    "b86020d8c306c4724780adfb6fc492d0a2d9cc48"
                ),
                "kaniko" => assert_eq!(
                    config["config"]["Labels"]["org.opencontainers.image.revision"],
                    "72c12e191799ee153012b3f6d02b2a0bf9d101d0"
                ),
                "apko" => {
                    assert_eq!(config["author"], "github.com/chainguard-dev/apko");
                    assert_eq!(config["history"][0]["created_by"], "apko");
                }
                "nix" => assert!(config["history"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|entry| entry["comment"]
                        .as_str()
                        .is_some_and(|comment| comment.starts_with("store paths:")))),
                "bazel" => assert!(config["history"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|entry| entry["created_by"]
                        .as_str()
                        .is_some_and(|command| command.starts_with("bazel build ")))),
                _ => panic!("unreviewed published builder"),
            }
        }
        assert_eq!(
            builders,
            ["apko", "bazel", "buildah", "docker", "kaniko", "nix"]
                .into_iter()
                .collect()
        );
        let sources: Value =
            serde_json::from_slice(&std::fs::read(root.join("corpus/sources.json")).unwrap())
                .unwrap();
        for source in sources["sources"].as_array().unwrap() {
            let raw =
                std::fs::read(root.join("corpus").join(source["file"].as_str().unwrap())).unwrap();
            assert_eq!(hash(&raw), source["sha256"]);
            assert_eq!(raw.len() as u64, source["length"].as_u64().unwrap());
        }
    }

    #[test]
    fn literal_metadata_bytes_and_acl_presence_cross_the_decoder_boundary() {
        use crate::support::metadata_fixtures::{ACCESS_ACL, CAP_V2, CONFLICTING_ACCESS_ACL};
        use oci::changeset::namespace::{compose, NamespaceError};
        use oci::changeset::{ChangesetLimits, StagedChangeset};
        let fixtures = crate::support::metadata_fixtures::corpus();
        let binary = fixtures
            .iter()
            .find(|fixture| fixture.name == "metadata-access-acl-binary")
            .unwrap();
        let text = fixtures
            .iter()
            .find(|fixture| fixture.name == "metadata-access-acl-text")
            .unwrap();
        let alternate = fixtures
            .iter()
            .find(|fixture| fixture.name == "metadata-access-acl-alternate-valid")
            .unwrap();
        let temporary = tempfile::tempdir().unwrap();
        let binary_tar = archive(&binary.layers[0]);
        let text_tar = archive(&text.layers[0]);
        assert_ne!(binary_tar, text_tar);
        let binary_stage = crate::ingest(&binary_tar, temporary.path(), 0);
        let text_stage = crate::ingest(&text_tar, temporary.path(), 1);
        let alternate_stage = crate::ingest(&archive(&alternate.layers[0]), temporary.path(), 2);
        assert_eq!(
            binary_stage.changeset().entries[0].metadata.xattrs[0].value,
            ACCESS_ACL
        );
        assert_eq!(
            text_stage.changeset().entries[0].metadata.xattrs[0].value,
            ACCESS_ACL
        );
        assert_eq!(
            alternate_stage.changeset().entries[0].metadata.xattrs[0].value,
            CONFLICTING_ACCESS_ACL
        );
        assert_eq!(binary_stage.changeset().entries[0].metadata.mode, 0o644);
        assert_eq!(alternate_stage.changeset().entries[0].metadata.mode, 0o644);
        compose(&[alternate_stage.changeset()], &ChangesetLimits::default()).unwrap();
        let binary_index = oci::changeset::index::encode_index(
            binary_stage.changeset(),
            &ChangesetLimits::default(),
        )
        .unwrap();
        let text_index = oci::changeset::index::encode_index(
            text_stage.changeset(),
            &ChangesetLimits::default(),
        )
        .unwrap();
        assert_eq!(
            binary_index, text_index,
            "equivalent text must produce the independently literal binary ACL"
        );
        let presence = &binary_stage.changeset().entries[0].presence;
        assert!(presence.xattrs && presence.acl_access && !presence.acl_default);
        for name in [
            "metadata-default-acl-directory",
            "metadata-default-acl-root-text",
        ] {
            let fixture = fixtures
                .iter()
                .find(|fixture| fixture.name == name)
                .unwrap();
            let stage = crate::ingest(
                &archive(&fixture.layers[0]),
                temporary.path(),
                if name.ends_with("text") { 4 } else { 3 },
            );
            assert!(stage.changeset().entries[0].presence.acl_default);
            assert!(!stage.changeset().entries[0].presence.acl_access);
        }
        for (number, name) in [
            "metadata-hardlink-acl-conflict-binary",
            "metadata-hardlink-acl-conflict-text",
        ]
        .into_iter()
        .enumerate()
        {
            let fixture = fixtures
                .iter()
                .find(|fixture| fixture.name == name)
                .unwrap();
            let stages: Vec<_> = fixture
                .layers
                .iter()
                .enumerate()
                .map(|(index, layer)| {
                    crate::ingest(&archive(layer), temporary.path(), 10 + number * 2 + index)
                })
                .collect();
            let layers: Vec<_> = stages.iter().map(StagedChangeset::changeset).collect();
            let error = compose(&layers, &ChangesetLimits::default()).unwrap_err();
            assert!(
                matches!(error, NamespaceError::HardlinkMetadataMismatch { name } if name == b"system.posix_acl_access"),
                "only the individually valid ACL disagreement may reject"
            );
        }
        let chain = fixtures
            .iter()
            .find(|fixture| fixture.name == "metadata-hardlink-chain")
            .unwrap();
        let mut oracle = Tree::default();
        for layer in &chain.layers {
            oracle.apply(layer).unwrap();
        }
        let root = Row {
            path: String::new(),
            kind: "directory".into(),
            mode: 0o755,
            uid: 0,
            gid: 0,
            mtime_seconds: 0,
            mtime_nanos: 0,
            xattrs: vec![],
            length: None,
            content: None,
            target: None,
            device_major: None,
            device_minor: None,
            group: None,
            links: None,
        };
        let attributes = vec![
            crate::support::oracle::Attribute {
                name: bytes(b"security.capability"),
                value: bytes(CAP_V2),
            },
            crate::support::oracle::Attribute {
                name: bytes(b"system.posix_acl_access"),
                value: bytes(ACCESS_ACL),
            },
            crate::support::oracle::Attribute {
                name: bytes(b"user.marker"),
                value: bytes(b"\0\xff\n="),
            },
        ];
        let b = Row {
            path: "Yg".into(),
            kind: "regular".into(),
            mode: 0o644,
            uid: 0,
            gid: 0,
            mtime_seconds: 0,
            mtime_nanos: 0,
            xattrs: attributes,
            length: Some(3),
            content: Some(hash(b"old")),
            target: None,
            device_major: None,
            device_minor: None,
            group: Some("Yg".into()),
            links: Some(2),
        };
        let mut c = b.clone();
        c.path = "Yw".into();
        assert_eq!(
            oracle.listing(),
            vec![root, b, c],
            "advisory and omitted headers cannot clear retained ACL/capability/user metadata"
        );
        check_fixture(chain, None);
    }

    #[test]
    fn producer_original_metadata_evidence_is_retained_without_claiming_round_trip_equality() {
        use base64::Engine;
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("testdata/changesets/metadata-producers");
        let evidence: serde_json::Value = serde_json::from_slice(&std::fs::read(root.join("producers.json")).expect("run make changeset-metadata; retain actual original-inode/producer/extraction evidence")).unwrap();
        assert!(
            evidence["sourceErrors"].as_array().unwrap().is_empty(),
            "source metadata environment was unavailable, not qualified"
        );
        let names: std::collections::BTreeSet<_> = evidence["intendedAttributes"]
            .as_array()
            .unwrap()
            .iter()
            .map(|attribute| {
                base64::engine::general_purpose::URL_SAFE_NO_PAD
                    .decode(attribute["name"].as_str().unwrap())
                    .unwrap()
            })
            .collect();
        for raw in [
            b"user.a=b".as_slice(),
            b"user.a%b",
            b"user.a%3Db",
            b"user.a%25b",
            b"user.a b",
            b"user.\xc3\xa9",
            b"user.\xff",
            b"user.a+b",
            b"user.empty",
        ] {
            assert!(names.contains(raw));
        }
        let original: Vec<Row> =
            serde_json::from_value(evidence["producerOriginal"].clone()).unwrap();
        let complete = original
            .iter()
            .find(|row| row.path == bytes(b"complete-set"))
            .unwrap();
        for attribute in evidence["intendedAttributes"].as_array().unwrap() {
            assert!(
                complete
                    .xattrs
                    .iter()
                    .any(|actual| actual.name == attribute["name"].as_str().unwrap()
                        && actual.value == attribute["value"].as_str().unwrap()),
                "the original kernel inode must carry the exact intended raw name/value"
            );
        }
        let producers = evidence["producers"].as_array().unwrap();
        assert_eq!(producers.len(), 30);
        let mut families = std::collections::BTreeMap::<&str, usize>::new();
        for producer in producers {
            *families
                .entry(producer["tool"]["producer"].as_str().unwrap())
                .or_default() += 1;
            assert!(!producer["tool"]["version"].as_str().unwrap().is_empty());
            if producer["tool"]["producer"] == "star" {
                for direction in ["createArguments", "extractArguments"] {
                    let arguments = producer[direction].as_array().unwrap();
                    assert!(
                        arguments.iter().any(|argument| argument == "-xattr-linux"),
                        "star Linux metadata evidence must use its Linux xattr option"
                    );
                    assert!(
                        arguments.iter().all(|argument| argument != "-xattr"),
                        "NFSv4-only -xattr is not a Linux metadata specimen"
                    );
                }
            }
            assert!(
                producer["sourceChanges"].as_array().unwrap().is_empty(),
                "producer changed the source inode, inspect retained evidence"
            );
            assert!(producer["initialSourceDifferences"]
                .as_array()
                .unwrap()
                .is_empty());
            if let Some(digest) = producer["archiveDigest"].as_str() {
                let tar = std::fs::read(root.join(producer["archive"].as_str().unwrap())).unwrap();
                assert_eq!(hash(&tar), digest);
                assert_eq!(
                    tar.len() as i64,
                    producer["archiveLength"].as_i64().unwrap()
                );
            }
            assert!(matches!(
                producer["status"].as_str().unwrap(),
                "equal"
                    | "policy-difference"
                    | "semantic-difference"
                    | "producer-rejected"
                    | "extraction-rejected"
                    | "environment-unavailable"
            ));
        }
        assert_eq!(
            families,
            std::collections::BTreeMap::from([("gnu-tar", 10), ("libarchive", 10), ("star", 10)])
        );
        let gnu = producers
            .iter()
            .find(|producer| producer["name"] == "gnu-tar-file-00")
            .unwrap();
        let star = producers
            .iter()
            .find(|producer| producer["name"] == "star-file-02")
            .unwrap();
        let ambiguous_key = bytes(b"SCHILY.xattr.user.a%3Db");
        let gnu_record = gnu["wireRecords"]
            .as_array()
            .unwrap()
            .iter()
            .find(|record| record["key"] == ambiguous_key)
            .expect("GNU original '=' must be retained as actual escaped SCHILY evidence");
        let star_record = star["wireRecords"]
            .as_array()
            .unwrap()
            .iter()
            .find(|record| record["key"] == ambiguous_key)
            .expect("star original literal '%3D' must be retained as actual raw SCHILY evidence");
        assert_eq!(gnu_record["rawRecord"], star_record["rawRecord"], "standalone wire-identical SCHILY records do not reveal different producer-original names");
        let gnu_original: Vec<Row> =
            serde_json::from_value(gnu["archivedOriginal"].clone()).unwrap();
        let star_original: Vec<Row> =
            serde_json::from_value(star["archivedOriginal"].clone()).unwrap();
        assert!(gnu_original.iter().any(|row| row
            .xattrs
            .iter()
            .any(|attribute| attribute.name == bytes(b"user.a=b"))));
        assert!(star_original.iter().any(|row| row
            .xattrs
            .iter()
            .any(|attribute| attribute.name == bytes(b"user.a%3Db"))));
        let libarchive = producers
            .iter()
            .find(|producer| producer["name"] == "libarchive-file-00")
            .unwrap();
        let keys: Vec<_> = libarchive["wireRecords"]
            .as_array()
            .unwrap()
            .iter()
            .map(|record| {
                base64::engine::general_purpose::URL_SAFE_NO_PAD
                    .decode(record["key"].as_str().unwrap())
                    .unwrap()
            })
            .collect();
        assert!(keys.iter().any(|key| key.starts_with(b"SCHILY.xattr.")));
        assert!(
            keys.iter().any(|key| key.starts_with(b"LIBARCHIVE.xattr.")),
            "retain the actual libarchive default dual-header representation"
        );
        // Equality is deliberately not asserted: raw producer intent is a
        // separate authority from any pair of readers agreeing with each other.
    }

    #[test]
    fn independently_archived_and_extracted_socket_is_admitted_losslessly() {
        let root =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("testdata/changesets/socket");
        let tar = std::fs::read(root.join("socket.tar")).expect(
            "run make changeset-socket once, retain exact upstream specimen and provenance",
        );
        let evidence: serde_json::Value =
            serde_json::from_slice(&std::fs::read(root.join("provenance.json")).unwrap()).unwrap();
        assert_eq!(hash(&tar), evidence["archiveDigest"]);
        let expected: Vec<Row> =
            serde_json::from_value(evidence["starExtractedListing"].clone()).unwrap();
        let independent = expected.iter().find(|row| row.path == "c29ja2V0").unwrap();
        assert_eq!(independent.kind, "socket");
        let staging = tempfile::tempdir().unwrap();
        let stage = crate::ingest(&tar, staging.path(), 0);
        assert_eq!(stage.pack_length(), 0);
        let repeated = crate::ingest(&tar, staging.path(), 1);
        crate::assert_same_file(stage.pack_path(), repeated.pack_path());
        assert_eq!(
            oci::changeset::index::encode_index(
                stage.changeset(),
                &oci::changeset::ChangesetLimits::default()
            )
            .unwrap(),
            oci::changeset::index::encode_index(
                repeated.changeset(),
                &oci::changeset::ChangesetLimits::default()
            )
            .unwrap()
        );
        let namespace = oci::changeset::namespace::compose(
            &[stage.changeset()],
            &oci::changeset::ChangesetLimits::default(),
        )
        .unwrap();
        let observed =
            crate::support::production::listing(&namespace, &[stage.pack_path().to_path_buf()]);
        assert_eq!(
            observed.iter().find(|row| row.path == "c29ja2V0").unwrap(),
            independent
        );
        // Root is deliberately *not* filtered from external reports; star's
        // extraction-root policy is distinct from Silo's synthetic root policy.
        assert_eq!(observed[0].path, "");
    }

    #[test]
    fn compressed_encodings_share_complete_pack_and_index_bytes() {
        use oci::changeset::{ingest_layer, ChangesetLimits, ContentDigest, LayerInput};
        use std::io::Write;
        let tar = archive(&[Operation::file(b"a", b"A"), Operation::file(b"bc", b"BC")]);
        let mut gzip = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        gzip.write_all(&tar).unwrap();
        let gzip = gzip.finish().unwrap();
        let zstd = zstd::stream::encode_all(tar.as_slice(), 3).unwrap();
        let expected = crate::support::abi::expected(
            &[Operation::file(b"a", b"A"), Operation::file(b"bc", b"BC")],
            &tar,
        );
        for (index, (transport, media_type)) in [
            (&tar, "application/vnd.oci.image.layer.v1.tar"),
            (&gzip, "application/vnd.oci.image.layer.v1.tar+gzip"),
            (&zstd, "application/vnd.oci.image.layer.v1.tar+zstd"),
        ]
        .into_iter()
        .enumerate()
        {
            let temporary = tempfile::tempdir().unwrap();
            let source = temporary.path().join("source");
            std::fs::write(&source, transport).unwrap();
            let input = LayerInput {
                blob_digest: ContentDigest::of_bytes(transport),
                diff_id: ContentDigest::of_bytes(&tar),
                media_type: media_type.into(),
                size_bytes: transport.len() as u64,
            };
            let stage = ingest_layer(
                &source,
                &input,
                temporary.path(),
                &crate::operation(index),
                &ChangesetLimits::default(),
            )
            .unwrap();
            assert_eq!(std::fs::read(stage.pack_path()).unwrap(), expected.pack);
            assert_eq!(
                oci::changeset::index::encode_index(stage.changeset(), &ChangesetLimits::default())
                    .unwrap()
                    .root
                    .bytes,
                expected.root
            );
        }
        assert_ne!(hash(&tar), hash(&gzip));
        assert_ne!(hash(&gzip), hash(&zstd));
    }

    #[test]
    #[ignore = "explicit supervisor-run deterministic artifact generation"]
    fn generate_goldens() {
        let root = std::env::var_os("SILO_CHANGESET_FIXTURES")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(generated_root);
        generate(&root);
    }

    #[test]
    #[ignore = "explicit acquired-image qualification, no network in ordinary tests"]
    fn qualify_acquired() {
        use oci::changeset::namespace::{compose, NamespaceError};
        use oci::changeset::{
            ingest_layer, ChangesetError, ChangesetLimits, ContentDigest, LayerInput,
        };
        let error_kind = |error: &ChangesetError| match error {
            ChangesetError::Invalid(_) => "invalid",
            ChangesetError::Unsupported(_) => "unsupported",
            ChangesetError::Resource { .. } => "resource",
            ChangesetError::Allocation(_) => "allocation",
            ChangesetError::Limit { .. } => "limit",
            ChangesetError::Io(_) => "io",
            ChangesetError::Json(_) => "json",
        };
        let root = std::path::PathBuf::from(
            std::env::var_os("SILO_CHANGESET_ACQUIRED").expect("acquisition output directory"),
        );
        let request: serde_json::Value =
            serde_json::from_slice(&std::fs::read(root.join("acquired.json")).unwrap()).unwrap();
        let mut cases = Vec::new();
        for (case_index, image) in request["cases"].as_array().unwrap().iter().enumerate() {
            let temp = tempfile::tempdir_in(&root).unwrap();
            let mut stages = Vec::new();
            let mut rejection = None;
            let mut rejection_kind = "";
            let mut artifacts = Vec::new();
            for (index, layer) in image["layers"].as_array().unwrap().iter().enumerate() {
                let source = root.join(layer["blob"].as_str().unwrap());
                let input = LayerInput {
                    blob_digest: layer["digest"]
                        .as_str()
                        .unwrap()
                        .parse::<ContentDigest>()
                        .unwrap(),
                    media_type: layer["mediaType"].as_str().unwrap().into(),
                    size_bytes: layer["size"].as_u64().unwrap(),
                    diff_id: layer["diffId"].as_str().unwrap().parse().unwrap(),
                };
                match ingest_layer(
                    &source,
                    &input,
                    temp.path(),
                    &crate::operation(index),
                    &ChangesetLimits::default(),
                ) {
                    Ok(stage) => {
                        let second = ingest_layer(
                            &source,
                            &input,
                            temp.path(),
                            &crate::operation(index + 1024),
                            &ChangesetLimits::default(),
                        )
                        .unwrap();
                        crate::assert_same_file(stage.pack_path(), second.pack_path());
                        assert_eq!(
                            oci::changeset::index::encode_index(
                                stage.changeset(),
                                &ChangesetLimits::default()
                            )
                            .unwrap(),
                            oci::changeset::index::encode_index(
                                second.changeset(),
                                &ChangesetLimits::default()
                            )
                            .unwrap()
                        );
                        let relative =
                            format!("silo-artifacts/case-{case_index:04}/layer-{index:04}");
                        let directory = root.join(&relative);
                        let mut artifact = crate::retain_actual(&stage, &directory);
                        artifact["directory"] = serde_json::to_value(relative).unwrap();
                        artifacts.push(artifact);
                        stages.push(stage);
                    }
                    Err(error) => {
                        rejection_kind = error_kind(&error);
                        rejection = Some(error.to_string());
                        break;
                    }
                }
            }
            let mut result = image.clone();
            result["artifacts"] = serde_json::to_value(artifacts).unwrap();
            if rejection.is_none() {
                let layers: Vec<_> = stages.iter().map(|stage| stage.changeset()).collect();
                match compose(&layers, &ChangesetLimits::default()) {
                    Ok(namespace) => {
                        let packs: Vec<_> = stages
                            .iter()
                            .map(|stage| stage.pack_path().to_path_buf())
                            .collect();
                        result["expected"] = serde_json::to_value(
                            crate::support::production::listing(&namespace, &packs),
                        )
                        .unwrap();
                    }
                    Err(error) => {
                        rejection_kind = match &error {
                            NamespaceError::Changeset(inner) => error_kind(inner),
                            _ => "namespace",
                        };
                        rejection = Some(error.to_string());
                    }
                }
            }
            if rejection.is_some() {
                result["expected"] = serde_json::json!([]);
            }
            result["siloRejectionKind"] = serde_json::to_value(rejection_kind).unwrap();
            result["siloRejection"] = serde_json::to_value(rejection).unwrap();
            cases.push(result);
        }
        std::fs::write(
            root.join("request.json"),
            serde_json::to_vec_pretty(&serde_json::json!({"schema":1,"cases":cases})).unwrap(),
        )
        .unwrap();
    }
}
