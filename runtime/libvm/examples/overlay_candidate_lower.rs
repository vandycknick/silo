//! Candidate-only OCI lower producer. It never grants a boot qualification.
//!
//! The caller owns this private fixture pool for the whole candidate lifetime;
//! no production catalog or garbage collector uses it.
use std::error::Error;
use std::fs::{self, File, OpenOptions};
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use libvm::storage::{composition, pool::StoragePool, vmdk::FlatLowerPlan};
use oci::changeset::index::encode_index_to;
use oci::changeset::{ChangesetLimits, LayerRecipe, LayerResult, StreamIdentity};
use oci::composition::CompositionRecipe;
use oci::erofs::Layer;

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<_> = std::env::args_os().collect();
    if args.len() != 3 {
        return Err("usage: overlay_candidate_lower OCI_REFERENCE OUTPUT_DIRECTORY".into());
    }
    let reference = args[1].to_str().ok_or("OCI reference is not UTF-8")?;
    let directory = Path::new(&args[2]);
    fs::create_dir(directory)?;
    let directory = directory.canonicalize()?;
    let images = directory.join("images");
    fs::create_dir(&images)?;
    fs::set_permissions(&images, fs::Permissions::from_mode(0o700))?;
    let pool = StoragePool::open(&images)?;
    let producer = oci::OciMaterializer::open(&images, oci::RegistryPolicy::default())?;
    let platform = oci::Platform::host()?;
    let resolved = producer.resolve(reference, &platform, None).await?;
    let limits = ChangesetLimits::default();
    let index_directory = directory.join("indexes");
    let layer_count = resolved.layer_digests().count();
    if layer_count as u64 > limits.max_layers {
        return Err("OCI layer occurrence count exceeds composition limit".into());
    }
    fs::create_dir(&index_directory)?;
    let mut inputs = Vec::with_capacity(layer_count);
    for occurrence in 0..layer_count {
        let operation = oci::StagingOperation::try_from(uuid::Uuid::new_v4().to_string())?;
        let staged = producer
            .ingest_changeset(&resolved, occurrence, &operation, &limits, None)
            .await?;
        let root = encode_index_to(staged.changeset(), &limits, |object| {
            fs::write(
                index_directory.join(object.digest.to_string()),
                object.bytes,
            )?;
            Ok(())
        })?;
        fs::write(index_directory.join(root.digest.to_string()), &root.bytes)?;
        let recipe = LayerRecipe {
            diff_id: staged.changeset().diff_id,
        };
        let (pack, guard) = pool.publish_stream_for_catalog(staged.pack_path())?;
        let result = LayerResult {
            recipe: recipe.id()?,
            pack_stream: StreamIdentity::from_sha256(*pack.id.as_bytes()),
            pack_length: pack.length,
            index_root: root.digest,
        };
        fs::write(
            directory.join(format!("layer-{occurrence}-recipe.json")),
            recipe.canonical_bytes()?,
        )?;
        fs::write(
            directory.join(format!("layer-{occurrence}-result.json")),
            result.canonical_bytes()?,
        )?;
        let file = File::open(&pack.path)?;
        inputs.push((staged, result, file, guard, pack.id));
    }
    let layers: Vec<_> = inputs
        .iter()
        .map(|(staged, result, pack, _, _)| Layer {
            result,
            changeset: staged.changeset(),
            pack,
        })
        .collect();
    let recipe = CompositionRecipe::from_layers(platform, &layers)?;
    let fsmeta_path = directory.join("fsmeta.erofs");
    let mut fsmeta = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(&fsmeta_path)?;
    let composed = composition::compose(&recipe, &layers, &mut fsmeta)?;
    composition::load_exact(&recipe, &layers, &composed.result, &fsmeta)?;
    let (object, _object_guard) = pool.publish_object_for_catalog(&fsmeta_path)?;
    if object.digest.as_bytes() != composed.result.fsmeta.digest.as_bytes()
        || object.length != composed.result.fsmeta.length
    {
        return Err("published fsmeta contradicts authenticated composition".into());
    }
    let mut occurrences = Vec::with_capacity(inputs.len() + 1);
    occurrences.push(pool.lower_object_occurrence(&object.digest)?);
    for (_, _, _, _, id) in &inputs {
        occurrences.push(pool.lower_occurrence(id)?);
    }
    let plan = FlatLowerPlan::new(&occurrences)?.preflight(0)?;
    plan.verify(&pool)?;
    if plan.logical_length() != composed.result.lower_length {
        return Err("descriptor geometry contradicts authenticated composition".into());
    }
    let descriptor = directory.join("lower.vmdk");
    fs::write(&descriptor, plan.descriptor()?)?;
    fs::write(directory.join("recipe.json"), recipe.canonical_bytes()?)?;
    fs::write(
        directory.join("result.json"),
        composed.result.canonical_bytes()?,
    )?;
    drop(fsmeta);
    fs::remove_file(fsmeta_path)?;
    println!(
        "{}",
        serde_json::json!({
            "descriptor": descriptor,
            "logicalLowerBytes": composed.result.lower_length,
            "filesystemUuid": uuid::Uuid::from_bytes(composed.result.fsmeta.uuid),
            "compositionResult": composed.result.id()?.to_string(),
            "fsmetaObject": object.digest.to_string(),
            "candidateOnly": true,
        })
    );
    Ok(())
}
