use libvm::{ImageDetail, ImageHandle, ImagePullOptions, ImagePullPolicy, ImageRemoveOptions};
use serde::Deserialize;
use serde_json::{json, Value};

use crate::buffer::SiloBuffer;
use crate::error::{catch_ffi, error_from_libvm, invalid_argument, SiloError};
use crate::handles::RuntimeHandle;
use crate::runtime::request_bytes;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ImageRequest {
    operation: String,
    reference: Option<String>,
    policy: Option<String>,
    #[serde(default)]
    force: bool,
}

#[no_mangle]
pub unsafe extern "C" fn silo_images_call(
    runtime: *const RuntimeHandle,
    request_ptr: *const u8,
    request_len: usize,
    out_data: *mut SiloBuffer,
) -> *mut SiloError {
    catch_ffi(|| {
        let runtime = runtime
            .as_ref()
            .ok_or_else(|| invalid_argument("runtime must not be null"))?;
        if out_data.is_null() {
            return Err(invalid_argument("out_data must not be null"));
        }
        *out_data = SiloBuffer::empty();
        let request: ImageRequest =
            serde_json::from_slice(request_bytes(request_ptr, request_len)?)
                .map_err(|error| invalid_argument(format!("decode image request: {error}")))?;
        let images = runtime.context.runtime.images();
        let value = runtime
            .context
            .tokio
            .block_on(async {
                match request.operation.as_str() {
                    "pull" => {
                        let reference = reference(&request)?;
                        let result = match request.policy.as_deref() {
                            Some(value) => {
                                images
                                    .pull_with(
                                        reference,
                                        ImagePullOptions {
                                            policy: Some(policy(value)?),
                                        },
                                    )
                                    .await
                            }
                            None => images.pull(reference).await,
                        };
                        result.map(image_handle)
                    }
                    "get" => images
                        .get(reference(&request)?)
                        .await
                        .map(|value| value.map(image_handle).unwrap_or(Value::Null)),
                    "list" => images
                        .list()
                        .await
                        .map(|values| Value::Array(values.into_iter().map(image_handle).collect())),
                    "inspect" => images
                        .inspect(reference(&request)?)
                        .await
                        .map(|value| value.map(image_detail).unwrap_or(Value::Null)),
                    "remove" => images
                        .remove_with(
                            reference(&request)?,
                            ImageRemoveOptions {
                                force: request.force,
                            },
                        )
                        .await
                        .map(|_| Value::Null),
                    "prune" => images.prune().await.map(|value| {
                        json!({
                            "references_removed": value.references_removed,
                            "artifacts_removed": value.artifacts_removed,
                            "bytes_removed": value.bytes_removed,
                        })
                    }),
                    _ => Err(libvm::LibVmError::InvalidCreateRequest {
                        name: "images".to_string(),
                        reason: "unsupported image operation".to_string(),
                    }),
                }
            })
            .map_err(error_from_libvm)?;
        *out_data = SiloBuffer::from_vec(
            serde_json::to_vec(&value)
                .map_err(|error| SiloError::new("Serialization", error.to_string()))?,
        );
        Ok(())
    })
}

fn reference(request: &ImageRequest) -> Result<&str, libvm::LibVmError> {
    request
        .reference
        .as_deref()
        .filter(|value| !value.is_empty())
        .ok_or_else(|| libvm::LibVmError::InvalidCreateRequest {
            name: "images".to_string(),
            reason: "image reference must not be empty".to_string(),
        })
}

fn policy(value: &str) -> Result<ImagePullPolicy, libvm::LibVmError> {
    match value {
        "if_missing" => Ok(ImagePullPolicy::IfMissing),
        "always" => Ok(ImagePullPolicy::Always),
        "never" => Ok(ImagePullPolicy::Never),
        _ => Err(libvm::LibVmError::InvalidCreateRequest {
            name: "images".to_string(),
            reason: format!("unsupported image pull policy {value:?}"),
        }),
    }
}

fn image_handle(value: ImageHandle) -> Value {
    json!({
        "requested_reference": value.requested_reference,
        "selected_reference": value.selected_reference,
        "selected_manifest_digest": value.selected_manifest_digest,
        "config_digest": value.config_digest,
        "image_id": value.image_id,
        "platform": {
            "os": value.platform_os,
            "architecture": value.platform_architecture,
            "variant": value.platform_variant,
        },
        "size_bytes": value.size_bytes,
        "created_at_unix_ms": value.created_at,
        "updated_at_unix_ms": value.updated_at,
        "last_used_at_unix_ms": value.last_used_at,
    })
}

fn image_detail(value: ImageDetail) -> Value {
    json!({
        "handle": image_handle(value.handle),
        "config": {
            "entrypoint": value.config.entrypoint,
            "command": value.config.cmd,
            "env": value.config.env,
            "working_dir": value.config.working_dir,
            "user": value.config.user,
            "labels": value.config.labels,
            "stop_signal": value.config.stop_signal,
        },
        "layers": value.layers.into_iter().map(|layer| json!({
            "blob_digest": layer.blob_digest,
            "diff_id": layer.diff_id,
            "media_type": layer.media_type,
            "compressed_size_bytes": layer.compressed_size_bytes,
            "uncompressed_size_bytes": layer.uncompressed_size_bytes,
            "position": layer.position,
        })).collect::<Vec<_>>(),
    })
}
