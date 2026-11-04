//! Bounded, independent guest observations through ordinary agent RPCs.
//! Files are read to EOF by DownloadFile (sysfs sizes are never trusted).

use std::collections::BTreeMap;
use std::time::Duration;

use protocol::v1;
use protocol::v1::guest_agent_service_client::GuestAgentServiceClient;
use protocol::v1::guest_filesystem_service_client::GuestFilesystemServiceClient;
use serde::{Deserialize, Serialize};
use tonic::transport::Channel;

use crate::attach::dto::{monotonic_ns, Checks, Content, Failure, Status};

const MAX_FILE_BYTES: u32 = 1024 * 1024;
const MAX_ITEMS: usize = 32;
const MAX_SAMPLES: u32 = 64;
const MAX_SAMPLE_INTERVAL_MS: u32 = 1000;
const STATUS_BOUND: Duration = Duration::from_secs(2);
const LISTING_PAGE: u32 = 256;
const MAX_LISTING_PAGES: usize = 64;
/// native_generation_controller.fields() accepts 1..=4096 record bytes.
const MAX_GENERATION_RECORD_BYTES: usize = 4096;
const GENERATION_DEVICE_ID: &[u8] = b"0x5347\n";
const VIRTIO_DEVICES: &str = "/sys/bus/virtio/devices";
/// Field order emitted by `generation_state_show` in the Silo vmgenid patch.
const GENERATION_FIELDS: [&str; 21] = [
    "version",
    "request_sequence",
    "request_id",
    "request_flags",
    "completed_sequence",
    "completed_id",
    "completed_flags",
    "rng_ready_before_call",
    "reseed_count",
    "reseed_sequence",
    "reseed_id",
    "reseed_return_order",
    "clock_complete_order",
    "ack_sequence",
    "ack_id",
    "ack_write_count",
    "ack_write_order",
    "ack_accessor_returned",
    "ack_return_order",
    "error",
    "event_order",
];

/// The guest agent reached over the single attached stream.
#[derive(Clone)]
pub(crate) struct Guest {
    channel: Channel,
}

impl Guest {
    pub(crate) fn new(channel: Channel) -> Self {
        Self { channel }
    }
    pub(crate) fn channel(&self) -> Channel {
        self.channel.clone()
    }
    pub(crate) fn agent(&self) -> GuestAgentServiceClient<Channel> {
        GuestAgentServiceClient::new(self.channel.clone())
            .max_decoding_message_size(protocol::STRUCTURED_16_MIB)
            .max_encoding_message_size(protocol::STRUCTURED_16_MIB)
    }
    pub(crate) fn files(&self) -> GuestFilesystemServiceClient<Channel> {
        GuestFilesystemServiceClient::new(self.channel.clone())
    }

    /// Reads one guest file to EOF, failing rather than truncating at `max`.
    pub(crate) async fn download(&self, path: &str, max: usize) -> Result<Vec<u8>, Failure> {
        let mut stream = self
            .files()
            .download_file(v1::DownloadFileRequest {
                path: Some(path.to_string()),
            })
            .await
            .map_err(Failure::rpc)?
            .into_inner();
        let mut bytes = Vec::new();
        while let Some(chunk) = stream.message().await.map_err(Failure::rpc)? {
            let data = chunk
                .data
                .ok_or_else(|| Failure::harness(format!("{path}: download chunk without data")))?;
            if bytes.len().saturating_add(data.len()) > max {
                return Err(Failure::harness(format!("{path}: exceeds {max} bytes")));
            }
            bytes.extend_from_slice(&data);
        }
        Ok(bytes)
    }

    pub(crate) async fn entry(&self, path: &str) -> Result<v1::FilesystemEntry, Failure> {
        self.files()
            .get_entry(v1::GetEntryRequest {
                path: Some(path.to_string()),
            })
            .await
            .map(tonic::Response::into_inner)
            .map_err(Failure::rpc)
    }

    /// Every entry name of a directory, following real cursors page by page.
    pub(crate) async fn names(&self, path: &str) -> Result<Vec<String>, Failure> {
        let mut names = Vec::new();
        let mut cursor = None;
        for _ in 0..MAX_LISTING_PAGES {
            let page = self
                .files()
                .list_directory(v1::ListDirectoryRequest {
                    path: Some(path.to_string()),
                    limit: Some(LISTING_PAGE),
                    cursor: cursor.take(),
                })
                .await
                .map_err(Failure::rpc)?
                .into_inner();
            for entry in page.entries {
                names.push(
                    entry
                        .name
                        .ok_or_else(|| Failure::harness(format!("{path}: entry without name")))?,
                );
            }
            match page.next_cursor {
                Some(next) => cursor = Some(next),
                None => return Ok(names),
            }
        }
        Err(Failure::harness(format!(
            "{path}: more than {MAX_LISTING_PAGES} listing pages"
        )))
    }

    pub(crate) async fn status(&self) -> StatusObservation {
        let started = std::time::Instant::now();
        let result = tokio::time::timeout(
            STATUS_BOUND,
            self.agent().get_status(v1::GetAgentStatusRequest {}),
        )
        .await;
        let latency_us = u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX);
        match result {
            Ok(Ok(response)) => StatusObservation {
                status: Some(Status::from(&response.into_inner())),
                error: None,
                latency_us,
            },
            Ok(Err(status)) => StatusObservation {
                status: None,
                error: Some(Failure::rpc(status)),
                latency_us,
            },
            Err(_) => StatusObservation {
                status: None,
                error: Some(Failure::harness(format!(
                    "GetStatus exceeded {}ms",
                    STATUS_BOUND.as_millis()
                ))),
                latency_us,
            },
        }
    }

    pub(crate) async fn cgroup(&self, group: CgroupGroup) -> CgroupObservation {
        let path = group.events_path();
        match self.download(path, 4096).await {
            Ok(bytes) => {
                let raw = Content::new(&bytes);
                match parse_events(&bytes) {
                    Ok((populated, frozen)) => CgroupObservation {
                        group,
                        path,
                        raw: Some(raw),
                        populated: Some(populated),
                        frozen: Some(frozen),
                        error: None,
                    },
                    Err(error) => CgroupObservation {
                        group,
                        path,
                        raw: Some(raw),
                        populated: None,
                        frozen: None,
                        error: Some(Failure::harness(error)),
                    },
                }
            }
            Err(error) => CgroupObservation {
                group,
                path,
                raw: None,
                populated: None,
                frozen: None,
                error: Some(error),
            },
        }
    }

    pub(crate) async fn counter(&self, path: &str) -> CounterObservation {
        match self.entry(path).await {
            Ok(entry) => match entry.size_bytes {
                Some(size) => CounterObservation {
                    path: path.to_string(),
                    size_bytes: Some(size),
                    error: None,
                },
                None => CounterObservation {
                    path: path.to_string(),
                    size_bytes: None,
                    error: Some(Failure::harness("entry without size_bytes")),
                },
            },
            Err(error) => CounterObservation {
                path: path.to_string(),
                size_bytes: None,
                error: Some(error),
            },
        }
    }

    pub(crate) async fn file(&self, read: &FileRead) -> FileObservation {
        match self.download(&read.path, read.max_bytes as usize).await {
            Ok(bytes) => FileObservation {
                path: read.path.clone(),
                bytes_read: Some(bytes.len()),
                sha256: Some(crate::capabilities::scenario_digest(&bytes)),
                content: Some(Content::new(&bytes)),
                error: None,
            },
            Err(error) => FileObservation {
                path: read.path.clone(),
                bytes_read: None,
                sha256: None,
                content: None,
                error: Some(error),
            },
        }
    }

    /// Discovers the Silo generation device by its exact virtio device ID,
    /// never by a hard-coded `virtioN`, then reads its driver record to EOF.
    pub(crate) async fn generation(&self) -> GenerationObservation {
        let mut observation = GenerationObservation::default();
        let names = match self.names(VIRTIO_DEVICES).await {
            Ok(names) => names,
            Err(error) => {
                observation.error = Some(error);
                return observation;
            }
        };
        for name in names {
            let path = format!("{VIRTIO_DEVICES}/{name}/device");
            match self.download(&path, 64).await {
                Ok(bytes) => {
                    if bytes == GENERATION_DEVICE_ID {
                        observation.matches.push(name.clone());
                    }
                    observation.devices.push(DeviceIdentity {
                        name,
                        device_raw: Some(Content::new(&bytes)),
                        error: None,
                    });
                }
                Err(error) => observation.devices.push(DeviceIdentity {
                    name,
                    device_raw: None,
                    error: Some(error),
                }),
            }
        }
        let [selected] = observation.matches.as_slice() else {
            observation.error = Some(Failure::harness(format!(
                "exactly one 0x5347 virtio device required, found {}",
                observation.matches.len()
            )));
            return observation;
        };
        let path = format!("{VIRTIO_DEVICES}/{selected}/generation_state");
        observation.selected = Some(selected.clone());
        observation.path = Some(path.clone());
        match self.download(&path, MAX_GENERATION_RECORD_BYTES).await {
            Ok(bytes) => {
                observation.absent = Some(false);
                observation.raw = Some(Content::new(&bytes));
                match generation_fields(&bytes) {
                    Ok(fields) => observation.fields = Some(fields),
                    Err(error) => observation.error = Some(Failure::harness(error)),
                }
            }
            Err(error) if error.not_found() => observation.absent = Some(true),
            Err(error) => observation.error = Some(error),
        }
        observation
    }

    /// Takes one complete observation, then optional repeated samples.
    pub(crate) async fn observe(&self, request: &Observe) -> eyre::Result<Observation> {
        let monotonic = monotonic_ns()?;
        let status = self.status().await;
        let mut cgroups = Vec::with_capacity(request.cgroups.len());
        for group in &request.cgroups {
            cgroups.push(self.cgroup(*group).await);
        }
        let mut counters = Vec::with_capacity(request.counters.len());
        for path in &request.counters {
            counters.push(self.counter(path).await);
        }
        let mut files = Vec::with_capacity(request.files.len());
        for read in &request.files {
            files.push(self.file(read).await);
        }
        let generation = match request.generation {
            Some(_) => Some(self.generation().await),
            None => None,
        };
        let mut samples = Vec::new();
        if let Some(sampling) = &request.samples {
            for _ in 0..sampling.count {
                tokio::time::sleep(Duration::from_millis(u64::from(sampling.interval_ms))).await;
                let sample = self.sample(request).await?;
                let grew = advanced(&counters, &sample.counters);
                samples.push(sample);
                if sampling.expect == SampleExpect::Advancing && grew {
                    break;
                }
            }
        }
        Ok(Observation {
            monotonic_ns: monotonic,
            status,
            cgroups,
            counters,
            files,
            generation,
            samples,
        })
    }

    async fn sample(&self, request: &Observe) -> eyre::Result<Sample> {
        let monotonic = monotonic_ns()?;
        let status = self.status().await;
        let mut cgroups = Vec::with_capacity(request.cgroups.len());
        for group in &request.cgroups {
            cgroups.push(self.cgroup(*group).await);
        }
        let mut counters = Vec::with_capacity(request.counters.len());
        for path in &request.counters {
            counters.push(self.counter(path).await);
        }
        Ok(Sample {
            monotonic_ns: monotonic,
            status,
            cgroups,
            counters,
        })
    }
}

fn advanced(initial: &[CounterObservation], sample: &[CounterObservation]) -> bool {
    !initial.is_empty()
        && initial.len() == sample.len()
        && initial.iter().zip(sample).all(|(before, after)| {
            matches!((before.size_bytes, after.size_bytes), (Some(before), Some(after)) if after > before)
        })
}

/// cgroup v2 `cgroup.events`: both `populated` and `frozen` are required.
pub(crate) fn parse_events(bytes: &[u8]) -> Result<(bool, bool), String> {
    let text = std::str::from_utf8(bytes).map_err(|error| error.to_string())?;
    let flag = |value: &str| match value {
        "0" => Ok(false),
        "1" => Ok(true),
        other => Err(format!("malformed cgroup event value {other:?}")),
    };
    let (mut populated, mut frozen) = (None, None);
    for line in text.lines() {
        match line.split_once(' ') {
            Some(("populated", value)) if populated.is_none() => populated = Some(flag(value)?),
            Some(("frozen", value)) if frozen.is_none() => frozen = Some(flag(value)?),
            Some(("populated" | "frozen", _)) => {
                return Err(format!("duplicate cgroup event line {line:?}"))
            }
            _ => {}
        }
    }
    match (populated, frozen) {
        (Some(populated), Some(frozen)) => Ok((populated, frozen)),
        _ => Err("cgroup.events lacks populated/frozen".to_string()),
    }
}

/// Exactly native_generation_controller.fields(): 1..=4096 ASCII bytes,
/// whitespace-separated `key=value` words, duplicate keys rejected.
pub(crate) fn generation_fields(raw: &[u8]) -> Result<BTreeMap<String, String>, String> {
    if raw.is_empty() || raw.len() > MAX_GENERATION_RECORD_BYTES {
        return Err("guest generation record byte bound".to_string());
    }
    if !raw.is_ascii() {
        return Err("guest generation record is not ASCII".to_string());
    }
    let text = std::str::from_utf8(raw).map_err(|error| error.to_string())?;
    let mut fields = BTreeMap::new();
    for word in text.split_ascii_whitespace() {
        let (key, value) = word
            .split_once('=')
            .ok_or_else(|| format!("generation word without '=': {word:?}"))?;
        if fields.insert(key.to_string(), value.to_string()).is_some() {
            return Err("duplicate generation evidence field".to_string());
        }
    }
    Ok(fields)
}

/// The driver record must carry exactly the patch's documented keys.
pub(crate) fn generation_schema_matches(fields: &BTreeMap<String, String>) -> bool {
    fields.len() == GENERATION_FIELDS.len()
        && GENERATION_FIELDS
            .iter()
            .all(|key| fields.contains_key(*key))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum CgroupGroup {
    Workloads,
    Activation,
}

impl CgroupGroup {
    pub(crate) fn events_path(self) -> &'static str {
        match self {
            Self::Workloads => "/sys/fs/cgroup/silo/workloads/cgroup.events",
            Self::Activation => "/sys/fs/cgroup/silo/activation/cgroup.events",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct FileRead {
    pub(crate) path: String,
    pub(crate) max_bytes: u32,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct GenerationRequest {
    #[serde(default)]
    pub(crate) expect_device: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum SampleExpect {
    Stationary,
    Advancing,
    Record,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Samples {
    pub(crate) count: u32,
    pub(crate) interval_ms: u32,
    pub(crate) expect: SampleExpect,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Observe {
    #[serde(default)]
    pub(crate) cgroups: Vec<CgroupGroup>,
    #[serde(default)]
    pub(crate) counters: Vec<String>,
    #[serde(default)]
    pub(crate) files: Vec<FileRead>,
    #[serde(default)]
    pub(crate) generation: Option<GenerationRequest>,
    #[serde(default)]
    pub(crate) samples: Option<Samples>,
    /// Absence probes may expect failed reads; otherwise every read must succeed.
    #[serde(default)]
    pub(crate) allow_read_errors: bool,
}

impl Observe {
    pub(crate) fn validate(&self) -> eyre::Result<()> {
        eyre::ensure!(
            self.cgroups.len() <= 2
                && self.counters.len() <= MAX_ITEMS
                && self.files.len() <= MAX_ITEMS,
            "observation item bound exceeded"
        );
        eyre::ensure!(
            self.files
                .iter()
                .all(|read| (1..=MAX_FILE_BYTES).contains(&read.max_bytes)),
            "file max_bytes must be 1..={MAX_FILE_BYTES}"
        );
        if let Some(samples) = &self.samples {
            eyre::ensure!(
                (1..=MAX_SAMPLES).contains(&samples.count)
                    && (1..=MAX_SAMPLE_INTERVAL_MS).contains(&samples.interval_ms),
                "samples must be count 1..={MAX_SAMPLES}, interval_ms 1..={MAX_SAMPLE_INTERVAL_MS}"
            );
            eyre::ensure!(
                samples.expect == SampleExpect::Record || !self.counters.is_empty(),
                "counter sample expectations require counters"
            );
        }
        Ok(())
    }

    /// Lifecycle operations always include the real workload freezer event.
    pub(crate) fn with_workloads(&self) -> Self {
        let mut observe = self.clone();
        if !observe.cgroups.contains(&CgroupGroup::Workloads) {
            observe.cgroups.insert(0, CgroupGroup::Workloads);
        }
        observe
    }
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct StatusObservation {
    pub(crate) status: Option<Status>,
    pub(crate) error: Option<Failure>,
    pub(crate) latency_us: u64,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct CgroupObservation {
    pub(crate) group: CgroupGroup,
    pub(crate) path: &'static str,
    pub(crate) raw: Option<Content>,
    pub(crate) populated: Option<bool>,
    pub(crate) frozen: Option<bool>,
    pub(crate) error: Option<Failure>,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct CounterObservation {
    pub(crate) path: String,
    pub(crate) size_bytes: Option<u64>,
    pub(crate) error: Option<Failure>,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct FileObservation {
    pub(crate) path: String,
    pub(crate) bytes_read: Option<usize>,
    pub(crate) sha256: Option<String>,
    pub(crate) content: Option<Content>,
    pub(crate) error: Option<Failure>,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct DeviceIdentity {
    pub(crate) name: String,
    pub(crate) device_raw: Option<Content>,
    pub(crate) error: Option<Failure>,
}

#[derive(Debug, Clone, Default, Serialize)]
pub(crate) struct GenerationObservation {
    pub(crate) devices: Vec<DeviceIdentity>,
    pub(crate) matches: Vec<String>,
    pub(crate) selected: Option<String>,
    pub(crate) path: Option<String>,
    pub(crate) absent: Option<bool>,
    pub(crate) raw: Option<Content>,
    pub(crate) fields: Option<BTreeMap<String, String>>,
    pub(crate) error: Option<Failure>,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct Sample {
    pub(crate) monotonic_ns: u64,
    pub(crate) status: StatusObservation,
    pub(crate) cgroups: Vec<CgroupObservation>,
    pub(crate) counters: Vec<CounterObservation>,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct Observation {
    pub(crate) monotonic_ns: u64,
    pub(crate) status: StatusObservation,
    pub(crate) cgroups: Vec<CgroupObservation>,
    pub(crate) counters: Vec<CounterObservation>,
    pub(crate) files: Vec<FileObservation>,
    pub(crate) generation: Option<GenerationObservation>,
    pub(crate) samples: Vec<Sample>,
}

impl Observation {
    pub(crate) fn cgroup(&self, group: CgroupGroup) -> Option<&CgroupObservation> {
        self.cgroups
            .iter()
            .find(|observation| observation.group == group)
    }
    pub(crate) fn status(&self) -> Option<&Status> {
        self.status.status.as_ref()
    }

    /// Checks shared by every observing operation.
    pub(crate) fn evaluate(&self, request: &Observe, checks: &mut Checks) {
        checks.check(
            "status_responsive",
            self.status.status.is_some(),
            format!("{:?} in {}us", self.status.error, self.status.latency_us),
        );
        if !request.allow_read_errors {
            let mut failed = Vec::new();
            failed.extend(
                self.cgroups
                    .iter()
                    .filter(|value| value.error.is_some())
                    .map(|value| value.path.to_string()),
            );
            failed.extend(
                self.counters
                    .iter()
                    .filter(|value| value.error.is_some())
                    .map(|value| value.path.clone()),
            );
            failed.extend(
                self.files
                    .iter()
                    .filter(|value| value.error.is_some())
                    .map(|value| value.path.clone()),
            );
            checks.check(
                "observation_reads",
                failed.is_empty(),
                format!("failed reads: {failed:?}"),
            );
        }
        if let (Some(request), Some(generation)) = (&request.generation, &self.generation) {
            checks.check(
                "generation_discovered",
                generation.error.is_none() && generation.selected.is_some(),
                format!("{:?} matches {:?}", generation.error, generation.matches),
            );
            if let Some(expected) = &request.expect_device {
                checks.check(
                    "generation_device_identity",
                    generation.selected.as_ref() == Some(expected),
                    format!("expected {expected}, selected {:?}", generation.selected),
                );
            }
            if let Some(fields) = &generation.fields {
                checks.check(
                    "generation_record_schema",
                    generation_schema_matches(fields),
                    format!("keys {:?}", fields.keys().collect::<Vec<_>>()),
                );
            }
        }
        if let Some(sampling) = &request.samples {
            let initial: Vec<_> = self.counters.iter().map(|value| value.size_bytes).collect();
            let series: Vec<Vec<Option<u64>>> = self
                .samples
                .iter()
                .map(|sample| {
                    sample
                        .counters
                        .iter()
                        .map(|value| value.size_bytes)
                        .collect()
                })
                .collect();
            match sampling.expect {
                SampleExpect::Record => {}
                SampleExpect::Stationary => checks.check(
                    "counters_stationary",
                    initial.iter().all(Option::is_some)
                        && series.len() == sampling.count as usize
                        && series.iter().all(|values| *values == initial),
                    format!("initial {initial:?} samples {series:?}"),
                ),
                SampleExpect::Advancing => checks.check(
                    "counters_advancing",
                    self.samples
                        .last()
                        .is_some_and(|sample| advanced(&self.counters, &sample.counters)),
                    format!("initial {initial:?} samples {series:?}"),
                ),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::attach::observe::{
        advanced, generation_fields, generation_schema_matches, parse_events, CgroupGroup,
        CounterObservation, FileRead, Observe, SampleExpect, Samples,
    };

    const RECORD: &[u8] = b"version=1 request_sequence=2 request_id=000102030405060708090a0b0c0d0e0f request_flags=1 completed_sequence=2 completed_id=000102030405060708090a0b0c0d0e0f completed_flags=1 rng_ready_before_call=1 reseed_count=3 reseed_sequence=2 reseed_id=000102030405060708090a0b0c0d0e0f reseed_return_order=4 clock_complete_order=5 ack_sequence=2 ack_id=000102030405060708090a0b0c0d0e0f ack_write_count=1 ack_write_order=6 ack_accessor_returned=1 ack_return_order=7 error=0 event_order=7\n";

    #[test]
    fn cgroup_events_require_both_kernel_flags() {
        assert_eq!(
            parse_events(b"populated 1\nfrozen 1\n").unwrap(),
            (true, true)
        );
        assert_eq!(
            parse_events(b"populated 0\nfrozen 0").unwrap(),
            (false, false)
        );
        assert!(parse_events(b"populated 1\n").is_err());
        assert!(parse_events(b"populated 1\nfrozen 2\n").is_err());
        assert!(parse_events(b"populated 1\nfrozen 1\nfrozen 0\n").is_err());
        assert!(parse_events(&[0xff]).is_err());
    }

    #[test]
    fn generation_fields_match_the_native_validator_shape() {
        let fields = generation_fields(RECORD).unwrap();
        assert_eq!(fields["request_sequence"], "2");
        assert_eq!(fields["ack_accessor_returned"], "1");
        assert!(generation_schema_matches(&fields));
        let mut missing = fields.clone();
        missing.remove("event_order");
        assert!(!generation_schema_matches(&missing));
        let mut extra = fields;
        extra.insert("generation_proof".into(), "1".into());
        assert!(!generation_schema_matches(&extra));
        assert!(generation_fields(b"").is_err());
        assert!(generation_fields(b"a=1 a=2").is_err());
        assert!(generation_fields(b"a=1 b").is_err());
        assert!(generation_fields(&[b'a'; 4097]).is_err());
        assert!(generation_fields("a=\u{e9}".as_bytes()).is_err());
    }

    fn counter(size: Option<u64>) -> CounterObservation {
        CounterObservation {
            path: "/c".into(),
            size_bytes: size,
            error: None,
        }
    }

    #[test]
    fn advancing_requires_every_counter_to_grow() {
        assert!(advanced(&[counter(Some(1))], &[counter(Some(2))]));
        assert!(!advanced(&[counter(Some(2))], &[counter(Some(2))]));
        assert!(!advanced(&[counter(None)], &[counter(Some(2))]));
        assert!(!advanced(&[], &[]));
        assert!(!advanced(
            &[counter(Some(1)), counter(Some(1))],
            &[counter(Some(2)), counter(Some(1))]
        ));
    }

    #[test]
    fn observe_requests_are_bounded() {
        let mut observe: Observe = serde_json::from_str("{}").unwrap();
        observe.validate().unwrap();
        assert_eq!(
            observe.with_workloads().cgroups,
            vec![CgroupGroup::Workloads]
        );
        observe.files.push(FileRead {
            path: "/x".into(),
            max_bytes: 0,
        });
        assert!(observe.validate().is_err());
        observe.files.clear();
        observe.samples = Some(Samples {
            count: 5,
            interval_ms: 80,
            expect: SampleExpect::Stationary,
        });
        assert!(observe.validate().is_err(), "expectation without counters");
        observe.counters.push("/c".into());
        observe.validate().unwrap();
        observe.samples = Some(Samples {
            count: 65,
            interval_ms: 80,
            expect: SampleExpect::Record,
        });
        assert!(observe.validate().is_err());
        assert!(serde_json::from_str::<Observe>(r#"{"unknown":1}"#).is_err());
    }
}
