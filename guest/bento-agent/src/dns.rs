use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV6};
use std::os::unix::fs::symlink;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use bento_core::agent::{
    AgentDnsConfig, AgentDnsRecord, AgentDnsRecordValue, AgentDnsZone,
    DNS_RECORD_HOST_BENTO_INTERNAL,
};
use hickory_proto::op::{Message, MessageType, OpCode, ResponseCode};
use hickory_proto::rr::{Name, RData, Record, RecordType};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::RwLock;
use tokio_util::sync::CancellationToken;

use crate::host::network::{discover_gateways, GatewayDiscovery};

const DEFAULT_LISTEN_IP: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);
const DEFAULT_LISTEN_PORT: u16 = 53;
const DNS_TIMEOUT: Duration = Duration::from_secs(2);
const MAX_DNS_PACKET_SIZE: usize = 512;
const RESOLV_CONF_CONTENT: &str = "options timeout:1 attempts:2\n";

#[derive(Clone)]
pub struct DnsServer {
    listen_addr: SocketAddr,
    state: Arc<RwLock<DnsState>>,
}

#[derive(Default)]
struct DnsState {
    upstream_servers: Vec<SocketAddr>,
    authoritative_zones: HashSet<String>,
    records: HashMap<String, Vec<AgentDnsRecordValue>>,
}

#[derive(Clone, Copy)]
enum Transport {
    Udp,
    Tcp,
}

impl DnsServer {
    pub async fn new(config: &AgentDnsConfig) -> eyre::Result<Self> {
        let discovery = discover_gateways().await?;
        let upstreams = select_upstreams(&discovery, &config.upstream_servers)?;
        let zones = with_builtin_bento_zone(config.zones.clone(), discovery.ipv4, discovery.ipv6);

        let server = Self {
            listen_addr: SocketAddr::new(config.listen_address, DEFAULT_LISTEN_PORT),
            state: Arc::new(RwLock::new(DnsState::default())),
        };

        server.set_upstreams(upstreams).await;
        server.set_zones(zones).await;

        Ok(server)
    }

    pub async fn set_upstreams(&self, upstream_servers: Vec<SocketAddr>) {
        self.state.write().await.upstream_servers = upstream_servers;
    }

    pub async fn set_zones(&self, zones: Vec<AgentDnsZone>) {
        let mut state = self.state.write().await;
        state.authoritative_zones.clear();
        state.records.clear();

        for zone in zones {
            let domain = normalize_name(&zone.domain);
            if zone.authoritative {
                state.authoritative_zones.insert(domain.clone());
            }

            for record in zone.records {
                let fqdn = normalize_record_name(&record.name, &domain);
                state.records.entry(fqdn).or_default().push(record.value);
            }
        }
    }

    pub async fn run(&self, shutdown: CancellationToken) -> eyre::Result<()> {
        let udp = Arc::new(UdpSocket::bind(self.listen_addr).await?);
        let tcp = TcpListener::bind(self.listen_addr).await?;
        tracing::info!(listen_addr = %self.listen_addr, "dns server listening");

        let mut udp_buf = [0u8; MAX_DNS_PACKET_SIZE];
        loop {
            tokio::select! {
                () = shutdown.cancelled() => {
                    tracing::info!(listen_addr = %self.listen_addr, "dns server shutting down");
                    return Ok(());
                }
                result = udp.recv_from(&mut udp_buf) => {
                    let (len, peer) = result?;
                    let data = udp_buf[..len].to_vec();
                    let server = self.clone();
                    let udp = Arc::clone(&udp);
                    tokio::spawn(async move {
                        match server.handle_query(&data, Transport::Udp).await {
                            Ok(response) => {
                                if let Err(err) = udp.send_to(&response, peer).await {
                                    tracing::debug!(error = %err, %peer, "dns udp response failed");
                                }
                            }
                            Err(err) => {
                                tracing::debug!(error = %err, %peer, "dns udp query failed");
                            }
                        }
                    });
                }
                result = tcp.accept() => {
                    let (stream, peer) = result?;
                    let server = self.clone();
                    tokio::spawn(async move {
                        if let Err(err) = server.handle_tcp_connection(stream).await {
                            tracing::debug!(error = %err, %peer, "dns tcp connection failed");
                        }
                    });
                }
            }
        }
    }

    pub fn write_resolv_conf(host: Option<IpAddr>) -> eyre::Result<()> {
        write_resolv_conf_at(
            Path::new("/etc/bento/resolv.conf"),
            Path::new("/etc/resolv.conf"),
            host.unwrap_or(DEFAULT_LISTEN_IP),
        )
    }

    async fn handle_tcp_connection(&self, mut stream: TcpStream) -> eyre::Result<()> {
        let mut length = [0u8; 2];
        stream.read_exact(&mut length).await?;
        let frame_len = u16::from_be_bytes(length) as usize;
        let mut data = vec![0u8; frame_len];
        stream.read_exact(&mut data).await?;

        let response = self.handle_query(&data, Transport::Tcp).await?;
        stream
            .write_all(&(response.len() as u16).to_be_bytes())
            .await?;
        stream.write_all(&response).await?;
        Ok(())
    }

    async fn handle_query(&self, data: &[u8], transport: Transport) -> eyre::Result<Vec<u8>> {
        let request = Message::from_vec(data)?;
        let Some(query) = request.queries.first() else {
            return Ok(build_response(&request, ResponseCode::FormErr, Vec::new()));
        };

        let qname = normalize_name(&query.name().to_ascii());
        let qtype = query.query_type();
        let state = self.state.read().await;

        if let Some(response) = answer_local_query(&request, &state, &qname, qtype)? {
            return Ok(response);
        }

        // After local lookup, authoritative zones must return NXDOMAIN instead of forwarding.
        if state
            .authoritative_zones
            .iter()
            .any(|zone| qname == *zone || qname.ends_with(&format!(".{zone}")))
        {
            return Ok(build_response(&request, ResponseCode::NXDomain, Vec::new()));
        }

        let upstreams = state.upstream_servers.clone();
        drop(state);

        forward_query(data, &upstreams, transport).await
    }
}

fn answer_local_query(
    request: &Message,
    state: &DnsState,
    qname: &str,
    qtype: RecordType,
) -> eyre::Result<Option<Vec<u8>>> {
    if let Some(records) = state.records.get(qname) {
        let answers =
            expand_local_records(&state.records, qname, records, qtype, &mut HashSet::new())?;
        if answers.is_empty() {
            return Ok(Some(build_response(
                request,
                ResponseCode::NoError,
                Vec::new(),
            )));
        }
        return Ok(Some(build_response(
            request,
            ResponseCode::NoError,
            answers,
        )));
    }

    Ok(None)
}

// DNS clients usually ask for A/AAAA records, not CNAME directly. When a local
// record is a CNAME, include it and keep following the target through Bento's
// local records so zone-backed aliases still resolve fully.
fn expand_local_records(
    records_by_name: &HashMap<String, Vec<AgentDnsRecordValue>>,
    name: &str,
    records: &[AgentDnsRecordValue],
    qtype: RecordType,
    visited: &mut HashSet<String>,
) -> eyre::Result<Vec<Record>> {
    let normalized_name = normalize_name(name);
    if !visited.insert(normalized_name.clone()) {
        return Ok(Vec::new());
    }

    let mut answers = Vec::new();
    for value in records {
        if should_include_record(value, qtype) {
            answers.push(record_from_value(&normalized_name, value)?);
        }

        if let Some(target) = cname_target_for_query(value, qtype) {
            let target = normalize_name(target);
            if let Some(target_records) = records_by_name.get(&target) {
                answers.extend(expand_local_records(
                    records_by_name,
                    &target,
                    target_records,
                    qtype,
                    visited,
                )?);
            }
        }
    }

    visited.remove(&normalized_name);
    Ok(answers)
}

fn should_include_record(value: &AgentDnsRecordValue, qtype: RecordType) -> bool {
    record_type(value) == qtype
        || matches!(value, AgentDnsRecordValue::Cname(_)) && qtype != RecordType::CNAME
}

fn cname_target_for_query(value: &AgentDnsRecordValue, qtype: RecordType) -> Option<&str> {
    if qtype == RecordType::CNAME {
        return None;
    }

    match value {
        AgentDnsRecordValue::Cname(target) => Some(target),
        _ => None,
    }
}

fn build_response(request: &Message, code: ResponseCode, answers: Vec<Record>) -> Vec<u8> {
    let mut response = Message::new(request.metadata.id, MessageType::Response, OpCode::Query);
    response.metadata.authoritative = code == ResponseCode::NXDomain || !answers.is_empty();
    response.metadata.response_code = code;
    response.add_queries(request.queries.clone());
    response.add_answers(answers);
    response.to_vec().unwrap_or_default()
}

fn record_from_value(name: &str, value: &AgentDnsRecordValue) -> eyre::Result<Record> {
    let record_name = Name::from_ascii(format!("{}.", normalize_name(name)))?;
    let rdata = match value {
        AgentDnsRecordValue::A(ip) => RData::A((*ip).into()),
        AgentDnsRecordValue::Aaaa(ip) => RData::AAAA((*ip).into()),
        AgentDnsRecordValue::Cname(target) => {
            let target = Name::from_ascii(format!("{}.", normalize_name(target)))?;
            RData::CNAME(hickory_proto::rr::rdata::CNAME(target))
        }
    };
    Ok(Record::from_rdata(record_name, 5, rdata))
}

fn record_type(value: &AgentDnsRecordValue) -> RecordType {
    match value {
        AgentDnsRecordValue::A(_) => RecordType::A,
        AgentDnsRecordValue::Aaaa(_) => RecordType::AAAA,
        AgentDnsRecordValue::Cname(_) => RecordType::CNAME,
    }
}

async fn forward_query(
    data: &[u8],
    upstreams: &[SocketAddr],
    transport: Transport,
) -> eyre::Result<Vec<u8>> {
    for upstream in upstreams {
        let result = match transport {
            Transport::Udp => forward_udp(data, *upstream).await,
            Transport::Tcp => forward_tcp(data, *upstream).await,
        };

        match result {
            Ok(response) => return Ok(response),
            Err(err) => {
                tracing::debug!(error = %err, upstream = %upstream, "dns upstream query failed");
            }
        }
    }

    eyre::bail!("all configured dns upstream queries failed")
}

async fn forward_udp(data: &[u8], upstream: SocketAddr) -> eyre::Result<Vec<u8>> {
    let bind_addr = match upstream {
        SocketAddr::V4(_) => SocketAddr::from(([0, 0, 0, 0], 0)),
        SocketAddr::V6(_) => SocketAddr::from(([0; 16], 0)),
    };

    let socket = UdpSocket::bind(bind_addr).await?;
    socket.send_to(data, upstream).await?;
    let mut buf = [0u8; MAX_DNS_PACKET_SIZE];
    let (len, from) = tokio::time::timeout(DNS_TIMEOUT, socket.recv_from(&mut buf)).await??;
    if from != upstream {
        eyre::bail!("unexpected dns udp response source: expected {upstream}, got {from}");
    }
    Ok(buf[..len].to_vec())
}

async fn forward_tcp(data: &[u8], upstream: SocketAddr) -> eyre::Result<Vec<u8>> {
    let mut stream = tokio::time::timeout(DNS_TIMEOUT, TcpStream::connect(upstream)).await??;
    stream.write_all(&(data.len() as u16).to_be_bytes()).await?;
    stream.write_all(data).await?;
    let mut length = [0u8; 2];
    tokio::time::timeout(DNS_TIMEOUT, stream.read_exact(&mut length)).await??;
    let frame_len = u16::from_be_bytes(length) as usize;
    let mut response = vec![0u8; frame_len];
    tokio::time::timeout(DNS_TIMEOUT, stream.read_exact(&mut response)).await??;
    Ok(response)
}

fn normalize_name(name: &str) -> String {
    name.trim().trim_end_matches('.').to_ascii_lowercase()
}

fn normalize_record_name(name: &str, zone: &str) -> String {
    let name = normalize_name(name);
    let zone = normalize_name(zone);
    if name == zone || name.ends_with(&format!(".{zone}")) {
        name
    } else {
        format!("{name}.{zone}")
    }
}

fn with_builtin_bento_zone(
    mut zones: Vec<AgentDnsZone>,
    ipv4: Option<Ipv4Addr>,
    ipv6: Option<Ipv6Addr>,
) -> Vec<AgentDnsZone> {
    let zone = ensure_bento_zone(&mut zones);
    zone.authoritative = true;
    zone.records.retain(|record| {
        let name = normalize_name(&record.name);
        let is_host_record = name == "host" || name == DNS_RECORD_HOST_BENTO_INTERNAL;
        if !is_host_record {
            return true;
        }

        !matches!(
            record.value,
            AgentDnsRecordValue::A(_) | AgentDnsRecordValue::Aaaa(_)
        )
    });

    if let Some(ip) = ipv4 {
        zone.records.push(AgentDnsRecord {
            name: String::from("host"),
            value: AgentDnsRecordValue::A(ip),
        });
    }

    if let Some(ip) = ipv6 {
        zone.records.push(AgentDnsRecord {
            name: String::from("host"),
            value: AgentDnsRecordValue::Aaaa(ip),
        });
    }

    zones
}

fn ensure_bento_zone(zones: &mut Vec<AgentDnsZone>) -> &mut AgentDnsZone {
    if let Some(index) = zones
        .iter()
        .position(|zone| normalize_name(&zone.domain) == "bento.internal")
    {
        return &mut zones[index];
    }

    zones.push(AgentDnsZone {
        domain: String::from("bento.internal"),
        authoritative: true,
        records: Vec::new(),
    });

    zones.last_mut().expect("bento.internal zone inserted")
}

fn write_resolv_conf_at(managed: &Path, actual: &Path, host: IpAddr) -> eyre::Result<()> {
    if let Some(parent) = managed.parent() {
        std::fs::create_dir_all(parent)?;
    }

    std::fs::write(managed, format!("nameserver {host}\n{RESOLV_CONF_CONTENT}"))?;

    if actual.exists() || actual.symlink_metadata().is_ok() {
        std::fs::remove_file(actual)?;
    }

    symlink(managed, actual)?;
    Ok(())
}

fn select_upstreams(
    discovery: &GatewayDiscovery,
    configured_upstreams: &[SocketAddr],
) -> eyre::Result<Vec<SocketAddr>> {
    if !configured_upstreams.is_empty() {
        return Ok(configured_upstreams.to_vec());
    }

    let mut upstreams = Vec::new();
    if let Some(ip) = discovery.ipv4 {
        upstreams.push(SocketAddr::new(IpAddr::V4(ip), DEFAULT_LISTEN_PORT));
    }
    if let Some(ip) = discovery.ipv6 {
        upstreams.push(SocketAddr::V6(SocketAddrV6::new(
            ip,
            DEFAULT_LISTEN_PORT,
            0,
            0,
        )));
    }

    if upstreams.is_empty() {
        eyre::bail!("no usable dns upstream resolvers available")
    }

    Ok(upstreams)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn write_resolv_conf_replaces_existing_file_with_symlink() {
        let temp = std::env::temp_dir().join(format!("bento-dns-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&temp);
        std::fs::create_dir_all(&temp).expect("create temp dir");
        let managed = temp.join("etc/bento/resolv.conf");
        let actual = temp.join("etc/resolv.conf");
        std::fs::create_dir_all(actual.parent().expect("parent")).expect("create parent");
        std::fs::write(&actual, "nameserver 8.8.8.8\n").expect("seed file");

        write_resolv_conf_at(&managed, &actual, IpAddr::V4(Ipv4Addr::LOCALHOST))
            .expect("write resolv conf");

        let link = std::fs::read_link(&actual).expect("resolv.conf symlink");
        assert_eq!(link, managed);
        let content = std::fs::read_to_string(&managed).expect("managed resolv.conf content");
        assert!(content.contains("nameserver 127.0.0.1"));
    }

    #[tokio::test]
    async fn local_zone_cname_resolution_returns_cname_and_target_record() {
        let server = DnsServer {
            listen_addr: SocketAddr::new(DEFAULT_LISTEN_IP, DEFAULT_LISTEN_PORT),
            state: Arc::new(RwLock::new(DnsState::default())),
        };
        server
            .set_zones(vec![
                AgentDnsZone {
                    domain: String::from("docker.internal"),
                    authoritative: false,
                    records: vec![AgentDnsRecord {
                        name: String::from("host"),
                        value: AgentDnsRecordValue::Cname(String::from("host.bento.internal")),
                    }],
                },
                AgentDnsZone {
                    domain: String::from("bento.internal"),
                    authoritative: true,
                    records: vec![AgentDnsRecord {
                        name: String::from("host.bento.internal"),
                        value: AgentDnsRecordValue::A(Ipv4Addr::new(192, 168, 64, 1)),
                    }],
                },
            ])
            .await;

        let request =
            Message::from_vec(&build_query("host.docker.internal", RecordType::A)).expect("query");
        let state = server.state.read().await;
        let response = answer_local_query(&request, &state, "host.docker.internal", RecordType::A)
            .expect("resolve local")
            .expect("local response");
        let response = Message::from_vec(&response).expect("response parse");

        assert_eq!(response.answers.len(), 2);
    }

    #[tokio::test]
    async fn authoritative_zone_miss_returns_nothing_from_local_lookup() {
        let server = DnsServer {
            listen_addr: SocketAddr::new(DEFAULT_LISTEN_IP, DEFAULT_LISTEN_PORT),
            state: Arc::new(RwLock::new(DnsState::default())),
        };
        server
            .set_zones(vec![AgentDnsZone {
                domain: String::from("bento.internal"),
                authoritative: true,
                records: Vec::new(),
            }])
            .await;

        let request = Message::from_vec(&build_query("missing.bento.internal", RecordType::A))
            .expect("query");
        let state = server.state.read().await;
        let response =
            answer_local_query(&request, &state, "missing.bento.internal", RecordType::A)
                .expect("resolve local");

        assert!(response.is_none());
        assert!(state.authoritative_zones.contains("bento.internal"));
    }

    #[test]
    fn host_record_injection_overrides_bento_internal() {
        let zones = with_builtin_bento_zone(
            vec![AgentDnsZone {
                domain: String::from("bento.internal"),
                authoritative: false,
                records: vec![AgentDnsRecord {
                    name: String::from("host.bento.internal"),
                    value: AgentDnsRecordValue::A(Ipv4Addr::new(10, 0, 0, 1)),
                }],
            }],
            Some(Ipv4Addr::new(192, 168, 64, 1)),
            None,
        );

        assert_eq!(zones.len(), 1);
        assert!(zones[0].authoritative);
        assert_eq!(zones[0].records.len(), 1);
        assert_eq!(zones[0].records[0].name, "host");
        assert_eq!(
            zones[0].records[0].value,
            AgentDnsRecordValue::A(Ipv4Addr::new(192, 168, 64, 1))
        );
    }

    #[test]
    fn builtin_bento_zone_is_created_when_missing() {
        let zones = with_builtin_bento_zone(
            Vec::new(),
            Some(Ipv4Addr::new(192, 168, 64, 1)),
            Some("fd00::1".parse().expect("valid ipv6")),
        );

        assert_eq!(zones.len(), 1);
        assert_eq!(zones[0].domain, "bento.internal");
        assert!(zones[0].authoritative);
        assert_eq!(zones[0].records.len(), 2);
    }

    fn build_query(name: &str, record_type: RecordType) -> Vec<u8> {
        let mut message = Message::new(7, MessageType::Query, OpCode::Query);
        message.add_query(hickory_proto::op::Query::query(
            Name::from_ascii(format!("{}.", normalize_name(name))).expect("valid name"),
            record_type,
        ));
        message.to_vec().expect("encode query")
    }
}
