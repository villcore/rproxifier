//! resolver implementations implementing different strategies for answering
//! incoming queries

use async_trait::async_trait;
use std::io::Result;
use std::io::{Error, ErrorKind};
use std::vec::Vec;

use crate::dns::authority::Authority;
use crate::dns::cache::SynchronizedCache;
use crate::dns::client::DnsClient;
use crate::dns::protocol::{DnsPacket, QueryType, ResultCode, DnsRecord, TransientTtl};
use std::any::Any;
use async_std_resolver::{AsyncStdResolver, ResolveError};
use async_std_resolver::lookup_ip::LookupIp;
use std::io;
use trust_dns_proto::rr::{RData, Record};
use std::collections::HashMap;
use std::net::{Ipv4Addr, IpAddr, SocketAddr};
use std::borrow::BorrowMut;
use dashmap::DashMap;
use std::collections::hash_map::RandomState;
use dashmap::mapref::one::Ref;
use std::sync::atomic::{Ordering, AtomicU32};
use tokio::sync::RwLock;
use std::sync::{Arc, Mutex};

#[async_trait]
pub trait DnsResolver {
    async fn resolve(&self, qname: &str, qtype: QueryType, recursive: bool) -> Result<DnsPacket>;

    fn as_any(&self) -> &dyn Any;
}

/// A Forwarding DNS Resolver
///
/// This resolver uses an external DNS server to service a query
pub struct ForwardingDnsResolver {
    server: (String, u16),
    cache: SynchronizedCache,
    dns_client: Box<dyn DnsClient + Sync + Send>,
    allow_recursive: bool,
}

impl ForwardingDnsResolver {
    pub async fn new(
        server: (String, u16),
        allow_recursive: bool,
        dns_client: Box<dyn DnsClient + Send + Sync>,
    ) -> ForwardingDnsResolver {
        ForwardingDnsResolver {
            server,
            cache: SynchronizedCache::new(),
            dns_client,
            allow_recursive,
        }
    }
}

#[async_trait]
impl DnsResolver for ForwardingDnsResolver {
    async fn resolve(&self, qname: &str, qtype: QueryType, recursive: bool) -> Result<DnsPacket> {
        if let QueryType::UNKNOWN(_) = qtype {
            let mut packet = DnsPacket::new();
            packet.header.rescode = ResultCode::NOTIMP;
            return Ok(packet);
        }

        if !recursive || !self.allow_recursive {
            let mut packet = DnsPacket::new();
            packet.header.rescode = ResultCode::REFUSED;
            return Ok(packet);
        }

        if let Some(qr) = self.cache.lookup(qname, qtype) {
            return Ok(qr);
        }

        if qtype == QueryType::A || qtype == QueryType::AAAA {
            if let Some(qr) = self.cache.lookup(qname, QueryType::CNAME) {
                return Ok(qr);
            }
        }
        let &(ref host, port) = &self.server;
        let result = self
            .dns_client
            .send_query(qname, qtype, (host.as_str(), port), true)
            .await;

        if let Ok(ref qr) = result {
            let _ = self.cache.store(&qr.answers);
        }

        result
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

/// A Recursive DNS resolver
///
/// This resolver can answer any request using the root servers of the internet
pub struct RecursiveDnsResolver {
    cache: SynchronizedCache,
    dns_client: Box<dyn DnsClient + Send + Sync>,
    allow_recursive: bool,
    #[allow(dead_code)]
    authority: Authority,
}

impl RecursiveDnsResolver {
    pub async fn new(
        allow_recursive: bool,
        dns_client: Box<dyn DnsClient + Sync + Send>,
    ) -> RecursiveDnsResolver {
        let authority = Authority::new();
        authority.load().await.expect("load authority");
        RecursiveDnsResolver {
            cache: SynchronizedCache::new(),
            dns_client,
            authority,
            allow_recursive,
        }
    }

    async fn perform(&self, qname: &str, qtype: QueryType) -> Result<DnsPacket> {
        // Find the closest name server by splitting the label and progessively
        // moving towards the root servers. I.e. check "google.com", then "com",
        // and finally "".
        let mut tentative_ns = None;

        let labels = qname.split('.').collect::<Vec<&str>>();
        for lbl_idx in 0..=labels.len() {
            let domain = labels[lbl_idx..].join(".");

            match self
                .cache
                .lookup(&domain, QueryType::NS)
                .and_then(|qr| qr.get_unresolved_ns(&domain))
                .and_then(|ns| self.cache.lookup(&ns, QueryType::A))
                .and_then(|qr| qr.get_random_a())
            {
                Some(addr) => {
                    tentative_ns = Some(addr);
                    break;
                }
                None => continue,
            }
        }

        let mut ns = match tentative_ns {
            Some(x) => x,
            None => return Err(Error::new(ErrorKind::NotFound, "No DNS server found")),
        };

        // Start querying name servers
        loop {
            let ns_copy = ns.clone();

            let server = (ns_copy.as_str(), 53);
            let response = self
                .dns_client
                .send_query(qname, qtype, server, false)
                .await?;

            // If we've got an actual answer, we're done!
            if !response.answers.is_empty() && response.header.rescode == ResultCode::NOERROR {
                let _ = self.cache.store(&response.answers);
                let _ = self.cache.store(&response.authorities);
                let _ = self.cache.store(&response.resources);
                return Ok(response.clone());
            }

            if response.header.rescode == ResultCode::NXDOMAIN {
                if let Some(ttl) = response.get_ttl_from_soa() {
                    let _ = self.cache.store_nxdomain(qname, qtype, ttl);
                }
                return Ok(response.clone());
            }

            // Otherwise, try to find a new nameserver based on NS and a
            // corresponding A record in the additional section
            if let Some(new_ns) = response.get_resolved_ns(qname) {
                // If there is such a record, we can retry the loop with that NS
                ns = new_ns.clone();
                let _ = self.cache.store(&response.answers);
                let _ = self.cache.store(&response.authorities);
                let _ = self.cache.store(&response.resources);

                continue;
            }

            // If not, we'll have to resolve the ip of a NS record
            let new_ns_name = match response.get_unresolved_ns(qname) {
                Some(x) => x,
                None => return Ok(response.clone()),
            };

            // Recursively resolve the NS
            let recursive_response = self.resolve(&new_ns_name, QueryType::A, true).await?;

            // Pick a random IP and restart
            if let Some(new_ns) = recursive_response.get_random_a() {
                ns = new_ns.clone();
            } else {
                return Ok(response.clone());
            }
        }
    }
}

#[async_trait]
impl DnsResolver for RecursiveDnsResolver {
    async fn resolve(&self, qname: &str, qtype: QueryType, recursive: bool) -> Result<DnsPacket> {
        if let QueryType::UNKNOWN(_) = qtype {
            let mut packet = DnsPacket::new();
            packet.header.rescode = ResultCode::NOTIMP;
            return Ok(packet);
        }

        if !recursive || !self.allow_recursive {
            let mut packet = DnsPacket::new();
            packet.header.rescode = ResultCode::REFUSED;
            return Ok(packet);
        }

        if let Some(qr) = self.cache.lookup(qname, qtype) {
            return Ok(qr);
        }

        if qtype == QueryType::A || qtype == QueryType::AAAA {
            if let Some(qr) = self.cache.lookup(qname, QueryType::CNAME) {
                return Ok(qr);
            }
        }

        self.perform(qname, qtype).await
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

pub struct DirectDnsResolver {
    dns_client: AsyncStdResolver
}

impl DirectDnsResolver {
    pub fn new(async_std_resolver: AsyncStdResolver) -> Self {
        DirectDnsResolver {
            dns_client: async_std_resolver,
        }
    }
}

#[async_trait]
impl DnsResolver for DirectDnsResolver {

    async fn resolve(&self, qname: &str, qtype: QueryType, recursive: bool) -> Result<DnsPacket> {
        tracing::info!("Resolve host [{}] ", qname);

        // TODO: local host file
        return match self.dns_client.lookup_ip(qname).await {
            Ok(lookup_result) => {
                let mut dns_records: Vec<DnsRecord> = lookup_result.as_lookup().record_iter()
                    .map(|r| {
                        let rd = r.rdata();
                        match rd {
                            RData::A(ip) => {
                                DnsRecord::A {
                                    domain: qname.to_string(),
                                    addr: *ip,
                                    ttl: TransientTtl(r.ttl()),
                                }
                            }

                            RData::AAAA(ip) => {
                                DnsRecord::AAAA {
                                    domain: qname.to_string(),
                                    addr: *ip,
                                    ttl: TransientTtl(r.ttl()),
                                }
                            }
                            _ => {
                                DnsRecord::UNKNOWN {
                                    domain: qname.to_string(),
                                    qtype: 0,
                                    data_len: 0,
                                    ttl: TransientTtl(r.ttl()),
                                }
                            }
                        }
                    })
                    .filter(|dns_record| {
                        match dns_record {
                            DnsRecord::UNKNOWN { .. } => {
                                false
                            }
                            _ => {
                                true
                            }
                        }
                    })
                    .collect();
                let mut dns_packet = DnsPacket::new();
                dns_packet.answers.append(&mut dns_records);
                Ok(dns_packet)
            }

            Err(e) => {
                tracing::error!("!!! Resolve host [{}] error, msg: {} ", qname, e.to_string());
                Err(io::Error::new(io::ErrorKind::Other, e))
            }
        }
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

pub enum UserConfigDnsType {

    /// 正则表达式，模糊匹配
    Regex(String, RelayPolicy),

    /// 普通文本，精确匹配
    PlanText(String, RelayPolicy),

    /// 包含匹配
    ContainsText(String, RelayPolicy),

    /// 默认规则，以上规则无法命中时默认规则
    Default(RelayPolicy)
}

/// 转发策略
pub enum RelayPolicy {

    /// 直接连接
    Direct,

    /// 代理连接
    Proxy(Ipv4Addr, u16),

    ///

    /// 拒绝访问
    Reject,

    /// 探测
    Probe(Box<RelayPolicy>)
}

pub struct UserConfigDnsResolver {
    domain_map: HashMap<String, Ipv4Addr>,
    ip_addr_map: HashMap<Ipv4Addr, String>,
    wrap_resolver:  Box<dyn DnsResolver + Sync + Send>
}

impl UserConfigDnsResolver {

    pub fn new(mut wrap_resolver: Box<dyn DnsResolver + Sync + Send>) -> Self {
        Self {
            domain_map: HashMap::new(),
            ip_addr_map: HashMap::new(),
            wrap_resolver
        }
    }

    pub fn get_host(&self, ip: &Ipv4Addr) -> Option<&String> {
        self.ip_addr_map.get(ip)
    }

    pub fn add_domain_addr(&mut self, host: String, ip: Ipv4Addr) {
        self.domain_map.insert(host.clone(), ip);
        self.ip_addr_map.insert(ip, host.clone());
    }
}

#[async_trait]
impl DnsResolver for UserConfigDnsResolver {
    async fn resolve(&self, qname: &str, qtype: QueryType, recursive: bool) -> Result<DnsPacket> {
        log::info!(">>>> {:?}", self.domain_map);
        match self.domain_map.get(qname) {
            Some(ip_addr) => {
                let dns_answer = DnsRecord::A {
                    domain: qname.to_string(),
                    addr: *ip_addr,
                    ttl: TransientTtl(60),
                };

                let mut dns_packet = DnsPacket::new();
                dns_packet.answers.push(dns_answer);
                Ok(dns_packet)
            }
            None => {
                let resolver = self.wrap_resolver.as_ref();
                resolver.resolve(qname, qtype, recursive).await
            }
        }
    }
    fn as_any(&self) -> &dyn Any {
        self
    }
}

/// fake_ip_manager
pub struct FakeIpManager {
    inner: Arc<Mutex<InnerFakeIpManager>>
}

impl FakeIpManager {

    pub fn new(start_ip: (u8, u8, u8, u8)) -> Self {
        Self {
            inner: Arc::new(Mutex::new(InnerFakeIpManager::new(start_ip)))
        }
    }

    pub fn get_or_create_fake_ip(&self, host: &str) -> Option<(u8, u8, u8, u8)> {
        let inner_write = self.inner.lock().unwrap();
        if let Some(fake_ip) = inner_write.get_fake_ip(host) {
            return Some(fake_ip)
        }

        // let mut inner_write = self.inner.write().await;
        match inner_write.get_fake_ip(host) {
            Some(fake_ip) => {
                return Some(fake_ip)
            }
            None => {
                Some(inner_write.create_fake_ip(host))
            }
        }
    }

    pub fn get_host(&self, fake_ip: &(u8, u8, u8, u8)) -> Option<String> {
        let inner = self.inner.lock().unwrap();
        match inner.get_host(fake_ip) {
            None => None,
            Some(host) => {
                Some(host.to_owned())
            }
        }
    }
}

pub struct InnerFakeIpManager {
    host_to_fake_ip: DashMap<String, (u8, u8, u8, u8)>,
    fake_ip_to_host: DashMap<(u8, u8, u8, u8), String>,
    next_fake_ip_seq: AtomicU32,
}

impl InnerFakeIpManager {

    pub fn new(start_ip: (u8, u8, u8, u8)) -> Self {
        let mut b = [0u8; 4];
        b[0] = start_ip.0;
        b[1] = start_ip.1;
        b[2] = start_ip.2;
        b[3] = start_ip.3;
        let next_fake_ip_seq: u32 = u32::from_be_bytes(b);
        Self {
            host_to_fake_ip: DashMap::with_capacity(1024),
            fake_ip_to_host: DashMap::with_capacity(1024),
            next_fake_ip_seq: AtomicU32::new(next_fake_ip_seq)
        }
    }

    pub fn get_host(&self, fake_ip: &(u8, u8, u8, u8)) -> Option<String> {
        match self.fake_ip_to_host.get(fake_ip) {
            None => None,
            Some(result) => {
                Some(result.value().to_owned())
            }
        }
    }

    fn get_fake_ip(&self, host: &str) -> Option<(u8, u8, u8, u8)> {
        match self.host_to_fake_ip.get(host) {
            None => None,
            Some(result) => {
                Some(result.value().to_owned())
            }
        }
    }

    fn create_fake_ip(&self, host: &str) -> (u8, u8, u8, u8) {
        let next_fake_ip = self.next_fake_ip();
        self.host_to_fake_ip.insert(host.to_string(), next_fake_ip);
        self.fake_ip_to_host.insert(next_fake_ip, host.to_string());
        next_fake_ip
    }

    fn next_fake_ip(&self) -> (u8, u8, u8, u8) {
        // FIXME: range exceed
        let next_fake_ip_seq = self.next_fake_ip_seq.load(Ordering::SeqCst);
        self.next_fake_ip_seq.fetch_add(1, Ordering::SeqCst);
        let a = next_fake_ip_seq.to_be_bytes();
        (a[0], a[1], a[2], a[3])
    }

    fn remove_host(&mut self) {
        todo!()
    }

    fn clear_all(&mut self) {
        todo!()
    }
}

pub struct ConfigDnsResolver {
    fake_ip_manager: Arc<FakeIpManager>,
    async_std_resolver: AsyncStdResolver
}

impl ConfigDnsResolver {

    pub fn new(fake_ip_manager: Arc<FakeIpManager>, async_std_resolver: AsyncStdResolver) -> Self {
        Self {
            fake_ip_manager,
            async_std_resolver
        }
    }

    pub async fn get_or_create_fake_ip(&self, host: &str) -> Option<(u8, u8, u8, u8)> {
        self.fake_ip_manager.clone().get_or_create_fake_ip(host)
    }

    pub async fn get_host(&mut self, ip_addr: &Ipv4Addr) -> Option<String> {
        let bytes = ip_addr.octets();
        let ip: (u8, u8, u8, u8) = (bytes[0], bytes[1], bytes[2], bytes[3]);
        self.fake_ip_manager.clone().get_host(&ip)
    }

    pub async fn resolve_host(&self, qname: &str) -> Result<DnsPacket> {
        match self.async_std_resolver.lookup_ip(qname).await {
            Ok(lookup_result) => {
                let mut dns_records: Vec<DnsRecord> = lookup_result.as_lookup().record_iter()
                    .map(|r| {
                        let rd = r.rdata();
                        match rd {
                            RData::A(ip) => {
                                DnsRecord::A {
                                    domain: qname.to_string(),
                                    addr: *ip,
                                    ttl: TransientTtl(r.ttl()),
                                }
                            }

                            RData::AAAA(ip) => {
                                DnsRecord::AAAA {
                                    domain: qname.to_string(),
                                    addr: *ip,
                                    ttl: TransientTtl(r.ttl()),
                                }
                            }
                            _ => {
                                DnsRecord::UNKNOWN {
                                    domain: qname.to_string(),
                                    qtype: 0,
                                    data_len: 0,
                                    ttl: TransientTtl(r.ttl()),
                                }
                            }
                        }
                    })
                    .filter(|dns_record| {
                        match dns_record {
                            DnsRecord::UNKNOWN { .. } => {
                                false
                            }
                            _ => {
                                true
                            }
                        }
                    })
                    .collect();
                let mut dns_packet = DnsPacket::new();
                dns_packet.answers.append(&mut dns_records);
                Ok(dns_packet)
            }

            Err(e) => {
                tracing::error!("!!! Resolve host [{}] error, msg: {} ", qname, e.to_string());
                Err(io::Error::new(io::ErrorKind::Other, e))
            }
        }
    }
}

#[async_trait]
impl DnsResolver for ConfigDnsResolver {
    async fn resolve(&self, qname: &str, qtype: QueryType, recursive: bool) -> Result<DnsPacket> {
        match self.get_or_create_fake_ip(qname).await {
            Some((a, b, c, d)) => {
                let dns_answer = DnsRecord::A {
                    domain: qname.to_string(),
                    addr: Ipv4Addr::new(a, b, c, d),
                    ttl: TransientTtl(60),
                };

                let mut dns_packet = DnsPacket::new();
                dns_packet.answers.push(dns_answer);
                Ok(dns_packet)
            }

            None => {
                self.resolve_host(qname).await
            }
        }
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

pub async fn resolve_host(async_std_resolver: Arc<AsyncStdResolver>, domain: &str) -> Result<IpAddr> {
    let response = async_std_resolver
        .lookup_ip(domain)
        .await
        .map_err(|_| Error::new(ErrorKind::NotFound, format!("{} not resolved", domain)))?;

    response
        .iter()
        .next()
        .ok_or_else(|| Error::new(ErrorKind::NotFound, format!("{} not resolved", domain)))
}

#[cfg(test)]
mod tests {
}
