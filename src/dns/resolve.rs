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
use std::net::Ipv4Addr;
use std::borrow::BorrowMut;

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

pub struct UserConfigDnsWrapResolver {
    domain_map: HashMap<String, Ipv4Addr>,
    wrap_resolver:  Box<dyn DnsResolver + Sync + Send>
}

impl UserConfigDnsWrapResolver {
    pub fn new(domain_map: HashMap<String, Ipv4Addr>, mut wrap_resolver: Box<dyn DnsResolver + Sync + Send>) -> Self {
        Self {
            domain_map,
            wrap_resolver
        }
    }
}

#[async_trait]
impl DnsResolver for UserConfigDnsWrapResolver {
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

#[cfg(test)]
mod tests {
}
