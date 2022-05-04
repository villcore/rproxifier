use std::sync::Arc;
use async_std_resolver::AsyncStdResolver;
use serde::{Serialize, Deserialize};
use crate::dns::resolve::{ConfigDnsResolver, FakeIpManager};
use crate::dns::server::DnsUdpServer;
use crate::{dns, NetworkInterface};
use std::sync::atomic::{AtomicBool, Ordering};
use crate::core::db::Db;

pub struct DnsManager {
    pub resolver: Arc<AsyncStdResolver>,
    pub forward_resolver: Arc<AsyncStdResolver>,
    pub fake_ip_manager: Arc<FakeIpManager>,
    pub dns_config_manager: Arc<DnsConfigManager>,
    pub dns_listen: String,
}

impl DnsManager {

    pub fn run_dns_server(self) {
        let fake_ip_manager = self.fake_ip_manager.clone();
        let async_resolver = (*self.resolver).clone();
        let forward_resolver = (*self.forward_resolver).clone();
        let dns_config_manager = self.dns_config_manager.clone();
        let config_dns_resolver = ConfigDnsResolver::new(dns_config_manager, fake_ip_manager, async_resolver, forward_resolver);
        tokio::spawn(self.start_config_dns_server(config_dns_resolver));
    }

    async fn start_config_dns_server(self, config_dns_resolver: ConfigDnsResolver) {
        log::info!("start dns server at {}", self.dns_listen);
        let dns_server: DnsUdpServer = dns::server::DnsUdpServer::new(
            self.dns_listen,
            Box::new(config_dns_resolver),
        ).await;
        dns_server.run_server().await;
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DnsHost {
    pub host: String,
    pub related_process_vec: Vec<String>,
    pub reverse_resolve: bool,
}

impl DnsHost {
    pub fn new(host: String, reverse_resolve: bool) -> Self {
        Self {
            host,
            reverse_resolve,
            related_process_vec: vec![]
        }
    }

    pub fn get_copy(&self) -> DnsHost {
        DnsHost {
            host: self.host.clone(),
            related_process_vec: self.related_process_vec.clone(),
            reverse_resolve: self.reverse_resolve
        }
    }
}

pub const DNS_HOST_CONFIG_KEY_PREFIX: &str = "DNS_H_";

pub struct DnsConfigManager {
    pub db: Arc<Db>,
    pub local_dns_started: AtomicBool,
    pub bind_dns_interface: NetworkInterface
}

impl DnsConfigManager {
    
    pub fn new(db: Arc<Db>) -> Self {
        Self {
            db,
            local_dns_started: AtomicBool::new(false),
            bind_dns_interface: NetworkInterface{
                interface_name: "".to_string(),
                ip_addr: "".to_string()
            }
        }
    }
    
    pub fn mark_local_dns_start(&self) {
        self.local_dns_started.compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed);
    }

    pub fn mark_local_dns_stop(&self) {
        self.local_dns_started.compare_exchange(true, false, Ordering::Acquire, Ordering::Relaxed);
    }

    pub fn get_local_dns_state(&self) -> bool {
        self.local_dns_started.load(Ordering::SeqCst)
    }

    pub fn set_host(&self, dns_host: DnsHost) -> anyhow::Result<()> {
        let key = DNS_HOST_CONFIG_KEY_PREFIX.to_string() + dns_host.host.as_str();
        self.db.set(key.as_str(), dns_host)
    }

    pub fn get_host(&self, host: &str) -> Option<DnsHost> {
        let key = DNS_HOST_CONFIG_KEY_PREFIX.to_string() + host;
        return match self.db.get_vec(key.as_str()) {
            None => {
                None
            }
            Some(vec) => {
                self.db.parse_value::<DnsHost>(&Some(vec))
            }
        }
    }

    pub fn delete_host(&self, host: String) -> anyhow::Result<()> {
        let key = DNS_HOST_CONFIG_KEY_PREFIX.to_string() + host.as_str();
        self.db.db.remove(key);
        Ok(())
    }

    pub fn get_all_host(&self) -> Vec<DnsHost> {
        self.db.db.range(DNS_HOST_CONFIG_KEY_PREFIX .. "DNS_I")
            .filter(|r| r.is_ok())
            .map(|r| r.unwrap())
            .map(|kv| {
                let a = String::from_utf8(kv.0.to_vec()).unwrap();
                let b: DnsHost = serde_json::from_slice(kv.1.as_ref()).unwrap();
                (a, b)
            })
            .map(|kv| {
                kv.1
            })
            .collect()
    }

    pub fn get_all_host_contains(&self, pattern: String) -> Vec<DnsHost> {
        if pattern.is_empty() {
            self.get_all_host()
        } else {
            self.get_all_host()
                .into_iter()
                .filter(|dns_host| dns_host.host.contains(&pattern))
                .collect::<Vec<DnsHost>>()
        }
    }

    pub fn add_related_process(&self, host: String, process_name: String) -> anyhow::Result<()> {
        match self.get_host(host.as_str()) {
            None => Ok(()),
            Some(mut dns_host) => {
                if !dns_host.related_process_vec.contains(&process_name.to_string()) {
                    dns_host.related_process_vec.push(process_name);
                }
                self.set_host(dns_host)
            }
        }
    }
}