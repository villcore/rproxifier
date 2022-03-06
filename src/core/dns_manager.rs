use std::sync::Arc;
use async_std_resolver::AsyncStdResolver;
use crate::dns::resolve::{ConfigDnsResolver, FakeIpManager};
use crate::dns::server::DnsUdpServer;
use crate::dns;

pub struct DnsManager {
    pub resolver: Arc<AsyncStdResolver>,
    pub fake_ip_manager: Arc<FakeIpManager>,
    pub dns_listen: String,
}

impl DnsManager {

    pub fn run_dns_server(self) {
        let fake_ip_manager = self.fake_ip_manager.clone();
        let async_resolver = (*self.resolver).clone();
        let config_dns_resolver = ConfigDnsResolver::new(fake_ip_manager, async_resolver);
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