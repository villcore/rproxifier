use crate::core::proxy_config_manager::{ProxyServerConfigType, ProxyServerConfig, RouteRule};
use serde::{Serialize, Deserialize};
use crate::core::dns_manager::DnsHost;

#[derive(Debug, Serialize, Deserialize)]
pub struct ProxyServerConfigResponse {
    pub name: String,
    pub addr: String,
    pub port: u16,
    pub available: bool,
}

impl ProxyServerConfigResponse {
    pub fn new(proxy_server_config: ProxyServerConfig) -> Self {
        let (name, addr, port, available) = {
            match proxy_server_config.config {
                ProxyServerConfigType::SocksV5(addr, port, _, _) => {
                    (proxy_server_config.name, addr, port, false)
                }
                ProxyServerConfigType::HTTP(addr, port) => {
                    (proxy_server_config.name, addr, port, false)
                }
            }
        };

        Self {
            name,
            addr,
            port,
            available
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AddProxyServerConfigRequest {
    pub name: String,
    pub addr: String,
    pub port: u16,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RemoveProxyServerConfigRequest {
    pub name: String,
    pub addr: String,
    pub port: u16,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GetDnsConfigRequest {
    pub host: String,
}


#[derive(Debug, Serialize, Deserialize)]
pub struct GetDnsConfigResponse {
    pub local_dns_server: String,
    pub gateway_server: String,
    pub all_dns_config: Vec<DnsHost>,
}

impl GetDnsConfigResponse {
    pub fn new(local_dns_server: String, gateway_server: String, all_dns_config: Vec<DnsHost>,) -> Self {
        Self{
            local_dns_server,
            gateway_server,
            all_dns_config
        }
    }
}