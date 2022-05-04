use std::net::Ipv4Addr;
use serde::{Serialize, Deserialize};
use crate::core::db::Db;
use std::sync::Arc;
use anyhow::Error;

#[derive(Debug, Serialize, Deserialize)]
pub struct ProxyServerConfig {
    pub name: String,
    pub config: ProxyServerConfigType,
    pub available: bool,
}

impl ProxyServerConfig {
    pub fn get_copy(&self) -> ProxyServerConfig {
        ProxyServerConfig {
            name: self.name.clone(),
            config: self.config.get_copy(),
            available: self.available,
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub enum ProxyServerConfigType {

    // addr, port, username, password
    SocksV5(String, u16, String, String),

    // addr, port
    HTTP(String, u16)
}

impl ProxyServerConfigType {
    pub fn get_copy(&self) -> ProxyServerConfigType {
        let new_config = match self {
            ProxyServerConfigType::SocksV5(addr, port, username, password) => ProxyServerConfigType::SocksV5(addr.to_string(), *port, username.to_string(), password.to_string()),
            ProxyServerConfigType::HTTP(addr, port) => ProxyServerConfigType::HTTP(addr.to_string(), *port)
        };
        return new_config;
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ConnectionRouteRule {
    pub hit_global_rule: bool,
    pub hit_process_rule: bool,
    pub need_proxy: bool,
    pub host_regex: String,
    pub route_rule: RouteRule,
}

impl ConnectionRouteRule {
    pub fn get_copy(&self) -> ConnectionRouteRule {
        ConnectionRouteRule {
            hit_global_rule: self.hit_global_rule,
            hit_process_rule: self.hit_process_rule,
            need_proxy: self.need_proxy,
            host_regex: self.host_regex.to_string(),
            route_rule: self.route_rule.get_copy()
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub enum HostRouteStrategy {
    Direct,

    // Proxy(proxy_name direct_proxy_server_ip, last_update_time)
    Proxy(String, Option<Ipv4Addr>, u64),

    // Probe(tested, need_proxy, proxy_name, proxy_server_direct_ip, last_update_time)
    Probe(bool, bool, String, Option<Ipv4Addr>, u64),

    Reject,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ProcessRegexRouteRule {
    pub process_path: String,
    pub route_rule: RegexRouteRule,
}

impl ProcessRegexRouteRule {
    pub fn get_route_rule(&self) -> RegexRouteRule {
        self.route_rule.get_copy()
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RegexRouteRule {
    pub host_regex: String,
    pub route_rule: RouteRule
}

impl RegexRouteRule {
    pub fn get_copy(&self) -> RegexRouteRule {
        RegexRouteRule {
            host_regex: self.host_regex.to_string(),
            route_rule: self.route_rule.get_copy()
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub enum RouteRule {

    Direct,

    // proxy_name
    Proxy(String),

    // proxy_name
    Probe(String),

    Reject,
}

impl RouteRule {
    pub fn get_copy(&self) -> RouteRule {
        match self {
            RouteRule::Direct => RouteRule::Direct,
            RouteRule::Proxy(proxy_name) => RouteRule::Proxy(proxy_name.to_string()),
            RouteRule::Probe(proxy_name) => RouteRule::Probe(proxy_name.to_string()),
            RouteRule::Reject => RouteRule::Reject
        }
    }
}

impl HostRouteStrategy {
    pub fn get_copy(&self) -> HostRouteStrategy {
        let route_strategy = match self {
            HostRouteStrategy::Direct => HostRouteStrategy::Direct,
            HostRouteStrategy::Proxy(proxy_name, direct_ip, last_update_time) => HostRouteStrategy::Proxy(proxy_name.to_string(), *direct_ip, *last_update_time),
            HostRouteStrategy::Probe(tested, need_proxy, proxy_name, direct_ip, last_update_time) => HostRouteStrategy::Probe(*tested, *need_proxy, proxy_name.to_string(), *direct_ip, *last_update_time),
            HostRouteStrategy::Reject => HostRouteStrategy::Reject
        };
        return route_strategy;
    }
}

pub const ALL_PROXY_SERVER_CONFIG_KEY: &str = "PS_CONF_ALL";
pub const PROXY_SERVER_CONFIG_KEY_PREFIX: &str = "PS_CONF_";

pub struct ProxyServerConfigManager {
    db: Arc<Db>
}

impl ProxyServerConfigManager {
    pub fn new(db: Arc<Db>) -> Self {
        Self {
            db
        }
    }

    pub fn get_proxy_server_config(&self, name: &str) -> Option<ProxyServerConfig> {
        let proxy_server_name = PROXY_SERVER_CONFIG_KEY_PREFIX.to_string() + name;
        return match self.db.get_vec(proxy_server_name.as_str()) {
            None => {
                None
            }
            Some(vec) => {
                self.db.parse_value::<ProxyServerConfig>(&Some(vec))
            }
        }
    }

    pub fn set_proxy_server_config(&self, proxy_server: ProxyServerConfig) -> anyhow::Result<()> {
        let name = proxy_server.name.clone();
        let proxy_server_name = PROXY_SERVER_CONFIG_KEY_PREFIX.to_string() + name.as_str();
        match self.db.set(proxy_server_name.as_str(), proxy_server) {
            Ok(_) => {
                let config_name = name.as_str();
                if let Some(mut all_configs) = self.get_all_proxy_server_config_name() {
                    let already_exist_some_configs = all_configs.iter()
                        .filter(|&config| config.to_string() == name)
                        .map(|config| config.to_string())
                        .collect::<Vec<String>>();
                    if already_exist_some_configs.len() == 0 {
                        all_configs.push(name.to_string());
                        self.set_all_proxy_server_config(&all_configs);
                        log::info!("set proxy server config {}", name)
                    } else {
                        log::info!("already set proxy server config {}", name)
                    }
                } else {
                    self.set_all_proxy_server_config(&vec![config_name.to_string()]);
                    log::info!("set proxy server config {}", config_name)
                }
            }
            Err(errors) => return Err(anyhow::anyhow!(format!("set {} proxy server config error, {}", name, errors.to_string())))
        }
        Ok(())
    }


    pub fn get_all_proxy_server_config_name(&self) -> Option<Vec<String>> {
        let vec = self.db.get_vec(ALL_PROXY_SERVER_CONFIG_KEY);
        self.db.parse_value(&vec)
    }

    pub fn get_all_proxy_server_config(&self) -> Option<Vec<ProxyServerConfig>> {
        if let Some(proxy_server_config_name) = self.get_all_proxy_server_config_name() {
            let proxy_server_configs = proxy_server_config_name.iter()
                .map(|config| self.get_proxy_server_config(config.as_str()))
                .filter(Option::is_some)
                .map(Option::unwrap)
                .collect::<Vec<ProxyServerConfig>>();
            return Some(proxy_server_configs);
        }
        None
    }

    pub fn set_all_proxy_server_config(&self, all_proxy_configs: &Vec<String>) -> anyhow::Result<()> {
        self.db.set_with_ref(ALL_PROXY_SERVER_CONFIG_KEY, all_proxy_configs)
    }

    pub fn remove_proxy_server_config(&self, name: &str) -> anyhow::Result<()> {
        if let Some(mut all_configs) = self.get_all_proxy_server_config_name() {
            let rest_some_configs = all_configs.iter()
                .filter(|&config| config.to_string() != name)
                .map(|config| config.to_string())
                .collect::<Vec<String>>();
                self.set_all_proxy_server_config(&rest_some_configs);
        }

        let proxy_server_name = PROXY_SERVER_CONFIG_KEY_PREFIX.to_string() + name;
        self.db.db.remove(&proxy_server_name);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::core::proxy_config_manager::{ProxyServerConfigManager, ProxyServerConfigType, RouteRule, RegexRouteRule};
    use std::sync::Arc;
    use crate::core::db::Db;
    use crate::core::proxy_config_manager::ProxyServerConfig;
    use crate::setup_log;

    #[test]
    pub fn test_proxy_server_config_manager() {
        setup_log();
        let db = Arc::new(Db::new("tmp/data"));
        let proxy_server_config_manager = ProxyServerConfigManager::new(db);
        proxy_server_config_manager.remove_proxy_server_config("xperia");

        let config = ProxyServerConfig {
            name: "xperia".to_string(),
            config: ProxyServerConfigType::SocksV5("192.168.50.58".to_string(), 10801, "".to_string(), "".to_string()),
            available: false
        };

        proxy_server_config_manager.set_proxy_server_config(config.get_copy());
        proxy_server_config_manager.set_proxy_server_config(config.get_copy());
        let config = proxy_server_config_manager.get_proxy_server_config("xperia");
        log::info!("get 'xperia' proxy server config = {:?}", config.unwrap());
        proxy_server_config_manager.remove_proxy_server_config("xperia");
        log::info!("Remove 'xperia' proxy server config");

        log::info!("get all proxy server config = {:?}", proxy_server_config_manager.get_all_proxy_server_config());
    }

    #[test]
    pub fn test_serde_json() {
        let h = RegexRouteRule {
            host_regex: "123".to_string(),
            route_rule: RouteRule::Proxy("xperia".to_string())
        };

        println!("{}", serde_json::to_string(&h).unwrap());
    }
}