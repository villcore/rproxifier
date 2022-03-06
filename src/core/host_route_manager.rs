use std::sync::Arc;
use crate::core::db::Db;
use std::net::Ipv4Addr;
use crate::core::nat_session::NatSessionManager;
use crate::core::proxy_config_manager::HostRouteStrategy;

pub const HOST_ROUTE_PREFIX: &str = "HR_";
pub const HOST_ROUTE_PATTERN: &str = "HRP";

pub struct HostRouteManager {
    db: Arc<Db>
}

impl HostRouteManager {
    pub fn new(db: Arc<Db>) -> Self {
        Self {
            db
        }
    }

    pub fn get_host_rule_pattern_list(&self) -> Vec<(String, regex::Regex, HostRouteStrategy)> {
        let host_rule_pattern_bytes = match self.db.get_vec(HOST_ROUTE_PATTERN) {
            Some(opt) => {
                opt
            }
            None => {
                log::error!("get value with host rule pattern key {} error", HOST_ROUTE_PATTERN);
                return vec![]
            }
        };

        return match self.db.parse_value::<Vec<(String, HostRouteStrategy)>>(&Some(host_rule_pattern_bytes)) {
            Some(pattern) => {
                let regex_route_list: Vec<(String, regex::Regex, HostRouteStrategy)> = pattern.into_iter()
                    .map(|(host, strategy)| {
                        match regex::Regex::new(&host) {
                            Ok(regex) => Some((host, regex, strategy)),
                            Err(errors) => {
                                log::error!("create regex {} error, {}", host, errors);
                                None
                            }
                        }
                    })
                    .filter(|result| result.is_some())
                    .map(|result| result.unwrap())
                    .collect();
                regex_route_list
            }
            None => {
                log::error!("get host rule pattern list error");
                vec![]
            }
        }
    }

    pub fn add_route_strategy(&self, host: String, strategy: HostRouteStrategy) -> anyhow::Result<()> {
        if let Ok(regex) = regex::Regex::new(&host) {
            let mut vec = self.get_host_rule_pattern_list();
            vec.push((host, regex, strategy));

            let store_vec = vec.into_iter()
                .map(|item|(item.0, item.2))
                .collect::<Vec<(String, HostRouteStrategy)>>();

            return self.db.set(HOST_ROUTE_PATTERN, store_vec)
        }
        Err(anyhow::anyhow!(format!("create regex {} error", host)))
    }

    pub fn get_route_strategy(&self, host: &str) -> Option<(HostRouteStrategy)> {
        let host_route_strategy_key = HOST_ROUTE_PREFIX.to_string() + host;
        match self.db.get_vec(&host_route_strategy_key) {
            Some(vec) => {
                return self.db.parse_value(&Some(vec))
            }
            None => {
                log::error!("get value with host rule pattern key {} error", HOST_ROUTE_PATTERN);
            }
        };

        let vec = self.get_host_rule_pattern_list();
        let mut iter = vec.iter();
        for (_, regex_matcher, strategy) in &mut iter {
            if let Some(_) = regex_matcher.captures(host) {
                let route_strategy = strategy.get_copy();
                self.db.set(host_route_strategy_key.as_str(), route_strategy);
                break;
            }
        }

        return match self.db.get_vec(host_route_strategy_key.as_str()) {
            Some(vec) => {
                return self.db.parse_value(&Some(vec))
            }
            None => {
                None
            }
        };
    }

    fn get_host_rule_strategy_from_db(&self, host_route_strategy_key: &str) -> Option<HostRouteStrategy> {
        return match self.db.get_vec(&host_route_strategy_key) {
            Some(vec) => {
                self.db.parse_value(&Some(vec))
            }
            None => {
                log::error!("get value with host rule pattern key {} empty", host_route_strategy_key);
                None
            }
        }
    }

    fn set_host_rule_strategy_to_db(&self, host_route_strategy_key: &str, host_rule_strategy: HostRouteStrategy) -> anyhow::Result<()> {
        return match self.db.set(host_route_strategy_key, host_rule_strategy) {
            Ok(_) => {
                Ok(())
            }
            Err(error) => Err(anyhow::anyhow!(error))
        };
    }

    pub fn mark_probe_direct(&self, host: &str, need_proxy: bool) {
        let host_route_strategy_key = HOST_ROUTE_PREFIX.to_string() + host;
        let new_strategy = match self.get_host_rule_strategy_from_db(host_route_strategy_key.as_str()) {
            None => None,
            Some(strategy) => {
                match strategy {
                    HostRouteStrategy::Probe(_, _, proxy_config_name, direct_ip_addr, last_update_time) => {
                        Some(HostRouteStrategy::Probe(true, need_proxy, proxy_config_name.clone(), direct_ip_addr, last_update_time))
                    }
                    _ => None
                }
            }
        };

        if let Some(strategy) = new_strategy {
            log::info!("mark probe direct, {} => {:?}", host_route_strategy_key, strategy);
            self.set_host_rule_strategy_to_db(host_route_strategy_key.as_str(), strategy);
        }
    }

    pub fn set_proxy_server_direct_ip(&self, host: &str, direct_ip_addr: Ipv4Addr) {
        let host_route_strategy_key = HOST_ROUTE_PREFIX.to_string() + host;
        let new_strategy = match self.get_host_rule_strategy_from_db(host_route_strategy_key.as_str()) {
            None => None,
            Some(strategy) => {
                match strategy {
                    HostRouteStrategy::Probe(tested, need_proxy, proxy_config_name, _, _) => {
                        Some(HostRouteStrategy::Probe(tested, need_proxy, proxy_config_name.clone(), Some(direct_ip_addr), NatSessionManager::get_now_time()))
                    }
                    _ => None
                }
            }
        };

        if let Some(strategy) = new_strategy {
            self.set_host_rule_strategy_to_db(host_route_strategy_key.as_str(), strategy);
        }
    }

    pub fn get_all_route_strategy(&self) -> Vec<(String, HostRouteStrategy)> {
        self.db.db.range(HOST_ROUTE_PREFIX .. "HS_")
            .filter(|r| r.is_ok())
            .map(|r| r.unwrap())
            .map(|kv| {
                let a = String::from_utf8(kv.0.to_vec()).unwrap();
                let b: HostRouteStrategy = serde_json::from_slice(kv.1.as_ref()).unwrap();
                (a, b)
            })
            .collect()
    }
}