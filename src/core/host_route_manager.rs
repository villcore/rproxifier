use std::net::Ipv4Addr;
use std::sync::Arc;

use crate::core::db::Db;
use crate::core::nat_session::NatSessionManager;
use crate::core::proxy_config_manager::{HostRouteStrategy, ProcessRegexRouteRule, ProxyServerConfigManager, ProxyServerConfigType, RegexRouteRule, RouteRule, ConnectionRouteRule};
use crate::ProcessInfo;
use dashmap::DashMap;

pub const HOST_ROUTE_PREFIX: &str = "HR_";
pub const HOST_ROUTE_PATTERN: &str = "HRP";

pub const GLOBAL_ROUTE_RULE: &str = "RR_GLOBAL";
pub const PROCESS_ROUTE_RULE: &str = "RR_PROCESS_";
pub const ALL_PROCESS_ROUTE_RULE: &str = "RR_ALL_PROCESS";

// PS_CONF_#DEFAULT#_REGEX -> DIRECT/REJECT/PROXY/PROBE

pub struct HostRouteManager {
    db: Arc<Db>,
    probe_proxy_host: DashMap<String, (bool, u64)>,
}

impl HostRouteManager {
    pub fn new(db: Arc<Db>) -> Self {
        Self {
            db,
            probe_proxy_host: Default::default()
        }
    }

    pub fn get_host_route_strategy(&self, process_info: Option<&ProcessInfo>, host: &str) -> Option<(HostRouteStrategy, ConnectionRouteRule)> {
        let need_proxy = self.is_probe_host_need_proxy(host);
        if let Some(process_info) = process_info {
            // process
            let process_path = process_info.process_execute_path.as_str();
            match self.get_process_route_rule(process_path) {
                None => {}
                Some(process_route_rule) => {
                    if process_route_rule.len() > 0 {
                        let regex_route_list: Vec<(RegexRouteRule, regex::Regex)> = process_route_rule.into_iter()
                            .map(|regex_route_rule| {
                                match regex::Regex::new(&regex_route_rule.host_regex) {
                                    Ok(regex) => Some((regex_route_rule, regex)),
                                    Err(errors) => {
                                        log::error!("create regex {} error, {}", host, errors);
                                        None
                                    }
                                }
                            })
                            .filter(|result| result.is_some())
                            .map(|result| result.unwrap())
                            .collect();

                        if regex_route_list.len() > 0 {
                            for (process_route_rule, regex) in regex_route_list {
                                if regex.is_match(&host) {
                                    match process_route_rule.route_rule {
                                        RouteRule::Direct => return Some((HostRouteStrategy::Direct, ConnectionRouteRule {
                                            hit_global_rule: false,
                                            hit_process_rule: true,
                                            host_regex: process_route_rule.host_regex.to_string(),
                                            need_proxy: false,
                                            route_rule: RouteRule::Direct
                                        })),
                                        RouteRule::Proxy(proxy_config) => {
                                            return Some((HostRouteStrategy::Proxy(proxy_config.clone(), None, 0), ConnectionRouteRule {
                                                hit_global_rule: false,
                                                hit_process_rule: true,
                                                host_regex: process_route_rule.host_regex.to_string(),
                                                need_proxy: true,
                                                route_rule: RouteRule::Proxy(proxy_config)
                                            }));
                                        }
                                        RouteRule::Probe(proxy_config) => {
                                            return if need_proxy {
                                                Some((HostRouteStrategy::Probe(false, true, proxy_config.clone(), None, 0), ConnectionRouteRule {
                                                    hit_global_rule: false,
                                                    hit_process_rule: true,
                                                    host_regex: process_route_rule.host_regex.to_string(),
                                                    need_proxy,
                                                    route_rule: RouteRule::Probe(proxy_config)
                                                }))
                                            } else {
                                                Some((HostRouteStrategy::Probe(true, false, proxy_config.clone(), None, 0), ConnectionRouteRule{
                                                    hit_global_rule: false,
                                                    hit_process_rule: true,
                                                    host_regex: process_route_rule.host_regex.to_string(),
                                                    need_proxy,
                                                    route_rule: RouteRule::Probe(proxy_config)
                                                }))
                                            }
                                        }
                                        RouteRule::Reject => return Some((HostRouteStrategy::Reject, ConnectionRouteRule {
                                            hit_global_rule: false,
                                            hit_process_rule: true,
                                            host_regex: process_route_rule.host_regex.to_string(),
                                            need_proxy: false,
                                            route_rule: RouteRule::Reject
                                        })),
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        // global
        if let Some(global_route_rule) = self.get_global_route_rule() {
            // 配置了全局路由策略
            let regex_route_list: Vec<(RegexRouteRule, regex::Regex)> = global_route_rule.into_iter()
                .map(|regex_route_rule| {
                    match regex::Regex::new(&regex_route_rule.host_regex) {
                        Ok(regex) => Some((regex_route_rule, regex)),
                        Err(errors) => {
                            log::error!("create regex {} error, {}", host, errors);
                            None
                        }
                    }
                })
                .filter(|result| result.is_some())
                .map(|result| result.unwrap())
                .collect();

            if regex_route_list.len() <= 0 {
                // 全局路由策略解析为空
                return Some((HostRouteStrategy::Direct, ConnectionRouteRule {
                    hit_global_rule: true,
                    hit_process_rule: false,
                    host_regex: "".to_string(),
                    need_proxy: false,
                    route_rule: RouteRule::Direct
                }))
            }

            for (route_rule, regex) in regex_route_list {
                if regex.is_match(&host) {
                    match route_rule.route_rule {
                        RouteRule::Direct => return Some((HostRouteStrategy::Direct, ConnectionRouteRule {
                            hit_global_rule: true,
                            hit_process_rule: false,
                            host_regex: route_rule.host_regex.to_string(),
                            need_proxy: false,
                            route_rule: RouteRule::Direct
                        })),
                        RouteRule::Proxy(proxy_config) => {
                            return Some((HostRouteStrategy::Proxy(proxy_config.clone(), None, 0), ConnectionRouteRule {
                                hit_global_rule: true,
                                hit_process_rule: false,
                                host_regex: route_rule.host_regex.to_string(),
                                need_proxy: true,
                                route_rule: RouteRule::Proxy(proxy_config)
                            }))
                        }
                        RouteRule::Probe(proxy_config) => {
                            return if need_proxy {
                                Some((HostRouteStrategy::Probe(false, true, proxy_config.clone(), None, 0), ConnectionRouteRule {
                                    hit_global_rule: true,
                                    hit_process_rule: false,
                                    host_regex: route_rule.host_regex.to_string(),
                                    need_proxy,
                                    route_rule: RouteRule::Probe(proxy_config)
                                }))
                            } else {
                                Some((HostRouteStrategy::Probe(true, false, proxy_config.clone(), None, 0), ConnectionRouteRule {
                                    hit_global_rule: true,
                                    hit_process_rule: false,
                                    host_regex: route_rule.host_regex.to_string(),
                                    need_proxy,
                                    route_rule: RouteRule::Probe(proxy_config)
                                }))
                            }
                        }
                        RouteRule::Reject => return Some((HostRouteStrategy::Reject, ConnectionRouteRule {
                            hit_global_rule: true,
                            hit_process_rule: false,
                            host_regex: route_rule.host_regex.to_string(),
                            need_proxy: false,
                            route_rule: RouteRule::Reject
                        })),
                    }
                }
            }
            return Some((HostRouteStrategy::Direct, ConnectionRouteRule {
                hit_global_rule: true,
                hit_process_rule: false,
                host_regex: "".to_string(),
                need_proxy: false,
                route_rule: RouteRule::Direct
            }))
        } else {
            // 没有配置全局路由策略
            return Some((HostRouteStrategy::Direct, ConnectionRouteRule {
                hit_global_rule: true,
                hit_process_rule: false,
                host_regex: "".to_string(),
                need_proxy: false,
                route_rule: RouteRule::Direct
            }))
        }
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
        };
    }

    fn set_host_rule_strategy_to_db(&self, host_route_strategy_key: &str, host_rule_strategy: HostRouteStrategy) -> anyhow::Result<()> {
        return match self.db.set(host_route_strategy_key, host_rule_strategy) {
            Ok(_) => {
                Ok(())
            }
            Err(error) => Err(anyhow::anyhow!(error))
        };
    }

    pub fn mark_probe_host_need_proxy(&self, host: &str) {
        self.probe_proxy_host.insert(host.to_string(), (true, NatSessionManager::get_now_time()));
    }

    pub fn is_probe_host_need_proxy(&self, host: &str) -> bool {
       if let Some(kv) = self.probe_proxy_host.get(host) {
          let (need_proxy, last_update_timestamp) = kv.value();
           if NatSessionManager::get_now_time() - last_update_timestamp > 10 * 60 {
               return false
           }
           *need_proxy
       } else {
           false
       }
    }

    pub fn add_global_route_rule(&self, regex_route_rule: RegexRouteRule) {
        let key = GLOBAL_ROUTE_RULE;
        match self.db.get_vec(key) {
            None => {
                self.db.set(key, vec![regex_route_rule]);
            }
            Some(vec) => {
                let route_rule = regex_route_rule.route_rule.get_copy();
                if let Some(mut route_rule_vec) = self.db.parse_value::<Vec<RegexRouteRule>>(&Some(vec)) {
                    let mut already_contains = false;
                    for rule in route_rule_vec.iter_mut() {
                        if rule.host_regex == regex_route_rule.host_regex {
                            rule.route_rule = route_rule.get_copy();
                            already_contains = true;
                        }
                    }

                    if already_contains {
                        self.db.set(key, route_rule_vec);
                    } else {
                        route_rule_vec.push(regex_route_rule);
                        self.db.set(key, route_rule_vec);
                    }
                } else {
                    self.db.set(key, vec![regex_route_rule]);
                }
            }
        };
    }

    pub fn remove_global_route_rule(&self, regex_route_rule: RegexRouteRule) {
        let key = GLOBAL_ROUTE_RULE;
        match self.db.get_vec(key) {
            None => {
                self.db.set(key, vec![regex_route_rule]);
            }
            Some(vec) => {
                let route_rule = regex_route_rule.route_rule.get_copy();
                if let Some(mut route_rule_vec) = self.db.parse_value::<Vec<RegexRouteRule>>(&Some(vec)) {
                    let new_route_rule_vec: Vec<RegexRouteRule> = route_rule_vec.into_iter()
                        .filter(|rule| rule.host_regex != regex_route_rule.host_regex)
                        .collect();
                    self.db.set(key, new_route_rule_vec);
                }
            }
        };
    }

    pub fn set_global_route_rule(&self, route_rule_vec: Vec<RegexRouteRule>) -> anyhow::Result<()> {
        let key = GLOBAL_ROUTE_RULE;
        self.db.set(key, route_rule_vec)
    }

    pub fn get_global_route_rule(&self) -> Option<Vec<RegexRouteRule>> {
        let key = GLOBAL_ROUTE_RULE;
        match self.db.get_vec(key) {
            None => {
                None
            }
            Some(vec) => {
                self.db.parse_value::<Vec<RegexRouteRule>>(&Some(vec))
            }
        }
    }

    pub fn add_process_route_rule(&self, process_regex_route_rule: ProcessRegexRouteRule) {
        let process_path = process_regex_route_rule.process_path.clone();
        // add to all process list
        match self.db.get_vec(ALL_PROCESS_ROUTE_RULE) {
            None => {
                self.db.set(ALL_PROCESS_ROUTE_RULE, vec![process_path.clone()]);
            }
            Some(vec) => {
                if let Some(mut all_process_route) = self.db.parse_value::<Vec<String>>(&Some(vec)) {
                    if !all_process_route.contains(&process_path) {
                        all_process_route.push(process_path.clone());
                        self.db.set(ALL_PROCESS_ROUTE_RULE, all_process_route);
                    }
                }
            }
        }

        let process_route_rule_key = PROCESS_ROUTE_RULE.to_string() + &process_path;
        let process_route_rule = process_regex_route_rule.get_route_rule();
        if let Some(vec) = self.db.get_vec(&process_route_rule_key) {
            if let Some(mut process_regex_route_rule_vec) = self.db.parse_value::<Vec<RegexRouteRule>>(&Some(vec)) {
                let mut already_contains = false;
                for rule in process_regex_route_rule_vec.iter_mut() {
                    if rule.host_regex == process_route_rule.host_regex {
                        rule.route_rule = process_route_rule.route_rule.get_copy();
                        already_contains = true;
                    }
                }

                if already_contains {
                    self.db.set(&process_route_rule_key, process_regex_route_rule_vec);
                } else {
                    process_regex_route_rule_vec.push(process_route_rule);
                    self.db.set(&process_route_rule_key, process_regex_route_rule_vec);
                }
            }
        } else {
            self.db.set(&process_route_rule_key, vec![process_route_rule]);
        }
    }

    pub fn remove_process_route_rule(&self, process_regex_route_rule: ProcessRegexRouteRule) {
        let process_route_rule_key = PROCESS_ROUTE_RULE.to_string() + &process_regex_route_rule.process_path;
        let process_route_rule = process_regex_route_rule.get_route_rule();
        if let Some(vec) = self.db.get_vec(&process_route_rule_key) {
            if let Some(mut process_regex_route_rule_vec) = self.db.parse_value::<Vec<RegexRouteRule>>(&Some(vec)) {
                let new_process_regex_route_rule_vec: Vec<RegexRouteRule> = process_regex_route_rule_vec.into_iter()
                    .filter(|rule| rule.host_regex != process_route_rule.host_regex)
                    .collect();
                self.db.set(&process_route_rule_key, new_process_regex_route_rule_vec);
            }
        }
    }

    pub fn set_process_route_rule(&self, process_route_rule_vec: Vec<ProcessRegexRouteRule>) -> anyhow::Result<()> {
        if process_route_rule_vec.len() <= 0 {
            Ok(())
        } else {
            let process_route_rule_key = PROCESS_ROUTE_RULE.to_string() + &process_route_rule_vec[0].process_path;
            let route_rule_vec: Vec<RegexRouteRule> = process_route_rule_vec.into_iter()
                .map(|rule| rule.route_rule)
                .collect();
            self.db.set(&process_route_rule_key, route_rule_vec)
        }
    }

    pub fn get_all_process_route_rule(&self) -> Option<Vec<ProcessRegexRouteRule>> {
        let all_process_path_vec = match self.db.get_vec(ALL_PROCESS_ROUTE_RULE) {
            None => {
                return None;
            }
            Some(vec) => {
                if let Some(process_path_vec) = self.db.parse_value::<Vec<String>>(&Some(vec)) {
                    process_path_vec
                } else {
                    return None;
                }
            }
        };

        let mut process_route_rule = vec![];
        for process_path in all_process_path_vec {
            let process_route_rule_key = PROCESS_ROUTE_RULE.to_string() + &process_path;
            match self.db.get_vec(&process_route_rule_key) {
                None => {}
                Some(vec) => {
                    if let Some(route_rule_vec) = self.db.parse_value::<Vec<RegexRouteRule>>(&Some(vec)) {
                        for route_rule in route_rule_vec {
                            process_route_rule.push(ProcessRegexRouteRule{
                                process_path: process_path.clone(),
                                route_rule
                            });
                        }

                    }
                }
            }
        }
        Some(process_route_rule)
    }

    pub fn get_process_route_rule(&self, process_path: &str) -> Option<Vec<RegexRouteRule>> {
        let process_route_rule_key = PROCESS_ROUTE_RULE.to_string() + process_path;
        return match self.db.get_vec(&process_route_rule_key) {
            None => {
                None
            }
            Some(vec) => {
                if let Some(process_path_vec) = self.db.parse_value::<Vec<RegexRouteRule>>(&Some(vec)) {
                    Some(process_path_vec)
                } else {
                    None
                }
            }
        }
    }
}