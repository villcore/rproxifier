use std::future::Future;
use std::iter::FromIterator;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4, ToSocketAddrs};
use std::num::ParseIntError;
use std::process::{Command, exit};
use std::str::FromStr;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError, RwLock};
use std::sync::mpsc::{channel, RecvTimeoutError, RecvError};
use std::thread::sleep;
use std::thread::spawn;
use std::time::Duration;

use async_std_resolver::{AsyncStdResolver, config, resolver};
use async_std_resolver::config::{NameServerConfig, NameServerConfigGroup, Protocol, ResolverConfig, ResolverOpts};
use bytes::BytesMut;
use dashmap::{DashMap, Map};
use dashmap::mapref::one::{Ref, RefMut};
use log::{error, info, Level};
use regex::Regex;
use smoltcp::Error;
use smoltcp::wire::{IpAddress, IpProtocol, Ipv4Address, Ipv4Cidr, Ipv4Packet, IpVersion, TcpPacket, UdpPacket};
use tokio::net::{TcpListener, TcpStream};
use tokio::runtime::Runtime;
use tokio::sync::mpsc::{Receiver, Sender};
use voluntary_servitude::vs;

#[cfg(target_os = "macos")]
use tun::darwin::TunSocket;

use crate::core::dns_manager::{DnsManager, DnsConfigManager, DnsHost};
use crate::core::nat_session::NatSessionManager;
use crate::core::relay_server::TcpRelayServer;
use crate::core::tun_server::TunServer;
use crate::dns::protocol::{DnsPacket, DnsRecord, QueryType, TransientTtl};
use crate::dns::resolve::{ConfigDnsResolver, DirectDnsResolver, DnsResolver, FakeIpManager, ForwardingDnsResolver, resolve_host, UserConfigDnsResolver};
use crate::dns::server::DnsUdpServer;
#[cfg(target_os = "macos")]
use crate::sys::sys::{DNSSetup, set_rlimit, setup_ip_route};
#[cfg(target_os = "windows")]
use crate::sys::sys::DNSSetup;
#[cfg(target_os = "windows")]
use crate::core::windivert::{Ipv4PacketInterceptor};
use serde::{Serialize, Deserialize};
use std::collections::HashMap;
use dns_parser::rdata::Opt;
use sled::IVec;
use sysinfo::{SystemExt, ProcessExt, PidExt, Process, NetworkExt};
use crate::core::host_route_manager::HostRouteManager;
use crate::core::proxy_config_manager::{HostRouteStrategy, ProxyServerConfigManager, ProxyServerConfig, ProxyServerConfigType, RegexRouteRule, ProcessRegexRouteRule};
use crate::core::active_connection_manager::ActiveConnectionManager;
use netstat2::{ProtocolSocketInfo, SocketInfo};
use crate::sys::sys::get_gateway;

mod dns;
mod sys;
mod tun;
mod core;
mod api;

fn main() {
    setup_log();
    let tcp_relay_listen_addr = if cfg!(target_os="windows") {"0.0.0.0".to_string()} else {"10.0.0.1".to_string()};
    let tcp_relay_listen_port = 13000;
    let db = Arc::new(core::db::Db::new("data/db"));
    let mut network = Arc::new(NetworkModule::new(
        "",
        10000,
        tcp_relay_listen_addr,
        tcp_relay_listen_port,
        db.clone())
    );

    let app = Arc::new(App::new(network));
    app.start();

    let app_cpy = app.clone();
    rouille::start_server("0.0.0.0:18000", move |request| {
        rouille::router!(request,
            (POST) (/net/start_net) => {
                let request_body: rouille::RequestBody = request.data().unwrap();
                let start_network: NetworkInterface = serde_json::from_reader(request_body).unwrap();
                app_cpy.setup_dns_with_primary_ip(start_network);
                rouille::Response::json(&true)
            },

            (POST) (/net/stop_net) => {
               let request_body: rouille::RequestBody = request.data().unwrap();
                let start_network: NetworkInterface = serde_json::from_reader(request_body).unwrap();
                app_cpy.clear_dns_with_primary_ip(start_network);
                rouille::Response::json(&true)
            },

            (POST) (/route/add_global_rule) => {
                let request_body: rouille::RequestBody = request.data().unwrap();
                let regex_route_rule: RegexRouteRule = serde_json::from_reader(request_body).unwrap();
                let app = app_cpy.network_module.clone();
                app.host_route_manager.add_global_route_rule(regex_route_rule);
                rouille::Response::json(&true)
            },

            (POST) (/route/remove_global_rule) => {
                let request_body: rouille::RequestBody = request.data().unwrap();
                let remove_regex_route_rule: RegexRouteRule = serde_json::from_reader(request_body).unwrap();
                let app = app_cpy.network_module.clone();
                app.host_route_manager.remove_global_route_rule(remove_regex_route_rule);
                rouille::Response::json(&true)
            },

            (POST) (/route/set_global_rule) => {
                let request_body: rouille::RequestBody = request.data().unwrap();
                let set_regex_route_rule_vec: Vec<RegexRouteRule> = serde_json::from_reader(request_body).unwrap();
                let app = app_cpy.network_module.clone();
                app.host_route_manager.set_global_route_rule(set_regex_route_rule_vec);
                rouille::Response::json(&true)
            },

            (GET) (/route/get_global_route) => {
                let app = app_cpy.network_module.clone();
                let global_route_rule_vec = app.host_route_manager.get_global_route_rule().unwrap_or_else(||vec![]);
                rouille::Response::json(&global_route_rule_vec)
            },

            (POST) (/route/add_process_rule) => {
                let request_body: rouille::RequestBody = request.data().unwrap();
                let regex_route_rule: ProcessRegexRouteRule = serde_json::from_reader(request_body).unwrap();
                let app = app_cpy.network_module.clone();
                app.host_route_manager.add_process_route_rule(regex_route_rule);
                rouille::Response::json(&true)
            },

            (GET) (/route/get_all_process_route) => {
                let app = app_cpy.network_module.clone();
                let global_route_rule_vec = app.host_route_manager.get_all_process_route_rule().unwrap_or_else(||vec![]);
                rouille::Response::json(&global_route_rule_vec)
            },

            (POST) (/route/set_process_rule) => {
                let request_body: rouille::RequestBody = request.data().unwrap();
                let regex_route_rule: Vec<ProcessRegexRouteRule> = serde_json::from_reader(request_body).unwrap();
                let app = app_cpy.network_module.clone();
                app.host_route_manager.set_process_route_rule(regex_route_rule);
                rouille::Response::json(&true)
            },

            (POST) (/route/remove_process_rule) => {
                let request_body: rouille::RequestBody = request.data().unwrap();
                let remove_regex_route_rule: ProcessRegexRouteRule = serde_json::from_reader(request_body).unwrap();
                let app = app_cpy.network_module.clone();
                app.host_route_manager.remove_process_route_rule(remove_regex_route_rule);
                rouille::Response::json(&true)
            },

            (POST) (/dns/set_dns_config) => {
                rouille::Response::json(&true)
            },

            (GET) (/proxy_server/proxy_server_list) => {
                let app = app_cpy.network_module.clone();
                if let Some(list) = app.proxy_server_config_manager.get_all_proxy_server_config() {
                    let proxy_server_list = list.into_iter()
                    .map(|config| api::ProxyServerConfigResponse::new(config))
                    .collect::<Vec<api::ProxyServerConfigResponse>>();
                    rouille::Response::json(&proxy_server_list)
                } else {
                    let empty_proxy_server_list: Vec<api::ProxyServerConfigResponse> = vec![];
                    rouille::Response::json(&empty_proxy_server_list)
                }
            },

            (POST) (/proxy_server/add_proxy_server) => {
                let request_body: rouille::RequestBody = request.data().unwrap();
                let proxy_server_config: api::AddProxyServerConfigRequest = serde_json::from_reader(request_body).unwrap();
                let app = app_cpy.network_module.clone();
                app.proxy_server_config_manager.set_proxy_server_config(ProxyServerConfig {
                    name: proxy_server_config.name,
                    config: ProxyServerConfigType::SocksV5(proxy_server_config.addr, proxy_server_config.port, "".to_string(), "".to_string()),
                    available: true
                });
                rouille::Response::json(&true)
            },

            (POST) (/proxy_server/remove_proxy_server) => {
                let request_body: rouille::RequestBody = request.data().unwrap();
                let proxy_server_config: api::RemoveProxyServerConfigRequest = serde_json::from_reader(request_body).unwrap();
                let app = app_cpy.network_module.clone();
                app.proxy_server_config_manager.remove_proxy_server_config(proxy_server_config.name.as_str());
                rouille::Response::json(&true)
            },

            (GET) (/connection/active_connection_list) => {
                let app = app_cpy.network_module.clone();
                let list = app.active_connection_manager.get_all_connection();
                rouille::Response::json(&list)
            },

            (GET) (/system/process_list) => {
                let app = app_cpy.network_module.clone();
                // let list = app.process_manager.get_all_process();
                rouille::Response::json(&true)
            },

            (GET) (/dns/get_dns_config_list) => {
                let all_dns_host: Vec<DnsHost> = Vec::default();
                rouille::Response::json(&api::GetDnsConfigResponse::new("".to_string(), "".to_string(), all_dns_host))
            },

            (POST) (/dns/set_dns_config) => {
                rouille::Response::json(&true)
            },

            (GET) (/overview/network) => {
                if cfg!(target_os="windows") {
                    let dummy_interface = NetworkInterface {
                        interface_name: "windows环境自动设置为最佳配置".to_string(),
                        ip_addr: "0.0.0.0".to_string()
                    };

                    let mut dummy_interfaces = Vec::with_capacity(1);
                    dummy_interfaces.push(dummy_interface.get_copy());
                    rouille::Response::json(&api::NetworkOverview{
                        interface_list: dummy_interfaces,
                        network_state: true,
                        bind_interface: dummy_interface
                    })
                } else {
                    let app = app_cpy.network_module.clone();
                    let interfaces = app.clone().system_manager.get_network_interface().unwrap_or_else(||vec![]);
                    let network_state = app.clone().dns_config_manager.get_local_dns_state();
                    let bind_dns_interface = &app.clone().bind_network_interface.lock().unwrap().get_copy();
                    rouille::Response::json(&api::NetworkOverview{
                        interface_list: interfaces,
                        network_state: network_state,
                        bind_interface: bind_dns_interface.get_copy()
                    })
                }
            },

            (GET) (/process/get_all_process) => {
                let process_query = request.get_param("process_query").unwrap_or_else(||"".to_string());
                let app = app_cpy.network_module.clone();
                let process_vec = app.system_manager.get_all_process(process_query);
                rouille::Response::json(&process_vec)
            },

            _ => rouille::Response::empty_404()
        )
    });
}

fn setup_log() {
    log4rs::init_file("./config/logrs.yaml", Default::default()).unwrap();
}

/// App
pub struct App {
    pub network_module: Arc<NetworkModule>,
}

impl App {
    pub fn new(network_module: Arc<NetworkModule>) -> Self {
        Self {
            network_module,
        }
    }

    pub fn start(&self) {
        // run network module
        let mut network = self.network_module.clone();
        let background_network = network.clone();
        spawn(move || background_network.run());
        // network.setup_dns();

        #[cfg(target_os = "windows")]
        {
            let mut network_module = self.network_module.clone();
            spawn(move || {
                let ipv4_packet_interceptor = Ipv4PacketInterceptor {
                    session_route_strategy: network_module.session_route_strategy.clone(),
                    nat_session_manager: network_module.nat_session_manager.clone(),
                    fake_ip_manager: network_module.fake_ip_manager.clone(),
                    proxy_config_manager: network_module.proxy_server_config_manager.clone(),
                    process_manager: network_module.system_manager.clone(),
                    connection_manager: network_module.active_connection_manager.clone(),
                    host_route_manager: network_module.host_route_manager.clone(),
                    tcp_relay_listen_port: network_module.tcp_relay_listen_port
                };

                ipv4_packet_interceptor.run();
            });
        }
    }

    pub fn setup_dns(&self) {
        log::info!("set up dns");
        NetworkModule::setup_dns(&self.network_module);
    }

    pub fn setup_dns_with_primary_ip(&self, network_interface: NetworkInterface) {
        if cfg!(target_os="macos") {
            let mut bind_network_interface = self.network_module.bind_network_interface.lock().unwrap();
            bind_network_interface.ip_addr = network_interface.ip_addr.clone();
            bind_network_interface.interface_name = network_interface.interface_name.clone();
            log::info!("setup dns with interface {:?}", network_interface.get_copy());

            let primary_ip = network_interface.interface_name;
            if primary_ip.is_empty() {
                self.setup_dns()
            } else {
                log::info!("set up dns with primary ip {}", primary_ip);
                self.network_module.setup_dns_with_interface_name(primary_ip);
            }
        }
    }

    pub fn clear_dns(&self) {
        log::info!("clear dns");
        self.network_module.clear_dns();
    }

    pub fn clear_dns_with_primary_ip(&self, network_interface: NetworkInterface) {
        if cfg!(target_os="macos") {
            let mut bind_network_interface = self.network_module.bind_network_interface.lock().unwrap();
            bind_network_interface.ip_addr = "".to_string();
            bind_network_interface.interface_name = "".to_string();
            let primary_ip = network_interface.interface_name.to_string();
            if primary_ip.is_empty() {
                self.network_module.clear_dns();
            } else {
                log::info!("clear dns with primary ip {}", primary_ip);
                self.network_module.clear_dns_with_interface_name(primary_ip);
            }
        }
    }

    pub fn clone(&self) -> App {
        let b = self.network_module.clone();
        App {
            network_module: b
        }
    }
}

///
pub struct NetworkModule {
    pub dns_listen: String,
    pub dns_setup: DNSSetup,
    pub nat_session_manager: Arc<Mutex<NatSessionManager>>,
    pub host_route_manager: Arc<HostRouteManager>,
    pub session_route_strategy: Arc<DashMap<u16, HostRouteStrategy>>,
    pub fake_ip_manager: Arc<FakeIpManager>,
    pub proxy_server_config_manager: Arc<ProxyServerConfigManager>,
    pub active_connection_manager: Arc<ActiveConnectionManager>,
    pub system_manager: Arc<SystemManager>,
    pub dns_config_manager: Arc<DnsConfigManager>,
    pub bind_network_interface: Arc<Mutex<NetworkInterface>>,
    pub tcp_relay_listen_addr: String,
    pub tcp_relay_listen_port: u16
}

impl NetworkModule {
    pub fn new(dns_listen: &str, net_session_begin_port: u16, tcp_relay_listen_addr: String, tcp_relay_listen_port: u16, db: Arc<core::db::Db>) -> Self {
        Self {
            dns_listen: dns_listen.to_string(),
            dns_setup: sys::sys::DNSSetup::new(dns_listen.to_string()),
            nat_session_manager: Arc::new(Mutex::new(NatSessionManager::new(net_session_begin_port))),
            host_route_manager: Arc::new(HostRouteManager::new(db.clone())),
            session_route_strategy: Arc::new(DashMap::with_capacity(512)),
            fake_ip_manager: Arc::new(FakeIpManager::new((10, 0, 0, 100))),
            proxy_server_config_manager: Arc::new(ProxyServerConfigManager::new(db.clone())),
            active_connection_manager: Arc::new(Default::default()),
            system_manager: Arc::new(SystemManager { system: Default::default() }),
            dns_config_manager: Arc::new(DnsConfigManager::new(db.clone())),
            bind_network_interface: Arc::new(Mutex::new(NetworkInterface { interface_name: "".to_string(), ip_addr: "".to_string()})),
            tcp_relay_listen_addr,
            tcp_relay_listen_port
        }
    }

    pub fn run_relay_server(&self) {
        log::info!("run relay server")
    }

    #[cfg(target_os = "macos")]
    pub fn set_rlimit(&self, limit: u64) {
        set_rlimit(limit);
    }

    pub fn run(&self) {
        #[cfg(target_os = "macos")]
        self.set_rlimit(30000);
        let nat_session_manager = self.nat_session_manager.clone();
        let fake_ip_manager = self.fake_ip_manager.clone();
        let host_route_manager = self.host_route_manager.clone();
        let session_route_strategy = self.session_route_strategy.clone();
        let proxy_server_config_manager = self.proxy_server_config_manager.clone();
        let active_connection_manager = self.active_connection_manager.clone();
        let process_manager = self.system_manager.clone();
        let dns_config_manager = self.dns_config_manager.clone();

        // start tun_server
        let (stared_event_sender, mut stared_event_receiver) = std::sync::mpsc::channel();
        self.run_sync_component(nat_session_manager.clone(), stared_event_sender);
        match stared_event_receiver.recv_timeout(Duration::from_secs(10)) {
            Ok(stared) => {
                log::info!("network sync component stared")
            }
            Err(_) => {
                log::info!("network sync component start fail");
                exit(1);
            }
        }

        // start dns_server & tcp_relay_server
        self.run_async_component(nat_session_manager.clone(),
                                 fake_ip_manager.clone(),
                                 host_route_manager.clone(),
                                 session_route_strategy.clone(),
                                 proxy_server_config_manager.clone(),
                                 active_connection_manager.clone(),
                                 process_manager.clone(),
                                 dns_config_manager.clone());
    }

    pub fn run_sync_component(&self, nat_session_manager: Arc<Mutex<NatSessionManager>>, stared_event_sender: std::sync::mpsc::Sender<bool>) {
        #[cfg(target_os = "windows")]
        {
            stared_event_sender.send(true);
            return;
        }

        let tun_ip = self.tcp_relay_listen_addr.clone();
        let relay_port = self.tcp_relay_listen_port;
        log::info!("run sync component");
        // start tun_server
        let mut tun_server = TunServer {
            tun_ip: tun_ip.clone(),
            tun_cidr: "10.0.0.0/16".to_string(),
            tun_name: "utun9".to_string(),
            relay_addr: Ipv4Addr::from_str(&tun_ip).unwrap(),
            relay_port,
            nat_session_manager,
        };
        spawn(move || tun_server.run_tun_server(stared_event_sender));
    }

    pub fn run_async_component(&self, nat_session_manager: Arc<Mutex<NatSessionManager>>,
                               fake_ip_manager: Arc<FakeIpManager>,
                               host_route_manager: Arc<HostRouteManager>,
                               session_route_strategy: Arc<DashMap<u16, HostRouteStrategy>>,
                               proxy_server_config_manager: Arc<ProxyServerConfigManager>,
                               active_connection_manager: Arc<ActiveConnectionManager>,
                               process_manager: Arc<SystemManager>,
                               dns_config_manager: Arc<DnsConfigManager>) {

        log::info!("run async component");
        let run_time = match tokio::runtime::Builder::new_current_thread()
            .enable_all()
            // .worker_threads(process_manager.get_available_processor_num())
            // .max_blocking_threads(process_manager.get_available_processor_num() * 2)
            .worker_threads(1)
            .max_blocking_threads(1)
            .build() {

            Ok(run_time) => {
                run_time
            }
            Err(errors) => {
                log::error!("create runtime error, {}", errors);
                return;
            }
        };
        run_time.block_on(async {

            // dns resolver
            let resolver_config = self.default_resolver_config();
            let resolver_opts = self.default_resolver_opts();
            let resolver = async_std_resolver::resolver(resolver_config, resolver_opts).await.expect("failed to connect resolver");

            // forward dns resolver
            let forward_resolver_config = self.forward_resolver_config();
            let forward_resolver_opts = self.default_resolver_opts();
            let forward_resolver = async_std_resolver::resolver(forward_resolver_config, forward_resolver_opts).await.expect("failed to connect resolver");

            // dns server
            let dns_server = DnsManager {
                resolver: Arc::new(resolver.clone()),
                forward_resolver: Arc::new(forward_resolver.clone()),
                fake_ip_manager: fake_ip_manager.clone(),
                dns_config_manager: dns_config_manager.clone(),
                dns_listen: "127.0.0.1:53".to_string(),
            };
            log::info!("start run dns sever");
            #[cfg(target_os = "macos")]
            dns_server.run_dns_server();
            log::info!("start run dns sever complete");

            let tcp_relay_listen_port = self.tcp_relay_listen_port;
            let tcp_relay_listen_port_octets = Ipv4Addr::from_str(&self.tcp_relay_listen_addr).unwrap().octets();
            // tcp_relay_server
            let tcp_relay_server = TcpRelayServer {
                resolver: Arc::new(resolver.clone()),
                fake_ip_manager: fake_ip_manager.clone(),
                nat_session_manager: nat_session_manager.clone(),
                host_route_manager: host_route_manager.clone(),
                session_route_strategy: session_route_strategy.clone(),
                active_connection_manager: active_connection_manager.clone(),
                proxy_server_config_manager: proxy_server_config_manager.clone(),
                listen_addr: (tcp_relay_listen_port_octets[0], tcp_relay_listen_port_octets[1], tcp_relay_listen_port_octets[2], tcp_relay_listen_port_octets[3]),
                listen_port: tcp_relay_listen_port,
                process_manager: process_manager.clone(),
                dns_config_manager
            };
            log::info!("start tcp relay sever");
            tcp_relay_server.run().await;
            log::info!("start tcp relay sever complete");
        });
    }

    pub fn setup_dns(&self) {
        log::info!("setup run dns server, listen at {}", self.dns_listen);
        self.dns_setup.set_dns();
        self.dns_config_manager.mark_local_dns_start();
    }

    pub fn setup_dns_with_interface_name(&self, interface_name: String) {
        log::info!("setup run dns server, listen at {}", self.dns_listen);
        self.dns_setup.set_dns_with_primary_interface_name(interface_name);
        self.dns_config_manager.mark_local_dns_start();
    }

    pub fn clear_dns(&self) {
        self.dns_setup.clear_dns();
        self.dns_config_manager.mark_local_dns_stop();
    }

    pub fn clear_dns_with_interface_name(&self, interface_name: String) {
        self.dns_setup.clear_dns_with_interface_name(interface_name);
        self.dns_config_manager.mark_local_dns_stop();
    }

    fn default_resolver_config(&self) -> ResolverConfig {
        #[cfg(target_os="macos")]
        let gateway = get_gateway();
        #[cfg(target_os="windows")]
        let gateway = "192.168.0.1".to_string();
        let num_concurrent_reqs = 3;
        let mut name_server_config_group = NameServerConfigGroup::with_capacity(num_concurrent_reqs);
        name_server_config_group.push(
            NameServerConfig {
                socket_addr: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::from_str(&gateway).unwrap(), 53)),
                protocol: Protocol::Udp,
                tls_dns_name: None,
                trust_nx_responses: false,
                bind_addr: None,
            }
        );
        return config::ResolverConfig::from_parts(None, Vec::new(), name_server_config_group);
    }

    fn forward_resolver_config(&self) -> ResolverConfig {

        #[cfg(target_os="macos")]
            let gateway_addr = get_gateway();

        #[cfg(target_os="windows")]
            let gateway_addr = "192.168.0.1".to_string();
        let num_concurrent_reqs = 3;
        let mut name_server_config_group = NameServerConfigGroup::with_capacity(num_concurrent_reqs);
        name_server_config_group.push(
            NameServerConfig {
                socket_addr: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::from_str(gateway_addr.as_str()).unwrap(), 53)),
                protocol: Protocol::Udp,
                tls_dns_name: None,
                trust_nx_responses: false,
                bind_addr: None,
            }
        );
        return config::ResolverConfig::from_parts(None, Vec::new(), name_server_config_group);
    }

    fn default_resolver_opts(&self) -> ResolverOpts {
        let mut resolver_opts = config::ResolverOpts::default();
        resolver_opts.timeout = Duration::from_millis(200);
        resolver_opts.num_concurrent_reqs = 3;
        resolver_opts
    }
}

///
pub struct AppConfig {
    pub tun_ip: String,
    pub tun_cidr: String,
    pub tun_name: String,
    pub relay_addr: Ipv4Addr,
    pub relay_port: u16,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ProcessInfo {
    pub pid: u32,
    pub process_name: String,
    pub process_execute_path: String,
}

impl Default for ProcessInfo {
    fn default() -> Self {
        Self {
            pid: 0,
            process_name: "".to_string(),
            process_execute_path: "".to_string()
        }
    }
}

impl ProcessInfo {

    pub fn get_copy(&self) -> ProcessInfo {
        ProcessInfo {
            pid: self.pid,
            process_name: self.process_name.to_string(),
            process_execute_path: self.process_execute_path.to_string()
        }
    }
}

pub struct SystemManager {
    pub system: sysinfo::System,
}

impl SystemManager {

    pub fn new() -> Self {
        Self {
            system: Default::default()
        }
    }

    pub fn get_process(&self, pid_num: u32) -> Option<ProcessInfo> {
        // TODO: FIXME
        let pid = sysinfo::Pid::from_u32(pid_num);
        let mut system = sysinfo::System::new();
        system.refresh_process(pid);
        return match system.process(pid) {
            None => None,
            Some(process) => {
                #[cfg(target_os="macos")]
                let cmd = {
                    if process.cmd().len() > 0 {
                        process.cmd()[0].to_string()
                    } else {
                        "".to_string()
                    }
                };

                #[cfg(target_os="windows")]
                let cmd = process.exe().to_str().unwrap_or_else(||"").to_string();
                Some(ProcessInfo {
                    pid: pid_num,
                    process_name: cmd.to_string(),
                    process_execute_path: cmd
                })
            }
        }
    }

    pub fn get_process_by_port(&self, port: u16) -> Option<SocketInfo> {
        let af_flags = netstat2::AddressFamilyFlags::IPV4;
        let proto_flags = netstat2::ProtocolFlags::TCP | netstat2::ProtocolFlags::UDP;
        return match netstat2::get_sockets_info(af_flags, proto_flags) {
            Ok(vec) => {
                for socket_info in vec {
                    if socket_info.local_port() == port {
                        return Some(socket_info)
                    }
                }
                None
            }
            Err(errors) => {
                None
            }
        }
    }

    pub fn get_network_interface(&self) -> Option<Vec<NetworkInterface>> {
        match local_ip_address::list_afinet_netifas() {
            Ok(vec) => {
                let mut interface_vec = vec![];
                for (interface, ip) in vec {
                    #[cfg(target_os = "macos")]
                    if matches!(ip, IpAddr::V4(_)) && interface != "lo0"{
                        interface_vec.push(NetworkInterface{
                            interface_name: interface,
                            ip_addr: ip.to_string()
                        })
                    }

                    #[cfg(target_os = "windows")]
                    if matches!(ip, IpAddr::V4(_)) && interface != "rproxifier-tun" && !interface.contains("Loopback") {
                        interface_vec.push(NetworkInterface{
                            interface_name: interface,
                            ip_addr: ip.to_string()
                        });
                    }
                }
                return Some(interface_vec)
            }
            Err(errors) => {
                log::error!("get network interface error")
            }
        }
        None
    }

    pub fn get_all_process(&self, match_str: String) -> Vec<ProcessInfo> {
        let mut system = sysinfo::System::new();
        system.refresh_processes();

        system.processes().into_iter()
            .map(|(pid, process)|{
                let process_name = process.name().to_string();
                let cmd = {
                    if process.cmd().len() > 0 {
                        process.cmd()[0].to_string()
                    } else {
                        process.name().to_string()
                    }
                };

                if process_name.contains(&match_str) || cmd.contains(&match_str) {
                    Some(ProcessInfo {
                        pid: pid.as_u32(),
                        process_name: process.name().to_string(),
                        process_execute_path: cmd
                    })
                } else {
                    None
                }
            })
            .filter(Option::is_some)
            .map(Option::unwrap)
            .collect()
    }

    fn get_available_processor_num_inner(&self) -> Option<usize> {
        Some(num_cpus::get_physical())
    }

    pub fn get_available_processor_num(&self) -> usize {
        Some(num_cpus::get_physical())
            .map_or(1, |core_num| std::cmp::max(core_num, 1))
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct NetworkInterface {
    pub interface_name: String,
    pub ip_addr: String,
}

impl NetworkInterface {
    pub fn get_copy(&self) -> NetworkInterface {
        NetworkInterface {
            interface_name: self.interface_name.to_string(),
            ip_addr: self.ip_addr.to_string()
        }
    }
}