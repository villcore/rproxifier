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

use crate::core::dns_manager::DnsManager;
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
use serde::{Serialize, Deserialize};
use std::collections::HashMap;
use sled::IVec;
use sysinfo::{SystemExt, ProcessExt, PidExt, Process};
use crate::core::host_route_manager::HostRouteManager;
use crate::core::proxy_config_manager::{HostRouteStrategy, ProxyServerConfigManager, ProxyServerConfig, ProxyServerConfigType};
use crate::core::active_connection_manager::ActiveConnectionManager;
use netstat2::{ProtocolSocketInfo, SocketInfo};

mod dns;
mod sys;
mod tun;
mod core;
mod pb;

fn main() {

    setup_log();
    let db = Arc::new(core::db::Db::new("data/db"));
    let mut network = Arc::new(NetworkModule::new("", 10000, db.clone()));

    // setup proxy server config
    network.proxy_server_config_manager.set_proxy_server_config(ProxyServerConfig {
        name: "xperia5".to_string(),
        config: ProxyServerConfigType::SocksV5("192.168.50.58".to_string(), 10808, "".to_string(), "".to_string()),
        available: false
    });

    // setup host route
    // network.host_route_manager.add_route_strategy("\\S+".to_string(), HostRouteStrategy::Proxy("xperia5".to_string(), None, 0));
    network.host_route_manager.add_route_strategy("\\S+".to_string(), HostRouteStrategy::Probe(false, false, "xperia5".to_string(), None, 0));

    //
    let app = Arc::new(App::new(network));
    app.start();

    let app_cpy = app.clone();
    rouille::start_server("localhost:8000", move |request| {
        rouille::router!(request,
            (GET) (/) => {
                rouille::Response::redirect_302("/hello/world")
            },

            (GET) (/hello/world) => {
                println!("hello world");
                rouille::Response::text("hello world")
            },

            (GET) (/panic) => {
                panic!("Oops!")
            },

            (GET) (/{id: u32}) => {
                println!("u32 {:?}", id);
                rouille::Response::empty_400()
            },

            (GET) (/{id: String}) => {
                println!("String {:?}", id);
                rouille::Response::text(format!("hello, {}", id))
            },

            (GET) (/net/get_net_state) => {
                rouille::Response::json(&true)
            },

            (GET) (/net/start_net_state) => {
                app_cpy.setup_dns();
                rouille::Response::json(&true)
            },

            (GET) (/net/stop_net_state) => {
                app_cpy.clear_dns();
                rouille::Response::json(&true)
            },

            (GET) (/route/host_route_list) => {
                let app = app_cpy.network_module.clone();
                let list = app.host_route_manager.get_all_route_strategy();
                rouille::Response::json(&list)
            },

            (GET) (/proxy_server/proxy_server_list) => {
                let app = app_cpy.network_module.clone();
                let list = app.proxy_server_config_manager.get_all_proxy_server_config();
                rouille::Response::json(&list)
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

            _ => rouille::Response::empty_404()
        )
    });
}

/*
fn main() {
    // setup log
    setup_log();

    // run network module
    let mut network = Arc::new(NetworkModule::new("", 10000));
    network.add_route_strategy("github.com".to_string(), HostRouteStrategy::Proxy("192.168.50.58".to_string(), 10808, None, 0));
    network.add_route_strategy("\\S+".to_string(), HostRouteStrategy::Probe(false, false, "192.168.50.58".to_string(), 10808, None, 0));
    let background_network = network.clone();
    spawn(move || background_network.run());

    // setup gui
    let app = App::new(network.clone());
    network.setup_dns();
    sleep(Duration::from_secs(10000));
}
 */

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
    }

    pub fn setup_dns(&self) {
        log::info!("set up dns");
        self.network_module.setup_dns();
    }

    pub fn clear_dns(&self) {
        log::info!("clear dns");
        self.network_module.clear_dns();
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
    pub fake_ip_manager: Arc<FakeIpManager>,
    pub proxy_server_config_manager: Arc<ProxyServerConfigManager>,
    pub active_connection_manager: Arc<ActiveConnectionManager>,
    pub process_manager: Arc<ProcessManager>
}

impl NetworkModule {
    pub fn new(dns_listen: &str, net_session_begin_port: u16, db: Arc<core::db::Db>) -> Self {
        Self {
            // TODO: windows
            dns_listen: dns_listen.to_string(),
            dns_setup: sys::sys::DNSSetup::new(dns_listen.to_string()),
            nat_session_manager: Arc::new(Mutex::new(NatSessionManager::new(net_session_begin_port))),
            host_route_manager: Arc::new(HostRouteManager::new(db.clone())),
            fake_ip_manager: Arc::new(FakeIpManager::new((10, 0, 0, 100))),
            proxy_server_config_manager: Arc::new(ProxyServerConfigManager::new(db.clone())),
            active_connection_manager: Arc::new(Default::default()),
            process_manager: Arc::new(ProcessManager { system: Default::default() })
        }
    }

    pub fn add_route_strategy(&self, host: String, strategy: HostRouteStrategy) {
        self.host_route_manager.add_route_strategy(host, strategy);
    }

    pub fn run_relay_server(&self) {
        log::info!("run relay server")
    }

    pub fn setup_dns(&self) {
        log::info!("setup run dns server, listen at {}", self.dns_listen);
        self.dns_setup.set_dns();
    }

    pub fn clear_dns(&self) {
        self.dns_setup.clear_dns();
    }

    #[cfg(target_os = "macos")]
    pub fn set_rlimit(&self, limit: u64) {
        set_rlimit(limit);
    }

    pub fn run_dns_server(&self) {
        log::info!("run dns server, listen at {}", self.dns_listen);
    }

    pub fn run(&self) {
        #[cfg(target_os = "macos")]
            self.set_rlimit(30000);
        let nat_session_manager = self.nat_session_manager.clone();
        let fake_ip_manager = self.fake_ip_manager.clone();
        let host_route_manager = self.host_route_manager.clone();
        let proxy_server_config_manager = self.proxy_server_config_manager.clone();
        let active_connection_manager = self.active_connection_manager.clone();
        let process_manager = self.process_manager.clone();

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
                                 proxy_server_config_manager.clone(),
                                 active_connection_manager.clone(),
                                 process_manager.clone());
    }

    pub fn run_sync_component(&self, nat_session_manager: Arc<Mutex<NatSessionManager>>, stared_event_sender: std::sync::mpsc::Sender<bool>) {
        log::info!("run sync component");
        // start tun_server
        let mut tun_server = TunServer {
            tun_ip: "10.0.0.1".to_string(),
            tun_cidr: "10.0.0.0/16".to_string(),
            tun_name: "utun9".to_string(),
            relay_addr: Ipv4Addr::from_str("10.0.0.1").unwrap(),
            relay_port: 1300,
            nat_session_manager,
        };
        spawn(move || tun_server.run_tun_server(stared_event_sender));
    }

    pub fn run_async_component(&self, nat_session_manager: Arc<Mutex<NatSessionManager>>,
                               fake_ip_manager: Arc<FakeIpManager>,
                               host_route_manager: Arc<HostRouteManager>,
                               proxy_server_config_manager: Arc<ProxyServerConfigManager>,
                               active_connection_manager: Arc<ActiveConnectionManager>,
                               process_manager: Arc<ProcessManager>) {

        log::info!("run async component");
        let run_time = match tokio::runtime::Builder::new_current_thread().enable_all().build() {
            Ok(run_time) => {
                run_time
            }
            Err(errors) => {
                log::error!("create runtime error, {}", errors);
                return;
            }
        };
        run_time.block_on(async {
            // dns_server
            let resolver_config = self.default_resolver_config();
            let resolver_opts = self.default_resolver_opts();
            let resolver = resolver(resolver_config, resolver_opts).await.expect("failed to connect resolver");
            let dns_server = DnsManager {
                resolver: Arc::new(resolver.clone()),
                fake_ip_manager: fake_ip_manager.clone(),
                dns_listen: "127.0.0.1:53".to_string(),
            };
            log::info!("start run dns sever");
            dns_server.run_dns_server();
            log::info!("start run dns sever complete");

            // tcp_relay_server
            let tcp_relay_server = TcpRelayServer {
                resolver: Arc::new(resolver.clone()),
                fake_ip_manager: fake_ip_manager.clone(),
                nat_session_manager: nat_session_manager.clone(),
                host_route_manager: host_route_manager.clone(),
                active_connection_manager: active_connection_manager.clone(),
                proxy_server_config_manager: proxy_server_config_manager.clone(),
                listen_addr: (127, 0, 0, 1),
                listen_port: 1300,
                process_manager: process_manager.clone()
            };
            log::info!("start tcp relay sever");
            tcp_relay_server.run().await;
            log::info!("start tcp relay sever complete");
        });
    }

    fn default_resolver_config(&self) -> ResolverConfig {
        let num_concurrent_reqs = 3;
        let mut name_server_config_group = NameServerConfigGroup::with_capacity(num_concurrent_reqs);
        name_server_config_group.push(
            NameServerConfig {
                socket_addr: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::from_str("114.114.114.114").unwrap(), 53)),
                protocol: Protocol::Udp,
                tls_dns_name: None,
                trust_nx_responses: false,
                bind_addr: None,
            }
        );

        name_server_config_group.push(
            NameServerConfig {
                socket_addr: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::from_str("223.5.5.5").unwrap(), 53)),
                protocol: Protocol::Udp,
                tls_dns_name: None,
                trust_nx_responses: false,
                bind_addr: None,
            }
        );

        name_server_config_group.push(
            NameServerConfig {
                socket_addr: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::from_str("114.114.114.114").unwrap(), 53)),
                protocol: Protocol::Tcp,
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

pub struct ProcessManager {
    pub system: sysinfo::System,
}

impl ProcessManager {

    pub fn new() -> Self {
        Self {
            system: Default::default()
        }
    }

    pub fn get_process(&self, pid_num: u32) -> Option<String> {
        // TODO: FIXME
        let pid = sysinfo::Pid::from_u32(pid_num);
        let mut system = sysinfo::System::new();
        system.refresh_process(pid);
        return match system.process(pid) {
            None => None,
            Some(process) => {
                Some(process.name().to_string())
            }
        }
    }

    pub fn get_process_by_port(&self, port: u16) -> Option<SocketInfo> {
        let af_flags = netstat2::AddressFamilyFlags::IPV4;
        let proto_flags = netstat2::ProtocolFlags::TCP;
        return match netstat2::get_sockets_info(af_flags, proto_flags) {
            Ok(vec) => {
                for socket_info in vec {
                    if socket_info.local_port() == port {
                        return Some(socket_info)
                    }
                }
                None
            }
            Err(_) => {
                None
            }
        }
    }
}

#[cfg(test)]
pub mod tests {
    use std::io::Error;
    use std::net::{Ipv4Addr, SocketAddrV4};
    use std::str::FromStr;

    use regex::Captures;
    use tokio::io;
    use tokio::net::{TcpStream, ToSocketAddrs};
    use tokio::time::Duration;

    use crate::{HostRouteManager, HostRouteStrategy, setup_log};
    use crate::HostRouteStrategy::{Probe, Proxy};
    use std::sync::Arc;
    use sled::Db;
    use sysinfo::SystemExt;
    use std::time::{SystemTime, UNIX_EPOCH};
    use netstat2::ProtocolSocketInfo;

    // #[test]
    // pub fn test_host_route_manager() {
    //     setup_log();
    //     log::info!("test");
    //
    //     let route = HostRouteManager::new(vec![
    //         ("google.com".to_string(), Proxy("www.baidu1.com".to_string(), 80, None, 0)),
    //         ("facebook.com".to_string(), Probe(false, false, "www.baidu2.com".to_string(), 80, None, 0)),
    //         ("www.youtube.com".to_string(), Proxy("www.bing3.com".to_string(), 80, None, 0))
    //     ]);
    //
    //     let host = "www.facebook.com";
    //     match route.get_route_strategy(host) {
    //         None => {
    //             log::info!("get host {} strategy invalid", host);
    //         }
    //         Some(strategy) => {
    //             log::info!("get host {} strategy {:?}", host, strategy);
    //         }
    //     }
    //     log::info!("first get complete");
    //
    //     route.mark_probe_direct(host, true);
    //     match route.get_route_strategy(host) {
    //         None => {
    //             log::info!("get host {} strategy invalid", host);
    //         }
    //         Some(strategy) => {
    //             log::info!("get host {} strategy {:?}", host, strategy);
    //         }
    //     }
    // }

    #[test]
    pub fn test_regex() {
        setup_log();
        let regex_a = regex::Regex::from_str("github.com").unwrap();
        match regex_a.captures("www.github.com") {
            None => {
                log::info!("capture empty")
            }
            Some(_) => {
                log::info!("capture valid")
            }
        }
    }

    #[test]
    pub fn test_tokio_connect_timeout() {
        setup_log();
        let run_time = match tokio::runtime::Builder::new_current_thread().enable_all().build() {
            Ok(run_time) => {
                run_time
            }
            Err(errors) => {
                log::error!("create runtime error, {}", errors);
                return;
            }
        };
        run_time.block_on(async {
            log::info!("connect start");
            let timeout_sec = Duration::from_secs(5);
            let connected_socket = tokio::select! {
                connected_socket = TcpStream::connect(("108.160.166.137", 443)) => {
                    match connected_socket {
                        Ok(socket) => {
                            Some(socket)
                        }
                        Err(errors) => {
                            None
                        }
                    }
                }

                _ = tokio::time::sleep(timeout_sec) => {
                    None
                }
            };
            log::info!("connect end");
        });
    }

    // #[test]
    // pub fn test_inner_host_route_strategy() {
    //     setup_log();
    //     let mut host = Arc::new(HostRouteManager::new(vec![]));
    //     host.add_route_strategy("github.com".to_string(), HostRouteStrategy::Proxy("192.168.50.58".to_string(), 10808, None, 0));
    //     host.add_route_strategy("\\S+".to_string(), HostRouteStrategy::Probe(false, false, "192.168.50.58".to_string(), 10808, None, 0));
    //     host.get_all_route_strategy();
    // }

    #[test]
    pub fn test_db() {
        setup_log();
        let db = match sled::open("data/db") {
            Ok(db) => {
                db
            }
            Err(errors) => {
                log::error!("open data file error, {}", errors);
                return;
            }
        };

        let host = "www.baidu.com";
        db.insert(host, "123");
        let host_result = db.get(host);
    }

    #[test]
    pub fn test_serde() {
        let a = vec![("123", HostRouteStrategy::Direct)];
        let json = serde_json::to_string(&a).unwrap();
        println!("{}", json);

        let b: Vec<(String, HostRouteStrategy)> = serde_json::from_str(&json).unwrap();
        println!("{:?}", b);

        let bytes = serde_json::to_vec(&a).unwrap();
        let bytes_obj: Vec<(String, HostRouteStrategy)> = serde_json::from_slice(&bytes).unwrap();
        println!("{:?}", bytes_obj);
    }

    #[test]
    pub fn test_get_process() {
        for i in 0..1 {
            let start = SystemTime::now();
            let since_the_epoch = start
                .duration_since(UNIX_EPOCH)
                .unwrap().as_millis();
            let af_flags = netstat2::AddressFamilyFlags::IPV4;
            let proto_flags = netstat2::ProtocolFlags::TCP;
            let sockets_info = netstat2::get_sockets_info(af_flags, proto_flags).unwrap();

            for i in sockets_info {
               let pid = i.associated_pids.get(0).unwrap();
                match i.protocol_socket_info {
                    ProtocolSocketInfo::Tcp(a) => {
                        println!("{} => {}", pid, a.local_port)
                    }
                    ProtocolSocketInfo::Udp(_) => {}
                }
            }

            let end = SystemTime::now();
            let end_the_epoch = end
                .duration_since(UNIX_EPOCH)
                .unwrap().as_millis();
            println!("{}", end_the_epoch - since_the_epoch)
        }
    }
}