use std::sync::{Arc, Mutex};
use async_std_resolver::AsyncStdResolver;
use crate::dns::resolve::{FakeIpManager, resolve_host};
use crate::core::nat_session::NatSessionManager;
use std::net::{Ipv4Addr, SocketAddr};
use tokio::time::Duration;
use tokio::net::{TcpStream, TcpListener, UdpSocket};
use crate::core::StreamPipe;
use crate::core::host_route_manager::HostRouteManager;
use crate::core::proxy_config_manager::{HostRouteStrategy, ProxyServerConfig, ProxyServerConfigType, ConnectionRouteRule, RouteRule};
use crate::{ProxyServerConfigManager, SystemManager, ProcessInfo};
use crate::core::active_connection_manager::{ActiveConnectionManager, ActiveConnection, ConnectionTransferType};
use crate::core::dns_manager::DnsConfigManager;
use std::io::Error;

pub struct TcpRelayServer {
    pub resolver: Arc<AsyncStdResolver>,
    pub fake_ip_manager: Arc<FakeIpManager>,
    pub nat_session_manager: Arc<Mutex<NatSessionManager>>,
    pub host_route_manager: Arc<HostRouteManager>,
    pub proxy_server_config_manager: Arc<ProxyServerConfigManager>,
    pub active_connection_manager: Arc<ActiveConnectionManager>,
    pub process_manager: Arc<SystemManager>,
    pub dns_config_manager: Arc<DnsConfigManager>,
    pub listen_addr: (u8, u8, u8, u8),
    pub listen_port: u16,
}

impl TcpRelayServer {

    pub async fn run(&self) {
        self.run_session_port_recycler();

        // bind address
        self.run_tcp_server().await;
    }

    fn run_session_port_recycler(&self) {
        let recycler_session_manager = self.nat_session_manager.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(60)).await;
                log::info!("start recycle invalid session port at time {}",  NatSessionManager::get_now_time());
                let mut session_manager = recycler_session_manager.lock().unwrap();
                session_manager.recycle_port();
                log::info!("recycle invalid session port complete at time {}",  NatSessionManager::get_now_time());
            }
        });
    }

    async fn run_tcp_server(&self) {
        // TODO: modify
        let listen_addr = (Ipv4Addr::new(0, 0, 0, 0), 13000);
        let tcp_listener = match TcpListener::bind(listen_addr).await {
            Ok(_tcp_listener) => {
                _tcp_listener
            }
            Err(err) => {
                log::error!("bind tun tcp server error {}", err.to_string());
                return;
            }
        };

        log::info!("tun tcp relay server listen on {}:{}", listen_addr.0, listen_addr.1);
        while let Ok((mut tcp_socket, socket_addr)) = tcp_listener.accept().await {
            self.accept_socket(tcp_socket, socket_addr).await;
        }
    }

    async fn accept_socket(&self, mut tcp_socket: TcpStream, socket_addr: SocketAddr) {
        log::info!("tun tcp relay server accept relay src socket {} ", socket_addr.to_string());
        let mut nat_session_manager = match self.nat_session_manager.lock() {
            Ok(nat_session_manager) => nat_session_manager,
            Err(errors) => {
                log::error!("get nat session manager error, {}", errors);
                return
            }
        };

        let session_port = socket_addr.port();
        match nat_session_manager.get_port_session_tuple(session_port) {
            None => {
                log::warn!("invalid session port {}", session_port);
            }
            Some((src_addr, src_port, dst_addr, dst_port)) => {
                log::info!("real address is {}:{} -> {}:{}", src_addr, src_port, dst_addr, dst_port);
                let resolver_copy = self.resolver.clone();
                let fake_ip_manager = self.fake_ip_manager.clone();
                let host_route_manager = self.host_route_manager.clone();
                let proxy_server_config_manager = self.proxy_server_config_manager.clone();
                let active_connection_manager = self.active_connection_manager.clone();
                let mut process_manager = self.process_manager.clone();
                let dns_config_manager = self.dns_config_manager.clone();

                tokio::spawn(async move {
                    let dst_addr_bytes = dst_addr.octets();
                    let fake_ip = (dst_addr_bytes[0], dst_addr_bytes[1], dst_addr_bytes[2], dst_addr_bytes[3]);
                    let origin_host_port = match fake_ip_manager.get_host(&fake_ip) {
                        None => {
                            log::error!("get host from fake_ip {} error", dst_addr.to_string());
                            return
                        }

                        Some(host) => (host, dst_port)
                    };

                    let process_info = if let Some(socket_info) = process_manager.get_process_by_port(src_port) {
                        let pid = *socket_info.associated_pids.get(0).unwrap_or_else(|| &0);
                        let process_info = process_manager.get_process(pid)
                            .unwrap_or_else(|| ProcessInfo {
                                pid: 0,
                                process_name: "".to_string(),
                                process_execute_path: "".to_string(),
                            });
                        Some(process_info)
                    } else {
                        Some(ProcessInfo {
                            pid: 0,
                            process_name: "".to_string(),
                            process_execute_path: "".to_string(),
                        })
                    }.unwrap();
                    let (rule_strategy, _) = match host_route_manager.get_host_route_strategy(Some(&process_info), &origin_host_port.0) {
                        None => (HostRouteStrategy::Direct, ConnectionRouteRule::new()),
                        Some(strategy) => strategy
                    };
                    match rule_strategy {
                        HostRouteStrategy::Proxy(proxy_config_name, direct_ip, last_update_time) => {
                            // host_route_manager
                            // TODO: dns_lookup cache.
                            let (addr, port) = match proxy_server_config_manager.get_proxy_server_config(proxy_config_name.as_str()) {
                                None => {
                                    log::error!("get proxy server {} error", proxy_config_name);
                                    return;
                                }
                                Some(proxy_config) => {
                                    match proxy_config.config {
                                        ProxyServerConfigType::SocksV5(addr, port, _, _) => {
                                            (addr, port)
                                        }
                                       _ => {
                                           return;
                                       }
                                    }
                                }
                            };
                            let (proxy_direct_ip, proxy_port) = match TcpRelayServer::resolve_host_ip(resolver_copy, &addr, port).await {
                                None => {
                                    return
                                },
                                Some((ip, port)) => (ip, port)
                            };

                            let target_addr = format!("{}:{}", origin_host_port.0, origin_host_port.1);
                            let mut proxy_socket = tokio_socks::tcp::Socks5Stream::connect((proxy_direct_ip.as_str(), proxy_port), target_addr).await.unwrap();
                            // TODO: add connection

                            // TcpRelayServer::add_active_connection(session_port, src_addr, src_port, dst_port, &active_connection_manager, connection_route_rule, Some(process_info.get_copy()), &origin_host_port);
                            let mut stream_pipe = StreamPipe::new(session_port, active_connection_manager.clone(),4096, tcp_socket, proxy_socket);
                            stream_pipe.pipe_loop().await
                        }
                        _ => {
                            return;
                        }
                    }
                });
            }
        }
    }

    pub(crate) fn add_active_connection(session_port: u16, src_addr: Ipv4Addr, src_port: u16, dst_port: u16,
                                        active_connection_manager: &Arc<ActiveConnectionManager>,
                                        connection_route_rule: ConnectionRouteRule,
                                        transfer_type: ConnectionTransferType,
                                        process_info: Option<ProcessInfo>,
                                        origin_host_port: &(String, u16)) {

        let process_info = process_info
            .unwrap_or_else(|| ProcessInfo {
                pid: 0,
                process_name: "".to_string(),
                process_execute_path: "".to_string()
            });
        active_connection_manager.add_connection(ActiveConnection {
            pid: process_info.pid,
            process_name: process_info.process_name,
            process_execute_path: process_info.process_execute_path,
            session_port,
            src_addr: src_addr.to_string(),
            src_port,
            dst_addr: origin_host_port.0.clone(),
            dst_port,
            route_rule: connection_route_rule,
            transfer_type,
            tx: 0,
            rx: 0,
            start_timestamp: NatSessionManager::get_now_time(),
            latest_touch_timestamp: NatSessionManager::get_now_time(),
            pre_tx: 0,
            pre_rx: 0,
            pre_touch_timestamp: 0
        });
    }

    pub async fn connect_with_timeout<A: tokio::net::ToSocketAddrs>(addr: A, timeout_sec: Duration) -> anyhow::Result<TcpStream> {
        let timeout_sec = Duration::from_secs(5);
        let connected_socket = tokio::select! {
            connected_socket = TcpStream::connect(addr) => {
                match connected_socket {
                    Ok(socket) => {
                        anyhow::Ok(socket)
                    }
                    Err(errors) => {
                        Err(anyhow::anyhow!(format!("connect error, {}", errors)))
                    }
                }
            }

            _ = tokio::time::sleep(timeout_sec) => {
                    Err(anyhow::anyhow!(format!("connect timeout")))
            }
        };
        return connected_socket;
    }

    async fn resolve_direct_ip_port(dst_addr: Ipv4Addr, dst_port: u16,
                                    resolver: Arc<AsyncStdResolver>,
                                    fake_ip_manager: Arc<FakeIpManager>) -> Option<(String, u16)> {

        let dst_addr_bytes = dst_addr.octets();
        let fake_ip = (dst_addr_bytes[0], dst_addr_bytes[1], dst_addr_bytes[2], dst_addr_bytes[3]);
        let direct_address_port = match fake_ip_manager.get_host(&fake_ip) {
            None => {
                log::error!("get host from fake_ip {} error", dst_addr.to_string());
                None
            }

            Some(host) => {
                log::info!("get host from fake_ip {} success, host {}", dst_addr.to_string(), host);
                TcpRelayServer::resolve_host_ip(resolver, &host, dst_port).await
            }
        };
        direct_address_port
    }

    async fn resolve_host_ip(resolver: Arc<AsyncStdResolver>, host: &str, port: u16) -> Option<((String, u16))> {
        let mut host_splits: Vec<&str> = host.split(".").collect();
        let host_num_splits: Vec<u8> = host_splits.iter()
            .map(|s| s.parse::<u8>())
            .filter(|r| r.is_ok())
            .map(|r| r.unwrap())
            .collect();

        let host_split_len = host_splits.len();
        if host_split_len == 4 && host_num_splits.len() == host_split_len {
            // 如果是点号ip地址格式，选择直接连接
            Some((host.to_string(), port))
        } else {
            // 如果是字符串host格式，需要dns解析
            match resolve_host(resolver, &host).await {
                Ok(ipv4_addr) => {
                    Some((ipv4_addr.to_string(), port))
                }
                Err(_) => {
                    log::error!("resolve host {} error", host);
                    None
                }
            }
        }
    }
}