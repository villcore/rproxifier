use std::collections::HashMap;
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
use bytes::BytesMut;
use dashmap::DashMap;
use dashmap::mapref::one::Ref;
use libc::exit;

pub const TCP_RELAY_SERVER_BUFFER_POOL_SIZE: usize = 256;
pub const TCP_RELAY_SOCKET_BUFFER_SIZE: usize = 4 * 1024;

pub struct TcpRelayServer {
    pub resolver: Arc<AsyncStdResolver>,
    pub fake_ip_manager: Arc<FakeIpManager>,
    pub nat_session_manager: Arc<Mutex<NatSessionManager>>,
    pub host_route_manager: Arc<HostRouteManager>,
    pub session_route_strategy: Arc<DashMap<u16, HostRouteStrategy>>,
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
                log::info!("start recycle invalid session port at time {}", NatSessionManager::get_now_time());
                let mut session_manager = recycler_session_manager.lock().unwrap();
                session_manager.recycle_port();
                log::info!("recycle invalid session port complete at time {}", NatSessionManager::get_now_time());
            }
        });
    }

    async fn run_tcp_server(&self) {
        // TODO: modify
        let (a, b, c, d) = self.listen_addr;
        let listen_addr = (Ipv4Addr::new(a, b, c, d), self.listen_port);
        let tcp_listener = match TcpListener::bind(listen_addr).await {
            Ok(_tcp_listener) => {
                _tcp_listener
            }
            Err(err) => {
                log::error!("bind tun tcp server error {}", err.to_string());
                return;
            }
        };

        let buffer_pool = Arc::new(crossbeam::queue::ArrayQueue::new(TCP_RELAY_SERVER_BUFFER_POOL_SIZE));
        log::info!("tun tcp relay server listen on {}:{}", listen_addr.0, listen_addr.1);
        while let Ok((mut tcp_socket, socket_addr)) = tcp_listener.accept().await {
            let buffer_pool = buffer_pool.clone();
            self.accept_socket(tcp_socket, socket_addr, buffer_pool).await;
        }
    }

    async fn accept_socket(&self, mut tcp_socket: TcpStream, socket_addr: SocketAddr, buffer_pool: Arc<crossbeam::queue::ArrayQueue<(BytesMut, BytesMut)>>) {
        #[cfg(target_os = "windows")]
        self.accept_socket_for_windows(tcp_socket, socket_addr, buffer_pool).await;
        #[cfg(target_os = "macos")]
        self.accept_socket_for_macos(tcp_socket, socket_addr, buffer_pool).await;
    }

    async fn accept_socket_for_windows(&self, mut tcp_socket: TcpStream, socket_addr: SocketAddr, buffer_pool: Arc<crossbeam::queue::ArrayQueue<(BytesMut, BytesMut)>>) {
        log::info!("tun tcp relay server accept relay src socket {} ", socket_addr.to_string());
        let mut nat_session_manager = match self.nat_session_manager.lock() {
            Ok(nat_session_manager) => nat_session_manager,
            Err(errors) => {
                log::error!("get nat session manager error, {}", errors);
                return;
            }
        };

        let session_port = socket_addr.port();
        match nat_session_manager.get_port_session_tuple(session_port) {
            None => {
                log::warn!("invalid session port {}", session_port);
            }
            Some((src_addr, src_port, dst_addr, dst_port)) => {
                log::info!("real address is {}:{} -> {}:{}", src_addr, src_port, dst_addr, dst_port);
                let fake_ip_manager = self.fake_ip_manager.clone();
                let host_route_manager = self.host_route_manager.clone();
                let session_route_strategy = self.session_route_strategy.clone();
                let proxy_server_config_manager = self.proxy_server_config_manager.clone();
                let active_connection_manager = self.active_connection_manager.clone();
                let mut process_manager = self.process_manager.clone();

                tokio::spawn(async move {
                    let dst_addr_bytes = dst_addr.octets();
                    let fake_ip = (dst_addr_bytes[0], dst_addr_bytes[1], dst_addr_bytes[2], dst_addr_bytes[3]);
                    let origin_host_port = match fake_ip_manager.get_host(&fake_ip) {
                        None => {
                            (dst_addr.to_string(), dst_port)
                        }

                        Some(host) => (host, dst_port)
                    };
                    let session_route_strategy = match session_route_strategy.get(&session_port) {
                        None => {
                            return;
                        }
                        Some(rule_strategy) => {
                            rule_strategy.value().get_copy()
                        }
                    };

                    log::info!("Get session route strategy {:?} for session_port {}", &session_route_strategy, session_port);
                    match session_route_strategy {
                        HostRouteStrategy::Direct => {
                            let (host, port) = (dst_addr, dst_port);
                            let mut dst_socket = match TcpStream::connect((host.to_string(), port)).await {
                                Ok(dst_socket) => {
                                    log::info!("session {} => connect real_addr {}:{}", session_port, &host, port);
                                    dst_socket
                                }
                                Err(errors) => {
                                    log::error!("session {} => connect real addr {}:{} error, {}", session_port, &host, port, errors);
                                    return;
                                }
                            };

                            let mut stream_pipe = StreamPipe::new(session_port, active_connection_manager.clone(), TCP_RELAY_SOCKET_BUFFER_SIZE, buffer_pool, tcp_socket, dst_socket);
                            stream_pipe.pipe_loop().await;
                        }

                        HostRouteStrategy::Proxy(proxy_config_name, direct_ip, last_update_time) => {
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
                            let (proxy_direct_ip, proxy_port) = (addr, port);
                            let target_addr = format!("{}:{}", origin_host_port.0, origin_host_port.1);
                            let mut proxy_socket = match tokio_socks::tcp::Socks5Stream::connect((proxy_direct_ip.as_str(), proxy_port), target_addr).await {
                                Ok(stream) => stream,
                                Err(errors) => {
                                    log::error!("Connect socks5 proxy {}:{} error, {}", proxy_direct_ip.as_str(), proxy_port, errors);
                                    return;
                                }
                            };
                            let mut stream_pipe = StreamPipe::new(session_port, active_connection_manager.clone(), TCP_RELAY_SOCKET_BUFFER_SIZE, buffer_pool, tcp_socket, proxy_socket);
                            stream_pipe.pipe_loop().await
                        }

                        HostRouteStrategy::Probe(already_checked, need_proxy, proxy_config_name, direct_ip, last_update_time) => {
                            let mut need_proxy = need_proxy;
                            let (dst_socket, direct_connected) = if !already_checked {
                                let (direct_address, direct_port) = (dst_addr.to_string(), dst_port);
                                log::info!("Try probe connect to {}:{}", &direct_address, direct_port);
                                let (dst_socket, direct_connected) = match TcpRelayServer::connect_with_timeout((direct_address, direct_port), Duration::from_secs(1)).await {
                                    Ok(mut dst_socket) => {
                                        log::info!("Try probe connect succeed");
                                        (Some(dst_socket), true)
                                    }
                                    Err(errors) => {
                                        log::error!("Try probe connect error, {}", errors);
                                        (None, false)
                                    }
                                };
                                host_route_manager.mark_probe_host_need_proxy(&origin_host_port.0, !direct_connected);
                                (dst_socket, direct_connected)
                            } else {
                                // need proxy already checked
                                if need_proxy {
                                    (None, false)
                                } else {
                                    let (direct_address, direct_port) = (dst_addr.to_string(), dst_port);
                                    log::info!("connect to {}:{}", direct_address, direct_port);
                                    match TcpRelayServer::connect_with_timeout((direct_address, direct_port), Duration::from_secs(1)).await {
                                        Ok(mut dst_socket) => {
                                            (Some(dst_socket), true)
                                        }
                                        Err(errors) => {
                                            // log::error!("Connect to {}:{} failed, {}", direct_address, direct_port, errors);
                                            return;
                                        }
                                    }
                                }
                            };

                            if direct_connected {
                                let mut stream_pipe = StreamPipe::new(session_port, active_connection_manager.clone(), TCP_RELAY_SOCKET_BUFFER_SIZE, buffer_pool, tcp_socket, dst_socket.unwrap());
                                stream_pipe.pipe_loop().await
                            } else {
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
                                // proxy
                                let (proxy_direct_ip, proxy_port) = (addr.to_string(), port);
                                let target_addr = format!("{}:{}", origin_host_port.0, origin_host_port.1);
                                let mut proxy_socket = tokio_socks::tcp::Socks5Stream::connect((proxy_direct_ip.as_str(), proxy_port), target_addr).await.unwrap();
                                // TODO: add connection

                                let mut stream_pipe = StreamPipe::new(session_port, active_connection_manager.clone(), TCP_RELAY_SOCKET_BUFFER_SIZE, buffer_pool, tcp_socket, proxy_socket);
                                stream_pipe.pipe_loop().await
                            }
                        }

                        HostRouteStrategy::Reject => {
                            log::info!("reject connection to {}:{}", origin_host_port.0, origin_host_port.1)
                        }
                    }
                });
            }
        }
    }

    async fn accept_socket_for_macos(&self, mut tcp_socket: TcpStream, socket_addr: SocketAddr, buffer_pool: Arc<crossbeam::queue::ArrayQueue<(BytesMut, BytesMut)>>) {
        log::info!("tun tcp relay server accept relay src socket {} ", socket_addr.to_string());
        let mut nat_session_manager = match self.nat_session_manager.lock() {
            Ok(nat_session_manager) => nat_session_manager,
            Err(errors) => {
                log::error!("get nat session manager error, {}", errors);
                return;
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
                    let process_info = if let Some(socket_info) = process_manager.get_process_by_port(src_port) {
                        let pid = *socket_info.associated_pids.get(0).unwrap_or_else(|| &0);
                        let process_info = process_manager.get_process(pid)
                            .unwrap_or_else(|| ProcessInfo::default());
                        Some(process_info)
                    } else {
                        Some(ProcessInfo::default())
                    }.unwrap();

                    let dst_addr_bytes = dst_addr.octets();
                    let fake_ip = (dst_addr_bytes[0], dst_addr_bytes[1], dst_addr_bytes[2], dst_addr_bytes[3]);
                    let origin_host_port = match fake_ip_manager.get_host(&fake_ip) {
                        None => {
                            log::error!("get host from fake_ip {} error", dst_addr.to_string());
                            return;
                        }

                        Some(host) => (host, dst_port)
                    };

                    let process_name = process_info.process_name.clone();
                    dns_config_manager.add_related_process(origin_host_port.0.clone(), process_name);

                    let (rule_strategy, connection_route_rule) = match host_route_manager.get_host_route_strategy(Some(&process_info), &origin_host_port.0) {
                        None => (HostRouteStrategy::Direct, ConnectionRouteRule::new()),
                        Some(strategy) => strategy
                    };
                    log::info!("Get session route strategy {:?} for session_port {}", &rule_strategy, session_port);
                    match rule_strategy {
                        HostRouteStrategy::Direct => {
                            let direct_address_port = TcpRelayServer::resolve_direct_ip_port(dst_addr, dst_port, resolver_copy, fake_ip_manager).await;
                            let (host, port) = match direct_address_port {
                                None => {
                                    log::error!("get host from fake_ip {} error", dst_addr.to_string());
                                    return;
                                }
                                Some((real_host, real_port)) => (real_host.to_string(), real_port)
                            };

                            let mut dst_socket = match TcpStream::connect((host.as_str(), port)).await {
                                Ok(dst_socket) => {
                                    log::info!("session {} => connect real_addr {}:{}", session_port, &host, port);
                                    dst_socket
                                }
                                Err(errors) => {
                                    log::error!("session {} => connect real addr {}:{} error, {}", session_port, &host, port, errors);
                                    return;
                                }
                            };

                            // TODO: add connection
                            TcpRelayServer::add_active_connection(session_port, src_addr, src_port, dst_port, &active_connection_manager, connection_route_rule, ConnectionTransferType::TCP, Some(process_info), &origin_host_port);
                            let mut stream_pipe = StreamPipe::new(session_port, active_connection_manager.clone(), TCP_RELAY_SOCKET_BUFFER_SIZE, buffer_pool, tcp_socket, dst_socket);
                            stream_pipe.pipe_loop().await;
                        }

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
                                    return;
                                }
                                Some((ip, port)) => (ip, port)
                            };

                            let target_addr = format!("{}:{}", origin_host_port.0, origin_host_port.1);
                            let mut proxy_socket = tokio_socks::tcp::Socks5Stream::connect((proxy_direct_ip.as_str(), proxy_port), target_addr).await.unwrap();
                            // TODO: add connection

                            TcpRelayServer::add_active_connection(session_port, src_addr, src_port, dst_port, &active_connection_manager, connection_route_rule, ConnectionTransferType::TCP, Some(process_info.get_copy()), &origin_host_port);
                            let mut stream_pipe = StreamPipe::new(session_port, active_connection_manager.clone(), TCP_RELAY_SOCKET_BUFFER_SIZE, buffer_pool, tcp_socket, proxy_socket);
                            stream_pipe.pipe_loop().await
                        }

                        HostRouteStrategy::Probe(already_checked, need_proxy, proxy_config_name, direct_ip, last_update_time) => {
                            let mut need_proxy = need_proxy;
                            let (dst_socket, direct_connected) = if !already_checked {
                                 let direct_address_port = match TcpRelayServer::resolve_direct_ip_port(dst_addr, dst_port, resolver_copy.clone(), fake_ip_manager).await {
                                        None => None,
                                        Some(direct_ip_port) => Some(direct_ip_port)
                                    };

                                    let (dst_socket, direct_connected) = match direct_address_port {
                                        None => (None, false),
                                        Some((direct_address, direct_port)) => {
                                            log::info!("connect to {}:{}", &direct_address, direct_port);
                                            match TcpRelayServer::connect_with_timeout((direct_address, direct_port), Duration::from_secs(1)).await {
                                                Ok(mut dst_socket) => {
                                                    log::info!("Try probe connect succeed");
                                                    (Some(dst_socket), true)
                                                },
                                                Err(errors) => {
                                                    log::error!("Try probe connect error, {}", errors);
                                                    (None, false)
                                                }
                                            }
                                        }
                                    };
                                host_route_manager.mark_probe_host_need_proxy(&origin_host_port.0, !direct_connected);
                                (dst_socket, direct_connected)
                            } else {
                                // need proxy already checked
                                if need_proxy {
                                    (None, false)
                                } else {
                                    let (direct_address, direct_port) = match TcpRelayServer::resolve_direct_ip_port(dst_addr, dst_port, resolver_copy.clone(), fake_ip_manager).await {
                                        None => return,
                                        Some(a) => a
                                    };

                                    log::info!("connect to {}:{}", direct_address, direct_port);
                                    match TcpRelayServer::connect_with_timeout((direct_address, direct_port), Duration::from_secs(1)).await {
                                        Ok(mut dst_socket) => {
                                            (Some(dst_socket), true)
                                        }
                                        Err(_errors) => {
                                            return;
                                        }
                                    }
                                }
                            };

                            if direct_connected {
                                TcpRelayServer::add_active_connection(session_port, src_addr, src_port, dst_port, &active_connection_manager, connection_route_rule, ConnectionTransferType::TCP, Some(process_info), &origin_host_port);
                                let mut stream_pipe = StreamPipe::new(session_port, active_connection_manager.clone(), TCP_RELAY_SOCKET_BUFFER_SIZE, buffer_pool, tcp_socket, dst_socket.unwrap());
                                stream_pipe.pipe_loop().await
                            } else {
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
                                // proxy
                                let (proxy_direct_ip, proxy_port) = match TcpRelayServer::resolve_host_ip(resolver_copy, &addr, port).await {
                                    None => {
                                        return;
                                    }
                                    Some((ip, port)) => (ip, port)
                                };

                                let target_addr = format!("{}:{}", origin_host_port.0, origin_host_port.1);
                                let mut proxy_socket = tokio_socks::tcp::Socks5Stream::connect((proxy_direct_ip.as_str(), proxy_port), target_addr).await.unwrap();
                                // TODO: add connection

                                TcpRelayServer::add_active_connection(session_port, src_addr, src_port, dst_port, &active_connection_manager, connection_route_rule, ConnectionTransferType::TCP, Some(process_info.get_copy()), &origin_host_port);
                                let mut stream_pipe = StreamPipe::new(session_port, active_connection_manager.clone(), TCP_RELAY_SOCKET_BUFFER_SIZE, buffer_pool, tcp_socket, proxy_socket);
                                stream_pipe.pipe_loop().await
                            }
                        }

                        HostRouteStrategy::Reject => {
                            log::info!("reject connection to {}:{}", origin_host_port.0, origin_host_port.1)
                        }
                    }
                    active_connection_manager.remove_connection(session_port);
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
                process_execute_path: "".to_string(),
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
            pre_touch_timestamp: 0,
        });
    }

    pub async fn connect_with_timeout<A: tokio::net::ToSocketAddrs>(addr: A, timeout_sec: Duration) -> anyhow::Result<TcpStream> {
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

pub struct UdpRelayServer {
    pub resolver: Arc<AsyncStdResolver>,
    pub fake_ip_manager: Arc<FakeIpManager>,
    pub nat_session_manager: Arc<Mutex<NatSessionManager>>,
    pub host_route_manager: Arc<HostRouteManager>,
    pub session_route_strategy: Arc<DashMap<u16, HostRouteStrategy>>,
    pub proxy_server_config_manager: Arc<ProxyServerConfigManager>,
    pub active_connection_manager: Arc<ActiveConnectionManager>,
    pub process_manager: Arc<SystemManager>,
    // pub dns_config_manager: Arc<DnsConfigManager>,
    // pub listen_addr: (u8, u8, u8, u8),
    // pub listen_port: u16,
}

impl UdpRelayServer {
    pub async fn run(&self) {
        let session_manager = self.nat_session_manager.clone();
        let session_udp_socket = Arc::new(DashMap::<u16, Arc<UdpSocket>>::new());
        let mut buf = vec![0; 2 * 1024];
        let udp_listen_socket = Arc::new(UdpSocket::bind("0.0.0.0:12000").await.unwrap());
        loop {
            let (recv_size, addr) = udp_listen_socket.recv_from(&mut buf).await.unwrap();
            let session_port = addr.port();
            let (src_addr, src_port, dst_addr, dst_port) = session_manager.lock().unwrap().get_port_session_tuple(session_port).unwrap();
            let remote_udp_socket = match session_udp_socket.get(&session_port) {
                Some(kv) => kv.value().clone(),
                None => {
                    let udp_socket = Arc::new(UdpSocket::bind("0.0.0.0:0").await.unwrap());
                    let local_udp_socket = udp_listen_socket.clone();
                    let remote_udp_socket = udp_socket.clone();
                    let inner_session_udp_socket = session_udp_socket.clone();
                    tokio::spawn(async move {
                        let mut buf = vec![0; 2 * 1024];
                        loop {
                            tokio::select! {
                              // handle src to dst pipe
                               recv_result = remote_udp_socket.recv_from(&mut buf) => {
                                let recv_size = match recv_result {
                                  Ok((recv_size, recv_socket_addr)) => recv_size,
                                  Err(errors) => break
                                };

                                if recv_size <= 0 {
                                    break;
                                }

                                match local_udp_socket.send_to(&buf[..recv_size], addr).await {
                                  Ok(_) => {},
                                  Err(errors) => {
                                     break
                                  }
                                }
                              },

                              _ = tokio::time::sleep(Duration::from_secs(10)) => {
                                break;
                              }
                            }
                        }
                        inner_session_udp_socket.remove(&session_port);
                    });
                    session_udp_socket.insert(session_port, udp_socket.clone());
                    udp_socket
                }
            };

            // TODO: set src_pid.
            remote_udp_socket.send_to(&buf[..recv_size], (dst_addr.to_string(), dst_port)).await;
        }
    }
}

#[cfg(test)]
pub mod tests {
    use std::future::Future;
    use std::net::{IpAddr, Ipv4Addr};
    use std::time::Duration;
    use crate::{setup_log, TcpRelayServer};

    #[test]
    pub fn test_connect_with_timeout() {
        setup_log();
        let run_time = match tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .worker_threads(2)
            .max_blocking_threads(4)
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
            log::info!("a");
            let a = TcpRelayServer::connect_with_timeout(("static.xx.fbcdn.net", 443), Duration::from_secs(1)).await.unwrap();
            log::info!("connect result = {:?}", a);
            log::info!("b")
        });
    }

    #[test]
    pub fn test_pinger() {
        setup_log();
    }
}