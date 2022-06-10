use std::arch::x86_64::_mm_add_ps;
use std::collections::{HashMap, HashSet, LinkedList};
use std::net::{IpAddr, Ipv4Addr, ToSocketAddrs};
use std::sync::{Arc, Mutex};
use crate::dns::resolve::FakeIpManager;
use windivert::*;
use std::process::{Command, exit};
use std::str::FromStr;
use std::sync::mpsc::{channel, Sender, sync_channel, SyncSender};
use std::thread::sleep;
use std::time::Duration;
use dashmap::DashMap;
use dns_parser::RData;
use smoltcp::wire::{IpProtocol, UdpPacket, TcpPacket, Ipv4Packet};
use smoltcp::Error;
use dns_parser::rdata::A;
use libc::sockaddr;
use rouille::url::quirks::host;
use serde::de::Unexpected::Option;
use windivert::address::WinDivertNetworkData;
use crate::{ActiveConnectionManager, HostRouteManager, HostRouteStrategy, NatSessionManager, ProcessInfo, ProxyServerConfigManager, ProxyServerConfigType, SystemManager, TcpRelayServer};
use crate::core::active_connection_manager::ConnectionTransferType;
use crate::core::proxy_config_manager::{ConnectionRouteRule, RouteRule};

const UDP_BUFFER_SIZE: usize = 64 * 1024;
const TCP_BUFFER_SIZE: usize = 64 * 1024;
const MAX_BUFFER_COUNT: usize = 32;

pub struct Ipv4PacketInterceptor {
    pub session_route_strategy: Arc<DashMap<u16, HostRouteStrategy>>,
    pub nat_session_manager: Arc<Mutex<NatSessionManager>>,
    pub fake_ip_manager: Arc<FakeIpManager>,
    pub proxy_config_manager: Arc<ProxyServerConfigManager>,
    pub process_manager: Arc<SystemManager>,
    pub connection_manager: Arc<ActiveConnectionManager>,
    pub host_route_manager: Arc<HostRouteManager>,
    pub tcp_relay_listen_port: u16,
}

impl Ipv4PacketInterceptor {
    pub fn run(&self) {
        // load cached dns
        self.load_cached_dns();

        // start connection monitor
        let connection_manager = self.connection_manager.clone();
        let process_manager = self.process_manager.clone();
        std::thread::spawn(move || {
            loop {
                // add connection
                // remove connection
                // incr connection data
                // kick out
                if let Some(connection_vec) = connection_manager.get_all_connection() {
                    for active_connection in connection_vec {
                        let src_port = active_connection.src_port;
                        if process_manager.get_process_by_port(src_port).is_none() {
                            connection_manager.remove_connection(src_port);
                        }
                    }
                }
                sleep(Duration::from_secs(60));
            }
        });

        let local_host_ip_addr_octets = Ipv4Addr::from_str("127.0.0.1").unwrap().octets();
        let relay_server_port = self.tcp_relay_listen_port;
        let filter = "ip";
        let handle = match WinDivert::new(filter, WinDivertLayer::Network, 0, Default::default()) {
            Ok(handle) => {
                handle
            }
            Err(errors) => {
                log::error!("create windivert handle error, {}", errors.to_string());
                exit(1);
            }
        };
        let handle_arc = Arc::new(handle);

        // start worker pool
        // let worker_num = self.process_manager.get_available_processor_num() + 1;
        let worker_num = 1;
        let buffer_pool = Arc::new(crossbeam::queue::ArrayQueue::new(worker_num * MAX_BUFFER_COUNT));
        let mut worker_mpsc: HashMap<usize, crossbeam::channel::Sender<(WinDivertNetworkData, Ipv4Packet<Vec<u8>>)>> = HashMap::with_capacity(worker_num);
        for worker_id in 0..worker_num {
            // mpsc
            let (tx, rx) = crossbeam::channel::bounded(MAX_BUFFER_COUNT);
            worker_mpsc.insert(worker_id, tx);

            // buffer pool
            let buffer_pool = buffer_pool.clone();
            let mut recycle_buffer_handler = move |buffer: Vec<u8>| {
                buffer_pool.push(buffer);
            };

            // start thread
            let pid = std::process::id();
            let allowed_skip_tcp_relay = false;
            let handle = handle_arc.clone();
            let fake_ip_manager = self.fake_ip_manager.clone();
            let nat_session_manager = self.nat_session_manager.clone();
            let host_route_manager = self.host_route_manager.clone();
            let proxy_config_manager = self.proxy_config_manager.clone();
            let process_manager = self.process_manager.clone();
            let connection_manager = self.connection_manager.clone();
            let session_route_strategy = self.session_route_strategy.clone();

            std::thread::spawn(move || {
                let dummy_proxy = HostRouteStrategy::Proxy(String::from(""), None, 0);
                let dummy_process_info = ProcessInfo::default();
                // let mut proxy_server_host_set: HashSet<String> = HashSet::with_capacity(16);
                let mut host_route_strategy_map: HashMap<u16, (HostRouteStrategy, ProcessInfo)> = HashMap::with_capacity(512);
                loop {
                    match rx.recv() {
                        Ok((addr, mut ipv4_packet)) => {
                            let outbound = addr.outbound();
                            let src_addr = Ipv4Addr::from(ipv4_packet.src_addr());
                            let dst_addr = Ipv4Addr::from(ipv4_packet.dst_addr());
                            let dst_addr_octets = dst_addr.octets();
                            match ipv4_packet.protocol() {
                                IpProtocol::Udp => {
                                    let mut udp_packet = match UdpPacket::new_checked(ipv4_packet.payload_mut()) {
                                        Ok(udp_packet) => udp_packet,
                                        Err(errors) => {
                                            log::error!("create udp packet error, {}", errors.to_string());
                                            let data = ipv4_packet.into_inner();
                                            recycle_buffer_handler(data);
                                            continue;
                                        }
                                    };

                                    let src_port = udp_packet.src_port();
                                    let dst_port = udp_packet.dst_port();

                                    if outbound {
                                        let fake_ip_manager = fake_ip_manager.clone();
                                        let host = match fake_ip_manager.get_host(&(dst_addr_octets[0], dst_addr_octets[1], dst_addr_octets[2], dst_addr_octets[3])) {
                                            None => {
                                                let mut data = ipv4_packet.into_inner();
                                                handle.send_with_buffer(addr.data.into_owned(), &mut data);
                                                recycle_buffer_handler(data);
                                                continue;
                                            }
                                            Some(host) => host
                                        };
                                        if !connection_manager.contains_connection(src_port) {
                                            let process_info = if let Some(socket_info) = process_manager.get_process_by_port(src_port) {
                                                let pid = *socket_info.associated_pids.get(0).unwrap_or_else(|| &0);
                                                let process_info = process_manager.get_process(pid)
                                                    .unwrap_or_else(|| ProcessInfo::default());
                                                Some(process_info)
                                            } else {
                                                Some(ProcessInfo::default())
                                            }.unwrap();
                                            // log::info!("process_info = {:?}", process_info);
                                            let mut connection_route_rule = ConnectionRouteRule::new();
                                            let host_route_manager = host_route_manager.clone();
                                            let host_route_strategy = match host_route_manager.get_host_route_strategy(Some(&process_info), &host) {
                                                None => HostRouteStrategy::Direct,
                                                Some((strategy, rule)) => {
                                                    connection_route_rule = rule;
                                                    strategy
                                                }
                                            };

                                            host_route_strategy_map.insert(src_port, (host_route_strategy, process_info.get_copy()));
                                            TcpRelayServer::add_active_connection(src_port, src_addr, src_port, dst_port, &connection_manager,
                                                                                  connection_route_rule, ConnectionTransferType::UDP, Some(process_info), &(host, src_port),
                                            );
                                        }

                                        let mut data = ipv4_packet.into_inner();
                                        connection_manager.incr_tx(src_port, data.len());
                                        handle.send_with_buffer(addr.data.into_owned(), &mut data);
                                        recycle_buffer_handler(data);
                                        continue;
                                    } else {
                                        // inbound
                                        if udp_packet.src_port() != 53 {
                                            let mut data = ipv4_packet.into_inner();
                                            connection_manager.incr_rx(src_port, data.len());
                                            handle.send_with_buffer(addr.data.into_owned(), &mut data);
                                            recycle_buffer_handler(data);
                                            continue;
                                        }

                                        // handle dns
                                        let udp_payload = udp_packet.payload_mut();
                                        let dns_packet = match dns_parser::Packet::parse(udp_payload) {
                                            Ok(dns_packet) => dns_packet,
                                            Err(errors) => {
                                                log::error!("parse dns udp packet error, {}", errors.to_string());
                                                let mut data = ipv4_packet.into_inner();
                                                handle.send_with_buffer(addr.data.into_owned(), &mut data);
                                                recycle_buffer_handler(data);
                                                continue;
                                            }
                                        };

                                        if dns_packet.header.query {
                                            log::warn!("parse dns query udp packet");
                                            let mut data = ipv4_packet.into_inner();
                                            handle.send_with_buffer(addr.data.into_owned(), &mut data);
                                            recycle_buffer_handler(data);
                                            continue;
                                        }

                                        update_fake_ip_dns(fake_ip_manager.clone(), dns_packet);
                                        let mut data = ipv4_packet.into_inner();
                                        handle.send_with_buffer(addr.data.into_owned(), &mut data);
                                        recycle_buffer_handler(data);
                                    }
                                }

                                IpProtocol::Tcp => {
                                    let mut tcp_packet_payload = ipv4_packet.payload_mut();
                                    let mut tcp_packet = match TcpPacket::new_checked(tcp_packet_payload) {
                                        Ok(tcp_packet) => tcp_packet,
                                        Err(errors) => {
                                            log::error!("create tcp packet error, {}", errors.to_string());
                                            let mut data = ipv4_packet.into_inner();
                                            handle.send_with_buffer(addr.data.into_owned(), &mut data);
                                            recycle_buffer_handler(data);
                                            continue;
                                        }
                                    };

                                    let src_port = tcp_packet.src_port();
                                    let dst_port = tcp_packet.dst_port();
                                    let dst_addr_octets = dst_addr.octets();
                                    let src_addr_octets = src_addr.octets();

                                    if outbound {
                                        if dst_addr_octets == local_host_ip_addr_octets {
                                            let mut data = ipv4_packet.into_inner();
                                            handle.send_with_buffer(addr.data.into_owned(), &mut data);
                                            recycle_buffer_handler(data);
                                            continue;
                                        }

                                        // TODO remove
                                        let fake_ip_manager = fake_ip_manager.clone();
                                        let host = match fake_ip_manager.get_host(&(dst_addr_octets[0], dst_addr_octets[1], dst_addr_octets[2], dst_addr_octets[3])) {
                                            None => dst_addr.to_string(),
                                            Some(host) => host
                                        };

                                        if tcp_packet.syn() {
                                            if src_port != relay_server_port {
                                                let process_info = if let Some(socket_info) = process_manager.get_process_by_port(src_port) {
                                                    let pid = *socket_info.associated_pids.get(0).unwrap_or_else(|| &0);
                                                    let process_info = process_manager.get_process(pid).unwrap_or_else(|| ProcessInfo::default());
                                                    Some(process_info)
                                                } else {
                                                    Some(ProcessInfo::default())
                                                }.unwrap();
                                                let mut connection_route_rule = ConnectionRouteRule::new();
                                                let host_route_manager = host_route_manager.clone();
                                                let host_route_strategy = match host_route_manager.get_host_route_strategy(Some(&process_info), &host) {
                                                    None => HostRouteStrategy::Direct,
                                                    Some((strategy, rule)) => {
                                                        connection_route_rule = rule;
                                                        strategy
                                                    }
                                                };
                                                host_route_strategy_map.insert(src_port, (host_route_strategy, process_info.get_copy()));
                                                TcpRelayServer::add_active_connection(src_port, src_addr, src_port, dst_port, &connection_manager,
                                                                                      connection_route_rule, ConnectionTransferType::TCP, Some(process_info), &(host, src_port),
                                                );
                                            }
                                        } else if tcp_packet.fin() {
                                            if src_port != relay_server_port {
                                                connection_manager.remove_connection(src_port);
                                            }
                                        }

                                        let (mut host_route_strategy, process_info) = match host_route_strategy_map.get(&src_port) {
                                            None => {
                                                if src_port == relay_server_port {
                                                    (&dummy_proxy, &dummy_process_info)
                                                } else {
                                                    (&HostRouteStrategy::Reject, &dummy_process_info)
                                                }
                                            }
                                            Some(b) => {
                                                (&b.0, &b.1)
                                            }
                                        };

                                        if process_info.pid == pid {
                                            let mut data = ipv4_packet.into_inner();
                                            handle.send_with_buffer(addr.data.into_owned(), &mut data);
                                            recycle_buffer_handler(data);
                                            continue;
                                        }

                                        // log::info!(" transfer {}:{} -> {}:{} -> {:?}", src_addr, src_port, dst_addr, dst_port, host_route_strategy);
                                        match host_route_strategy {
                                            HostRouteStrategy::Proxy(_, _, _) => {}
                                            HostRouteStrategy::Reject => {
                                                let data = ipv4_packet.into_inner();
                                                connection_manager.incr_tx(src_port, data.len());
                                                recycle_buffer_handler(data);
                                                continue;
                                            }
                                            HostRouteStrategy::Probe(already_checked, need_proxy, proxy_config_name, direct_ip, last_update_time) => {
                                                if allowed_skip_tcp_relay {
                                                    if *already_checked && !*need_proxy {
                                                        let mut data = ipv4_packet.into_inner();
                                                        connection_manager.incr_tx(src_port, data.len());
                                                        handle.send_with_buffer(addr.data.into_owned(), &mut data);
                                                        recycle_buffer_handler(data);
                                                        continue;
                                                    }
                                                }
                                            }
                                            HostRouteStrategy::Direct => {
                                                if allowed_skip_tcp_relay {
                                                    let mut data = ipv4_packet.into_inner();
                                                    connection_manager.incr_tx(src_port, data.len());
                                                    handle.send_with_buffer(addr.data.into_owned(), &mut data);
                                                    recycle_buffer_handler(data);
                                                    continue;
                                                }
                                            }
                                        }

                                        // relay to local
                                        if src_port == relay_server_port {
                                            let mut nat_session_manager = nat_session_manager.lock().unwrap();
                                            let (origin_src_addr, origin_src_port, origin_dst_addr, origin_dst_port) = match nat_session_manager.get_port_session_tuple(dst_port) {
                                                None => {
                                                    let mut data = ipv4_packet.into_inner();
                                                    handle.send_with_buffer(addr.data.into_owned(), &mut data);
                                                    recycle_buffer_handler(data);
                                                    continue;
                                                }
                                                Some((origin_src_addr, origin_src_port, origin_dst_addr, origin_dst_port)) => {
                                                    (origin_src_addr, origin_src_port, origin_dst_addr, origin_dst_port)
                                                }
                                            };

                                            let new_src_addr = origin_dst_addr;
                                            let new_src_port = origin_dst_port;
                                            let new_dst_addr = origin_src_addr;
                                            let new_dst_port = origin_src_port;
                                            let seq_number = tcp_packet.seq_number();

                                            tcp_packet.set_src_port(new_src_port);
                                            tcp_packet.set_dst_port(new_dst_port);
                                            tcp_packet.fill_checksum(&new_src_addr.into(), &new_dst_addr.into());
                                            ipv4_packet.set_src_addr(new_src_addr.into());
                                            ipv4_packet.set_dst_addr(new_dst_addr.into());
                                            ipv4_packet.fill_checksum();
                                            let mut data = ipv4_packet.into_inner();
                                            connection_manager.incr_rx(new_dst_port, data.len());
                                            handle.send_with_buffer(addr.data.into_owned(), &mut data);
                                            recycle_buffer_handler(data);
                                            continue;
                                        } else {
                                            // modify tcp packet
                                            let nat_session_manager = nat_session_manager.clone();
                                            let mut nat_session_manager = match nat_session_manager.lock() {
                                                Ok(nat_session_manager) => {
                                                    nat_session_manager
                                                }

                                                Err(errors) => {
                                                    log::error!("get nat session manager lock error");
                                                    let mut data = ipv4_packet.into_inner();
                                                    handle.send_with_buffer(addr.data.into_owned(), &mut data);
                                                    recycle_buffer_handler(data);
                                                    continue;
                                                }
                                            };
                                            let port = match nat_session_manager.get_session_port((src_addr, src_port, dst_addr, dst_port)) {
                                                None => {
                                                    let mut data = ipv4_packet.into_inner();
                                                    handle.send_with_buffer(addr.data.into_owned(), &mut data);
                                                    recycle_buffer_handler(data);
                                                    continue;
                                                }
                                                Some(port) => port
                                            };
                                            if tcp_packet.syn() {
                                                session_route_strategy.insert(port, host_route_strategy.get_copy());
                                            }

                                            let new_src_addr = dst_addr;
                                            let new_src_port = port;
                                            let new_dst_addr = src_addr;
                                            let new_dst_port = relay_server_port;
                                            let seq_number = tcp_packet.seq_number();

                                            tcp_packet.set_src_port(new_src_port);
                                            tcp_packet.set_dst_port(new_dst_port);
                                            tcp_packet.fill_checksum(&new_src_addr.into(), &new_dst_addr.into());
                                            ipv4_packet.set_src_addr(new_src_addr.into());
                                            ipv4_packet.set_dst_addr(new_dst_addr.into());
                                            ipv4_packet.fill_checksum();
                                            let mut data = ipv4_packet.into_inner();
                                            connection_manager.incr_tx(src_port, data.len());
                                            handle.send_with_buffer(addr.data.into_owned(), &mut data);
                                            recycle_buffer_handler(data);
                                            continue;
                                        }
                                    } else {
                                        let mut data = ipv4_packet.into_inner();
                                        connection_manager.incr_rx(dst_port, data.len());
                                        handle.send_with_buffer(addr.data.into_owned(), &mut data);
                                        recycle_buffer_handler(data);
                                        continue;
                                    }
                                }

                                _ => {
                                    let mut data = ipv4_packet.into_inner();
                                    handle.send_with_buffer(addr.data.into_owned(), &mut data);
                                    recycle_buffer_handler(data);
                                }
                            }
                        }
                        Err(errors) => {
                            log::error!("Recv windivert packet errors, {}", errors.to_string());
                            return;
                        }
                    }
                }
            });
        };

        // start recv windivert packet
        let handle = handle_arc.clone();
        loop {
            let mut buffer = match buffer_pool.pop() {
                None => {
                    let mut buffer = Vec::with_capacity(UDP_BUFFER_SIZE);
                    unsafe { buffer.set_len(UDP_BUFFER_SIZE); }
                    buffer
                }
                Some(mut buffer) => {
                    unsafe { buffer.set_len(UDP_BUFFER_SIZE); }
                    buffer
                }
            };

            match handle.recv_with_buffer(buffer) {
                Ok((packet_len, windivert_packet)) => {
                    let windivert_parsed_packet = windivert_packet.parse();
                    let (src_port, addr, ipv4_packet) = match windivert_parsed_packet {
                        WinDivertParsedPacket::Network { addr, mut data } => {
                            // log::info!("Recv with buffer vec len = {}, cap = {}", packet_len, data.capacity());
                            let mut ipv4_packet = match Ipv4Packet::new_checked(data) {
                                Ok(p) => p,
                                Err(errors) => {
                                    log::error!("read ip_v4 packet error, {}", errors.to_string());
                                    continue;
                                }
                            };
                            match ipv4_packet.protocol() {
                                IpProtocol::Udp => {
                                    let ipv4_packet_payload = ipv4_packet.payload_mut();
                                    let udp_packet = match UdpPacket::new_checked(ipv4_packet_payload) {
                                        Ok(udp_packet) => udp_packet,
                                        Err(errors) => {
                                            log::error!("create udp packet error, {}", errors.to_string());
                                            continue;
                                        }
                                    };
                                    let src_port = udp_packet.src_port();
                                    (src_port, addr, ipv4_packet)
                                }
                                IpProtocol::Tcp => {
                                    let ipv4_packet_payload = ipv4_packet.payload_mut();
                                    let tcp_packet = match TcpPacket::new_checked(ipv4_packet_payload) {
                                        Ok(tcp_packet) => tcp_packet,
                                        Err(errors) => {
                                            log::error!("create tcp packet error, {}", errors.to_string());
                                            continue;
                                        }
                                    };
                                    let src_port = tcp_packet.src_port();
                                    (src_port, addr, ipv4_packet)
                                }
                                _ => {
                                    let mut data = ipv4_packet.into_inner();
                                    handle.send_with_buffer(addr.data.into_owned(), &mut data);
                                    buffer_pool.push(data);
                                    continue;
                                }
                            }
                        }
                        _ => {
                            handle.send(windivert_parsed_packet);
                            continue;
                        }
                    };
                    let selected_worker_id = (src_port as usize % worker_num);
                    if let Some(tx) = worker_mpsc.get(&selected_worker_id) {
                        tx.send((addr, ipv4_packet));
                    }
                }
                Err(errors) => {
                    log::error!("Recv windivert packet errors, {}", errors.to_string());
                    continue
                }
            }
        }
    }

    fn load_cached_dns(&self) {
        let fake_ip_manager = self.fake_ip_manager.clone();
        for (host, ip_vec) in  self.get_cached_dns() {
            for ip in ip_vec {
                let octets = ip.octets();
                log::info!("set fake_ip {}:{}", host, ip);
                fake_ip_manager.set_host_ip(&host, (octets[0], octets[1], octets[2], octets[3]));
            }
        }
    }

    pub fn get_cached_dns(&self) -> Vec<(String, Vec<Ipv4Addr>)> {
        let mut cached_dns = Vec::with_capacity(512);
        let dns_helper_cmd = "dns_helper.exe";
        let cmd_output = match Command::new(dns_helper_cmd).output() {
            Ok(cmd_out) => cmd_out,
            Err(_errors) => return cached_dns
        };

        let stdout_str = String::from_utf8_lossy(&cmd_output.stdout);
        let dns_a_record_lines = stdout_str.lines();
        for dns_a_record in dns_a_record_lines {
            let host_port = dns_a_record.to_string() + ":80";
            let socket_addr_vec: Vec<Ipv4Addr> = host_port.to_socket_addrs()
                .map_or(Vec::new().into_iter(), |v| v)
                .map(|socket_addr| socket_addr.ip())
                .map(|ip| match ip {
                    IpAddr::V4(addr) => Some(addr),
                    IpAddr::V6(_) => None
                })
                .filter(|opt| opt.is_some())
                .map(|opt| opt.unwrap())
                .collect();

            if !socket_addr_vec.is_empty() {
                cached_dns.push((dns_a_record.to_string(), socket_addr_vec));
            }
        }
        cached_dns
    }
}

pub fn update_fake_ip_dns(fake_ip_manager: Arc<FakeIpManager>, dns_packet: dns_parser::Packet) {
        let header = dns_packet.header;
        if header.query {
            return;
        }

        if header.questions <= 0 || header.answers <= 0 {
            return;
        }

        let question = dns_packet.questions.get(0).unwrap();
        let host = format!("{}", question.qname);

        for answer in dns_packet.answers {
            let rdata = answer.data;
            match rdata {
                RData::A(record) => {
                    let ip = record.0;
                    let ip_bytes = ip.octets();
                    let ip_tuple = (ip_bytes[0], ip_bytes[1], ip_bytes[2], ip_bytes[3]);
                    log::info!("set fake_ip {}:{}", host.to_string(), ip);
                    fake_ip_manager.set_host_ip(&host, ip_tuple);
                    break;
                }
                _ => {}
            }
        }
    }
