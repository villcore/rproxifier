use std::collections::{HashMap, HashSet};
use std::net::Ipv4Addr;
use std::sync::{Arc, Mutex};
use crate::dns::resolve::FakeIpManager;
use windivert::*;
use std::process::exit;
use std::str::FromStr;
use std::sync::mpsc::{channel, Sender, sync_channel, SyncSender};
use std::thread::sleep;
use std::time::Duration;
use dns_parser::RData;
use smoltcp::wire::{IpProtocol, UdpPacket, TcpPacket, Ipv4Packet};
use smoltcp::Error;
use dns_parser::rdata::A;
use rouille::url::quirks::host;
use crate::{ActiveConnectionManager, HostRouteManager, HostRouteStrategy, NatSessionManager, ProcessInfo, ProxyServerConfigManager, ProxyServerConfigType, SystemManager, TcpRelayServer};
use crate::core::active_connection_manager::ConnectionTransferType;
use crate::core::proxy_config_manager::{ConnectionRouteRule, RouteRule};

const UDP_BUFFER_SIZE: usize = 64 * 1024;
const TCP_BUFFER_SIZE: usize = 16 * 1024;

pub struct Ipv4PacketInterceptor {
    pub nat_session_manager: Arc<Mutex<NatSessionManager>>,
    pub fake_ip_manager: Arc<FakeIpManager>,
    pub proxy_config_manager: Arc<ProxyServerConfigManager>,
    pub process_manager: Arc<SystemManager>,
    pub connection_manager: Arc<ActiveConnectionManager>,
    pub host_route_manager: Arc<HostRouteManager>,
}

impl Ipv4PacketInterceptor {

    pub fn run(&self) {
        // start connection monitor
        let connection_manager = self.connection_manager.clone();
        let process_manager = self.process_manager.clone();
        std::thread::spawn(move || {
            loop {
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

        let relay_server_port = 13000u16;
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
        let worker_num = self.process_manager.get_available_processor_num().map_or(1, |core_num| std::cmp::max(core_num * 2, 1));
        let mut worker_mpsc: HashMap<usize, SyncSender<WinDivertParsedPacket>> = HashMap::with_capacity(worker_num);
        for worker_id in 0..worker_num {
            // mpsc
            let (tx, rx) = sync_channel(1024);
            worker_mpsc.insert(worker_id, tx);

            // start thread
            let handle = handle_arc.clone();
            let fake_ip_manager = self.fake_ip_manager.clone();
            let nat_session_manager = self.nat_session_manager.clone();
            let host_route_manager = self.host_route_manager.clone();
            let proxy_config_manager = self.proxy_config_manager.clone();
            let process_manager = self.process_manager.clone();
            let connection_manager = self.connection_manager.clone();
            std::thread::spawn(move || {
                let mut proxy_server_host_set: HashSet<String> = HashSet::with_capacity(16);
                let mut host_route_strategy_map: HashMap<u16, (HostRouteStrategy, ProcessInfo)> = HashMap::with_capacity(512);
                loop {
                    //
                    match rx.recv() {
                        Ok(windivert_parsed_packet) => {
                            match windivert_parsed_packet {
                                WinDivertParsedPacket::Network { addr, mut data } => {
                                    // handle dns udp packet
                                    let outbound = addr.outbound();
                                    let mut ipv4_packet = match Ipv4Packet::new_checked(&mut data) {
                                        Ok(p) => p,
                                        Err(errors) => {
                                            log::error!("read ip_v4 packet error, {}", errors.to_string());
                                            handle.send(WinDivertParsedPacket::Network { addr, data });
                                            continue;
                                        }
                                    };

                                    let src_addr = Ipv4Addr::from(ipv4_packet.src_addr());
                                    let dst_addr = Ipv4Addr::from(ipv4_packet.dst_addr());
                                    let dst_addr_octets = dst_addr.octets();
                                    match ipv4_packet.protocol() {
                                        IpProtocol::Udp => {
                                            let mut udp_packet = match UdpPacket::new_checked(ipv4_packet.payload_mut()) {
                                                Ok(udp_packet) => udp_packet,
                                                Err(errors) => {
                                                    log::error!("create udp packet error, {}", errors.to_string());
                                                    handle.send(WinDivertParsedPacket::Network { addr, data });
                                                    continue;
                                                }
                                            };

                                            let src_port = udp_packet.src_port();
                                            let dst_port = udp_packet.dst_port();

                                            if outbound {
                                                let fake_ip_manager = fake_ip_manager.clone();
                                                let host = match fake_ip_manager.get_host(&(dst_addr_octets[0], dst_addr_octets[1], dst_addr_octets[2], dst_addr_octets[3])) {
                                                    None => {
                                                        handle.send(WinDivertParsedPacket::Network { addr, data });
                                                        continue;
                                                    }
                                                    Some(host) => host
                                                };
                                                if !connection_manager.contains_connection(src_port) {
                                                    // log::info!("udp outbound, {} -> {}:{} => {}:{}", &host, src_addr, src_port, dst_addr, dst_port);
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
                                                    // log::info!("udp process_info = {:?}", process_info);
                                                    let mut connection_route_rule = ConnectionRouteRule::new();
                                                    let host_route_manager = host_route_manager.clone();
                                                    let host_route_strategy = HostRouteStrategy::Direct;
                                                    host_route_strategy_map.insert(src_port, (host_route_strategy, process_info.get_copy()));
                                                    TcpRelayServer::add_active_connection(src_port, src_addr, src_port, dst_port, &connection_manager,
                                                                                          connection_route_rule, ConnectionTransferType::UDP, Some(process_info), &(host, src_port)
                                                    );
                                                }

                                                connection_manager.incr_tx(src_port, data.len());
                                                handle.send(WinDivertParsedPacket::Network { addr, data });
                                                continue;
                                            } else {
                                                // inbound
                                                if udp_packet.src_port() != 53 {
                                                    connection_manager.incr_rx(src_port, data.len());
                                                    handle.send(WinDivertParsedPacket::Network { addr, data });
                                                    continue;
                                                }

                                                // handle dns
                                                let udp_payload = udp_packet.payload_mut();
                                                let dns_packet = match dns_parser::Packet::parse(udp_payload) {
                                                    Ok(dns_packet) => dns_packet,
                                                    Err(errors) => {
                                                        log::error!("parse dns udp packet error, {}", errors.to_string());
                                                        handle.send(WinDivertParsedPacket::Network { addr, data });
                                                        continue;
                                                    }
                                                };

                                                if dns_packet.header.query {
                                                    log::warn!("parse dns query udp packet");
                                                    handle.send(WinDivertParsedPacket::Network { addr, data });
                                                    continue;
                                                }

                                                Ipv4PacketInterceptor::update_fake_ip_dns(fake_ip_manager.clone(), dns_packet);
                                                handle.send(WinDivertParsedPacket::Network { addr, data });
                                            }
                                        }

                                        IpProtocol::Tcp => {

                                            let mut tcp_packet_payload = ipv4_packet.payload_mut();
                                            let mut tcp_packet = match TcpPacket::new_checked(tcp_packet_payload) {
                                                Ok(tcp_packet) => tcp_packet,
                                                Err(errors) => {
                                                    log::error!("create tcp packet error, {}", errors.to_string());
                                                    handle.send(WinDivertParsedPacket::Network { addr, data });
                                                    continue;
                                                }
                                            };

                                            let src_port = tcp_packet.src_port();
                                            let dst_port = tcp_packet.dst_port();

                                            let dst_addr_octets = dst_addr.octets();
                                            let src_addr_octets = src_addr.octets();

                                            let local_host = Ipv4Addr::from_str("127.0.0.1").unwrap();
                                            if outbound {
                                                if dst_addr_octets == local_host.octets() {
                                                    handle.send(WinDivertParsedPacket::Network { addr, data });
                                                    continue;
                                                }

                                                // TODO remove
                                                let fake_ip_manager = fake_ip_manager.clone();
                                                let host = match fake_ip_manager.get_host(&(dst_addr_octets[0], dst_addr_octets[1], dst_addr_octets[2], dst_addr_octets[3])) {
                                                    None => {
                                                        handle.send(WinDivertParsedPacket::Network { addr, data });
                                                        continue;
                                                    }
                                                    Some(host) => host
                                                };

                                                if proxy_server_host_set.contains(&host) {
                                                    handle.send(WinDivertParsedPacket::Network { addr, data });
                                                    continue;
                                                }

                                                // let seq_number = tcp_packet.seq_number();
                                                if tcp_packet.syn() {
                                                    if let Some(proxy_server_config_vec) = proxy_config_manager.get_all_proxy_server_config() {
                                                        for proxy_server_config in proxy_server_config_vec {
                                                            match proxy_server_config.config {
                                                                ProxyServerConfigType::SocksV5(addr, _, _, _) => {
                                                                    proxy_server_host_set.insert(addr);
                                                                },
                                                                _ => {}
                                                            }
                                                        }
                                                    }

                                                    // log::info!("------- new tcp pipe {} -> {}:{} -> {}:{} -> seq_num {}", &host, src_addr, src_port, dst_addr, dst_port, seq_number);
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
                                                    // log::info!("process_info = {:?}", process_info);
                                                    let mut connection_route_rule = ConnectionRouteRule::new();
                                                    let host_route_manager = host_route_manager.clone();
                                                    let host_route_strategy = match host_route_manager.get_host_route_strategy(Some(&process_info), &host) {
                                                        None => HostRouteStrategy::Direct,
                                                        Some((strategy, rule)) => {
                                                            connection_route_rule = rule;
                                                            strategy
                                                        },
                                                    };
                                                    host_route_strategy_map.insert(src_port, (host_route_strategy, process_info.get_copy()));
                                                    TcpRelayServer::add_active_connection(src_port, src_addr, src_port, dst_port, &connection_manager,
                                                                                          connection_route_rule, ConnectionTransferType::TCP, Some(process_info), &(host, src_port)
                                                    );
                                                } else if tcp_packet.fin() {
                                                    // log::info!("======= close tcp pipe {}:{} -> {}:{} -> seq_num {}", src_addr, src_port, dst_addr, dst_port, seq_number);
                                                }

                                                // log::info!(" transfer {}:{} -> {}:{} -> seq_num {} -> {:?}", src_addr, src_port, dst_addr, dst_port, seq_number, host_route_strategy);
                                                let mut host_route_strategy = match host_route_strategy_map.get(&src_port) {
                                                    None => {
                                                        &HostRouteStrategy::Reject
                                                    },
                                                    Some(b) => {
                                                        &b.0
                                                    }
                                                };

                                                match host_route_strategy {
                                                    HostRouteStrategy::Proxy(_, _, _) => {}
                                                    HostRouteStrategy::Reject => {
                                                        connection_manager.incr_tx(src_port, data.len());
                                                        continue
                                                    },
                                                    _ => {
                                                        connection_manager.incr_tx(src_port, data.len());
                                                        // handle.send(WinDivertParsedPacket::Network { addr, data });
                                                        continue;
                                                    }
                                                }

                                                // relay to local
                                                if src_port == relay_server_port {
                                                    let mut nat_session_manager = nat_session_manager.lock().unwrap();
                                                    let (origin_src_addr, origin_src_port, origin_dst_addr, origin_dst_port) = match nat_session_manager.get_port_session_tuple(dst_port) {
                                                        None => {
                                                            handle.send(WinDivertParsedPacket::Network { addr, data });
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
                                                    // log::info!("Relay server Send new >>>>>>>>>>>>>>>>>>>>>>>>>>>>>> {}:{} -> {}:{} / origin {}:{} -> {}:{} -> seq {}", new_src_addr, new_src_port, new_dst_addr, new_dst_port, src_addr, src_port, dst_addr, dst_port, seq_number);
                                                    connection_manager.incr_tx(dst_port, data.len());
                                                    handle.send(WinDivertParsedPacket::Network { addr, data });
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
                                                            handle.send(WinDivertParsedPacket::Network { addr, data });
                                                            continue;
                                                        }
                                                    };
                                                    let port = match nat_session_manager.get_session_port((src_addr, src_port, dst_addr, dst_port)) {
                                                        None => {
                                                            handle.send(WinDivertParsedPacket::Network { addr, data });
                                                            continue;
                                                        },
                                                        Some(port) => port
                                                    };

                                                    // TODO: copy data;
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
                                                    handle.send(WinDivertParsedPacket::Network { addr, data });
                                                    continue;
                                                }
                                            } else {
                                                // log::info!("Inbound >>>>>>>>>>>>>>>>>>>>>>>>");
                                                connection_manager.incr_rx(dst_port, data.len());
                                                handle.send(WinDivertParsedPacket::Network { addr, data });
                                                continue;
                                            }
                                        }

                                        _ => {
                                            handle.send(WinDivertParsedPacket::Network { addr, data });
                                        }
                                    }
                                }
                                other => {
                                    handle.send(other);
                                }
                            }
                        }
                        Err(errors) => {
                            log::error!("Recv windivert packet errors, {}", errors.to_string());
                            return;
                        }
                    }
                    // TODO: shutdown exit
                }
            });
        };

        // start recv windivert packet
        let handle = handle_arc.clone();
        loop {
            match handle.recv(UDP_BUFFER_SIZE) {
                Ok(windivert_packet) => {
                    let windivert_parsed_packet = windivert_packet.parse();
                    let (src_port, windivert_packet) = match windivert_parsed_packet {
                        WinDivertParsedPacket::Network { addr, mut data } => {
                            let ipv4_packet = match Ipv4Packet::new_checked(&data) {
                                Ok(p) => p,
                                Err(errors) => {
                                    log::error!("read ip_v4 packet error, {}", errors.to_string());
                                    handle.send(WinDivertParsedPacket::Network { addr, data });
                                    continue;
                                }
                            };
                            let ipv4_packet_payload = ipv4_packet.payload();
                            match ipv4_packet.protocol() {
                                IpProtocol::Udp => {
                                    let udp_packet = match UdpPacket::new_checked(ipv4_packet_payload) {
                                        Ok(udp_packet) => udp_packet,
                                        Err(errors) => {
                                            log::error!("create udp packet error, {}", errors.to_string());
                                            handle.send(WinDivertParsedPacket::Network {addr, data});
                                            continue;
                                        }
                                    };
                                    let src_port = udp_packet.src_port();
                                    (src_port, WinDivertParsedPacket::Network {addr, data})
                                }
                                IpProtocol::Tcp => {
                                    let tcp_packet = match TcpPacket::new_checked(ipv4_packet_payload) {
                                        Ok(tcp_packet) => tcp_packet,
                                        Err(errors) => {
                                            log::error!("create tcp packet error, {}", errors.to_string());
                                            handle.send(WinDivertParsedPacket::Network { addr, data });
                                            continue;
                                        }
                                    };
                                    let src_port = tcp_packet.src_port();
                                    (src_port, WinDivertParsedPacket::Network {addr, data})
                                }
                                _ => {
                                    handle.send(WinDivertParsedPacket::Network { addr, data });
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
                        tx.send(windivert_packet);
                    } else {
                        return;
                    }
                }
                Err(errors) => {
                    log::error!("Recv windivert packet errors, {}", errors.to_string());
                    return;
                }
            }
        }
    }

    fn update_fake_ip(&self, dns_packet: dns_parser::Packet) {
        let header = dns_packet.header;
        if header.query {
            return
        }

        if header.questions <= 0 || header.answers <= 0 {
            return
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
                    let fake_ip_manager = self.fake_ip_manager.clone();
                    log::info!("set fake_ip {}:{}", host.to_string(), ip);
                    fake_ip_manager.set_host_ip(&host, ip_tuple);
                    break
                }
                _ => {}
            }
        }
    }

    pub fn update_fake_ip_dns(fake_ip_manager: Arc<FakeIpManager>, dns_packet: dns_parser::Packet) {
        let header = dns_packet.header;
        if header.query {
            return
        }

        if header.questions <= 0 || header.answers <= 0 {
            return
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
                    break
                }
                _ => {}
            }
        }
    }
}
