use std::net::Ipv4Addr;
use std::sync::{Arc, Mutex};
use crate::dns::resolve::FakeIpManager;
use windivert::*;
use std::process::exit;
use std::str::FromStr;
use dns_parser::RData;
use smoltcp::wire::{IpProtocol, UdpPacket, TcpPacket, Ipv4Packet};
use smoltcp::Error;
use dns_parser::rdata::A;
use crate::NatSessionManager;

const UDP_BUFFER_SIZE: usize = 64 * 1024;
const TCP_BUFFER_SIZE: usize = 16 * 1024;

pub struct Ipv4PacketInterceptor {
    pub nat_session_manager: Arc<Mutex<NatSessionManager>>,
    pub fake_ip_manager: Arc<FakeIpManager>,
}

impl Ipv4PacketInterceptor {

    pub fn run(&self) {
        let filter = "ip";
        let handle = match windivert::WinDivert::new(filter, WinDivertLayer::Network, 0, Default::default()) {
            Ok(handle) => {
                handle
            }
            Err(errors) => {
                log::error!("create windivert handle error, {}", errors.to_string());
                exit(1);
            }
        };

        let relay_server_port = 13000u16;

        loop {
            let windivert_packet = match handle.recv(UDP_BUFFER_SIZE) {
                Ok(packet) => {
                    packet
                }

                Err(errors) => {
                    log::error!("windivert recv udp packet error, {}", errors.to_string());
                    continue;
                }
            };

            let parsed_packet = windivert_packet.parse();
            match parsed_packet {
                WinDivertParsedPacket::Network { addr, mut data } => {
                    // handle dns udp packet
                    let outbound = addr.outbound();

                    let mut mut_data_slice = Vec::with_capacity(data.len());
                    mut_data_slice.extend_from_slice(data.as_slice());
                    let mut data_slice = mut_data_slice.as_mut_slice();
                    let mut ipv4_packet = match Ipv4Packet::new_checked(data_slice) {
                        Ok(p) => p,
                        Err(errors) => {
                            log::error!("read ip_v4 packet error, {}", errors.to_string());
                            handle.send(WinDivertParsedPacket::Network { addr, data });
                            continue;
                        }
                    };

                    let src_addr = Ipv4Addr::from(ipv4_packet.src_addr());
                    let dst_addr = Ipv4Addr::from(ipv4_packet.dst_addr());

                    match ipv4_packet.protocol() {

                        IpProtocol::Udp => {
                            if outbound {
                                handle.send(WinDivertParsedPacket::Network { addr, data });
                                continue;
                            }

                            let mut udp_packet = match UdpPacket::new_checked(ipv4_packet.payload_mut()) {
                                Ok(udp_packet) => udp_packet,
                                Err(errors) => {
                                    log::error!("create udp packet error, {}", errors.to_string());
                                    handle.send(WinDivertParsedPacket::Network { addr, data });
                                    continue;
                                }
                            };

                            if udp_packet.src_port() != 53 {
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

                            // log::info!("dns packet => {:?}", dns_packet);
                            self.update_fake_ip(dns_packet);
                            handle.send(WinDivertParsedPacket::Network { addr, data });
                            continue;
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

                            // let src_addr = Ipv4Addr::from(ipv4_packet.src_addr());
                            let src_port = tcp_packet.src_port();
                            // let dst_addr = Ipv4Addr::from(ipv4_packet.dst_addr());
                            let dst_port = tcp_packet.dst_port();

                            let dst_addr_octets = dst_addr.octets();
                            let src_addr_octets = src_addr.octets();

                            let local_host = Ipv4Addr::from_str("127.0.0.1").unwrap();
                            if outbound {
                                if dst_addr_octets == local_host.octets() {
                                    handle.send(WinDivertParsedPacket::Network { addr, data });
                                    continue;
                                }

                                // TODO proxy server tmp
                                let proxy_server_host = Ipv4Addr::from_str("192.168.50.90").unwrap();
                                if dst_addr_octets == proxy_server_host.octets() {
                                    handle.send(WinDivertParsedPacket::Network { addr, data });
                                    continue;
                                }

                                // TODO direct 流量在这里最好过滤掉

                                // outbound tcp packet
                                // send to relay

                                // relay to local
                                if src_port == relay_server_port {
                                    handle.send(WinDivertParsedPacket::Network { addr, data });
                                    continue;
                                } else {
                                    // modify tcp packet
                                    let mut nat_session_manager = match self.nat_session_manager.lock() {
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
                                    log::info!("Send new >>>>>>>>>>>>>>>>>>>>>>>>>>>>>> {}:{} -> {}:{} / origin {}:{} -> {}:{} -> seq_num {}", new_src_addr, new_src_port, new_dst_addr, new_dst_port, src_addr, src_port, dst_addr, dst_port, seq_number);
                                    let new_ip_packet_payload = ipv4_packet.as_ref();
                                    let vec = Vec::from(new_ip_packet_payload);
                                    data = vec;
                                    handle.send(WinDivertParsedPacket::Network { addr, data });
                                    continue;
                                }
                            } else {
                                log::info!("Inbound >>>>>>>>>>>>>>>>>>>>>>>>");
                                handle.send(WinDivertParsedPacket::Network { addr, data });
                                continue;
                            }
                        }

                        _ => {
                            handle.send(WinDivertParsedPacket::Network { addr, data });
                            continue;
                        }
                    }

                }
                other => {
                    handle.send(other);
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
}

pub struct TestPacketInterceptor {
    pub nat_session_manager: Arc<Mutex<NatSessionManager>>,
    pub fake_ip_manager: Arc<FakeIpManager>,
}

impl TestPacketInterceptor {

    pub fn run(&self) {
        let filter = "tcp.SrcPort = 13000";
        let handle = match windivert::WinDivert::new(filter, WinDivertLayer::Network, 0, Default::default()) {
            Ok(handle) => {
                handle
            }
            Err(errors) => {
                log::error!("create windivert handle error, {}", errors.to_string());
                exit(1);
            }
        };

        let relay_server_port = 13000u16;

        loop {
            let windivert_packet = match handle.recv(UDP_BUFFER_SIZE) {
                Ok(packet) => {
                    packet
                }

                Err(errors) => {
                    log::error!("windivert recv udp packet error, {}", errors.to_string());
                    continue;
                }
            };

            let parsed_packet = windivert_packet.parse();
            match parsed_packet {
                WinDivertParsedPacket::Network { addr, mut data } => {
                    // handle dns udp packet
                    let outbound = addr.outbound();

                    let mut mut_data_slice = Vec::with_capacity(data.len());
                    mut_data_slice.extend_from_slice(data.as_slice());
                    let mut data_slice = mut_data_slice.as_mut_slice();
                    let mut ipv4_packet = match Ipv4Packet::new_checked(data_slice) {
                        Ok(p) => p,
                        Err(errors) => {
                            log::error!("read ip_v4 packet error, {}", errors.to_string());
                            handle.send(WinDivertParsedPacket::Network { addr, data });
                            continue;
                        }
                    };

                    let src_addr = Ipv4Addr::from(ipv4_packet.src_addr());
                    let dst_addr = Ipv4Addr::from(ipv4_packet.dst_addr());

                    match ipv4_packet.protocol() {
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

                            // let src_addr = Ipv4Addr::from(ipv4_packet.src_addr());
                            let src_port = tcp_packet.src_port();
                            // let dst_addr = Ipv4Addr::from(ipv4_packet.dst_addr());
                            let dst_port = tcp_packet.dst_port();

                            let dst_addr_octets = dst_addr.octets();
                            let src_addr_octets = src_addr.octets();

                            let local_host = Ipv4Addr::from_str("127.0.0.1").unwrap();
                            if outbound {
                                if dst_addr_octets == local_host.octets() {
                                    handle.send(WinDivertParsedPacket::Network { addr, data });
                                    continue;
                                }

                                // TODO proxy server tmp
                                let proxy_server_host = Ipv4Addr::from_str("192.168.50.90").unwrap();
                                if dst_addr_octets == proxy_server_host.octets() {
                                    handle.send(WinDivertParsedPacket::Network { addr, data });
                                    continue;
                                }

                                // TODO direct 流量在这里最好过滤掉

                                // outbound tcp packet
                                // send to relay

                                // relay to local
                                if src_port == relay_server_port {
                                    let mut nat_session_manager = self.nat_session_manager.lock().unwrap();
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
                                    log::info!("Relay server Send new >>>>>>>>>>>>>>>>>>>>>>>>>>>>>> {}:{} -> {}:{} / origin {}:{} -> {}:{} -> seq {}", new_src_addr, new_src_port, new_dst_addr, new_dst_port, src_addr, src_port, dst_addr, dst_port, seq_number);
                                    let new_ip_packet_payload = ipv4_packet.as_ref();
                                    let vec = Vec::from(new_ip_packet_payload);
                                    data = vec;
                                    handle.send(WinDivertParsedPacket::Network { addr, data });
                                    continue;
                                }
                                    handle.send(WinDivertParsedPacket::Network { addr, data });
                                    continue;
                            } else {
                                log::info!("Inbound >>>>>>>>>>>>>>>>>>>>>>>>");
                                handle.send(WinDivertParsedPacket::Network { addr, data });
                                continue;
                            }
                        }

                        _ => {
                            handle.send(WinDivertParsedPacket::Network { addr, data });
                            continue;
                        }
                    }

                }
                other => {
                    handle.send(other);
                }
            }
        }
    }
}
