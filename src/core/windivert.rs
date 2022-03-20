use std::sync::Arc;
use crate::dns::resolve::FakeIpManager;
use windivert::*;
use std::process::exit;
use smoltcp::wire::{UdpPacket, TcpPacket, Ipv4Packet};
use smoltcp::Error;
use dns_parser::rdata::A;

const UDP_BUFFER_SIZE: usize = 64 * 1024;
const TCP_BUFFER_SIZE: usize = 16 * 1024;

pub struct DnsInterceptor {
    pub fake_ip_manager: Arc<FakeIpManager>,
}

impl DnsInterceptor {

    pub fn run(&self) {
        let filter = "SrcPort = 53";
        let handle = match windivert::WinDivert::new(filter, WindivertLayer::Network, 0, Default::default()) {
            Ok(handle) => {
                handle
            }
            Err(errors) => {
                log::error!("create windivert handle error, {}", errors.to_string());
                exit(1);
            }
        };

        loop {
            let windivert_packet = match handle.recv(UDP_BUFFER_SIZE) {
                Ok(udp_packet) => {
                    udp_packet
                }

                Err(errors) => {
                    log::error!("windivert recv udp packet error, {}", errors.to_string());
                    continue;
                }
            };

            let windivert_packet_payload = windivert_packet.data.as_slice();
            let udp_packet = match UdpPacket::new_checked(windivert_packet_payload) {
                Ok(udp_packet) => {
                    udp_packet
                }
                Err(errors) => {
                    log::error!("check udp packet incorrect, {}", errors.to_string());
                    continue;
                }
            };

            let udp_packet_payload = udp_packet.payload();
            let dns_packet = match dns_parser::Packet::parse(udp_packet_payload) {
                Ok(dns_packet) => {
                    dns_packet
                }
                Err(errors) => {
                    log::error!("parse dns packet error, {}", errors.to_string());
                    continue;
                }
            };

            self.update_fake_ip(dns_packet);
            handle.send(windivert_packet);
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

        for answer in dns_packet.answers {
            if let A(ip) = answer.data {
                let host = format!("{}", answer.name);
                let ip_bytes = ip.octets();
                let ip_tuple = (ip_bytes[0], ip_bytes[1], ip_bytes[2], ip_bytes[3]);
                let fake_ip_manager = self.fake_ip_manager.clone();
                log::info!("Set fake ip {}:{}", host.to_string(), ip);
                fake_ip_manager.set_host_ip(&host, ip_tuple);
                break
            }
        }
    }
}
//
// pub struct TcpInterceptor {
//     //
// }
//
// impl TcpInterceptor {
//     pub fn run(&self) {
//         // 是否需要两个interceptor，拦截入口出口？
//         // 1. 出口流量addr部位
//         // 2.
//         let filter = "tcp";
//         let handle = match windivert::WinDivert::new(filter, 0, 0, 0) {
//             Ok(handle) => {
//                 handle
//             }
//             Err(errors) => {
//                 log::error!("create windivert handle error, {}", errors.to_string());
//                 exit(1);
//             }
//         };
//
//         loop {
//             let mut windivert_packet = match handle.recv(TCP_BUFFER_SIZE) {
//                 Ok(udp_packet) => {
//                     udp_packet
//                 }
//
//                 Err(errors) => {
//                     log::error!("windivert recv tcp packet error, {}", errors.to_string());
//                     continue;
//                 }
//             };
//
//             let windivert_packet_payload = windivert_packet.data.as_slice();
//             let len = windivert_packet_payload.len();
//             let mut fixed_bytes = Vec::with_capacity(len);
//             fixed_bytes.extend_from_slice(windivert_packet_payload);
//             let mut bytes = fixed_bytes.as_mut_slice();
//
//             let mut ip_packet = match Ipv4Packet::new_checked(bytes) {
//                 Ok(p) => p,
//                 Err(errors) => {
//                     log::error!("create ip packet error, {}", errors.to_string());
//                     continue;
//                 }
//             };
//
//             let src_addr = ip_packet.src_addr();
//             let dst_addr = ip_packet.dst_addr();
//             let mut tcp_packet = match TcpPacket::new_checked(ip_packet.payload_mut()) {
//                 Ok(tcp_packet) => {
//                     tcp_packet
//                 }
//                 Err(errors) => {
//                     log::error!("check tcp packet incorrect, {}", errors.to_string());
//                     continue;
//                 }
//             };
//
//             let src_port = tcp_packet.src_port();
//             let dst_port = tcp_packet.dst_port();
//             let src_addr = Ipv4Addr::from(src_addr);
//             let dst_addr = Ipv4Addr::from(dst_addr);
//
//             let mut nat_session_manager = match nat_session_manager.lock() {
//                 Ok(nat_session_manager) => {
//                     nat_session_manager
//                 }
//
//                 Err(_) => {
//                    log::error!("lock session manager failed");
//                     continue;
//                 }
//             };
//             let port = match nat_session_manager.get_session_port((src_addr, src_port, dst_addr, dst_port)) {
//                 None => continue,
//                 Some(port) => port
//             };
//
//             tcp_packet.set_src_port(port);
//             tcp_packet.set_dst_port(relay_port);
//             tcp_packet.fill_checksum(&dst_addr.into(), &relay_addr.into());
//             ip_packet.set_src_addr(dst_addr.into());
//             ip_packet.set_dst_addr(relay_addr.into());
//             ip_packet.fill_checksum();
//
//             let packet_bytes = ipv4_packet.as_ref();
//             windivert_packet.data = packet_bytes;
//             handle.send(windivert_packet);
//         }
//     }
// }
