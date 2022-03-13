use smoltcp::wire::{IpProtocol, Ipv4Packet, TcpPacket, IpVersion, UdpPacket};
use std::net::Ipv4Addr;
use std::sync::{Arc, Mutex};
use crate::core::nat_session::NatSessionManager;
use std::str::FromStr;
use crate::sys::sys::setup_ip_route;
use crate::tun;
use std::thread::sleep;
use std::thread::spawn;
use std::time::Duration;
use std::io::{Read, Write};

pub struct TunServer {
    pub tun_ip: String,
    pub tun_cidr: String,
    pub tun_name: String,
    pub relay_addr: Ipv4Addr,
    pub relay_port: u16,
    pub nat_session_manager: Arc<Mutex<NatSessionManager>>,
}

impl TunServer {
    pub fn new(tun_ip: String, tun_cidr: String, tun_name: String, relay_port: u16,
               nat_session_manager: Arc<Mutex<NatSessionManager>>) -> Self {
        let relay_addr = Ipv4Addr::from_str(&tun_ip).unwrap();
        TunServer {
            tun_ip,
            tun_cidr,
            tun_name,
            relay_addr,
            relay_port,
            nat_session_manager,
        }
    }

    pub fn run_tun_server(mut self, stared_event_sender: std::sync::mpsc::Sender<bool>) {
        spawn(move || self.run_tun_server_inner(stared_event_sender));
    }

    pub fn run_tun_server_inner(&mut self, stared_event_sender: std::sync::mpsc::Sender<bool>) {
        #[cfg(target_os = "macos")]
            let mut tun_socket = match tun::darwin::TunSocket::new(&self.tun_name) {
            Ok(tun_socket) => tun_socket,
            Err(error) => {
                log::error!("create darwin tun error, {}", error.to_string());
                return;
            }
        };

        #[cfg(target_os = "macos")]
            setup_ip_route(&self.tun_name, &self.tun_ip, &self.tun_cidr);

        #[cfg(target_os = "windows")]
            let mut tun_socket = match tun::windows::TunSocket::new("rproxifier-tun") {
            Ok(tun_socket) => tun_socket,
            Err(error) => {
                log::error!("create windows tun error, {}", error.to_string());
                return;
            }
        };

        // windows sleep for a while
        #[cfg(target_os = "windows")]
            sleep(Duration::from_secs(5));

        stared_event_sender.send(true);
        let relay_addr = self.relay_addr;
        let relay_port = self.relay_port;
        self.run_ip_packet_transfer(tun_socket, relay_addr, relay_port);
    }

    fn run_ip_packet_transfer<T>(&mut self, mut tun_socket: T, relay_addr: Ipv4Addr, relay_port: u16) where T: Read + Write {
        loop {
            match self.transfer_ip_packet(&mut tun_socket, relay_addr, relay_port) {
                Err(errors) => {
                    log::error!("transfer tcp packet error, {}", errors);
                }
                _ => {}
            }
        }
    }

    fn transfer_ip_packet<T>(&mut self, mut tun_socket: T,
                             relay_addr: Ipv4Addr, relay_port: u16) -> anyhow::Result<()>
        where T: Read + Write {
        let nat_session_manager = self.nat_session_manager.clone();
        let mut socket_buf = [0u8; u16::MAX as usize];
        let mut ipv4_packet = match self.read_ipv4_packet(&mut tun_socket, &mut socket_buf) {
            Ok(packet) => packet,
            Err(errors) => return Err(anyhow::anyhow!("tun not supported udp"))
        };

        match ipv4_packet.protocol() {
            IpProtocol::Tcp => {
                if let Err(errors) = self.transfer_tcp_packet(&mut tun_socket, relay_addr, relay_port, nat_session_manager, ipv4_packet) {
                    return Err(errors);
                }
            }

            IpProtocol::Udp => {
                if let Err(errors) = self.transfer_udp_packet(&mut tun_socket, relay_addr, relay_port, nat_session_manager, ipv4_packet) {
                    return Err(anyhow::anyhow!("tun not supported udp"));
                }
            }

            other => {
                return Err(anyhow::anyhow!(format!("unsupported ipv4 protocol {} ", other)));
            }
        }
        Ok(())
    }

    fn read_ipv4_packet<'a, T>(&self, mut tun_socket: T, byte_mut: &'a mut [u8]) -> anyhow::Result<Ipv4Packet<&'a mut [u8]>> where T: Read + Write {
        let _read_size = match tun_socket.read(byte_mut) {
            Ok(size) => { size }
            Err(error) => {
                return Err(anyhow::anyhow!(format!("tun socket read error, {}", error)));
            }
        };

        let ip_version = match IpVersion::of_packet(byte_mut) {
            Ok(ip_version) => {
                ip_version
            }
            Err(error) => {
                return Err(anyhow::anyhow!(format!("check ip packet version error, {}", error)));
            }
        };

        if ip_version == IpVersion::Ipv6 {
            return Err(anyhow::anyhow!(format!("tun not supported ipv6 packet")));
        }

        match Ipv4Packet::new_checked(byte_mut) {
            Ok(p) => Ok(p),
            Err(errors) => {
                return Err(anyhow::anyhow!(format!("tun read ip_v4 packet error, {}", errors)));
            }
        }
    }

    fn transfer_tcp_packet<T>(&self, tun_socket: &mut T,
                              relay_addr: Ipv4Addr, relay_port: u16,
                              nat_session_manager: Arc<Mutex<NatSessionManager>>,
                              mut ipv4_packet: Ipv4Packet<&mut [u8]>) -> anyhow::Result<()>
        where T: Read + Write {
        let (src_addr, dst_addr) = {
            (ipv4_packet.src_addr(), ipv4_packet.dst_addr())
        };

        let mut tcp_packet = match TcpPacket::new_checked(ipv4_packet.payload_mut()) {
            Ok(packet) => packet,
            Err(error) => return Err(anyhow::anyhow!(format!("create checked tcp packet error, {}", error)))
        };

        let src_port = tcp_packet.src_port();
        let dst_port = tcp_packet.dst_port();
        let src_addr = Ipv4Addr::from(src_addr);
        let dst_addr = Ipv4Addr::from(dst_addr);

        let mut nat_session_manager = match nat_session_manager.lock() {
            Ok(nat_session_manager) => {
                nat_session_manager
            }

            Err(errors) => {
                return Err(anyhow::anyhow!(format!(", {}", errors)));
            }
        };

        let new_ip_packet = {
            if src_addr == relay_addr && src_port == relay_port {
                if let Some((src_addr, src_port, dst_addr, dst_port)) = nat_session_manager.get_port_session_tuple(dst_port) {
                    tcp_packet.set_src_port(dst_port);
                    tcp_packet.set_dst_port(src_port);
                    tcp_packet.fill_checksum(&dst_addr.into(), &src_addr.into());
                    ipv4_packet.set_src_addr(dst_addr.into());
                    ipv4_packet.set_dst_addr(src_addr.into());
                    ipv4_packet.fill_checksum();
                    ipv4_packet
                } else {
                    return Err(anyhow::anyhow!(format!("get invalid nat session with port, {}", dst_port)));
                }
            } else {
                let port = match nat_session_manager.get_session_port((src_addr, src_port, dst_addr, dst_port)) {
                    None => return Err(anyhow::anyhow!(format!("get session port with tuple {}:{} -> {}:{} error", src_addr, src_port, dst_addr, dst_port))),
                    Some(port) => port
                };

                tcp_packet.set_src_port(port);
                tcp_packet.set_dst_port(relay_port);
                tcp_packet.fill_checksum(&dst_addr.into(), &relay_addr.into());
                ipv4_packet.set_src_addr(dst_addr.into());
                ipv4_packet.set_dst_addr(relay_addr.into());
                ipv4_packet.fill_checksum();
                ipv4_packet
            }
        };
        let packet_bytes = new_ip_packet.as_ref();
        tun_socket.write(packet_bytes);
        Ok(())
    }

    fn transfer_udp_packet<T>(&self, tun_socket: &mut T,
                              relay_addr: Ipv4Addr, relay_port: u16,
                              nat_session_manager: Arc<Mutex<NatSessionManager>>,
                              mut ipv4_packet: Ipv4Packet<&mut [u8]>) -> anyhow::Result<()>
        where T: Read + Write {
        let (src_addr, dst_addr) = {
            (ipv4_packet.src_addr(), ipv4_packet.dst_addr())
        };

        let mut udp_packet = match UdpPacket::new_checked(ipv4_packet.payload_mut()) {
            Ok(packet) => packet,
            Err(error) => return Err(anyhow::anyhow!(format!("create checked tcp packet error, {}", error)))
        };

        let src_port = udp_packet.src_port();
        let dst_port = udp_packet.dst_port();
        let src_addr = Ipv4Addr::from(src_addr);
        let dst_addr = Ipv4Addr::from(dst_addr);

        log::info!("transfer udp packet {}:{} -> {}:{}", src_addr.to_string(), src_port, dst_addr.to_string(), dst_port);
        let mut nat_session_manager = match nat_session_manager.lock() {
            Ok(nat_session_manager) => {
                nat_session_manager
            }

            Err(errors) => {
                return Err(anyhow::anyhow!(format!(", {}", errors)));
            }
        };

        let new_ip_packet = {
            if src_addr == relay_addr && src_port == relay_port {
                if let Some((src_addr, src_port, dst_addr, dst_port)) = nat_session_manager.get_port_session_tuple(dst_port) {
                    udp_packet.set_src_port(dst_port);
                    udp_packet.set_dst_port(src_port);
                    udp_packet.fill_checksum(&dst_addr.into(), &src_addr.into());
                    ipv4_packet.set_src_addr(dst_addr.into());
                    ipv4_packet.set_dst_addr(src_addr.into());
                    ipv4_packet.fill_checksum();
                    ipv4_packet
                } else {
                    return Err(anyhow::anyhow!(format!("get invalid nat session with port, {}", dst_port)));
                }
            } else {
                let port = match nat_session_manager.get_session_port((src_addr, src_port, dst_addr, dst_port)) {
                    None => return Err(anyhow::anyhow!(format!("get session port with tuple {}:{} -> {}:{} error", src_addr, src_port, dst_addr, dst_port))),
                    Some(port) => port
                };

                udp_packet.set_src_port(port);
                udp_packet.set_dst_port(relay_port);
                udp_packet.fill_checksum(&dst_addr.into(), &relay_addr.into());
                ipv4_packet.set_src_addr(dst_addr.into());
                ipv4_packet.set_dst_addr(relay_addr.into());
                ipv4_packet.fill_checksum();
                ipv4_packet
            }
        };
        let packet_bytes = new_ip_packet.as_ref();
        tun_socket.write(packet_bytes);
        Ok(())
    }
}