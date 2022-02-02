use std::time::Duration;

use std::process::{Command, exit};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4};
use async_std_resolver::{resolver, config, AsyncStdResolver};

use crate::dns::resolve::{ForwardingDnsResolver, DirectDnsResolver, UserConfigDnsResolver, DnsResolver, ConfigDnsResolver, FakeIpManager, resolve_host};
use crate::dns::server::DnsUdpServer;
use smoltcp::wire::{IpAddress, IpProtocol, Ipv4Cidr, Ipv4Packet, TcpPacket, UdpPacket, IpVersion};

use log::{info, error};
use wintun::{Session, WintunError};

use std::collections::{HashMap, LinkedList};
use smoltcp::Error;
use tokio::net::{TcpStream, TcpListener};
use std::sync::{Arc, RwLock, Mutex};
use std::str::FromStr;
use bytes::BytesMut;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use crate::dns::protocol::{QueryType, DnsPacket, DnsRecord, TransientTtl};
use std::any::Any;
use std::borrow::BorrowMut;
use std::future::Future;
use std::thread::{sleep, spawn};
use async_std_resolver::config::{NameServerConfigGroup, NameServerConfig, Protocol};
use crate::sys::run_cmd;

fn main() {
    setup_log();
    // TODO construct config
    // TODO start_server_with_config
    info!("Hello, world!");

   let nat_session_manager = Arc::new(Mutex::new(NatSessionManager::new(10000)));

   let run_time = tokio::runtime::Builder::new_current_thread()
       .enable_all()
       .build()
       .unwrap();

   let dns_listen = "";
   // let dns_setup = sys::darwin::DNSSetup::new(dns_listen.to_string());
   // start tun_server
   let tun_session_manager = nat_session_manager.clone();
   let tun_server_join_handle = spawn(move || run_tun_server(tun_session_manager));

   // start tun_relay_server

   // TODO: remove this.
   sleep(Duration::from_secs(5));

   let relay_server_session_manager = nat_session_manager.clone();
   run_time.block_on(start(relay_server_session_manager));

   tun_server_join_handle.join();
    info!("Stop.");
    exit(0)
}

fn setup_log() {
    log4rs::init_file("config/logrs.yaml", Default::default()).unwrap();
}

fn run_macos() {
    println!("running on platform macos");
}

fn run_linux() {}

mod dns;
mod sys;
mod tun;

async fn start(nat_session_manager: Arc<Mutex<NatSessionManager>>) {
    let num_concurrent_reqs = 3;
    let mut name_server_config_group = NameServerConfigGroup::with_capacity(num_concurrent_reqs);
    name_server_config_group.push(
        NameServerConfig {
            socket_addr: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::from_str("114.114.114.114").unwrap(), 53)),
            protocol: Protocol::Udp,
            tls_dns_name: None,
            trust_nx_responses: false
        }
    );

    name_server_config_group.push(
        NameServerConfig {
            socket_addr: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::from_str("223.5.5.5").unwrap(), 53)),
            protocol: Protocol::Udp,
            tls_dns_name: None,
            trust_nx_responses: false
        }
    );

    name_server_config_group.push(
        NameServerConfig {
            socket_addr: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::from_str("114.114.114.114").unwrap(), 53)),
            protocol: Protocol::Tcp,
            tls_dns_name: None,
            trust_nx_responses: false
        }
    );

    // resolver config
    let resolver_config = config::ResolverConfig::from_parts(None, Vec::new(), name_server_config_group);

    // resolver opts
    let mut resolver_opts = config::ResolverOpts::default();
    resolver_opts.timeout = Duration::from_millis(200);
    resolver_opts.num_concurrent_reqs = num_concurrent_reqs;

    let resolver = resolver(resolver_config, resolver_opts).await.expect("failed to connect resolver");

    // TODO: config fake ip.
    let fake_ip_manager = Arc::new(FakeIpManager::new((10, 0, 0, 100)));
    let config_dns_resolver = ConfigDnsResolver::new(fake_ip_manager.clone(), resolver.clone());
    tokio::spawn(start_config_dns_server(config_dns_resolver));

    // tcp_relay_server
    let resolver_arc = Arc::new(resolver);
    tokio::spawn(run_tun_tcp_relay_server(
        resolver_arc,
        fake_ip_manager.clone(),
        nat_session_manager.clone(),
        "10.0.0.1",
        1300)
    ).await;
}

async fn start_config_dns_server(config_dns_resolver: ConfigDnsResolver) {
    log::info!("start dns server");
    // TODO: config.
    let dns_listen = "127.0.0.1:53";
    let dns_server: DnsUdpServer = dns::server::DnsUdpServer::new(
        dns_listen.to_string(),
        Box::new(config_dns_resolver),
    ).await;
    dns_server.run_server().await;
    log::info!("stop dns server");
}

// TODO: use tokio
fn run_tun_server(nat_session_manager: Arc<Mutex<NatSessionManager>>) {

    // TODO: use common config
    let tun_ip = "10.0.0.1";
    let tun_cidr = "10.0.0.0/16";
    let tun_name = "utun9";

    let relay_addr = Ipv4Addr::from_str(tun_ip).unwrap();
    let relay_port = 1300u16;
    //
    // info!("start tun {}", tun_name);

    let lib_path = "wintun.dll";
    let mut wintun = unsafe { wintun::load_from_path(lib_path) }.expect("Failed to load wintun dll");
    let tun_name = "rproxifier-tun";
    let mut adapter = match wintun::Adapter::open(&wintun, tun_name) {
        Ok(a) => a,
        Err(_) => wintun::Adapter::create(&wintun, tun_name, tun_name, None)
            .expect("Failed to create wintun adapter!"),
    };

    let adapter_index = adapter.get_adapter_index().unwrap();
    log::info!("Adapter {} interface index is {}", tun_name, adapter_index);
    let output = Command::new("netsh")
        .arg("interface")
        .arg("ip")
        .arg("set")
        .arg("address")
        .arg(adapter_index.to_string().as_str())
        .arg("static")
        .arg("10.0.0.1")
        .output();

    match output {
        Ok(status) => {
            log::info!("set interface status is {}", status.status)
        }
        Err(err) => {
            log::info!("set interface error: {}", err.to_string())
        }
    }

    let version = wintun::get_running_driver_version(&wintun).unwrap();
    info!("Using wintun version: {:?}", version);

    let session = Arc::new(adapter.start_session(wintun::MAX_RING_CAPACITY).unwrap());
    let reader_session = session.clone();

    loop {
        match reader_session.receive_blocking() {
            Ok(mut packet) => {
                let mut buf = packet.bytes_mut();
                let ip_version = match IpVersion::of_packet(&buf[..]) {
                    Err(_) => {
                        log::error!("check ip packet version error");
                        continue;
                    }
                    Ok(ip_version) => ip_version
                };

                if ip_version == IpVersion::Ipv6 {
                    log::error!("tun not supported ipv6 packet");
                    continue;
                }

                match Ipv4Packet::new_checked(&mut buf[..]) {
                    Ok(ipv4_packet) => {
                        // println!("Ip protocol = {}, src = {}, dst = {}", ipv4_packet.protocol().to_string(), ipv4_packet.src_addr(), ipv4_packet.dst_addr());
                        let mut ipv4_packet = match Ipv4Packet::new_checked( &mut buf[..]) {
                            Err(_) => {
                                log::error!("tun read ip_v4 packet error");
                                continue;
                            }
                            Ok(p) => p
                        };

                        let src_addr = Ipv4Addr::from(ipv4_packet.src_addr());
                        let dst_addr = Ipv4Addr::from(ipv4_packet.dst_addr());

                        match ipv4_packet.protocol() {
                            IpProtocol::Tcp => {
                                 let mut tcp_packet = TcpPacket::new_checked(ipv4_packet.payload_mut()).unwrap();
                                let src_port = tcp_packet.src_port();
                                let dst_port = tcp_packet.dst_port();
                                 // log::info!("tun read tcp package from src {}:{}, dst {}:{} ", src_addr, src_port, dst_addr, dst_port);

                                if src_addr == relay_addr && src_port == relay_port {
                                    let session_manager_copy = nat_session_manager.lock().unwrap();
                                    if let Some((src_addr, src_port, dst_addr, dst_port)) = session_manager_copy.get_port_session_tuple(dst_port) {
                                        let new_src_addr = dst_addr;
                                        let new_src_port = dst_port;
                                        let new_dst_addr = src_addr;
                                        let new_dst_port = src_port;

                                        tcp_packet.set_src_port(new_src_port);
                                        tcp_packet.set_dst_port(new_dst_port);
                                        tcp_packet.fill_checksum(&new_src_addr.into(), &new_dst_addr.into());
                                        ipv4_packet.set_src_addr(new_src_addr.into());
                                        ipv4_packet.set_dst_addr(new_dst_addr.into());
                                        ipv4_packet.fill_checksum();
                                        let packet_bytes = ipv4_packet.as_ref();
                                        // log::info!("1tun write new packet, src_addr {}, src_port {}, dst_addr {}, dst_port {}, packet size = {}",
                                        //          ipv4_packet.src_addr().to_string(), new_src_port,
                                        //          ipv4_packet.dst_addr().to_string(), new_dst_port,
                                        //          packet_bytes.len()
                                        // );

                                        let bytes_size = packet_bytes.len() as u16;
                                        let mut send_packet = session.allocate_send_packet(bytes_size).unwrap();
                                        let send_packet_bytes = send_packet.bytes_mut();
                                        send_packet_bytes.copy_from_slice(packet_bytes);
                                        session.send_packet(send_packet);
                                    } else {
                                        log::info!("<<<<<<< error1");
                                        continue;
                                    }
                                } else {
                                    // TODO: modify addr, port
                                    let copy = nat_session_manager.clone();
                                    let mut session_manager_write = copy.lock().unwrap();
                                    let port = session_manager_write.get_session_port((src_addr, src_port, dst_addr, dst_port));
                                    let port_opt = Some(port);
                                    if let Some(port) = port_opt {
                                        let new_src_addr = dst_addr;
                                        let new_src_port = port.unwrap();
                                        let new_dst_addr = relay_addr;
                                        let new_dst_port = 1300u16;

                                        tcp_packet.set_src_port(new_src_port);
                                        tcp_packet.set_dst_port(new_dst_port);
                                        tcp_packet.fill_checksum(&new_src_addr.into(), &new_dst_addr.into());
                                        ipv4_packet.set_src_addr(new_src_addr.into());
                                        ipv4_packet.set_dst_addr(new_dst_addr.into());
                                        ipv4_packet.fill_checksum();
                                        let packet_bytes = ipv4_packet.as_ref();
                                        // log::info!("2tun write new packet, src_addr {}, src_port {}, dst_addr {}, dst_port {} packet size = {}",
                                        //          ipv4_packet.src_addr().to_string(), new_src_port,
                                        //          ipv4_packet.dst_addr().to_string(), new_dst_port,
                                        //          packet_bytes.len()
                                        // );
                                        let bytes_size = packet_bytes.len() as u16;
                                        let mut send_packet = session.allocate_send_packet(bytes_size).unwrap();
                                        let send_packet_bytes = send_packet.bytes_mut();
                                        send_packet_bytes.copy_from_slice(packet_bytes);
                                        session.send_packet(send_packet);
                                    } else {
                                        log::info!("<<<<<<< error2");
                                        continue;
                                    }
                                }
                             }
                            IpProtocol::Udp => {
                                log::error!("tun not supported udp");
                                continue;
                            }
                            other => {
                                log::error!("unsupported ipv4 protocol {} ", other);
                            }
                        }
                    }
                    Err(_) => {
                        tracing::error!("tun read ip_v4 packet error");
                        continue;
                    }
                };
            }
            Err(_) => {
                println!("Got error while reading packet");
                break;
            },
        }
    }
    println!("Press enter to stop session");
}

async fn run_tun_tcp_relay_server(resolver_arc: Arc<AsyncStdResolver>, fake_ip_manager: Arc<FakeIpManager>, nat_session_manager: Arc<Mutex<NatSessionManager>>, addr: &str, port: u16) {
    // bind address
    let tcp_relay_server_addr = format!("{}:{}", addr, port);
    match TcpListener::bind((Ipv4Addr::new(10, 0, 0, 1), 1300)).await {
        Ok(tcp_listener) => {
            log::info!("======================tun tcp relay server listen {}", tcp_relay_server_addr);
            // accept
            while let Ok((mut tcp_socket, socket_addr)) = tcp_listener.accept().await {
                let session_port = socket_addr.port();
                log::info!("============================accept relay src socket {} ", socket_addr.to_string());
                let nat_session_read = nat_session_manager.lock().unwrap();
                if let Some((src_addr, src_port, dst_addr, dst_port)) = nat_session_read.get_port_session_tuple(session_port) {
                    log::info!("============================ real address is {}:{} to {}:{}",
                        src_addr, src_port, dst_addr, dst_port
                    );

                    let resolver_copy = resolver_arc.clone();
                    let fake_ip_manager_copy = fake_ip_manager.clone();
                    tokio::spawn(async move {
                        let dst_addr_bytes = dst_addr.octets();
                        let real_host_port = match fake_ip_manager_copy.get_host(&(dst_addr_bytes[0], dst_addr_bytes[1], dst_addr_bytes[2], dst_addr_bytes[3])) {
                            None => {
                                log::error!("get host from fake_ip {} error", dst_addr.to_string());
                                None
                            }

                            Some(host) => {
                                log::info!("get host from fake_ip {} success, host {}", dst_addr.to_string(), host);

                                let mut host_splits: Vec<&str> = host.split(".").collect();
                                let host_num_splits: Vec<u8> = host_splits.iter()
                                    .map(|s| s.parse::<u8>())
                                    .filter(|r| r.is_ok())
                                    .map(|r| r.unwrap())
                                    .collect();

                                let host_split_len = host_splits.len();
                                if host_split_len == 4 && host_num_splits.len() == host_split_len {
                                    // 如果是点号ip地址格式，选择直接连接
                                    Some((host, dst_port))
                                } else {
                                    // 如果是字符串host格式，需要dns解析
                                    match resolve_host(resolver_copy, &host).await {
                                        Ok(ipv4_addr) => {
                                            Some((ipv4_addr.to_string(), dst_port))
                                        }
                                        Err(_) => {
                                            log::error!("resolve host {} error", host);
                                            None
                                        }
                                    }
                                }
                            }
                        };

                        match real_host_port {
                            None => {
                                log::error!("get host from fake_ip {} error", dst_addr.to_string());
                                return
                            }
                            Some((real_host, real_port)) => {
                                // fake_id_manager
                                log::info!("======================================================== real_addr {}:{}", real_host, real_port);
                                let (mut src_read, mut src_write) = tcp_socket.split();

                                let mut dst_socket = TcpStream::connect((real_host, real_port)).await.unwrap();
                                let (mut dst_read, mut dst_write) = dst_socket.split();

                                let mut src_to_dst_buf = BytesMut::with_capacity(4096 * 4);
                                let mut dst_to_src_buf = BytesMut::with_capacity(4096 * 4);

                                loop {
                                    tokio::select! {
                                        read_size = src_read.read_buf(&mut src_to_dst_buf) => {
                                            let size = read_size.unwrap() as usize;
                                            if size <= 0 {
                                                log::info!("**********dst write close");
                                                break;
                                            }

                                            dst_write.write_buf(&mut src_to_dst_buf).await;
                                            src_to_dst_buf.clear();
                                            // log::info!("dst write >>>>> {}", size);
                                        },

                                        write_size = dst_read.read_buf(&mut dst_to_src_buf) => {
                                            let size = write_size.unwrap() as usize;
                                            if size <= 0 {
                                                log::info!("**********src write close");
                                                break;
                                            }
                                            src_write.write_buf(&mut dst_to_src_buf).await;
                                            dst_to_src_buf.clear();
                                            // log::info!("src write >>>>> {}", size);
                                        }
                                    }
                                }
                                log::info!("******************************************************");
                            }
                        }
                    });
                }

            }
        }

        Err(err) => {
            log::info!("======================tun tcp relay server {} error {}", tcp_relay_server_addr.to_string(), err.to_string());
        }
    }
}

pub struct NatSessionManager {
    pub inner: Arc<Mutex<InnerNatSessionManager>>,
}

impl NatSessionManager {

    pub fn new(begin_port: u16) -> Self {
        Self {
            inner: Arc::new(Mutex::new(
                InnerNatSessionManager {
                    session_addr_to_port: HashMap::new(),
                    session_port_to_addr: HashMap::new(),
                    recycle_port_list: LinkedList::new(),
                    next_port_seq: begin_port,
                }
            )),
        }
    }

    pub fn get_session_port(&mut self, tuple: (Ipv4Addr, u16, Ipv4Addr, u16)) -> Option<u16> {
        let mut inner = self.inner.lock().unwrap();
        match inner.session_addr_to_port.get(&tuple) {
            None => {
                let port = inner.next_port();
                inner.session_addr_to_port.insert(tuple, port);
                inner.session_port_to_addr.insert(port, tuple);
                Some(port)
            }

            Some(port) => {
                Some(*port)
            }
        }
    }

    pub fn get_port_session_tuple(&self, port: u16) -> Option<(Ipv4Addr, u16, Ipv4Addr, u16)> {
        match self.inner.lock().unwrap().session_port_to_addr.get(&port) {
            None => {
                None
            }
            Some((src_addr, src_port, dst_addr, dst_port)) => {
                Some((src_addr.clone(), *src_port, dst_addr.clone(), *dst_port))
            }
        }
    }

    pub fn recycle_port(&mut self, port: u16) {
        let mut inner = self.inner.lock().unwrap();
        inner.recycle_port(port);
    }

    // TODO: use channel monitor
    pub fn start_recycle_monitor() {

    }
}

pub struct InnerNatSessionManager {
    pub session_addr_to_port: HashMap<(Ipv4Addr, u16, Ipv4Addr, u16), u16>,
    pub session_port_to_addr: HashMap<u16, (Ipv4Addr, u16, Ipv4Addr, u16)>,
    pub recycle_port_list: LinkedList<u16>,
    pub next_port_seq: u16,
}

impl InnerNatSessionManager {

    pub fn next_port(&mut self) -> u16 {
        return match self.get_recycle_port() {
            None => self.calculate_next_port(),
            Some(port) => port
        };
    }

    fn calculate_next_port(&mut self) -> u16 {
        let next_port = self.next_port_seq;
        self.next_port_seq = self.next_port_seq + 1;
        next_port
    }

    fn get_recycle_port(&mut self) -> Option<u16> {
        self.recycle_port_list.pop_front()
    }

    fn recycle_port(&mut self, port: u16) {
        if let Some((src_addr, src_port, dst_addr, dst_port)) = self.session_port_to_addr.get(&port) {
            self.session_addr_to_port.remove(&(*src_addr, *src_port, *dst_addr, *dst_port,));
            self.session_port_to_addr.remove(&port);
        }
    }
}
