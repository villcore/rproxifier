use std::io::{Read, Write, ErrorKind};
use std::thread::sleep;
use std::thread::spawn;
use std::time::Duration;
use std::process::{Command, exit};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4, ToSocketAddrs};
use async_std_resolver::{resolver, config, AsyncStdResolver};
use crate::dns::resolve::{ForwardingDnsResolver, DirectDnsResolver, UserConfigDnsResolver, DnsResolver, ConfigDnsResolver, FakeIpManager, resolve_host};
use crate::dns::server::DnsUdpServer;
use smoltcp::wire::{IpAddress, IpProtocol, Ipv4Cidr, Ipv4Packet, TcpPacket, UdpPacket, IpVersion};

use log::{info, error, Level};
use std::collections::{HashMap, LinkedList};
use crate::sys::darwin::{setup_ip_route, set_rlimit, DNSSetup};
use smoltcp::Error;
use tun::darwin::TunSocket;
use tokio::net::{TcpStream, TcpListener};
use std::sync::{Arc, RwLock, Mutex, PoisonError, MutexGuard};
use std::str::FromStr;
use bytes::BytesMut;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use crate::dns::protocol::{QueryType, DnsPacket, DnsRecord, TransientTtl};
use std::any::Any;
use std::future::Future;
use async_std_resolver::config::{NameServerConfigGroup, NameServerConfig, Protocol, ResolverConfig, ResolverOpts};
use tokio::sync::mpsc::{Sender, Receiver};
use eframe::egui;
use eframe::egui::{Context, CentralPanel, TopBottomPanel, Layout, Align, RichText, Color32};
use eframe::epi::Frame;
use eframe::epi::egui::Ui;
use tokio::runtime::Runtime;
use std::sync::mpsc::{channel, RecvTimeoutError};

mod dns;
mod sys;
mod tun;
mod gui;

fn main() {
    // setup log
    setup_log();

    // run network module
    let mut network = Arc::new(NetworkModule::new("", 10000));
    let background_network = network.clone();
    spawn(move || background_network.run());

    // setup gui
    let app = App::new(network.clone());
    let options = eframe::NativeOptions {
        transparent: true,
        drag_and_drop_support: true,
        ..Default::default()
    };
    eframe::run_native(Box::new(app), options);
}

fn setup_log() {
    log4rs::init_file("config/logrs.yaml", Default::default()).unwrap();
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
                    port_activity_time: HashMap::new(),
                    recycle_port_list: LinkedList::new(),
                    next_port_seq: begin_port,
                }
            )),
        }
    }

    pub fn get_session_port(&mut self, tuple: (Ipv4Addr, u16, Ipv4Addr, u16)) -> Option<u16> {
        let mut inner = self.inner.lock().unwrap();
        let port = match inner.session_addr_to_port.get(&tuple) {
            None => {
                let port = inner.next_port();
                inner.session_addr_to_port.insert(tuple, port);
                inner.session_port_to_addr.insert(port, tuple);
                port
            }

            Some(port) => {
                *port
            }
        };

        inner.port_activity_time.insert(port, NatSessionManager::get_now_time());
        Some(port)
    }

    pub fn get_now_time() -> u64 {
        return std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
    }

    pub fn get_port_session_tuple(&mut self, port: u16) -> Option<(Ipv4Addr, u16, Ipv4Addr, u16)> {
        let mut inner = self.inner.lock().unwrap();
        let session_tuple = match inner.session_port_to_addr.get(&port) {
            None => {
                None
            }
            Some((src_addr, src_port, dst_addr, dst_port)) => {
                Some((src_addr.clone(), *src_port, dst_addr.clone(), *dst_port))
            }
        };

        if let Some(_) = session_tuple {
            inner.port_activity_time.insert(port, NatSessionManager::get_now_time());
        }
        session_tuple
    }

    /// 回收端口
    pub fn recycle_port(&mut self) {
        let mut inner = self.inner.lock().unwrap();
        let now = NatSessionManager::get_now_time();
        let invalid_port_list = inner.port_activity_time.iter()
            .filter(|(k, v)| now - **v > 600).map(|(k, _)|*k).collect::<Vec<u16>>();

        for port in invalid_port_list {
            inner.recycle_port(port);
            inner.port_activity_time.remove(&port);
        }
    }
}

pub struct InnerNatSessionManager {
    pub session_addr_to_port: HashMap<(Ipv4Addr, u16, Ipv4Addr, u16), u16>,
    pub session_port_to_addr: HashMap<u16, (Ipv4Addr, u16, Ipv4Addr, u16)>,
    pub port_activity_time: HashMap<u16, u64>,
    pub recycle_port_list: LinkedList<u16>,
    pub next_port_seq: u16,
}

impl InnerNatSessionManager {
    pub fn next_port(&mut self) -> u16 {
        log::info!("current recycle port queue count {}", self.recycle_port_list.len());
        return match self.get_recycle_port() {
            None => {
                let port = self.calculate_next_port();
                log::info!("get new calculate next port {}", port);
                port
            }
            Some(port) => {
                log::info!("get available recycle port {}", port);
                port
            }
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
            self.session_addr_to_port.remove(&(*src_addr, *src_port, *dst_addr, *dst_port, ));
            self.session_port_to_addr.remove(&port);
            self.recycle_port_list.push_back(port);
            log::info!("recycle port {}, total recycle port count {}", port, self.recycle_port_list.len());
        }
    }
}

/// App
pub struct App {
    network_module: Arc<NetworkModule>,

    // gui
    function_menu_list: Vec<(String, String)>,
    selected_menu: String,
    network_stared: bool
}

impl App {
    pub fn new(network_module: Arc<NetworkModule>) -> Self {
        Self {
            network_module,
            function_menu_list: vec![
                ("Overview".to_string(), "🔧 Overview".to_string()),
                ("Process".to_string(), "🔧 Process".to_string()),
                ("Connection".to_string(), "🔧 Connection".to_string()),
                ("DnsConfig".to_string(), "🔧 Dns Config".to_string()),
                ("Proxy".to_string(), "🔧 Proxy".to_string())
            ],
            selected_menu: "Overview".to_string(),
            network_stared: false
        }
    }

    fn main_function_menu_ui(&mut self, ui: &mut Ui) {

        // menu label
        ui.vertical_centered(|ui| {
            ui.heading("💻 Menu");
        });
        ui.separator();

        // menu list
        for (menu_item, menu_title) in self.function_menu_list.iter() {
            if ui.selectable_label(menu_item.to_string() == self.selected_menu, menu_title).clicked() {
                self.selected_menu = menu_item.to_string();
            }
            ui.separator();
        }
    }
}

impl eframe::epi::App for App {
    fn update(&mut self, ctx: &Context, frame: &Frame) {
        egui::SidePanel::left("left_menu").show(ctx, |ui| {
            self.main_function_menu_ui(ui);
        });

        // TODO: overview
        egui::CentralPanel::default().show(ctx, |ui|{

            ui.vertical_centered(|ui| {
                ui.heading("Overview");
                ui.separator();
            });

            ui.horizontal(|ui| {
                ui.with_layout(Layout::right_to_left(), |ui|{
                    ui.add_space(30.0);
                    if gui::toggle::toggle_ui_compact(ui, &mut self.network_stared).changed() {
                        if self.network_stared {
                            self.network_module.setup_dns()
                        } else {
                            self.network_module.clear_dns()
                        }
                    }

                    ui.add_space(10.0);
                    if self.network_stared {
                        ui.label(RichText::new("network started").color(Color32::from_rgb(0x20, 0xaf, 0x24)).strong());
                    } else {
                        ui.label(RichText::new("network not started").color(Color32::RED).strong());
                    }
                });
            });
        });
    }

    fn name(&self) -> &str {
        "rproxifier"
    }

    fn on_exit(&mut self) {
        if self.network_stared {
            self.network_module.clear_dns();
        }
    }
}

pub struct OverviewModule {
    network_module: Arc<NetworkModule>
}

impl eframe::epi::App for OverviewModule {

    fn update(&mut self, ctx: &Context, frame: &Frame) {

    }

    fn name(&self) -> &str {
        "Overview"
    }
}

///
pub struct NetworkModule {
    pub dns_listen: String,
    pub dns_setup: DNSSetup,
    pub nat_session_manager: Arc<Mutex<NatSessionManager>>,
    // pub fake_ip_manager: Arc<FakeIpManager>,
    // pub config_dns_resolver: ConfigDnsResolver,
}

impl NetworkModule {
    pub fn new(dns_listen: &str, net_session_begin_port: u16) -> Self {
        Self {
            // TODO: windows
            dns_listen: dns_listen.to_string(),
            dns_setup: sys::darwin::DNSSetup::new(dns_listen.to_string()),
            nat_session_manager: Arc::new(Mutex::new(NatSessionManager::new(net_session_begin_port))),
        }
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

    pub fn set_rlimit(&self, limit: u64) {
        set_rlimit(limit);
    }

    pub fn run_dns_server(&self) {
        log::info!("run dns server, listen at {}", self.dns_listen);
    }

    pub fn run(&self) {
        self.set_rlimit(30000);
        let nat_session_manager = Arc::new(Mutex::new(NatSessionManager::new(10000)));
        let fake_ip_manager = Arc::new(FakeIpManager::new((10, 0, 0, 100)));

        // start tun_server
        let (stared_event_sender, mut stared_event_receiver) = std::sync::mpsc::channel();
        self.run_sync_component(nat_session_manager.clone(), stared_event_sender);
        match stared_event_receiver.recv_timeout(Duration::from_secs(5)) {
            Ok(stared) => {
                log::info!("network sync component stared")
            }
            Err(_) => {
                log::info!("network sync component start fail");
                exit(1);
            }
        }

        // start dns_server & tcp_relay_server
        self.run_async_component(nat_session_manager.clone(), fake_ip_manager.clone());
    }

    pub fn run_sync_component(&self, nat_session_manager: Arc<Mutex<NatSessionManager>>, stared_event_sender: std::sync::mpsc::Sender<bool>) {
        log::info!("run sync component");
        // start tun_server
        let mut tun_server = TunServer {
            tun_ip: "10.0.0.1".to_string(),
            tun_cidr: "10.0.0.0/16".to_string(),
            tun_name: "utun9".to_string(),
            relay_addr:  Ipv4Addr::from_str("10.0.0.1").unwrap(),
            relay_port: 1300,
            nat_session_manager
        };
        spawn(move || tun_server.run_tun_server(stared_event_sender));
    }

    pub fn run_async_component(&self, nat_session_manager: Arc<Mutex<NatSessionManager>>, fake_ip_manager: Arc<FakeIpManager>) {
        log::info!("run async component");
        let run_time = match tokio::runtime::Builder::new_current_thread().enable_all().build() {
            Ok(run_time) => {
                run_time
            },
            Err(errors) => {
                log::error!("create runtime error, {}", errors);
                return
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
                dns_listen: "127.0.0.1:53".to_string()
            };
            log::info!("start run dns sever");
            dns_server.run_dns_server();
            log::info!("start run dns sever complete");

            // tcp_relay_server
            let tcp_relay_server = TcpRelayServer {
                resolver: Arc::new(resolver.clone()),
                fake_ip_manager: fake_ip_manager.clone(),
                nat_session_manager: nat_session_manager.clone(),
                listen_addr: (127, 0, 0, 1),
                listen_port: 1300
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
            }
        );

        name_server_config_group.push(
            NameServerConfig {
                socket_addr: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::from_str("223.5.5.5").unwrap(), 53)),
                protocol: Protocol::Udp,
                tls_dns_name: None,
                trust_nx_responses: false,
            }
        );

        name_server_config_group.push(
            NameServerConfig {
                socket_addr: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::from_str("114.114.114.114").unwrap(), 53)),
                protocol: Protocol::Tcp,
                tls_dns_name: None,
                trust_nx_responses: false,
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

///
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
        let mut tun_socket = match tun::darwin::TunSocket::new(&self.tun_name) {
            Ok(tun_socket) => tun_socket,
            Err(error) => {
                log::error!("create darwin tun error, {}", error.to_string());
                return;
            }
        };
        setup_ip_route(&self.tun_name, &self.tun_ip, &self.tun_cidr);
        stared_event_sender.send(true);

        let relay_addr = self.relay_addr;
        let relay_port = self.relay_port;
        self.run_ip_packet_transfer(tun_socket, relay_addr, relay_port);
    }

    fn run_ip_packet_transfer(&mut self, mut tun_socket: TunSocket, relay_addr: Ipv4Addr, relay_port: u16) {
        loop {
            match self.transfer_ip_packet(&mut tun_socket, relay_addr, relay_port) {
                Err(errors) => {
                    log::error!("transfer tcp packet error, {}", errors);
                }
                _ => {}
            }
        }
    }

    fn transfer_ip_packet(&mut self, mut tun_socket: &mut TunSocket,
                          relay_addr: Ipv4Addr, relay_port: u16) -> anyhow::Result<()> {
        let nat_session_manager = self.nat_session_manager.clone();
        let mut socket_buf = [0u8; 4096];
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
                return Err(anyhow::anyhow!("tun not supported udp"));
            }

            other => {
                return Err(anyhow::anyhow!(format!("unsupported ipv4 protocol {} ", other)));
            }
        }
        Ok(())
    }

    fn transfer_tcp_packet(&self, tun_socket: &mut TunSocket,
                           relay_addr: Ipv4Addr, relay_port: u16,
                           nat_session_manager: Arc<Mutex<NatSessionManager>>,
                           mut ipv4_packet: Ipv4Packet<&mut [u8]>) -> anyhow::Result<()> {
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

    fn read_ipv4_packet<'a>(&self, tun_socket: &mut TunSocket, byte_mut: &'a mut [u8]) -> anyhow::Result<Ipv4Packet<&'a mut [u8]>> {
        let read_size = match tun_socket.read(byte_mut) {
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
}

///
pub struct TcpRelayServer {
    pub resolver: Arc<AsyncStdResolver>,
    pub fake_ip_manager: Arc<FakeIpManager>,
    pub nat_session_manager: Arc<Mutex<NatSessionManager>>,
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
        let listen_addr = (Ipv4Addr::new(10, 0, 0, 1), 1300);
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
                let fake_ip_manager_copy = self.fake_ip_manager.clone();
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
                        }
                        Some((real_host, real_port)) => {
                            let (host, port) = (real_host.as_str(), real_port);
                            let (mut src_read, mut src_write) = tcp_socket.split();
                            let mut dst_socket = match TcpStream::connect((host, port)).await {
                                Ok(dst_socket) => {
                                    log::info!("session {} => connect real_addr {}:{}", session_port, host, port);
                                    dst_socket
                                }
                                Err(errors) => {
                                    log::error!("session {} => connect real addr {}:{} error, {}", session_port, host, port, errors);
                                    return;
                                }
                            };

                            let (mut dst_read, mut dst_write) = dst_socket.split();

                            let mut src_to_dst_buf = BytesMut::with_capacity(4096);
                            let mut dst_to_src_buf = BytesMut::with_capacity(4096);

                            loop {
                                tokio::select! {
                                        read_size = src_read.read_buf(&mut src_to_dst_buf) => {
                                            let size = match read_size {
                                                 Ok(size) => {
                                                     size as usize
                                                 }
                                                 Err(errors) => {
                                                     break;
                                                 }
                                            };

                                            if size <= 0 {
                                                log::info!("**********dst write close");
                                                break;
                                            }

                                            dst_write.write_buf(&mut src_to_dst_buf).await;
                                            src_to_dst_buf.clear();
                                        },

                                        write_size = dst_read.read_buf(&mut dst_to_src_buf) => {
                                            let size = match write_size {
                                                 Ok(size) => {
                                                     size as usize
                                                 }
                                                 Err(errors) => {
                                                     break;
                                                 }
                                            };

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
                        }
                    }
                });
            }
        }
    }
}

///
pub struct DnsManager {
    pub resolver: Arc<AsyncStdResolver>,
    pub fake_ip_manager: Arc<FakeIpManager>,
    pub dns_listen: String,
}

impl DnsManager {

    pub fn run_dns_server(self) {
        let fake_ip_manager = self.fake_ip_manager.clone();
        let async_resolver = (*self.resolver).clone();
        let config_dns_resolver = ConfigDnsResolver::new(fake_ip_manager, async_resolver);
        tokio::spawn(self.start_config_dns_server(config_dns_resolver));
    }

    async fn start_config_dns_server(self, config_dns_resolver: ConfigDnsResolver) {
        log::info!("start dns server at {}", self.dns_listen);
        let dns_server: DnsUdpServer = dns::server::DnsUdpServer::new(
            self.dns_listen,
            Box::new(config_dns_resolver),
        ).await;
        dns_server.run_server().await;
    }
}