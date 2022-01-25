use std::io::Read;
use std::thread::{sleep, spawn};
use std::time::Duration;

use std::process::{Command, exit};
use std::net::{IpAddr, Ipv4Addr};
use async_std_resolver::{resolver, config, AsyncStdResolver};
use crate::dns::server::DnsUdpServer;
use smoltcp::wire::{IpAddress, IpProtocol, Ipv4Cidr, Ipv4Packet, TcpPacket, UdpPacket};

use log::{info, error};
use std::collections::HashMap;
use std::sync::Arc;
use wintun::{Session, WintunError};
use crate::dns::resolve::{DirectDnsResolver, UserConfigDnsWrapResolver};
// use crate::sys::darwin::setup_ip;

mod dns;

fn main() {
    setup_log();
    info!("Hello, world!");
    // run_macos();

    let run_time = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();

    let dns_listen = "";
    // let dns_setup = sys::darwin::DNSSetup::new(dns_listen.to_string());

    // start tun_server
    let tun_server_join_handle = spawn(|| start_tun_server());

    // run dns server
    run_time.block_on(start_user_config_dns_server());

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

fn run_windows() {
    println!("running on platform windows");

    let lib_path = "wintun.dll";
    let wintun = unsafe { wintun::load_from_path(lib_path) }.expect("Failed to load wintun dll");

    let tun_name = "rproxifier-tun";
    let adapter = match wintun::Adapter::open(&wintun, tun_name) {
        Ok(a) => a,
        Err(_) => wintun::Adapter::create(&wintun, tun_name, tun_name, None)
            .expect("Failed to create wintun adapter!"),
    };

    // TODO: setup route
    // TODO: start read & write
    // TODO: notice direct
}

async fn start_user_config_dns_server() {
    info!("start dns server");
    let resolver_config = config::ResolverConfig::default();
    let resolver_opts = config::ResolverOpts::default();
    let resolver = resolver(resolver_config, resolver_opts).await
        .expect("failed to connect resolver");

    let dns_listen = "127.0.0.1:53";
    let direct_dns_resolver = DirectDnsResolver::new(resolver);
    let mut domain_map = HashMap::new();
    domain_map.insert("www.bing.com".to_string(), Ipv4Addr::new(18, 0, 0, 10));
    let user_config_dns_resolver = UserConfigDnsWrapResolver::new(domain_map, Box::new(direct_dns_resolver));
    let dns_server: DnsUdpServer = dns::server::DnsUdpServer::new(
        dns_listen.to_string(),
        Box::new(user_config_dns_resolver)
    ).await;
    dns_server.run_server().await;
    info!("stop dns server");
}

fn start_tun_server() {

    // TODO: use common config
    let tun_ip = "18.0.0.1";
    let tun_cidr = "18.0.0.0/16";
    let netmask = "255.255.255.0";

    //
    //
    // info!("start tun {}", tun_name);

    let lib_path = "wintun.dll";
    let wintun = unsafe { wintun::load_from_path(lib_path) }.expect("Failed to load wintun dll");

    let tun_name = "rproxifier-tun";
    let adapter = match wintun::Adapter::open(&wintun, tun_name) {
        Ok(a) => a,
        Err(_) => wintun::Adapter::create(&wintun, tun_name, tun_name, None)
            .expect("Failed to create wintun adapter!"),
    };

    let version = wintun::get_running_driver_version(&wintun).unwrap();
    info!("Using wintun version: {:?}", version);

    let session = Arc::new(adapter.start_session(wintun::MAX_RING_CAPACITY).unwrap());
    let reader_session = session.clone();

    loop {
        match reader_session.receive_blocking() {
            Ok(packet) => {
                let mut buf = packet.bytes();
                match Ipv4Packet::new_checked(&buf[..]) {
                    Ok(ipv4_packet) => {
                        println!("Ip protocol = {}, src = {}, dst = {}", ipv4_packet.protocol().to_string(), ipv4_packet.src_addr(), ipv4_packet.dst_addr());
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
    // modify ipv4 packet address & port

    // // config route
    // setup_ip(tun_name, tun_ip, tun_cidr);

    //
    // start tun handle
    // let mut buf = [0u8; 2048];
    // loop {
    //     let read_size = tun_socket.read(&mut buf).unwrap();
    //     if read_size == 0 {
    //         log::error!("tun read error");
    //         break;
    //     }
    //
    //     let mut ipv4_packet = match Ipv4Packet::new_checked(&buf[..read_size]) {
    //         Ok(p) => {
    //             p
    //         }
    //         Err(_) => {
    //             tracing::error!("tun read ip_v4 packet error");
    //             continue;
    //         }
    //     };
    //
    //     // modify ipv4 packet address & port
    //     println!("Ip protocol = {}, src = {}, dst = {}", ipv4_packet.protocol().to_string(), ipv4_packet.src_addr(), ipv4_packet.dst_addr());
    //     match ipv4_packet.protocol() {
    //         IpProtocol::Tcp => {
    //             let tcp_packet = TcpPacket::new_checked(ipv4_packet.payload()).unwrap();
    //             log::info!("tun read tcp package from src {} src_port {} ", ipv4_packet.src_addr(), tcp_packet.src_port());
    //
    //             // TODO: modify
    //         }
    //         // IpProtocol::Udp => {
    //         //
    //         // }
    //         other => {
    //             log::error!("unsupported ipv4 protocol {} ", other);
    //         }
    //     }
    //     // device.write(&buf[..read_size]);
}
