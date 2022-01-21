use std::io::{Read, Write};
use std::thread::sleep;
use std::time::Duration;
use log::{
    info,
    error,
};
use tun::Device;
use std::process::{Command, exit};
use std::net::IpAddr;
use async_std_resolver::{resolver, config, AsyncStdResolver};

fn main() {
    setup_log();
    info!("Hello, world!");
    // run_macos();

    let run_time = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();

    // run dns server
    run_time.block_on(start_dns_client());

    exit(0)
}

fn setup_log() {
    log4rs::init_file("config/logrs.yaml", Default::default()).unwrap();
}

fn run_macos() {
    info!("running on platform macos");

    // let tun_name = "utun10";
    let tun_ip = "10.0.0.1";
    let netmask = "255.255.255.0";

    let mut config = tun::Configuration::default();
    config
        .address(tun_ip)
        .netmask(netmask)
        .mtu(1500)
        .up();

    let mut device = tun::create(&config).unwrap();
    let tun_name_str = device.name();
    info!("Start tun {}", tun_name_str);

    info!("Start sleep.");
    sleep(Duration::from_secs(100));
    info!("End sleep.");

    // config route
    // TODO

    // start tun handle
    let mut buf = [0u8; 2048];
    loop {
        let read_size = device.read(&mut buf).unwrap();
        info!("Tun read {} size ", read_size);
        device.write(&buf[..read_size]);
    }
}

fn run_windows() {
    info!("running on platform windows");
    // TODO: setup route
    // TODO: start read & write
    // TODO: notice direct
}

fn run_linux() {}

fn run_cmd(cmd: &str, args: &[&str]) {
    let cmd_output = Command::new(cmd)
        .args(args)
        .output()
        .expect(&*format!("run cmd {} failed", cmd));

}

pub struct DnsClient {
    inner_resolver: AsyncStdResolver
}

impl DnsClient {

    async fn new() -> Self {

        let resolver = resolver(
            config::ResolverConfig::default(),
            config::ResolverOpts::default()).await.expect("failed to connect resolver");

        Self {
            inner_resolver: resolver
        }
    }

    async fn lookup(&self, domain: &str) -> Option<IpAddr> {
        let mut response = self.inner_resolver.lookup_ip(domain).await.unwrap();
        response.iter().next()
    }
}

async fn start_dns_client() {
    let dns_client = DnsClient::new().await;
    match dns_client.lookup("www.baidu.com").await {
        None => {
            info!("Get empty ip addr")
        }
        Some(ip_addr) => {
            info!("Get valid ip addr {} ", ip_addr)
        }
    }
}