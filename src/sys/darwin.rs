use std::net::IpAddr;
use tracing::info;
use std::process::Command;

pub struct DNSSetup {
    primary_network: String,
    original_dns: Vec<String>,
}

impl DNSSetup {
    #[allow(clippy::new_without_default)]
    pub fn new(dns: String) -> Self {
        let network = get_primary_network();
        info!("Primary netowrk service is {}", &network);
        let original_dns = run_cmd("networksetup", &["-getdnsservers", &network])
            .lines()
            .filter(|l| *l != "127.0.0.1" && *l != dns)
            .filter_map(|l| l.parse::<IpAddr>().ok())
            .map(|ip| ip.to_string())
            .collect::<Vec<_>>();

        info!("Original DNS is {:?}", &original_dns);
        if !original_dns.is_empty() {
            let mut args = vec!["-setdnsservers", &network, "127.0.0.1"];
            for dns in &original_dns {
                args.push(&dns);
            }
            let _ = run_cmd("networksetup", &args);
        } else if dns.is_empty() {
            let _ = run_cmd("networksetup", &["-setdnsservers", &network, "127.0.0.1"]);
        } else {
            let _ = run_cmd(
                "networksetup",
                &["-setdnsservers", &network, "127.0.0.1", &dns],
            );
        }
        DNSSetup {
            primary_network: network,
            original_dns,
        }
    }
}

impl Drop for DNSSetup {
    fn drop(&mut self) {
        let mut args = vec!["-setdnsservers", &self.primary_network];
        if self.original_dns.is_empty() {
            args.push("empty");
        } else {
            for dns in &self.original_dns {
                args.push(dns);
            }
        };
        info!("Restore original DNS: {:?}", self.original_dns);

        let _ = run_cmd("networksetup", &args);
    }
}

pub fn setup_ip(tun_name: &str, ip: &str, cidr: &str) {
    let _ = run_cmd("ifconfig", &[tun_name, ip, ip]);
    let _ = run_cmd("route", &["add", cidr, ip]);
}

fn get_primary_network() -> String {
    let route_ret = run_cmd("route", &["-n", "get", "0.0.0.0"]);
    let device = route_ret
        .lines()
        .find(|l| l.contains("interface:"))
        .and_then(|l| l.split_whitespace().last())
        .map(|s| s.trim())
        .expect("get primary device");
    info!("Primary device is {}", device);
    let network_services = run_cmd("networksetup", &["-listallhardwareports"]);
    let mut iter = network_services.lines().peekable();
    loop {
        if let Some(line) = iter.next() {
            if let Some(next_line) = iter.peek() {
                if next_line.split(':').last().map(|l| l.contains(device)) == Some(true) {
                    if let Some(network) = line.split(':').last().map(|s| s.trim()) {
                        return network.to_string();
                    }
                }
            } else {
                panic!("No primary network found");
            }
        } else {
            panic!("No primary network found");
        }
    }
}

pub fn run_cmd(cmd: &str, args: &[&str]) -> String {
    let output = Command::new(cmd)
        .args(args)
        .output()
        .expect("run cmd failed");
    log::info!(">>> - {} {:?}", cmd, args);

    if !output.status.success() {
        panic!(
            "{} {}\nstdout: {}\nstderr: {}",
            cmd,
            args.join(" "),
            std::str::from_utf8(&output.stdout).expect("utf8"),
            std::str::from_utf8(&output.stderr).expect("utf8")
        );
    }
    std::str::from_utf8(&output.stdout)
        .expect("utf8")
        .to_string()
}
