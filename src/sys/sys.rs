use std::net::IpAddr;
use tracing::info;
use std::process::Command;
use std::io;
use anyhow::anyhow;

pub struct DNSSetup {
    dns_listen: String,
}

impl DNSSetup {
    #[allow(clippy::new_without_default)]
    pub fn new(dns: String) -> Self {
        let dns_listen = dns.clone();
        DNSSetup {
            dns_listen,
        }
    }

    pub fn set_dns(&self) {
        if cfg!(target_os="macos") {
            let network = get_primary_network();
            let original_dns = get_original_dns(&self.dns_listen);
            if !original_dns.is_empty() {
                let mut args = vec!["-setdnsservers", &network, "127.0.0.1"];
                for dns in original_dns {
                    args.push(&self.dns_listen);
                }
                let _ = run_cmd("networksetup", &args);
            } else if self.dns_listen.is_empty() {
                let _ = run_cmd("networksetup", &["-setdnsservers", &network, "127.0.0.1"]);
            } else {
                let _ = run_cmd(
                    "networksetup",
                    &["-setdnsservers", &network, "127.0.0.1", &self.dns_listen],
                );
            }
        } else {
            // match interfaces::Interface::get_all() {
            //     Ok(interface_vec) => {
            //         for i in interface_vec {
            //             log::info!("<<<<<<<<<<<<<<<<<<<<<<<<<<< {}", i.name)
            //         }
            //     }
            //     Err(_) => {}
            // }
        }
    }

    pub fn set_dns_with_primary_interface_name(&self, interface_name: String) {
        if cfg!(target_os="macos") {
            let network = get_primary_network_with_interface(&interface_name);
            let original_dns = get_original_dns(&self.dns_listen);
            if !original_dns.is_empty() {
                let mut args = vec!["-setdnsservers", &network, "127.0.0.1"];
                for dns in original_dns {
                    args.push(&self.dns_listen);
                }
                let _ = run_cmd("networksetup", &args);
            } else if self.dns_listen.is_empty() {
                let _ = run_cmd("networksetup", &["-setdnsservers", &network, "127.0.0.1"]);
            } else {
                let _ = run_cmd(
                    "networksetup",
                    &["-setdnsservers", &network, "127.0.0.1", &self.dns_listen],
                );
            }
        } else {
            // TODO: setup_ip()
            let output = Command::new("netsh")
                .arg("interface")
                .arg("ip")
                .arg("set")
                .arg("dns")
                .arg(interface_name.as_str())
                .arg("static")
                .arg("127.0.0.1")
                .output();
            match output {
                Ok(status) => {
                    log::info!("set interface dns result is {}", status.status)
                }
                Err(err) => {
                    log::info!("set interface dns error: {}", err.to_string())
                }
            }
        }
    }

    pub fn clear_dns(&self) {
        if cfg!(target_os="macos") {
            let network = get_primary_network();
            let original_dns = get_original_dns(&self.dns_listen);
            let mut args = vec!["-setdnsservers", &network];
            if original_dns.is_empty() {
                args.push("empty");
            } else {
                for dns in &original_dns {
                    args.push(dns);
                }
            };
            info!("Restore original DNS: {:?}", original_dns);
            let _ = run_cmd("networksetup", &args);
        } else {
            // TODO: windows
            let output = Command::new("ipconfig")
                .arg("/flushdns")
                .output();

            match output {
                Ok(status) => {
                    log::info!("flush dns status {}", status.status)
                }
                Err(err) => {
                    log::info!("flush dns status error: {}", err.to_string())
                }
            }
        }
    }

    pub fn clear_dns_with_interface_name(&self, interface_name: String) {
        if cfg!(target_os="macos") {
            let network = get_primary_network_with_interface(&interface_name);
            let original_dns = get_original_dns(&self.dns_listen);
            let mut args = vec!["-setdnsservers", &network];
            if original_dns.is_empty() {
                args.push("empty");
            } else {
                for dns in &original_dns {
                    args.push(dns);
                }
            };
            info!("Restore original DNS: {:?}", original_dns);
            let _ = run_cmd("networksetup", &args);
        } else {
            // windows
            let output = Command::new("netsh")
                .arg("interface")
                .arg("ip")
                .arg("set")
                .arg("dnsserver")
                .arg(interface_name.as_str())
                .arg("dhcp")
                .output();
            match output {
                Ok(status) => {
                    log::info!("set interface dns result is {}", status.status)
                }
                Err(err) => {
                    log::info!("set interface dns error: {}", err.to_string())
                }
            }
        }
    }
}

impl Drop for DNSSetup {
    fn drop(&mut self) {
        self.clear_dns()
    }
}

pub fn setup_ip_route(tun_name: &str, ip: &str, cidr: &str) {
    if cfg!(target_os="macos") {
        let _ = run_cmd("ifconfig", &[tun_name, ip, ip]);
        let _ = run_cmd("route", &["add", cidr, ip]);
    } else {
        // TODO: windows
    }
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

fn get_primary_network_with_interface(interface_name: &str) -> String {
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

pub fn get_gateway() -> String {
    let route_ret = run_cmd("route", &["-n", "get", "0.0.0.0"]);
    let device = route_ret
        .lines()
        .find(|l| l.contains("gateway:"))
        .and_then(|l| l.split_whitespace().last())
        .map(|s| s.trim())
        .expect("get primary device");
    return device.to_string();
}

fn get_original_dns(dns: &str) -> Vec<String> {
    let network = get_primary_network();
    info!("Primary netowrk service is {}", &network);
    let original_dns = run_cmd("networksetup", &["-getdnsservers", &network])
        .lines()
        .filter(|l| *l != "127.0.0.1" && *l != dns)
        .filter_map(|l| l.parse::<IpAddr>().ok())
        .map(|ip| ip.to_string())
        .collect::<Vec<_>>();
    return original_dns
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

#[cfg(target_os="macos")]
pub fn set_rlimit(limit: u64) -> anyhow::Result<()> {
        let limit = libc::rlimit {
            rlim_cur: limit,
            rlim_max: limit,
        };

        let ret = unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &limit) };
        if ret == -1 {
            return Err(anyhow!("set rlimt file error"));
        }
        Ok(())
}