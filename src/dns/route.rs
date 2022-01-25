
pub fn setup_ip(tun_name: &str, ip: &str, cidr: &str) {
    let _ = run_cmd("ifconfig", &[tun_name, ip, ip]);
    let _ = run_cmd("route", &["add", cidr, ip]);
}