use std::io::Read;
use std::thread::sleep;
use std::time::Duration;

fn main() {
    println!("Hello, world!");
    run_macos();
    run_windows();
}

fn run_macos() {
    println!("running on platform macos.");
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
    sleep(Duration::from_secs(100))
}
