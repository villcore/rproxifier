use std::io::Read;

fn main() {
    println!("Hello, world!");
    run_macos();
}

fn run_macos() {
    println!("running on platform macos");
    // sudo route add -net 192.168.20.0 -netmask 255.255.255.0 -interface utun2

    let mut config = tun::Configuration::default();
    config
        .address((192, 168, 20, 1))
        .netmask((255, 255, 255, 0))
        .up();

    config.platform(|config| {
    });

    let mut dev = tun::create(&config).unwrap();
    let mut buf = [0u8; 128];
    loop {
        let amount = dev.read(&mut buf).unwrap();
        println!("{:?}", &buf[0..amount])
    }
}
