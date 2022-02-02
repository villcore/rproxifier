use std::process::Command;

#[cfg(any(target_os = "macos", target_os = "ios"))]
#[path = "darwin.rs"]
pub mod darwin;

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