#[cfg(any(target_os = "macos", target_os = "ios"))]
#[path = "darwin.rs"]
pub mod darwin;