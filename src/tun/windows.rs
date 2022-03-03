use std::io;
use std::io::{Read, Write};
use std::process::Command;
use std::sync::Arc;
use anyhow:: {anyhow, Result, Error};
use wintun::{Adapter, Packet, Session, Wintun, WintunError};

pub struct TunSocket {
    pub adapter: Arc<Adapter>,
    pub session: Arc<Session>,
}

impl Drop for TunSocket {
    fn drop(&mut self) {
        self.session.shutdown();
    }
}

impl TunSocket {
    pub fn new(tun_name: &str) -> anyhow::Result<TunSocket> {
        let lib_path = "wintun.dll";
        let mut wintun = match unsafe { wintun::load_from_path(lib_path) } {
            Ok(wintun) => wintun,
            Err(errors) => return Err(anyhow!("load wintun path from {} error, {}", lib_path, errors))
        };

        let mut adapter = match wintun::Adapter::open(&wintun, tun_name) {
            Ok(adapter_arc) => adapter_arc,
            Err(_) => {
                if let Ok(new_adapter) = wintun::Adapter::create(&wintun, tun_name, tun_name, None) {
                    new_adapter
                } else {
                    return Err(anyhow::anyhow!("create wintun adapter error"))
                }
            },
        };
        let adapter_index = adapter.get_adapter_index().unwrap();
        log::info!("Adapter {} interface index is {}", tun_name, adapter_index);

        // TODO: setup_ip()
        let output = Command::new("netsh")
            .arg("interface")
            .arg("ip")
            .arg("set")
            .arg("address")
            .arg(adapter_index.to_string().as_str())
            .arg("static")
            .arg("10.0.0.1")
            .output();
        match output {
            Ok(status) => {
                log::info!("set interface status is {}", status.status)
            }
            Err(err) => {
                log::info!("set interface error: {}", err.to_string())
            }
        }

        let version = wintun::get_running_driver_version(&wintun).unwrap();
        log::info!("Using wintun version: {:?}", version);
        match adapter.start_session(wintun::MAX_RING_CAPACITY) {
            Ok(session) => Ok(
                Self {
                    adapter,
                    session: Arc::new(session)
                }),
            Err(errors) => return Err(anyhow!("start wintun session error, {}", errors))
        }
    }

    fn write_packet(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let packet_bytes_size = buf.len();
        let mut send_packet = match self.session.allocate_send_packet(packet_bytes_size as u16) {
            Ok(send_packet) => send_packet,
            Err(errors) => {
                return Err(io::Error::from_raw_os_error(0))
            }
        };

        let send_packet_bytes = send_packet.bytes_mut();
        send_packet_bytes.copy_from_slice(buf);
        self.session.send_packet(send_packet);
        Ok(packet_bytes_size)
    }

    fn read_packet(&mut self, mut buf: &mut [u8]) -> std::io::Result<usize> {
        // FIXME: ensure buf len = u16::MAX
        match self.session.clone().receive_blocking() {
            Ok(mut packet) => {
                let packet_bytes = packet.bytes();
                buf.write(packet_bytes)
            }
            Err(errors) => {
                Err(io::Error::from_raw_os_error(0))
            }
        }
    }
}

impl Read for TunSocket {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.read_packet(buf)
    }
}

impl Write for TunSocket {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.write_packet(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}