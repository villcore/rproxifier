use std::sync::{Arc, Mutex};
use std::collections::{HashMap, LinkedList};
use std::net::Ipv4Addr;

pub struct NatSessionManager {
    pub inner: Arc<Mutex<InnerNatSessionManager>>,
}

impl NatSessionManager {
    pub fn new(begin_port: u16) -> Self {
        Self {
            inner: Arc::new(Mutex::new(
                InnerNatSessionManager {
                    session_addr_to_port: HashMap::new(),
                    session_port_to_addr: HashMap::new(),
                    port_activity_time: HashMap::new(),
                    recycle_port_list: LinkedList::new(),
                    next_port_seq: begin_port,
                }
            )),
        }
    }

    pub fn get_session_port(&mut self, tuple: (Ipv4Addr, u16, Ipv4Addr, u16)) -> Option<u16> {
        let mut inner = self.inner.lock().unwrap();
        let port = match inner.session_addr_to_port.get(&tuple) {
            None => {
                let port = inner.next_port();
                inner.session_addr_to_port.insert(tuple, port);
                inner.session_port_to_addr.insert(port, tuple);
                port
            }

            Some(port) => {
                *port
            }
        };

        inner.port_activity_time.insert(port, NatSessionManager::get_now_time());
        Some(port)
    }

    pub fn get_now_time() -> u64 {
        return std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
    }

    pub fn get_port_session_tuple(&mut self, port: u16) -> Option<(Ipv4Addr, u16, Ipv4Addr, u16)> {
        let mut inner = self.inner.lock().unwrap();
        let session_tuple = match inner.session_port_to_addr.get(&port) {
            None => {
                None
            }
            Some((src_addr, src_port, dst_addr, dst_port)) => {
                Some((src_addr.clone(), *src_port, dst_addr.clone(), *dst_port))
            }
        };

        if let Some(_) = session_tuple {
            inner.port_activity_time.insert(port, NatSessionManager::get_now_time());
        }
        session_tuple
    }

    /// 回收端口
    pub fn recycle_port(&mut self) {
        let mut inner = self.inner.lock().unwrap();
        let now = NatSessionManager::get_now_time();
        let invalid_port_list = inner.port_activity_time.iter()
            .filter(|(k, v)| now - **v > 600).map(|(k, _)|*k).collect::<Vec<u16>>();

        for port in invalid_port_list {
            inner.recycle_port(port);
            inner.port_activity_time.remove(&port);
        }
    }
}

pub struct InnerNatSessionManager {
    pub session_addr_to_port: HashMap<(Ipv4Addr, u16, Ipv4Addr, u16), u16>,
    pub session_port_to_addr: HashMap<u16, (Ipv4Addr, u16, Ipv4Addr, u16)>,
    pub port_activity_time: HashMap<u16, u64>,
    pub recycle_port_list: LinkedList<u16>,
    pub next_port_seq: u16,
}

impl InnerNatSessionManager {
    pub fn next_port(&mut self) -> u16 {
        return match self.get_recycle_port() {
            None => {
                let port = self.calculate_next_port();
                port
            }
            Some(port) => {
                port
            }
        };
    }

    fn calculate_next_port(&mut self) -> u16 {
        let next_port = self.next_port_seq;
        self.next_port_seq = self.next_port_seq + 1;
        next_port
    }

    fn get_recycle_port(&mut self) -> Option<u16> {
        self.recycle_port_list.pop_front()
    }

    fn recycle_port(&mut self, port: u16) {
        if let Some((src_addr, src_port, dst_addr, dst_port)) = self.session_port_to_addr.get(&port) {
            self.session_addr_to_port.remove(&(*src_addr, *src_port, *dst_addr, *dst_port, ));
            self.session_port_to_addr.remove(&port);
            self.recycle_port_list.push_back(port);
            log::info!("recycle port {}, total recycle port count {}", port, self.recycle_port_list.len());
        }
    }
}

#[cfg(test)]
pub mod tests {
    use crate::core::nat_session::NatSessionManager;

    #[test]
    pub fn test_get_now_time() {
        println!("{}", NatSessionManager::get_now_time())
    }
}