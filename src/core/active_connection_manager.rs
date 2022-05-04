use dashmap::{DashMap, Map};
use std::collections::hash_map::RandomState;
use dashmap::mapref::one::Ref;
use serde::{Serialize, Deserialize};
use crate::core::nat_session::NatSessionManager;
use crate::core::proxy_config_manager::ConnectionRouteRule;

#[derive(Debug, Serialize, Deserialize)]
pub struct ActiveConnection {

    pub pid: u32,
    pub process_name: String,
    pub process_execute_path: String,
    pub session_port: u16,
    pub src_addr: String,
    pub src_port: u16,
    pub dst_addr: String,
    pub dst_port: u16,
    pub route_rule: ConnectionRouteRule,
    pub transfer_type: ConnectionTransferType,

    // current trans
    pub tx: usize,
    pub rx: usize,
    pub latest_touch_timestamp: u64,

    // pre trans
    pub pre_tx: usize,
    pub pre_rx: usize,
    pub pre_touch_timestamp: u64,
    pub start_timestamp: u64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ActiveConnectionView {

    pub pid: u32,
    pub process_name: String,
    pub process_execute_path: String,
    pub session_port: u16,
    pub src_addr: String,
    pub src_port: u16,
    pub dst_addr: String,
    pub dst_port: u16,
    pub route_rule: ConnectionRouteRule,

    // current trans
    pub tx: usize,
    pub rx: usize,
    pub latest_touch_timestamp: u64,

    // pre trans
    pub pre_tx: usize,
    pub pre_rx: usize,
    pub pre_touch_timestamp: u64,
    pub start_timestamp: u64,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum ConnectionTransferType {
    TCP,
    UDP
}

impl ToString for ConnectionTransferType {
    fn to_string(&self) -> String {
        match self {
            ConnectionTransferType::TCP => "TCP".to_string(),
            ConnectionTransferType::UDP => "UDP".to_string()
        }
    }
}

impl ActiveConnection {

    pub fn incr_rx(&mut self, bytes: usize) {
        self.rx = self.rx + bytes;
        self.latest_touch_timestamp = NatSessionManager::get_now_time();
    }

    pub fn incr_tx(&mut self, bytes: usize) {
        self.tx = self.tx + bytes;
        self.latest_touch_timestamp = NatSessionManager::get_now_time();
    }

    pub fn get_read_copy(&self) -> ActiveConnectionView {
        ActiveConnectionView {
            pid: self.pid,
            process_name: self.process_name.to_string(),
            process_execute_path: self.process_execute_path.to_string(),
            session_port: self.session_port,
            src_addr: self.src_addr.to_string() + "   (" + &self.transfer_type.to_string() + ")",
            src_port: self.src_port,
            dst_addr: self.dst_addr.to_string(),
            dst_port: self.dst_port,
            route_rule: self.route_rule.get_copy(),
            tx: self.tx,
            rx: self.rx,
            start_timestamp: self.start_timestamp,
            latest_touch_timestamp: self.latest_touch_timestamp,
            pre_tx: self.pre_rx,
            pre_rx: self.pre_tx,
            pre_touch_timestamp: self.pre_touch_timestamp,
        }
    }

    pub fn calculate_trans(&mut self) {
        self.pre_touch_timestamp = self.latest_touch_timestamp;
        self.pre_tx = self.tx;
        self.pre_rx = self.rx;
    }
}

pub struct ActiveConnectionManager {
    pub connection_map : dashmap::DashMap<u16, ActiveConnection>,
    pub connection_force_close_signal : dashmap::DashMap<u16, tokio::sync::mpsc::Sender<bool>>
}

impl Default for ActiveConnectionManager {
    fn default() -> Self {
        Self {
            connection_map: DashMap::new(),
            connection_force_close_signal: DashMap::new()
        }
    }
}

impl ActiveConnectionManager {

    pub fn add_connection(&self, connection: ActiveConnection) -> anyhow::Result<()> {
        self.connection_map.insert(connection.session_port, connection);
        Ok(())
    }

    pub fn remove_connection(&self, session_port: u16) -> anyhow::Result<()> {
        self.connection_map.remove(&session_port);
        Ok(())
    }

    pub fn contains_connection(&self, session_port: u16) -> bool {
        self.connection_map.contains_key(&session_port)
    }

    pub fn incr_rx(&self, session_port: u16, bytes: usize) -> anyhow::Result<()>  {
        match self.connection_map.get_mut(&session_port) {
            Some(mut kv) => {
                let mut connection = kv.value_mut();
                connection.incr_rx(bytes)
            }
            None => {}
        }
        Ok(())
    }

    pub fn incr_tx(&self, session_port: u16, bytes: usize) -> anyhow::Result<()> {
        match self.connection_map.get_mut(&session_port) {
            Some(mut kv) => {
                let mut connection = kv.value_mut();
                connection.incr_tx(bytes)
            }
            None => {}
        }
        Ok(())
    }

    pub fn get_all_connection(&self) -> Option<Vec<ActiveConnectionView>> {
        let connections: Vec<ActiveConnectionView> = self.connection_map.iter_mut()
            .map(|mut kv| {
                let active_connection = kv.value_mut();
                let origin = active_connection.get_read_copy();
                active_connection.calculate_trans();
                origin
            })
            .collect();
        Some(connections)
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    #[test]
    pub fn test_rate_limiter() {
    }
}
