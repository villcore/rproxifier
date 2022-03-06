use dashmap::{DashMap, Map};
use std::collections::hash_map::RandomState;
use dashmap::mapref::one::Ref;
use serde::{Serialize, Deserialize};
use crate::core::nat_session::NatSessionManager;

#[derive(Debug, Serialize, Deserialize)]
pub struct ActiveConnection {

    pub pid: u32,
    pub process_name: String,
    pub session_port: u16,
    pub src_addr: String,
    pub src_port: u16,
    pub dst_addr: String,
    pub dst_port: u16,
    pub tx: usize,
    pub rx: usize,
    pub start_timestamp: u64,
    pub latest_touch_timestamp: u64,
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

    pub fn get_copy(&self) -> ActiveConnection {
        ActiveConnection {
            pid: self.pid,
            process_name: self.process_name.to_string(),
            session_port: self.session_port,
            src_addr: self.src_addr.to_string(),
            src_port: self.src_port,
            dst_addr: self.dst_addr.to_string(),
            dst_port: self.dst_port,
            tx: self.tx / 1024,
            rx: self.rx / 1024,
            start_timestamp: self.start_timestamp,
            latest_touch_timestamp: self.latest_touch_timestamp
        }
    }
}

pub struct ActiveConnectionManager {
    pub connection_map : dashmap::DashMap<u16, ActiveConnection>
}

impl Default for ActiveConnectionManager {
    fn default() -> Self {
        Self {
            connection_map: DashMap::new()
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

    pub fn get_all_connection(&self) -> Option<Vec<ActiveConnection>> {
        let connections: Vec<ActiveConnection> = self.connection_map.iter()
            .map(|kv| kv.value().get_copy())
            .collect();
        Some(connections)
    }
}
