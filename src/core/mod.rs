use tokio::io::{AsyncRead, AsyncWrite};
use tokio::io::AsyncReadExt;
use tokio::io::AsyncWriteExt;
use bytes::BytesMut;
use std::sync::Arc;
use crate::core::active_connection_manager::ActiveConnectionManager;

pub mod nat_session;
pub mod dns_manager;
pub mod relay_server;
pub mod tun_server;
pub mod proxy_config_manager;
pub mod db;
pub mod host_route_manager;
pub mod active_connection_manager;
#[cfg(target_os = "windows")]
pub mod windivert;

pub struct StreamPipe<S, D> where S: AsyncRead + AsyncWrite, D: AsyncRead + AsyncWrite{
    pub session_port: u16,
    pub active_connection_manager: Arc<ActiveConnectionManager>,
    pub buf_size: usize,
    buffer_pool: Arc<crossbeam::queue::ArrayQueue<(BytesMut, BytesMut)>>,
    pub src_stream: S,
    pub dst_stream: D,
}

impl <S, D> StreamPipe<S, D> where S: AsyncRead + AsyncWrite + Unpin, D: AsyncRead + AsyncWrite + Unpin {

    pub fn new(session_port: u16,
               active_connection_manager: Arc<ActiveConnectionManager>,
               buf_size: usize,
               buffer_pool: Arc<crossbeam::queue::ArrayQueue<(BytesMut, BytesMut)>>,
               src_stream: S,
               dst_stream: D) -> Self {
        StreamPipe { session_port, active_connection_manager, buf_size, buffer_pool, src_stream, dst_stream }
    }

    pub async fn pipe_loop(&mut self) {
        let (mut src_to_dst_buf, mut dst_to_src_buf) = match self.buffer_pool.pop() {
            None => (BytesMut::with_capacity(self.buf_size), BytesMut::with_capacity(self.buf_size)),
            Some((mut src_to_dst_buf, mut dst_to_src_buf)) => (src_to_dst_buf, dst_to_src_buf)
        };

        loop {
            tokio::select! {

              // handle src to dst pipe
              read_size = self.src_stream.read_buf(&mut src_to_dst_buf) => {
                let size = match read_size {
                  Ok(size) => {size as usize}
                  Err(errors) => {break}
                };

                if size <= 0 {
                    break;
                }

                self.active_connection_manager.incr_tx(self.session_port, size);
                self.dst_stream.write_buf(&mut src_to_dst_buf).await;
              },

              // handle dst to dst pipe
              write_size = self.dst_stream.read_buf(&mut dst_to_src_buf) => {
                let size = match write_size {
                     Ok(size) => {
                         size as usize
                     }
                     Err(errors) => {
                         break;
                     }
                };

                if size <= 0 {
                    break;
                }
                self.active_connection_manager.incr_rx(self.session_port, size);
                self.src_stream.write_buf(&mut dst_to_src_buf).await;
              }
            }
        }

        src_to_dst_buf.clear();
        dst_to_src_buf.clear();
        self.buffer_pool.push((src_to_dst_buf, dst_to_src_buf));
    }
}