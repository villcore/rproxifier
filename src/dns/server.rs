//! UDP and TCP server implementations for DNS

use crate::dns::buffer::{BytePacketBuffer, PacketBuffer, VectorPacketBuffer};
use crate::dns::context::ServerContext;
use crate::dns::protocol::{DnsPacket, DnsRecord, QueryType, ResultCode};
use crate::dns::resolve::DnsResolver;
use async_std::net::UdpSocket;
use async_std::task::spawn;
use std::sync::Arc;

macro_rules! return_or_report {
    ( $x:expr, $message:expr ) => {
        match $x {
            Ok(res) => res,
            Err(_) => {
                eprintln!($message);
                return;
            }
        }
    };
}

macro_rules! ignore_or_report {
    ( $x:expr, $message:expr ) => {
        match $x {
            Ok(_) => {}
            Err(_) => {
                eprintln!($message);
                return;
            }
        };
    };
}

/// Utility function for resolving domains referenced in for example CNAME or SRV
/// records. This usually spares the client from having to perform additional
/// lookups.
async fn resolve_cnames<'a>(
    lookup_list: &'a [DnsRecord],
    results: &'a mut Vec<DnsPacket>,
    resolver: &'a (dyn DnsResolver + Send + Sync),
    depth: u16,
) {
    let mut unmatched: Vec<_> = lookup_list
        .iter()
        .map(|rec| (rec.clone(), depth + 1))
        .collect();

    loop {
        if unmatched.is_empty() {
            break;
        }

        let mut new_unmatched = vec![];
        for (rec, depth) in unmatched {
            if depth <= 10 {
                match rec {
                    DnsRecord::CNAME { ref host, .. } | DnsRecord::SRV { ref host, .. } => {
                        if let Ok(result2) = resolver.resolve(host, QueryType::A, true).await {
                            new_unmatched.extend(
                                result2
                                    .get_unresolved_cnames()
                                    .into_iter()
                                    .map(|rec| (rec, depth + 1)),
                            );
                            results.push(result2);
                        }
                    }
                    _ => {}
                }
            }
        }
        unmatched = new_unmatched;
    }
}

/// Perform the actual work for a query
///
/// Incoming requests are validated to make sure they are well formed and adhere
/// to the server configuration. If so, the request will be passed on to the
/// active resolver and a query will be performed. It will also resolve some
/// possible references within the query, such as CNAME hosts.
///
/// This function will always return a valid packet, even if the request could not
/// be performed, since we still want to send something back to the client.
pub async fn execute_query(context: Arc<ServerContext>, request: &DnsPacket) -> DnsPacket {
    let allow_recursive = context.allow_recursive;
    let mut packet = DnsPacket::new();
    packet.header.id = request.header.id;
    packet.header.recursion_available = allow_recursive;
    packet.header.response = true;

    if request.header.recursion_desired && !allow_recursive {
        packet.header.rescode = ResultCode::REFUSED;
    } else if request.questions.is_empty() {
        packet.header.rescode = ResultCode::FORMERR;
    } else {
        let mut results = Vec::new();

        let question = &request.questions[0];
        packet.questions.push(question.clone());

        let resolver = context.resolver.as_ref();
        let rescode = match resolver
            .resolve(
                &question.name,
                question.qtype,
                request.header.recursion_desired,
            )
            .await
        {
            Ok(result) => {
                let rescode = result.header.rescode;

                let unmatched = result.get_unresolved_cnames();
                results.push(result);

                resolve_cnames(&unmatched, &mut results, resolver, 0).await;

                rescode
            }
            Err(_) => ResultCode::SERVFAIL,
        };

        packet.header.rescode = rescode;

        for result in results {
            for rec in result.answers {
                packet.answers.push(rec);
            }
            for rec in result.authorities {
                packet.authorities.push(rec);
            }
            for rec in result.resources {
                packet.resources.push(rec);
            }
        }
    }

    packet
}

/// The UDP server
///
/// Accepts DNS queries through UDP, and uses the `ServerContext` to determine
/// how to service the request. Packets are read on a single thread, after which
/// a new thread is spawned to service the request asynchronously.
pub struct DnsUdpServer {
    context: Arc<ServerContext>,
}

impl DnsUdpServer {
    pub async fn new(listen: String, resolver: Box<dyn DnsResolver + Send + Sync>) -> DnsUdpServer {
        let context = Arc::new(ServerContext::new(listen, resolver).await);
        DnsUdpServer { context }
    }

    pub fn context(&self) -> Arc<ServerContext> {
        self.context.clone()
    }

    /// Launch the server
    ///
    /// This method takes ownership of the server, preventing the method from
    /// being called multiple times.
    pub async fn run_server(self) {
        // Bind the socket
        let socket = Arc::new(UdpSocket::bind(&self.context.listen).await.unwrap());

        loop {
            // Read a query packet
            let mut req_buffer = BytePacketBuffer::new();
            let (_, src) = match socket.recv_from(&mut req_buffer.buf).await {
                Ok(x) => x,
                Err(e) => {
                    println!("Failed to read from UDP socket: {:?}", e);
                    continue;
                }
            };

            log::info!("Receive dns query, src address {} ", src.to_string());
            let context = self.context.clone();
            let socket_clone = socket.clone();

            spawn(async move {
                // Parse it
                let request = return_or_report!(
                    DnsPacket::from_buffer(&mut req_buffer),
                    "failed to parse packet"
                );

                let mut size_limit = 512;

                // Check for EDNS
                if request.resources.len() == 1 {
                    if let DnsRecord::OPT { packet_len, .. } = request.resources[0] {
                        size_limit = packet_len as usize;
                    }
                }

                // Create a response buffer, and ask the context for an appropriate
                // resolver
                let mut res_buffer = VectorPacketBuffer::new();

                let mut packet = execute_query(context, &request).await;
                let _ = packet.write(&mut res_buffer, size_limit);

                // Fire off the response
                let len = res_buffer.pos();
                let data =
                    return_or_report!(res_buffer.get_range(0, len), "Failed to get buffer data");
                ignore_or_report!(
                    socket_clone.send_to(data, src).await,
                    "Failed to send response packet"
                );
            });
        }
    }
}