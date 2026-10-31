use std::{io, net::SocketAddr, sync::Arc, time::Duration};

use async_trait::async_trait;
use percent_encoding::percent_decode_str;
use serde::Deserialize;
use serde_json::{Value, json};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadHalf, WriteHalf},
    net::TcpStream,
    sync::{Mutex, mpsc},
    time::{Instant, timeout},
};
use tokio_rustls::{
    TlsConnector,
    rustls::{ClientConfig, RootCertStore, pki_types::ServerName},
};
use tokio_util::sync::CancellationToken;
use turn::client::{Client, ClientConfig as TurnConfig};
use url::Url;
use webrtc_util::{Conn, Error as ConnError};

use crate::{Error, ProfileError, ProfileErrorKind};

#[derive(Clone)]
pub(crate) struct Route(Option<Proxy>);

#[derive(Clone)]
struct Proxy {
    scheme: String,
    host: String,
    port: u16,
    auth: Option<(String, String)>,
    tls: Option<Arc<ClientConfig>>,
}

impl Route {
    pub(crate) fn parse(value: Option<&str>) -> Result<Self, Error> {
        let Some(value) = value.filter(|value| !value.is_empty()) else {
            return Ok(Self(None));
        };
        let invalid = || Error::Configuration("invalid target proxy configuration");
        let url = Url::parse(value).map_err(|_| invalid())?;
        if !matches!(url.scheme(), "http" | "https" | "socks5")
            || url.host_str().is_none()
            || !matches!(url.path(), "" | "/")
            || url.query().is_some()
            || url.fragment().is_some()
        {
            return Err(invalid());
        }
        let port = url.port().unwrap_or(match url.scheme() {
            "http" => 80,
            "https" => 443,
            _ => 1080,
        });
        if port == 0 {
            return Err(invalid());
        }
        let auth = if !url.username().is_empty() || url.password().is_some() {
            let username = percent_decode_str(url.username())
                .decode_utf8()
                .map_err(|_| invalid())?
                .into_owned();
            let password = percent_decode_str(url.password().unwrap_or(""))
                .decode_utf8()
                .map_err(|_| invalid())?
                .into_owned();
            if url.scheme() == "socks5" && (username.len() > 255 || password.len() > 255) {
                return Err(invalid());
            }
            Some((username, password))
        } else {
            None
        };
        Ok(Self(Some(Proxy {
            scheme: url.scheme().to_owned(),
            host: url
                .host_str()
                .ok_or_else(invalid)?
                .trim_matches(['[', ']'])
                .to_owned(),
            port,
            auth,
            tls: if url.scheme() == "https" {
                Some(
                    tls_config()
                        .map_err(|_| Error::Configuration("invalid proxy TLS configuration"))?,
                )
            } else {
                None
            },
        })))
    }

    async fn connect(&self, peer: SocketAddr) -> io::Result<(Box<dyn Stream>, SocketAddr)> {
        let Some(proxy) = &self.0 else {
            let stream = TcpStream::connect(peer).await?;
            let local = stream.local_addr()?;
            return Ok((Box::new(stream), local));
        };
        let tcp = TcpStream::connect((proxy.host.as_str(), proxy.port)).await?;
        let local = tcp.local_addr()?;
        let mut stream: Box<dyn Stream> = if let Some(config) = &proxy.tls {
            let name = ServerName::try_from(proxy.host.clone())
                .map_err(|_| io::Error::other("invalid proxy host"))?;
            Box::new(
                TlsConnector::from(config.clone())
                    .connect(name, tcp)
                    .await?,
            )
        } else {
            Box::new(tcp)
        };
        match proxy.scheme.as_str() {
            "http" | "https" => {
                // Provider owns CONNECT parsing and authentication.
                let host = match peer {
                    SocketAddr::V4(_) => peer.ip().to_string(),
                    SocketAddr::V6(_) => format!("[{}]", peer.ip()),
                };
                if let Some((username, password)) = &proxy.auth {
                    async_http_proxy::http_connect_tokio_with_basic_auth(
                        &mut stream,
                        &host,
                        peer.port(),
                        username,
                        password,
                    )
                    .await
                    .map_err(|_| io::Error::other("target proxy connection failed"))?;
                } else {
                    async_http_proxy::http_connect_tokio(&mut stream, &host, peer.port())
                        .await
                        .map_err(|_| io::Error::other("target proxy connection failed"))?;
                }
            }
            _ => {
                let auth = proxy.auth.as_ref().map(|(user, password)| {
                    async_socks5::Auth::new(user.clone(), password.clone())
                });
                async_socks5::connect(&mut stream, peer, auth)
                    .await
                    .map_err(|_| io::Error::other("target proxy connection failed"))?;
            }
        }
        Ok((stream, local))
    }
}

pub(crate) fn tls_config() -> io::Result<Arc<ClientConfig>> {
    let roots = RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let config = ClientConfig::builder_with_provider(Arc::new(
        tokio_rustls::rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .map_err(|_| io::Error::other("invalid TLS provider configuration"))?
    .with_root_certificates(roots)
    .with_no_client_auth();
    Ok(Arc::new(config))
}

trait Stream: AsyncRead + AsyncWrite + Unpin + Send + Sync {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send + Sync> Stream for T {}

/// webrtc-util 0.17.1 has no connected TCP Conn. This adapter only delimits
/// complete stream records; turn 0.17.2 owns every STUN/TURN message and timer.
struct TcpPackets {
    read: Mutex<Option<ReadHalf<Box<dyn Stream>>>>,
    write: Mutex<Option<WriteHalf<Box<dyn Stream>>>>,
    local: SocketAddr,
    peer: SocketAddr,
    closed: CancellationToken,
    failed: CancellationToken,
}

impl TcpPackets {
    fn new(stream: Box<dyn Stream>, local: SocketAddr, peer: SocketAddr) -> Self {
        let (read, write) = tokio::io::split(stream);
        Self {
            read: Mutex::new(Some(read)),
            write: Mutex::new(Some(write)),
            local,
            peer,
            closed: CancellationToken::new(),
            failed: CancellationToken::new(),
        }
    }

    async fn read_packet(&self, buf: &mut [u8]) -> io::Result<usize> {
        let mut guard = self.read.lock().await;
        let stream = guard.as_mut().ok_or_else(closed)?;
        if buf.len() < 4 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "TURN packet buffer too short",
            ));
        }
        stream.read_exact(&mut buf[..4]).await?;
        let payload = usize::from(u16::from_be_bytes([buf[2], buf[3]]));
        let (length, padding) = match buf[0] >> 6 {
            0 => (20 + payload, 0),
            1 => (4 + payload, (4 - payload % 4) % 4),
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "invalid TURN TCP record",
                ));
            }
        };
        if length > buf.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "TURN TCP record exceeds packet buffer",
            ));
        }
        stream.read_exact(&mut buf[4..length]).await?;
        if padding != 0 {
            let mut pad = [0; 3];
            stream.read_exact(&mut pad[..padding]).await?;
        }
        Ok(length)
    }
}

fn closed() -> io::Error {
    io::Error::new(io::ErrorKind::ConnectionAborted, "TURN stream closed")
}

#[async_trait]
impl Conn for TcpPackets {
    async fn connect(&self, addr: SocketAddr) -> Result<(), ConnError> {
        if addr == self.peer {
            Ok(())
        } else {
            Err(io::Error::other("TURN stream already connected").into())
        }
    }

    async fn recv(&self, buf: &mut [u8]) -> Result<usize, ConnError> {
        tokio::select! {
            biased;
            _ = self.closed.cancelled() => Err(closed().into()),
            result = self.read_packet(buf) => result.map_err(|error| {
                if error.kind() != io::ErrorKind::InvalidInput && !self.closed.is_cancelled() {
                    self.failed.cancel();
                }
                error.into()
            }),
        }
    }

    async fn recv_from(&self, buf: &mut [u8]) -> Result<(usize, SocketAddr), ConnError> {
        self.recv(buf).await.map(|size| (size, self.peer))
    }

    async fn send(&self, buf: &[u8]) -> Result<usize, ConnError> {
        let mut guard = self.write.lock().await;
        let stream = guard.as_mut().ok_or_else(closed)?;
        tokio::select! {
            biased;
            _ = self.closed.cancelled() => Err(closed().into()),
            result = stream.write_all(buf) => result.map(|()| buf.len()).map_err(|error| {
                if !self.closed.is_cancelled() {
                    self.failed.cancel();
                }
                error.into()
            }),
        }
    }

    async fn send_to(&self, buf: &[u8], target: SocketAddr) -> Result<usize, ConnError> {
        if target != self.peer {
            return Err(io::Error::other("TURN stream destination mismatch").into());
        }
        self.send(buf).await
    }

    fn local_addr(&self) -> Result<SocketAddr, ConnError> {
        Ok(self.local)
    }
    fn remote_addr(&self) -> Option<SocketAddr> {
        Some(self.peer)
    }

    async fn close(&self) -> Result<(), ConnError> {
        self.closed.cancel();
        self.read.lock().await.take();
        if let Some(mut writer) = self.write.lock().await.take() {
            timeout(Duration::from_secs(3), writer.shutdown())
                .await
                .map_err(|_| {
                    io::Error::new(io::ErrorKind::TimedOut, "TURN stream shutdown timed out")
                })??;
        }
        Ok(())
    }

    fn as_any(&self) -> &(dyn std::any::Any + Send + Sync) {
        self
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct IceServer {
    pub host: String,
    pub port: u16,
    pub transport: String,
    pub username: String,
    pub credential: String,
}

impl IceServer {
    pub(crate) fn valid(&self) -> bool {
        self.transport == "tcp"
            && self.port != 0
            && !self.host.is_empty()
            && !self
                .host
                .chars()
                .any(|c| c.is_control() || c.is_whitespace() || matches!(c, '/' | '@' | '?' | '#'))
    }
}

pub(crate) async fn gather(
    id: i64,
    server: IceServer,
    route: Route,
    release: CancellationToken,
    cancel: CancellationToken,
    replies: mpsc::UnboundedSender<Value>,
    limit: Duration,
) -> Result<(), ProfileError> {
    let started = Instant::now();
    let connection = async {
        // The provider requires a numeric logical peer. Resolve once, then tunnel
        // that exact endpoint; this never opens a UDP socket or a fallback route.
        let peer = tokio::net::lookup_host((server.host.as_str(), server.port))
            .await?
            .next()
            .ok_or_else(|| io::Error::other("TURN endpoint did not resolve"))?;
        let (stream, local) = route.connect(peer).await?;
        Ok::<_, io::Error>(Arc::new(TcpPackets::new(stream, local, peer)))
    };
    let conn = tokio::select! {
        biased;
        _ = cancel.cancelled() => return Ok(()),
        _ = release.cancelled() => return Ok(()),
        result = timeout(limit, connection) => match result {
            Ok(Ok(conn)) => conn,
            _ => { let _ = replies.send(json!({"type":"ice.result", "id":id, "observation":null})); return Ok(()); }
        },
    };
    let config = TurnConfig {
        stun_serv_addr: String::new(),
        turn_serv_addr: conn.peer.to_string(),
        username: server.username,
        password: server.credential,
        realm: String::new(),
        software: String::new(),
        rto_in_ms: 0,
        conn: conn.clone(),
        vnet: None,
    };
    let opened = tokio::select! {
        biased;
        _ = cancel.cancelled() => None,
        _ = release.cancelled() => None,
        result = timeout(limit, Client::new(config)) => Some(result),
    };
    let client = match opened {
        Some(Ok(Ok(client))) => client,
        other => {
            let close_result = conn.close().await;
            if other.is_some() {
                let _ = replies.send(json!({"type":"ice.result", "id":id, "observation":null}));
            }
            return close_result.map_err(|_| transport("TURN stream cleanup failed"));
        }
    };
    let outcome = async {
        if client.listen().await.is_err() {
            let _ = replies.send(json!({"type":"ice.result", "id":id, "observation":null}));
            return Ok(());
        }
        let relay = tokio::select! {
            biased;
            _ = cancel.cancelled() => return Ok(()),
            _ = release.cancelled() => return Ok(()),
            result = timeout(limit, client.allocate()) => match result {
                Ok(Ok(relay)) => relay,
                _ => { let _ = replies.send(json!({"type":"ice.result", "id":id, "observation":null})); return Ok(()); }
            },
        };
        let observation = relay.local_addr().map(|address| {
            let elapsed = started.elapsed().as_secs_f64() * 1000.0;
            json!({
                "candidates":[{"value":format!("candidate:1 1 udp 16777215 {} {} typ relay", address.ip(), address.port()), "elapsed_ms":elapsed}],
                "complete_at_ms":started.elapsed().as_secs_f64() * 1000.0,
            })
        });
        let failed = match observation {
            Ok(observation) => {
                let _ = replies.send(json!({"type":"ice.result", "id":id, "observation":observation}));
                tokio::select! {
                    biased;
                    _ = cancel.cancelled() => false,
                    _ = release.cancelled() => false,
                    _ = conn.failed.cancelled() => true,
                }
            }
            Err(_) => {
                let _ = replies.send(json!({"type":"ice.result", "id":id, "observation":null}));
                false
            }
        };
        // Provider stops refresh timers and sends authenticated Refresh(0).
        // Its public close does not wait for an ACK; no deletion is asserted.
        let allocation_closed = timeout(Duration::from_secs(3), relay.close()).await;
        if failed && !cancel.is_cancelled() && !release.is_cancelled() {
            return Err(transport("TURN stream failed"));
        }
        allocation_closed
            .map_err(|_| transport("TURN allocation cleanup timed out"))?
            .map_err(|_| transport("TURN allocation cleanup failed"))
    }.await;
    let stream_closed = conn.close().await;
    let client_closed = client.close().await;
    outcome?;
    client_closed.map_err(|_| transport("TURN client cleanup failed"))?;
    stream_closed.map_err(|_| transport("TURN stream cleanup failed"))
}

fn transport(message: &'static str) -> ProfileError {
    ProfileError::new(ProfileErrorKind::Transport, message, None)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn packets(stream: tokio::io::DuplexStream) -> TcpPackets {
        TcpPackets::new(
            Box::new(stream),
            "127.0.0.1:1000".parse().unwrap(),
            "127.0.0.1:3478".parse().unwrap(),
        )
    }

    #[tokio::test]
    async fn fragmented_stun_and_padded_channel_records_keep_their_boundaries() {
        let (stream, mut peer) = tokio::io::duplex(64);
        let packets = packets(stream);
        let mut stun = [0u8; 24];
        stun[1] = 1;
        stun[3] = 4;
        stun[4..8].copy_from_slice(&[0x21, 0x12, 0xa4, 0x42]);
        stun[20..].copy_from_slice(&[1, 2, 3, 4]);
        let channel = [0x40, 0, 0, 3, 10, 11, 12, 0];
        let writer = tokio::spawn(async move {
            for byte in stun.into_iter().chain(channel) {
                peer.write_all(&[byte]).await.unwrap();
                tokio::task::yield_now().await;
            }
        });
        let mut buffer = [0u8; 32];
        assert_eq!(packets.read_packet(&mut buffer).await.unwrap(), 24);
        assert_eq!(&buffer[..24], &stun);
        assert_eq!(packets.read_packet(&mut buffer).await.unwrap(), 7);
        assert_eq!(&buffer[..7], &channel[..7]);
        writer.await.unwrap();
        packets.close().await.unwrap();
    }

    #[tokio::test]
    async fn oversized_record_is_rejected() {
        let (stream, mut peer) = tokio::io::duplex(8);
        let packets = packets(stream);
        peer.write_all(&[0, 1, 255, 255]).await.unwrap();
        let mut buffer = [0u8; 32];
        assert_eq!(
            packets.read_packet(&mut buffer).await.unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
        packets.close().await.unwrap();
    }

    #[tokio::test]
    async fn unexpected_eof_or_framing_failure_preserves_explicit_writer_shutdown() {
        let records: &[&[u8]] = &[
            &[],
            &[0, 1],
            &[0, 1, 0, 0],
            &[0x40, 0, 0, 1, 7],
            &[0x80, 0, 0, 0],
            &[0, 1, 255, 255],
        ];
        for record in records {
            let (stream, mut peer) = tokio::io::duplex(32);
            let packets = packets(stream);
            peer.write_all(record).await.unwrap();
            peer.shutdown().await.unwrap();
            let mut buffer = [0u8; 32];
            let result = timeout(Duration::from_secs(1), packets.recv_from(&mut buffer))
                .await
                .unwrap();
            assert!(result.is_err());
            assert!(packets.failed.is_cancelled());
            assert!(!packets.closed.is_cancelled());
            assert_eq!(packets.send(&[9]).await.unwrap(), 1);
            let mut received = [0u8; 1];
            peer.read_exact(&mut received).await.unwrap();
            assert_eq!(received, [9]);
            packets.close().await.unwrap();
            packets.close().await.unwrap();
            assert_eq!(
                timeout(Duration::from_secs(1), peer.read(&mut received))
                    .await
                    .unwrap()
                    .unwrap(),
                0
            );
        }
    }

    #[tokio::test]
    async fn write_failure_signals_unexpected_stream_loss() {
        let (stream, peer) = tokio::io::duplex(8);
        let packets = packets(stream);
        drop(peer);
        assert!(packets.send(&[1]).await.is_err());
        assert!(packets.failed.is_cancelled());
        assert!(!packets.closed.is_cancelled());
        packets.close().await.unwrap();
    }

    #[tokio::test]
    async fn close_interrupts_an_incomplete_consumer_read() {
        let (stream, mut peer) = tokio::io::duplex(8);
        let packets = Arc::new(self::packets(stream));
        let reader = packets.clone();
        let blocked = tokio::spawn(async move {
            let mut buffer = [0u8; 32];
            reader.recv(&mut buffer).await
        });
        // Twelve bytes cannot fit until recv has consumed part of the record.
        peer.write_all(&[0, 1, 0, 4, 0x21, 0x12, 0xa4, 0x42, 0, 0, 0, 0])
            .await
            .unwrap();
        timeout(Duration::from_secs(1), packets.close())
            .await
            .unwrap()
            .unwrap();
        let result = timeout(Duration::from_secs(1), blocked)
            .await
            .unwrap()
            .unwrap();
        assert!(result.is_err());
        assert!(!packets.failed.is_cancelled());
    }

    #[tokio::test]
    async fn concurrent_sends_serialize_whole_packets_without_interleaving() {
        let (stream, mut peer) = tokio::io::duplex(1);
        let packets = Arc::new(packets(stream));
        let first = packets.clone();
        let second = packets.clone();
        let one = tokio::spawn(async move { first.send(&[1; 24]).await.unwrap() });
        let two = tokio::spawn(async move { second.send(&[2; 24]).await.unwrap() });
        let mut received = [0u8; 48];
        peer.read_exact(&mut received).await.unwrap();
        let first_value = received[0];
        assert!(first_value == 1 || first_value == 2);
        assert_eq!(&received[..24], &[first_value; 24]);
        assert_eq!(&received[24..], &[3 - first_value; 24]);
        assert_eq!(one.await.unwrap(), 24);
        assert_eq!(two.await.unwrap(), 24);
        packets.close().await.unwrap();
    }
}
