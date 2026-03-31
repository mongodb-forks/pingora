// Copyright 2026 Cloudflare, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Extra information about the connection

use std::fmt::{Display, Formatter, Result as FmtResult};
use std::net::{IpAddr, SocketAddrV4, SocketAddrV6};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use once_cell::sync::OnceCell;
use pingora_error::{Error, ErrorType, Result};

use super::l4::ext::{get_original_dest, get_recv_buf, get_snd_buf, get_tcp_info, TCP_INFO};
use super::l4::socket::SocketAddr;
use super::raw_connect::ProxyDigest;
use super::tls::digest::SslDigest;

/// The information can be extracted from a connection
#[derive(Clone, Debug, Default)]
pub struct Digest {
    /// Information regarding the TLS of this connection if any
    pub ssl_digest: Option<Arc<SslDigest>>,
    /// Timing information
    pub timing_digest: Vec<Option<TimingDigest>>,
    /// information regarding the CONNECT proxy this connection uses.
    pub proxy_digest: Option<Arc<ProxyDigest>>,
    /// Information about underlying socket/fd of this connection
    pub socket_digest: Option<Arc<SocketDigest>>,
    /// Parsed proxy protocol information, if any
    pub proxy_protocol_addrs_digest: Option<Arc<ProxyProtocolAddrsDigest>>,
}

/// The interface to return protocol related information
pub trait ProtoDigest {
    fn get_digest(&self) -> Option<&Digest> {
        None
    }
}

/// The timing information of the connection
#[derive(Clone, Debug)]
pub struct TimingDigest {
    /// When this connection was established
    pub established_ts: SystemTime,
}

impl Default for TimingDigest {
    fn default() -> Self {
        TimingDigest {
            established_ts: SystemTime::UNIX_EPOCH,
        }
    }
}

#[derive(Debug)]
/// The interface to return socket-related information
pub struct SocketDigest {
    #[cfg(unix)]
    raw_fd: std::os::unix::io::RawFd,
    #[cfg(windows)]
    raw_sock: std::os::windows::io::RawSocket,
    /// Remote socket address
    pub peer_addr: OnceCell<Option<SocketAddr>>,
    /// Local socket address
    pub local_addr: OnceCell<Option<SocketAddr>>,
    /// Original destination address
    pub original_dst: OnceCell<Option<SocketAddr>>,
}

impl SocketDigest {
    #[cfg(unix)]
    pub fn from_raw_fd(raw_fd: std::os::unix::io::RawFd) -> SocketDigest {
        SocketDigest {
            raw_fd,
            peer_addr: OnceCell::new(),
            local_addr: OnceCell::new(),
            original_dst: OnceCell::new(),
        }
    }

    #[cfg(windows)]
    pub fn from_raw_socket(raw_sock: std::os::windows::io::RawSocket) -> SocketDigest {
        SocketDigest {
            raw_sock,
            peer_addr: OnceCell::new(),
            local_addr: OnceCell::new(),
            original_dst: OnceCell::new(),
        }
    }

    #[cfg(unix)]
    pub fn peer_addr(&self) -> Option<&SocketAddr> {
        self.peer_addr
            .get_or_init(|| SocketAddr::from_raw_fd(self.raw_fd, true))
            .as_ref()
    }

    #[cfg(windows)]
    pub fn peer_addr(&self) -> Option<&SocketAddr> {
        self.peer_addr
            .get_or_init(|| SocketAddr::from_raw_socket(self.raw_sock, true))
            .as_ref()
    }

    #[cfg(unix)]
    pub fn local_addr(&self) -> Option<&SocketAddr> {
        self.local_addr
            .get_or_init(|| SocketAddr::from_raw_fd(self.raw_fd, false))
            .as_ref()
    }

    #[cfg(windows)]
    pub fn local_addr(&self) -> Option<&SocketAddr> {
        self.local_addr
            .get_or_init(|| SocketAddr::from_raw_socket(self.raw_sock, false))
            .as_ref()
    }

    fn is_inet(&self) -> bool {
        self.local_addr().and_then(|p| p.as_inet()).is_some()
    }

    #[cfg(unix)]
    pub fn tcp_info(&self) -> Option<TCP_INFO> {
        if self.is_inet() {
            get_tcp_info(self.raw_fd).ok()
        } else {
            None
        }
    }

    #[cfg(windows)]
    pub fn tcp_info(&self) -> Option<TCP_INFO> {
        if self.is_inet() {
            get_tcp_info(self.raw_sock).ok()
        } else {
            None
        }
    }

    #[cfg(unix)]
    pub fn get_recv_buf(&self) -> Option<usize> {
        if self.is_inet() {
            get_recv_buf(self.raw_fd).ok()
        } else {
            None
        }
    }

    #[cfg(windows)]
    pub fn get_recv_buf(&self) -> Option<usize> {
        if self.is_inet() {
            get_recv_buf(self.raw_sock).ok()
        } else {
            None
        }
    }

    #[cfg(unix)]
    pub fn get_snd_buf(&self) -> Option<usize> {
        if self.is_inet() {
            get_snd_buf(self.raw_fd).ok()
        } else {
            None
        }
    }

    #[cfg(windows)]
    pub fn get_snd_buf(&self) -> Option<usize> {
        if self.is_inet() {
            get_snd_buf(self.raw_sock).ok()
        } else {
            None
        }
    }

    #[cfg(unix)]
    pub fn original_dst(&self) -> Option<&SocketAddr> {
        self.original_dst
            .get_or_init(|| {
                get_original_dest(self.raw_fd)
                    .ok()
                    .flatten()
                    .map(SocketAddr::Inet)
            })
            .as_ref()
    }

    #[cfg(windows)]
    pub fn original_dst(&self) -> Option<&SocketAddr> {
        self.original_dst
            .get_or_init(|| {
                get_original_dest(self.raw_sock)
                    .ok()
                    .flatten()
                    .map(SocketAddr::Inet)
            })
            .as_ref()
    }
}

#[derive(Clone, Debug)]
/// Represents all possible address values in a v1 proxy protocol header
pub enum V1Addresses {
    Ipv4 {
        source: SocketAddrV4,
        destination: SocketAddrV4,
    },
    Ipv6 {
        source: SocketAddrV6,
        destination: SocketAddrV6,
    },
}

#[derive(Clone, Debug)]
/// Represents all possible address values in a v2 proxy protocol header
pub enum V2Addresses {
    Ipv4 {
        source: SocketAddrV4,
        destination: SocketAddrV4,
    },
    Ipv6 {
        source: SocketAddrV6,
        destination: SocketAddrV6,
    },
    Unix {
        source: [u8; 108],
        destination: [u8; 108],
    },
}

#[derive(Clone, Debug)]
/// Stores the address block provided in a proxy protocol header 
pub enum ProxyProtocolAddrsDigest {
    V1AddrBlock(V1Addresses),
    V2AddrBlock(V2Addresses),
}

impl ProxyProtocolAddrsDigest {
    pub fn from_v1_ipv4(source: SocketAddrV4, destination: SocketAddrV4) -> Self {
        ProxyProtocolAddrsDigest::V1AddrBlock(V1Addresses::Ipv4 { source, destination })
    }

    pub fn from_v1_ipv6(source: SocketAddrV6, destination: SocketAddrV6) -> Self {
        ProxyProtocolAddrsDigest::V1AddrBlock(V1Addresses::Ipv6 { source, destination })
    }

    pub fn from_v2_ipv4(source: SocketAddrV4, destination: SocketAddrV4) -> Self {
        ProxyProtocolAddrsDigest::V2AddrBlock(V2Addresses::Ipv4 { source, destination })
    }

    pub fn from_v2_ipv6(source: SocketAddrV6, destination: SocketAddrV6) -> Self {
        ProxyProtocolAddrsDigest::V2AddrBlock(V2Addresses::Ipv6 { source, destination })
    }

    pub fn from_v2_unix(source: [u8; 108], destination: [u8; 108]) -> Self {
        ProxyProtocolAddrsDigest::V2AddrBlock(V2Addresses::Unix { source, destination })
    }

    /// Returns `(source_ip, source_port, destination_ip, destination_port)` for
    /// IPv4/IPv6 variants, or `None` for Unix addresses.
    pub fn addrs_and_ports(&self) -> Result<(IpAddr, u16, IpAddr, u16)> {
        match self {
            ProxyProtocolAddrsDigest::V1AddrBlock(v1) => match v1 {
                V1Addresses::Ipv4 { source, destination } => Ok((
                    IpAddr::V4(*source.ip()),
                    source.port(),
                    IpAddr::V4(*destination.ip()),
                    destination.port(),
                )),
                V1Addresses::Ipv6 { source, destination } => Ok((
                    IpAddr::V6(*source.ip()),
                    source.port(),
                    IpAddr::V6(*destination.ip()),
                    destination.port(),
                )),
            },
            ProxyProtocolAddrsDigest::V2AddrBlock(v2) => match v2 {
                V2Addresses::Ipv4 { source, destination } => Ok((
                    IpAddr::V4(*source.ip()),
                    source.port(),
                    IpAddr::V4(*destination.ip()),
                    destination.port(),
                )),
                V2Addresses::Ipv6 { source, destination } => Ok((
                    IpAddr::V6(*source.ip()),
                    source.port(),
                    IpAddr::V6(*destination.ip()),
                    destination.port(),
                )),
                V2Addresses::Unix { .. } => Error::e_explain(ErrorType::UnsupportedProxyProtocolAddr, "only IP addresses are supported over proxy protocol"),
            },
        }
    }
}

impl Display for V1Addresses {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        match self {
            V1Addresses::Ipv4 { source, destination } => {
                write!(f, "source: {source}, destination: {destination}")
            }
            V1Addresses::Ipv6 { source, destination } => {
                write!(f, "source: {source}, destination: {destination}")
            }
        }
    }
}

impl Display for V2Addresses {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        match self {
            V2Addresses::Ipv4 { source, destination } => {
                write!(f, "source: {source}, destination: {destination}")
            }
            V2Addresses::Ipv6 { source, destination } => {
                write!(f, "source: {source}, destination: {destination}")
            }
            V2Addresses::Unix { source, destination } => {
                let src = unix_addr_to_str(source);
                let dst = unix_addr_to_str(destination);
                write!(f, "source: {src}, destination: {dst}")
            }
        }
    }
}

impl Display for ProxyProtocolAddrsDigest {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        match self {
            ProxyProtocolAddrsDigest::V1AddrBlock(addrs) => {
                write!(f, "{addrs}")
            }
            ProxyProtocolAddrsDigest::V2AddrBlock(addrs) => {
                write!(f, "{addrs}")
            }
        }
    }
}

/// Convert a proxy-protocol Unix address (108-byte, null-padded) to a display string.
fn unix_addr_to_str(addr: &[u8; 108]) -> String {
    let len = addr.iter().position(|&b| b == 0).unwrap_or(addr.len());
    String::from_utf8_lossy(&addr[..len]).into_owned()
}

/// The interface to return timing information
pub trait GetTimingDigest {
    /// Return the timing for each layer from the lowest layer to upper
    fn get_timing_digest(&self) -> Vec<Option<TimingDigest>>;
    fn get_read_pending_time(&self) -> Duration {
        Duration::ZERO
    }
    fn get_write_pending_time(&self) -> Duration {
        Duration::ZERO
    }
}

/// The interface to set or return proxy information
pub trait GetProxyDigest {
    fn get_proxy_digest(&self) -> Option<Arc<ProxyDigest>>;
    fn set_proxy_digest(&mut self, _digest: ProxyDigest) {}
}

/// The interface to set or return socket information
pub trait GetSocketDigest {
    fn get_socket_digest(&self) -> Option<Arc<SocketDigest>>;
    fn set_socket_digest(&mut self, _socket_digest: SocketDigest) {}
}

/// The interface to set or return proxy protocol addr information
pub trait GetProxyProtocolAddrsDigest {
    fn get_proxy_protocol_addrs_digest(&self) -> Option<Arc<ProxyProtocolAddrsDigest>>;
    fn set_proxy_protocol_addrs_digest(&mut self, _proxy_protocol_addrs_digest: ProxyProtocolAddrsDigest) {}
}
