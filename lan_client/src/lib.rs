
use std::{
    io,
    net::{IpAddr, Ipv4Addr, Shutdown, SocketAddr, TcpStream, UdpSocket},
    thread,
    time::{Duration, Instant},
};

use crate::lan_protocol::{
    DISCOVERY_PORT, Response, SecureChannel, TCP_PORT, create_discovery_request,
    decode_read_results, verify_discovery_offer,
};

pub use crate::lan_protocol::{
    MAX_SCATTER_READS, MAX_TOTAL_READ_SIZE, PreparedRead, ReadSpan, ReadTarget,
};

pub mod lan_protocol;

const DISCOVERY_ROUND: Duration = Duration::from_secs(1);
const LOCAL_CONNECT_TIMEOUT: Duration = Duration::from_millis(150);
const LAN_CONNECT_TIMEOUT: Duration = Duration::from_secs(3);

pub const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(5);

const RETRY_PAUSE: Duration = Duration::from_millis(400);

pub struct MemoryClient {
    channel: SecureChannel,
    peer: SocketAddr,

    socket: TcpStream,

    poisoned: Option<String>,
}

pub struct TimedRead {
    pub buffers: Vec<Vec<u8>>,
    pub rtt: Duration,
}

impl TimedRead {
    pub fn total_bytes(&self) -> usize {
        self.buffers.iter().map(Vec::len).sum()
    }
}

impl MemoryClient {
    pub fn connect(peer: SocketAddr) -> Result<Self, String> {
        let stream = TcpStream::connect_timeout(&peer, LAN_CONNECT_TIMEOUT)
            .map_err(|error| format!("connect {peer}: {error}"))?;
        Self::adopt(stream, peer)
    }

    fn adopt(stream: TcpStream, peer: SocketAddr) -> Result<Self, String> {

        let socket = stream
            .try_clone()
            .map_err(|error| format!("duplicate socket handle for {peer}: {error}"))?;
        let channel = SecureChannel::connect(stream)?;
        let client = Self {
            channel,
            peer,
            socket,
            poisoned: None,
        };

        client.set_request_timeout(Some(DEFAULT_REQUEST_TIMEOUT))?;
        Ok(client)
    }

    const SERVER_ADDRESS: &'static str = "POOR_DMA_SERVER";

    fn address_from_environment() -> Option<SocketAddr> {
        let value = std::env::var(Self::SERVER_ADDRESS).ok()?;
        let value = value.trim();
        if value.is_empty() {
            return None;
        }

        value
            .parse::<SocketAddr>()
            .ok()
            .or_else(|| value.parse::<IpAddr>().ok().map(|ip| SocketAddr::new(ip, TCP_PORT)))
    }

    pub fn connect_discovered() -> Result<Self, String> {
        if let Some(address) = Self::address_from_environment() {
            return Self::connect(address);
        }
        let localhost = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), TCP_PORT);
        if let Ok(stream) = TcpStream::connect_timeout(&localhost, LOCAL_CONNECT_TIMEOUT)
            && let Ok(client) = Self::adopt(stream, localhost)
        {
            return Ok(client);
        }
        Self::connect(discover_server()?)
    }

    pub fn connect_discovered_within(budget: Duration) -> Result<Self, String> {
        let deadline = Instant::now() + budget;
        let mut last;
        loop {
            match Self::connect_discovered() {
                Ok(client) => return Ok(client),
                Err(error) => last = error,
            }
            if Instant::now() >= deadline {
                return Err(format!(
                    "no poor_dma server after {:.1}s: {last}",
                    budget.as_secs_f32()
                ));
            }
            thread::sleep(RETRY_PAUSE);
        }
    }

    pub fn peer(&self) -> SocketAddr {
        self.peer
    }

    pub fn set_request_timeout(&self, timeout: Option<Duration>) -> Result<(), String> {
        self.socket
            .set_read_timeout(timeout)
            .map_err(|error| format!("set read timeout: {error}"))?;
        self.socket
            .set_write_timeout(timeout)
            .map_err(|error| format!("set write timeout: {error}"))
    }

    pub fn poison_reason(&self) -> Option<&str> {
        self.poisoned.as_deref()
    }

    pub fn is_usable(&self) -> bool {
        self.poisoned.is_none()
    }

    fn guard<T>(&mut self, outcome: Result<T, String>) -> Result<T, String> {
        if let Err(error) = &outcome
            && self.poisoned.is_none()
        {
            self.poisoned = Some(error.clone());
        }
        outcome
    }

    fn check_usable(&self) -> Result<(), String> {
        match &self.poisoned {
            Some(reason) => Err(format!(
                "connection to {} is no longer usable ({reason}); reconnect",
                self.peer
            )),
            None => Ok(()),
        }
    }

    pub fn command(&mut self, args: &[String]) -> Result<Response, String> {
        self.check_usable()?;
        let sent = self.channel.send_request(args);
        self.guard(sent)?;
        let received = self.channel.receive_response();
        self.guard(received)
    }

    pub fn read(
        &mut self,
        target: &ReadTarget,
        address: u64,
        size: usize,
    ) -> Result<Vec<u8>, String> {
        let span = ReadSpan::new(address, size)?;
        let mut results = self.read_scatter(target, &[span])?;
        results
            .pop()
            .ok_or_else(|| "server returned no result for typed read".to_string())
    }

    pub fn read_scatter(
        &mut self,
        target: &ReadTarget,
        spans: &[ReadSpan],
    ) -> Result<Vec<Vec<u8>>, String> {
        let prepared = PreparedRead::new(target, spans)?;
        self.read_prepared(&prepared)
    }

    pub fn read_prepared(&mut self, prepared: &PreparedRead) -> Result<Vec<Vec<u8>>, String> {
        self.check_usable()?;
        let sent = self.channel.send_prepared_read(prepared);
        self.guard(sent)?;
        let received = self.channel.receive_response();
        let response = self.guard(received)?;

        if !response.success {
            return Err(response.message);
        }
        let results = decode_read_results(&response.data)?;
        let expected_sizes = prepared.result_sizes();
        if results.len() != expected_sizes.len() {
            return Err(format!(
                "server returned {} result(s) for {} span(s)",
                results.len(),
                expected_sizes.len()
            ));
        }
        for (index, (result, expected)) in results.iter().zip(expected_sizes).enumerate() {
            if result.len() != *expected as usize {
                return Err(format!(
                    "result {index} has {} byte(s), expected {}",
                    result.len(),
                    expected
                ));
            }
        }
        Ok(results)
    }

    pub fn read_prepared_timed(&mut self, prepared: &PreparedRead) -> Result<TimedRead, String> {
        let started = Instant::now();
        let buffers = self.read_prepared(prepared)?;
        Ok(TimedRead {
            buffers,
            rtt: started.elapsed(),
        })
    }

    pub fn read_u32(&mut self, target: &ReadTarget, address: u64) -> Result<u32, String> {
        let bytes = self.read(target, address, 4)?;
        Ok(u32::from_le_bytes(bytes.try_into().unwrap()))
    }

    pub fn read_u64(&mut self, target: &ReadTarget, address: u64) -> Result<u64, String> {
        let bytes = self.read(target, address, 8)?;
        Ok(u64::from_le_bytes(bytes.try_into().unwrap()))
    }
}

impl Drop for MemoryClient {

    fn drop(&mut self) {
        let _ = self.socket.shutdown(Shutdown::Both);
    }
}

fn discovery_targets() -> Vec<SocketAddr> {
    let mut targets = vec![
        SocketAddr::new(IpAddr::V4(Ipv4Addr::BROADCAST), DISCOVERY_PORT),
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), DISCOVERY_PORT),
    ];
    if let Ok(probe) = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)) {
        for probe_target in ["8.8.8.8:80", "192.168.1.1:80", "10.0.0.1:80"] {
            if probe.connect(probe_target).is_ok() {
                if let Ok(local) = probe.local_addr() {
                    if let IpAddr::V4(ipv4) = local.ip() {
                        if !ipv4.is_loopback() && !ipv4.is_unspecified() {
                            let octets = ipv4.octets();
                            let subnet_bcast = SocketAddr::new(
                                IpAddr::V4(Ipv4Addr::new(octets[0], octets[1], octets[2], 255)),
                                DISCOVERY_PORT,
                            );
                            if !targets.contains(&subnet_bcast) {
                                targets.push(subnet_bcast);
                            }
                        }
                    }
                }
            }
        }
    }
    targets
}

pub fn discover_server() -> Result<SocketAddr, String> {
    let socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))
        .map_err(|error| format!("bind discovery socket: {error}"))?;
    socket
        .set_broadcast(true)
        .map_err(|error| format!("enable UDP broadcast: {error}"))?;
    socket
        .set_read_timeout(Some(Duration::from_millis(50)))
        .map_err(|error| format!("set discovery timeout: {error}"))?;

    let request = create_discovery_request();
    let targets = discovery_targets();
    let deadline = Instant::now() + DISCOVERY_ROUND;
    let send_interval = Duration::from_millis(150);
    let mut last_send = Instant::now() - send_interval;
    let mut packet = [0u8; 256];

    loop {
        if last_send.elapsed() >= send_interval {
            for target in &targets {
                let _ = socket.send_to(&request, target);
            }
            last_send = Instant::now();
        }

        match socket.recv_from(&mut packet) {
            Ok((size, mut source)) => {
                if let Some(port) = verify_discovery_offer(&packet[..size], &request) {
                    source.set_port(port);
                    return Ok(source);
                }
            }
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock
                        | io::ErrorKind::TimedOut
                        | io::ErrorKind::ConnectionReset
                ) => {}
            Err(error) => return Err(format!("receive LAN discovery: {error}")),
        }
        if Instant::now() >= deadline {
            return Err("no server offer".to_string());
        }
    }
}
