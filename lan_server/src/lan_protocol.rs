use std::{
    fmt,
    io::{Read, Write},
    net::TcpStream,
    sync::atomic::{AtomicU64, Ordering},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

pub const DISCOVERY_PORT: u16 = 39_171;
pub const TCP_PORT: u16 = 39_172;
pub const MAX_REQUEST_SIZE: usize = 64 * 1024;
pub const MAX_RESPONSE_SIZE: usize = 64 * 1024 * 1024;

pub const MAX_SCATTER_READS: usize = 1024;
pub const MAX_TOTAL_READ_SIZE: usize = 16 * 1024 * 1024;

const DISCOVER_MAGIC: &[u8; 8] = b"PDMADSC1";
const OFFER_MAGIC: &[u8; 8] = b"PDMAOFR1";
const HELLO_MAGIC: &[u8; 8] = b"PDMAHEL1";
const AUTH_MAGIC: &[u8; 8] = b"PDMAAUT1";
const ACCEPT_MAGIC: &[u8; 8] = b"PDMAACK1";
const DISCOVERY_NONCE_SIZE: usize = 8;
const REQUEST_COMMAND: u8 = 0;
const REQUEST_MEMORY_READ: u8 = 1;
const TARGET_KERNEL: u8 = 0;
const TARGET_PROCESS_NAME: u8 = 1;
const TARGET_PROCESS_PID: u8 = 2;
const MAX_PROCESS_NAME_SIZE: usize = 260;
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);
static DISCOVERY_COUNTER: AtomicU64 = AtomicU64::new(1);

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ReadTarget {
    Kernel,
    ProcessName(String),
    ProcessPid(u32),
}

impl ReadTarget {
    pub fn process_name(name: impl Into<String>) -> Result<Self, String> {
        let name = name.into();
        if name.is_empty() {
            return Err("process name cannot be empty".to_string());
        }
        if name.len() > MAX_PROCESS_NAME_SIZE {
            return Err(format!(
                "process name exceeds {MAX_PROCESS_NAME_SIZE} UTF-8 bytes"
            ));
        }
        Ok(Self::ProcessName(name))
    }

    pub fn process_pid(pid: u32) -> Result<Self, String> {
        if pid == 0 {
            return Err("process PID cannot be zero".to_string());
        }
        Ok(Self::ProcessPid(pid))
    }
}

impl fmt::Display for ReadTarget {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Kernel => formatter.write_str("kernel"),
            Self::ProcessName(name) => write!(formatter, "process:{name}"),
            Self::ProcessPid(pid) => write!(formatter, "pid:{pid}"),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReadSpan {
    pub address: u64,
    pub size: u32,
}

#[derive(Clone, Debug)]
pub struct PreparedRead {
    payload: Vec<u8>,
    result_sizes: Vec<u32>,
}

impl PreparedRead {
    pub fn new(target: &ReadTarget, spans: &[ReadSpan]) -> Result<Self, String> {
        Ok(Self {
            payload: encode_memory_read_request(target, spans)?,
            result_sizes: spans.iter().map(|span| span.size).collect(),
        })
    }

    pub fn result_sizes(&self) -> &[u32] {
        &self.result_sizes
    }
}

impl ReadSpan {
    pub fn new(address: u64, size: usize) -> Result<Self, String> {
        if size == 0 || size > MAX_TOTAL_READ_SIZE {
            return Err(format!(
                "read size must be between 1 and {MAX_TOTAL_READ_SIZE} bytes"
            ));
        }
        Ok(Self {
            address,
            size: size as u32,
        })
    }
}

#[derive(Debug)]
pub enum Request {
    Command(Vec<String>),
    MemoryRead {
        target: ReadTarget,
        spans: Vec<ReadSpan>,
    },
}

#[derive(Debug)]
pub struct Response {
    pub success: bool,
    pub message: String,
    pub data: Vec<u8>,
}

impl Response {
    pub fn text(message: String) -> Self {
        Self {
            success: true,
            message,
            data: Vec::new(),
        }
    }

    pub fn data(message: String, data: Vec<u8>) -> Self {
        Self {
            success: true,
            message,
            data,
        }
    }

    pub fn error(message: String) -> Self {
        Self {
            success: false,
            message,
            data: Vec::new(),
        }
    }
}

pub struct SecureChannel {
    stream: TcpStream,
}

impl SecureChannel {
    pub fn connect(stream: TcpStream) -> Result<Self, String> {
        configure_stream(&stream)?;
        let mut stream = stream;

        let mut hello = [0u8; 8];
        stream
            .read_exact(&mut hello)
            .map_err(|error| format!("read server handshake: {error}"))?;
        if &hello != HELLO_MAGIC {
            return Err("server sent invalid handshake magic".to_string());
        }
        stream
            .write_all(AUTH_MAGIC)
            .map_err(|error| format!("write client handshake: {error}"))?;

        let mut acceptance = [0u8; 8];
        stream
            .read_exact(&mut acceptance)
            .map_err(|error| format!("read server handshake acceptance: {error}"))?;
        if &acceptance != ACCEPT_MAGIC {
            return Err("server rejected protocol handshake".to_string());
        }

        clear_timeouts(&stream)?;
        Ok(Self { stream })
    }

    pub fn accept(stream: TcpStream) -> Result<Self, String> {
        configure_stream(&stream)?;
        let mut stream = stream;
        stream
            .write_all(HELLO_MAGIC)
            .map_err(|error| format!("write server handshake: {error}"))?;

        let mut auth = [0u8; 8];
        stream
            .read_exact(&mut auth)
            .map_err(|error| format!("read client handshake: {error}"))?;
        if &auth != AUTH_MAGIC {
            return Err("client sent invalid protocol handshake".to_string());
        }
        stream
            .write_all(ACCEPT_MAGIC)
            .map_err(|error| format!("write server handshake acceptance: {error}"))?;

        clear_timeouts(&stream)?;
        Ok(Self { stream })
    }

    pub fn send_request(&mut self, args: &[String]) -> Result<(), String> {
        let payload = encode_command_request(args)?;
        self.write_frame(&payload, MAX_REQUEST_SIZE)
    }

    pub fn send_memory_read(
        &mut self,
        target: &ReadTarget,
        spans: &[ReadSpan],
    ) -> Result<(), String> {
        let prepared = PreparedRead::new(target, spans)?;
        self.send_prepared_read(&prepared)
    }

    pub fn send_prepared_read(&mut self, prepared: &PreparedRead) -> Result<(), String> {
        self.write_frame(&prepared.payload, MAX_REQUEST_SIZE)
    }

    pub fn receive_request(&mut self) -> Result<Request, String> {
        let payload = self.read_frame(MAX_REQUEST_SIZE)?;
        decode_request(&payload)
    }

    pub fn send_response(&mut self, response: &Response) -> Result<(), String> {
        let payload = encode_response(response)?;
        self.write_frame(&payload, MAX_RESPONSE_SIZE)
    }

    pub fn receive_response(&mut self) -> Result<Response, String> {
        let payload = self.read_frame(MAX_RESPONSE_SIZE)?;
        decode_response(&payload)
    }

    fn write_frame(&mut self, payload: &[u8], maximum: usize) -> Result<(), String> {
        if payload.len() > maximum {
            return Err(format!("outgoing frame exceeds {maximum} bytes"));
        }
        let length = u32::try_from(payload.len())
            .map_err(|_| "frame length exceeds u32".to_string())?;
        self.stream
            .write_all(&length.to_be_bytes())
            .map_err(|error| format!("write frame length: {error}"))?;
        self.stream
            .write_all(payload)
            .map_err(|error| format!("write frame: {error}"))?;
        Ok(())
    }

    fn read_frame(&mut self, maximum: usize) -> Result<Vec<u8>, String> {
        let mut length_bytes = [0u8; 4];
        self.stream
            .read_exact(&mut length_bytes)
            .map_err(|error| format!("read frame length: {error}"))?;
        let length = u32::from_be_bytes(length_bytes) as usize;
        if length > maximum {
            return Err(format!("invalid frame length {length}"));
        }
        let mut payload = vec![0u8; length];
        self.stream
            .read_exact(&mut payload)
            .map_err(|error| format!("read frame payload: {error}"))?;
        Ok(payload)
    }
}

pub fn create_discovery_request() -> Vec<u8> {
    let nonce = discovery_nonce();
    let mut packet = Vec::with_capacity(8 + DISCOVERY_NONCE_SIZE);
    packet.extend_from_slice(DISCOVER_MAGIC);
    packet.extend_from_slice(&nonce.to_be_bytes());
    packet
}

pub fn verify_discovery_request(packet: &[u8]) -> Option<u64> {
    if packet.len() != 8 + DISCOVERY_NONCE_SIZE || &packet[..8] != DISCOVER_MAGIC {
        return None;
    }
    Some(u64::from_be_bytes(packet[8..].try_into().ok()?))
}

pub fn create_discovery_offer(request_nonce: u64) -> Vec<u8> {
    let port = TCP_PORT.to_be_bytes();
    let mut packet = Vec::with_capacity(8 + DISCOVERY_NONCE_SIZE + 2);
    packet.extend_from_slice(OFFER_MAGIC);
    packet.extend_from_slice(&request_nonce.to_be_bytes());
    packet.extend_from_slice(&port);
    packet
}

pub fn verify_discovery_offer(packet: &[u8], request: &[u8]) -> Option<u16> {
    if request.len() != 8 + DISCOVERY_NONCE_SIZE
        || packet.len() != 8 + DISCOVERY_NONCE_SIZE + 2
        || &packet[..8] != OFFER_MAGIC
    {
        return None;
    }
    let request_nonce = &request[8..8 + DISCOVERY_NONCE_SIZE];
    if &packet[8..8 + DISCOVERY_NONCE_SIZE] != request_nonce {
        return None;
    }
    let port_offset = 8 + DISCOVERY_NONCE_SIZE;
    Some(u16::from_be_bytes(
        packet[port_offset..port_offset + 2].try_into().ok()?,
    ))
}

fn configure_stream(stream: &TcpStream) -> Result<(), String> {
    stream
        .set_nodelay(true)
        .map_err(|error| format!("enable TCP_NODELAY: {error}"))?;
    stream
        .set_read_timeout(Some(HANDSHAKE_TIMEOUT))
        .map_err(|error| format!("set handshake read timeout: {error}"))?;
    stream
        .set_write_timeout(Some(HANDSHAKE_TIMEOUT))
        .map_err(|error| format!("set handshake write timeout: {error}"))?;
    Ok(())
}

fn clear_timeouts(stream: &TcpStream) -> Result<(), String> {
    stream
        .set_read_timeout(None)
        .map_err(|error| format!("clear read timeout: {error}"))?;
    stream
        .set_write_timeout(None)
        .map_err(|error| format!("clear write timeout: {error}"))
}


fn discovery_nonce() -> u64 {
    let clock = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64;
    clock ^ DISCOVERY_COUNTER.fetch_add(1, Ordering::Relaxed)
}

fn encode_command_request(args: &[String]) -> Result<Vec<u8>, String> {
    let count = u16::try_from(args.len()).map_err(|_| "too many command arguments".to_string())?;
    let mut output = Vec::new();
    output.push(REQUEST_COMMAND);
    output.extend_from_slice(&count.to_be_bytes());
    for argument in args {
        let bytes = argument.as_bytes();
        let length = u32::try_from(bytes.len()).map_err(|_| "argument too long".to_string())?;
        output.extend_from_slice(&length.to_be_bytes());
        output.extend_from_slice(bytes);
    }
    if output.len() > MAX_REQUEST_SIZE {
        return Err(format!("encoded request exceeds {MAX_REQUEST_SIZE} bytes"));
    }
    Ok(output)
}

fn encode_memory_read_request(target: &ReadTarget, spans: &[ReadSpan]) -> Result<Vec<u8>, String> {
    validate_spans(spans)?;
    let mut output = Vec::with_capacity(4 + spans.len() * 12);
    output.push(REQUEST_MEMORY_READ);
    match target {
        ReadTarget::Kernel => output.push(TARGET_KERNEL),
        ReadTarget::ProcessName(name) => {
            let bytes = name.as_bytes();
            if bytes.is_empty() || bytes.len() > MAX_PROCESS_NAME_SIZE {
                return Err(format!(
                    "process name must contain 1 to {MAX_PROCESS_NAME_SIZE} UTF-8 bytes"
                ));
            }
            output.push(TARGET_PROCESS_NAME);
            output.extend_from_slice(&(bytes.len() as u16).to_be_bytes());
            output.extend_from_slice(bytes);
        }
        ReadTarget::ProcessPid(pid) => {
            if *pid == 0 {
                return Err("process PID cannot be zero".to_string());
            }
            output.push(TARGET_PROCESS_PID);
            output.extend_from_slice(&pid.to_be_bytes());
        }
    }
    output.extend_from_slice(&(spans.len() as u16).to_be_bytes());
    for span in spans {
        output.extend_from_slice(&span.address.to_be_bytes());
        output.extend_from_slice(&span.size.to_be_bytes());
    }
    if output.len() > MAX_REQUEST_SIZE {
        return Err(format!("encoded request exceeds {MAX_REQUEST_SIZE} bytes"));
    }
    Ok(output)
}

fn decode_request(payload: &[u8]) -> Result<Request, String> {
    let mut cursor = Cursor::new(payload);
    match cursor.read_u8()? {
        REQUEST_COMMAND => decode_command_request(&mut cursor),
        REQUEST_MEMORY_READ => decode_memory_read_request(&mut cursor),
        value => Err(format!("invalid request type {value}")),
    }
}

fn decode_command_request(cursor: &mut Cursor<'_>) -> Result<Request, String> {
    let count = cursor.read_u16()? as usize;
    let mut args = Vec::with_capacity(count);
    for _ in 0..count {
        let length = cursor.read_u32()? as usize;
        let bytes = cursor.read_bytes(length)?;
        args.push(
            String::from_utf8(bytes.to_vec())
                .map_err(|_| "command argument is not valid UTF-8".to_string())?,
        );
    }
    cursor.finish()?;
    Ok(Request::Command(args))
}

fn decode_memory_read_request(cursor: &mut Cursor<'_>) -> Result<Request, String> {
    let target = match cursor.read_u8()? {
        TARGET_KERNEL => ReadTarget::Kernel,
        TARGET_PROCESS_NAME => {
            let length = cursor.read_u16()? as usize;
            if length == 0 || length > MAX_PROCESS_NAME_SIZE {
                return Err(format!("invalid process-name length {length}"));
            }
            let name = String::from_utf8(cursor.read_bytes(length)?.to_vec())
                .map_err(|_| "process name is not valid UTF-8".to_string())?;
            ReadTarget::ProcessName(name)
        }
        TARGET_PROCESS_PID => {
            let pid = cursor.read_u32()?;
            if pid == 0 {
                return Err("process PID cannot be zero".to_string());
            }
            ReadTarget::ProcessPid(pid)
        }
        value => return Err(format!("invalid memory target type {value}")),
    };
    let count = cursor.read_u16()? as usize;
    if count == 0 || count > MAX_SCATTER_READS {
        return Err(format!("invalid scatter-read count {count}"));
    }
    let mut spans = Vec::with_capacity(count);
    for _ in 0..count {
        spans.push(ReadSpan {
            address: cursor.read_u64()?,
            size: cursor.read_u32()?,
        });
    }
    cursor.finish()?;
    validate_spans(&spans)?;
    Ok(Request::MemoryRead { target, spans })
}

fn validate_spans(spans: &[ReadSpan]) -> Result<(), String> {
    if spans.is_empty() || spans.len() > MAX_SCATTER_READS {
        return Err(format!(
            "scatter read requires 1 to {MAX_SCATTER_READS} spans"
        ));
    }
    let mut total = 0usize;
    for span in spans {
        let size = span.size as usize;
        if size == 0 || size > MAX_TOTAL_READ_SIZE {
            return Err(format!(
                "read size must be between 1 and {MAX_TOTAL_READ_SIZE} bytes"
            ));
        }
        total = total
            .checked_add(size)
            .ok_or_else(|| "total scatter-read size overflow".to_string())?;
    }
    if total > MAX_TOTAL_READ_SIZE {
        return Err(format!(
            "total scatter-read size exceeds {MAX_TOTAL_READ_SIZE} bytes"
        ));
    }
    Ok(())
}

pub fn encode_read_results(results: &[Vec<u8>]) -> Result<Vec<u8>, String> {
    if results.is_empty() || results.len() > MAX_SCATTER_READS {
        return Err(format!(
            "read result requires 1 to {MAX_SCATTER_READS} buffers"
        ));
    }
    let mut output = Vec::new();
    output.extend_from_slice(&(results.len() as u16).to_be_bytes());
    let mut total = 0usize;
    for result in results {
        total = total
            .checked_add(result.len())
            .ok_or_else(|| "total read-result size overflow".to_string())?;
        if total > MAX_TOTAL_READ_SIZE {
            return Err(format!(
                "total read-result size exceeds {MAX_TOTAL_READ_SIZE} bytes"
            ));
        }
        let length = u32::try_from(result.len())
            .map_err(|_| "individual read result exceeds u32".to_string())?;
        output.extend_from_slice(&length.to_be_bytes());
        output.extend_from_slice(result);
    }
    Ok(output)
}

pub fn decode_read_results(payload: &[u8]) -> Result<Vec<Vec<u8>>, String> {
    let mut cursor = Cursor::new(payload);
    let count = cursor.read_u16()? as usize;
    if count == 0 || count > MAX_SCATTER_READS {
        return Err(format!("invalid read-result count {count}"));
    }
    let mut results = Vec::with_capacity(count);
    let mut total = 0usize;
    for _ in 0..count {
        let length = cursor.read_u32()? as usize;
        total = total
            .checked_add(length)
            .ok_or_else(|| "total read-result size overflow".to_string())?;
        if total > MAX_TOTAL_READ_SIZE {
            return Err(format!(
                "total read-result size exceeds {MAX_TOTAL_READ_SIZE} bytes"
            ));
        }
        results.push(cursor.read_bytes(length)?.to_vec());
    }
    cursor.finish()?;
    Ok(results)
}

fn encode_response(response: &Response) -> Result<Vec<u8>, String> {
    let message = response.message.as_bytes();
    let message_length =
        u32::try_from(message.len()).map_err(|_| "response message too long".to_string())?;
    let data_length =
        u32::try_from(response.data.len()).map_err(|_| "response data too long".to_string())?;
    let mut output = Vec::with_capacity(1 + 8 + message.len() + response.data.len());
    output.push(u8::from(response.success));
    output.extend_from_slice(&message_length.to_be_bytes());
    output.extend_from_slice(&data_length.to_be_bytes());
    output.extend_from_slice(message);
    output.extend_from_slice(&response.data);
    if output.len() > MAX_RESPONSE_SIZE {
        return Err(format!(
            "encoded response exceeds {MAX_RESPONSE_SIZE} bytes"
        ));
    }
    Ok(output)
}

fn decode_response(payload: &[u8]) -> Result<Response, String> {
    let mut cursor = Cursor::new(payload);
    let success = match cursor.read_u8()? {
        0 => false,
        1 => true,
        value => return Err(format!("invalid response status {value}")),
    };
    let message_length = cursor.read_u32()? as usize;
    let data_length = cursor.read_u32()? as usize;
    let message = String::from_utf8(cursor.read_bytes(message_length)?.to_vec())
        .map_err(|_| "response message is not valid UTF-8".to_string())?;
    let data = cursor.read_bytes(data_length)?.to_vec();
    cursor.finish()?;
    Ok(Response {
        success,
        message,
        data,
    })
}

struct Cursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Cursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn read_u8(&mut self) -> Result<u8, String> {
        Ok(self.read_bytes(1)?[0])
    }

    fn read_u16(&mut self) -> Result<u16, String> {
        Ok(u16::from_be_bytes(self.read_bytes(2)?.try_into().unwrap()))
    }

    fn read_u32(&mut self) -> Result<u32, String> {
        Ok(u32::from_be_bytes(self.read_bytes(4)?.try_into().unwrap()))
    }

    fn read_u64(&mut self) -> Result<u64, String> {
        Ok(u64::from_be_bytes(self.read_bytes(8)?.try_into().unwrap()))
    }

    fn read_bytes(&mut self, length: usize) -> Result<&'a [u8], String> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or_else(|| "protocol length overflow".to_string())?;
        let bytes = self
            .bytes
            .get(self.offset..end)
            .ok_or_else(|| "truncated protocol payload".to_string())?;
        self.offset = end;
        Ok(bytes)
    }

    fn finish(&self) -> Result<(), String> {
        if self.offset == self.bytes.len() {
            Ok(())
        } else {
            Err("protocol payload contains trailing bytes".to_string())
        }
    }
}
