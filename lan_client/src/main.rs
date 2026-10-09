use std::{
    io::{self, Write},
    net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream, UdpSocket},
    thread,
    time::{Duration, Instant},
};

use poor_dma_client::lan_protocol::{
    DISCOVERY_PORT, PreparedRead, ReadSpan, ReadTarget, Response, SecureChannel, TCP_PORT,
    create_discovery_request, decode_read_results, verify_discovery_offer,
};

const RED: &str = "";
const GREEN: &str = "";
const CYAN: &str = "";
const RESET: &str = "";
const DISCOVERY_ROUND: Duration = Duration::from_secs(1);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(3);

fn main() {
    if let Err(error) = run() {
        eprintln!("{RED}[-] ERROR{RESET}");
        eprintln!("    Message       : {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let (direct, one_shot) = parse_startup_args()?;

    print_disconnected("searching for server");
    let mut channel = connect_loop(direct)?;

    if !one_shot.is_empty() {
        if one_shot[0].eq_ignore_ascii_case("poll") {
            run_poll(&mut channel, &one_shot)?;
        } else {
            execute(&mut channel, &one_shot)?;
        }
        return Ok(());
    }

    println!("Commands use same syntax as poor_dma_server. Type help or exit.");
    let stdin = io::stdin();
    loop {
        print!("poor-dma> ");
        io::stdout()
            .flush()
            .map_err(|error| format!("flush prompt: {error}"))?;
        let mut line = String::new();
        if stdin
            .read_line(&mut line)
            .map_err(|error| format!("read command: {error}"))?
            == 0
        {
            println!();
            break;
        }

        let args = split_command_line(line.trim())?;
        if args.is_empty() {
            continue;
        }
        if args[0].eq_ignore_ascii_case("exit") || args[0].eq_ignore_ascii_case("quit") {
            break;
        }
        if args[0].eq_ignore_ascii_case("help") {
            print_help();
            continue;
        }

        let result = if args[0].eq_ignore_ascii_case("poll") {
            run_poll(&mut channel, &args)
        } else {
            execute(&mut channel, &args)
        };
        if let Err(error) = result {
            print_disconnected(&error);
            channel = connect_loop(direct)?;
            println!("{CYAN}[i] RECONNECT{RESET}");
            println!("    Status        : RESTORED");
            println!("    Retry         : previous command was not retried");
        }
    }
    Ok(())
}

fn parse_startup_args() -> Result<(Option<SocketAddr>, Vec<String>), String> {
    let mut args = std::env::args().skip(1).collect::<Vec<_>>();
    let direct = if args.first().is_some_and(|arg| arg == "--server") {
        if args.len() < 2 {
            return Err("--server requires an IPv4 address or address:port".to_string());
        }
        let value = args.remove(1);
        args.remove(0);
        Some(parse_server_address(&value)?)
    } else {
        None
    };
    Ok((direct, args))
}

fn parse_server_address(value: &str) -> Result<SocketAddr, String> {
    if let Ok(address) = value.parse::<SocketAddr>() {
        return Ok(address);
    }
    let ip = value
        .parse::<IpAddr>()
        .map_err(|_| format!("invalid server address: {value}"))?;
    Ok(SocketAddr::new(ip, TCP_PORT))
}

fn connect_loop(direct: Option<SocketAddr>) -> Result<SecureChannel, String> {
    loop {
        if direct.is_none() {
            let localhost = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), TCP_PORT);
            if let Ok(stream) = TcpStream::connect_timeout(&localhost, Duration::from_millis(150))
                && let Ok(channel) = SecureChannel::connect(stream)
            {
                println!("\r{GREEN}[+] CONNECTION{RESET}                                      ");
                println!("    Status        : CONNECTED");
                println!("    Server        : {localhost}");
                println!("    Transport     : persistent TCP");
                return Ok(channel);
            }
        }

        let address = match direct {
            Some(address) => address,
            None => match discover() {
                Ok(address) => address,
                Err(error) => {
                    print!("\r{RED}[-] CONNECTION{RESET} status=DISCONNECTED reason={error:<60}");
                    let _ = io::stdout().flush();
                    continue;
                }
            },
        };

        match TcpStream::connect_timeout(&address, CONNECT_TIMEOUT)
            .map_err(|error| format!("connect {address}: {error}"))
            .and_then(SecureChannel::connect)
        {
            Ok(channel) => {
                println!("\r{GREEN}[+] CONNECTION{RESET}                                      ");
                println!("    Status        : CONNECTED");
                println!("    Server        : {address}");
                println!("    Transport     : persistent TCP");
                return Ok(channel);
            }
            Err(error) => {
                print_disconnected(&error);
                thread::sleep(DISCOVERY_ROUND);
            }
        }
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

fn discover() -> Result<SocketAddr, String> {
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
            return Err("no server offer; retrying".to_string());
        }
    }
}

fn execute(channel: &mut SecureChannel, args: &[String]) -> Result<(), String> {
    println!("{CYAN}[>] REQUEST{RESET}");
    println!("    Command       : {}", args.join(" "));
    let started = Instant::now();
    let response = request(channel, args)?;
    let latency = started.elapsed();
    if response.success {
        println!("{GREEN}[+] RESPONSE{RESET}");
        println!("    Status        : OK");
        println!(
            "    RTT           : {:.3} ms",
            latency.as_secs_f64() * 1_000.0
        );
        println!("    Text bytes    : {}", response.message.len());
        println!("    Data bytes    : {}", response.data.len());
        if !response.message.is_empty() {
            println!();
            println!("{}", response.message);
        }
        print_data(&response.data);
        Ok(())
    } else {
        eprintln!("{RED}[-] RESPONSE{RESET}");
        eprintln!("    Status        : ERROR");
        eprintln!(
            "    RTT           : {:.3} ms",
            latency.as_secs_f64() * 1_000.0
        );
        eprintln!("    Message       : {}", response.message);
        Ok(())
    }
}

fn request(channel: &mut SecureChannel, args: &[String]) -> Result<Response, String> {
    channel.send_request(args)?;
    channel.receive_response()
}

fn run_poll(channel: &mut SecureChannel, args: &[String]) -> Result<(), String> {
    if args.len() < 2 {
        return Err(
            "usage: poll [--count N] <process> <va> [size], or poll [--count N] <kernel-va> [size]"
                .to_string(),
        );
    }

    let mut command_index = 1usize;
    let mut frame_limit = None;
    if args.get(command_index).is_some_and(|arg| arg == "--count") {
        let count = args
            .get(command_index + 1)
            .ok_or_else(|| "--count requires a positive frame count".to_string())?
            .parse::<u64>()
            .map_err(|_| "--count requires a positive frame count".to_string())?;
        if count == 0 {
            return Err("--count requires a positive frame count".to_string());
        }
        frame_limit = Some(count);
        command_index += 2;
    }
    let command = args
        .get(command_index..)
        .filter(|command| !command.is_empty())
        .ok_or_else(|| "poll requires a memory-read command".to_string())?;
    let (target, span) = parse_typed_read(command)?;
    let read_plan = PreparedRead::new(&target, &[span])?;

    println!("{CYAN}[i] POLL WARMUP{RESET}");
    println!("    Command       : {}", command.join(" "));
    println!("    Target        : {target}");
    let warmup = request_typed_read(channel, &read_plan)?;
    if !warmup.success {
        eprintln!("{RED}[-] POLL{RESET}");
        eprintln!("    Status        : ERROR");
        eprintln!("    Message       : {}", warmup.message);
        return Ok(());
    }
    let warmup_data = decode_single_read(&warmup)?;

    println!("{GREEN}[+] POLL{RESET}");
    println!("    Status        : ACTIVE");
    println!("    Mode          : maximum sequential typed reads");
    println!("    Bytes/read    : {}", warmup_data.len());
    println!("    Stop          : Ctrl+C");

    let started = Instant::now();
    let mut completed = 0u64;
    let mut rtt_total = Duration::ZERO;
    let mut rtt_min = Duration::MAX;
    let mut rtt_max = Duration::ZERO;
    let mut next_display = started;

    loop {
        if frame_limit.is_some_and(|limit| completed >= limit) {
            break;
        }
        let request_started = Instant::now();
        let response = request_typed_read(channel, &read_plan)?;
        let finished = Instant::now();
        if !response.success {
            eprintln!("\n{RED}[-] POLL{RESET}");
            eprintln!("    Status        : ERROR");
            eprintln!("    Message       : {}", response.message);
            break;
        }
        let data = decode_single_read(&response)?;

        let rtt = finished.duration_since(request_started);
        rtt_total += rtt;
        rtt_min = rtt_min.min(rtt);
        rtt_max = rtt_max.max(rtt);
        completed += 1;

        if finished >= next_display {
            let elapsed = finished
                .duration_since(started)
                .as_secs_f64()
                .max(f64::EPSILON);
            let reads_per_second = completed as f64 / elapsed;
            let average_ms = rtt_total.as_secs_f64() * 1_000.0 / completed as f64;
            print!(
                "\r{GREEN}[+] POLL{RESET} rate={reads_per_second:>9.2} read/s rtt current={:>7.3} avg={average_ms:>7.3} min={:>7.3} max={:>7.3} ms value={}      ",
                rtt.as_secs_f64() * 1_000.0,
                rtt_min.as_secs_f64() * 1_000.0,
                rtt_max.as_secs_f64() * 1_000.0,
                format_poll_value(&data)
            );
            io::stdout()
                .flush()
                .map_err(|error| format!("flush poll status: {error}"))?;
            next_display = finished + Duration::from_millis(250);
        }
    }

    if completed != 0 {
        let elapsed = started.elapsed().as_secs_f64().max(f64::EPSILON);
        println!("\n[+] POLL COMPLETE");
        println!("    Reads         : {completed}");
        println!(
            "    Average rate  : {:.2} read/s",
            completed as f64 / elapsed
        );
        println!(
            "    Average RTT   : {:.3} ms",
            rtt_total.as_secs_f64() * 1_000.0 / completed as f64
        );
    }
    Ok(())
}

fn request_typed_read(
    channel: &mut SecureChannel,
    read_plan: &PreparedRead,
) -> Result<Response, String> {
    channel.send_prepared_read(read_plan)?;
    channel.receive_response()
}

fn decode_single_read(response: &Response) -> Result<Vec<u8>, String> {
    let mut results = decode_read_results(&response.data)?;
    if results.len() != 1 {
        return Err(format!(
            "server returned {} results for one typed read",
            results.len()
        ));
    }
    Ok(results.pop().unwrap())
}

fn parse_typed_read(args: &[String]) -> Result<(ReadTarget, ReadSpan), String> {
    let (target, address, size) = match args {
        [command, address] if command.eq_ignore_ascii_case("read-kernel") => {
            (ReadTarget::Kernel, parse_number(address, "address")?, 8)
        }
        [command, address, size] if command.eq_ignore_ascii_case("read-kernel") => (
            ReadTarget::Kernel,
            parse_number(address, "address")?,
            parse_read_size(size)?,
        ),
        [command, process, address] if command.eq_ignore_ascii_case("read-process") => (
            parse_read_target(process)?,
            parse_number(address, "address")?,
            8,
        ),
        [command, process, address, size] if command.eq_ignore_ascii_case("read-process") => (
            parse_read_target(process)?,
            parse_number(address, "address")?,
            parse_read_size(size)?,
        ),
        [address] => (ReadTarget::Kernel, parse_number(address, "address")?, 8),
        [first, second] => match parse_number(first, "address") {
            Ok(address) => (ReadTarget::Kernel, address, parse_read_size(second)?),
            Err(_) => (
                parse_read_target(first)?,
                parse_number(second, "address")?,
                8,
            ),
        },
        [process, address, size] => (
            parse_read_target(process)?,
            parse_number(address, "address")?,
            parse_read_size(size)?,
        ),
        _ => return Err("poll requires one valid memory-read command".to_string()),
    };
    Ok((target, ReadSpan::new(address, size)?))
}

fn parse_read_target(value: &str) -> Result<ReadTarget, String> {
    if let Some(pid) = value.strip_prefix("pid:") {
        return ReadTarget::process_pid(
            pid.parse::<u32>()
                .map_err(|_| format!("invalid PID selector: {value}"))?,
        );
    }
    if !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit()) {
        return ReadTarget::process_pid(
            value
                .parse::<u32>()
                .map_err(|_| format!("invalid PID selector: {value}"))?,
        );
    }
    ReadTarget::process_name(value)
}

fn parse_read_size(value: &str) -> Result<usize, String> {
    usize::try_from(parse_number(value, "size")?)
        .map_err(|_| format!("size does not fit usize: {value}"))
}

fn parse_number(value: &str, name: &str) -> Result<u64, String> {
    let normalized = value.replace('_', "");
    normalized
        .strip_prefix("0x")
        .or_else(|| normalized.strip_prefix("0X"))
        .map_or_else(
            || normalized.parse::<u64>(),
            |hex| u64::from_str_radix(hex, 16),
        )
        .map_err(|_| format!("invalid {name}: {value}"))
}

fn format_poll_value(data: &[u8]) -> String {
    if data.len() <= 8 {
        let mut little_endian = [0u8; 8];
        little_endian[..data.len()].copy_from_slice(data);
        return format!("0x{:X}", u64::from_le_bytes(little_endian));
    }
    let mut value = String::new();
    for byte in data.iter().take(8) {
        use std::fmt::Write as _;
        write!(value, "{byte:02X}").expect("writing to String cannot fail");
    }
    if data.len() > 8 {
        value.push_str("...");
    }
    value
}

fn print_data(data: &[u8]) {
    if data.is_empty() {
        return;
    }
    println!("[+] DATA");
    println!("    Bytes         : {}", data.len());
    if data.len() <= 8 {
        let mut little_endian = [0u8; 8];
        little_endian[..data.len()].copy_from_slice(data);
        println!(
            "    Value (LE)    : 0x{:X}",
            u64::from_le_bytes(little_endian)
        );
    }
    println!("    HEX DUMP");
    for (line_number, line) in data.chunks(16).enumerate() {
        print!("    {:08X} :", line_number * 16);
        for byte in line {
            print!(" {byte:02X}");
        }
        println!();
    }
}

fn split_command_line(line: &str) -> Result<Vec<String>, String> {
    let mut args = Vec::new();
    let mut current = String::new();
    let mut quote = None;
    let mut escaped = false;

    for character in line.chars() {
        if escaped {
            current.push(character);
            escaped = false;
            continue;
        }
        if character == '\\' && quote == Some('"') {
            escaped = true;
            continue;
        }
        if matches!(character, '\'' | '"') {
            if quote == Some(character) {
                quote = None;
            } else if quote.is_none() {
                quote = Some(character);
            } else {
                current.push(character);
            }
            continue;
        }
        if character.is_whitespace() && quote.is_none() {
            if !current.is_empty() {
                args.push(std::mem::take(&mut current));
            }
        } else {
            current.push(character);
        }
    }
    if escaped || quote.is_some() {
        return Err("unterminated quote or escape in command".to_string());
    }
    if !current.is_empty() {
        args.push(current);
    }
    Ok(args)
}

fn print_disconnected(reason: &str) {
    println!("{RED}[-] CONNECTION{RESET}");
    println!("    Status        : DISCONNECTED");
    println!("    Reason        : {reason}");
}

fn print_help() {
    println!("  <process>                     main image base");
    println!("  <process> <module>            named module base");
    println!("  <process> all                 all module bases");
    println!("  <kernel-va> [size]            kernel virtual read");
    println!("  <process> <va> [size]         process/kernel virtual read");
    println!("  system | processes | modules <process> | fixcr3 <process>");
    println!("  poll [--count N] <read-command>");
    println!("      example: poll --count 1000 notepad.exe 0x7FF700000000 8");
    println!("  exit | quit");
}
