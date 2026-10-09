use std::{
    collections::HashMap,
    net::{Ipv4Addr, TcpListener, UdpSocket},
    thread,
    time::{Duration, Instant},
};

use poor_dma_server::lan_protocol::{
    DISCOVERY_PORT, ReadTarget, Request, Response, SecureChannel, TCP_PORT, create_discovery_offer,
    encode_read_results, verify_discovery_request,
};

use crate::{
    cli::{self, Command},
    driver::Ksld,
    memory::{TranslationCache, VirtualMemory, checked_field, is_kernel_address, is_user_address},
    offsets::Offsets,
    output,
    windows::{
        kernel::{KernelIdentity, locate_system_process},
        loader::{ModuleInfo, enumerate_modules, enumerate_modules_via_pfn},
        process::{ProcessInfo, ProcessSelector, ambiguous, enumerate_processes, find_processes},
    },
};

const CACHE_VALIDATION_INTERVAL: Duration = Duration::from_secs(1);
const IMAGE_FILE_NAME_LENGTH: usize = 15;

#[derive(Clone)]
struct ResolvedProcess {
    process: ProcessInfo,
    dtb: u64,
    modules: Vec<ModuleInfo>,
}

struct CachedProcess {
    resolved: ResolvedProcess,
    last_validation: Instant,
}

struct ServerState {
    driver: Ksld,
    kernel_dtb: u64,
    ram_size: u64,
    offsets: Offsets,
    kernel: KernelIdentity,
    process_cache: HashMap<String, CachedProcess>,
    translation_caches: HashMap<u64, TranslationCache>,
    kernel_translation_cache: TranslationCache,
    kernel_cache_started: Instant,
}

struct TrafficStats {
    window_started: Instant,
    requests: u64,
    response_bytes: u64,
    last_command: String,
}

impl TrafficStats {
    fn new() -> Self {
        Self {
            window_started: Instant::now(),
            requests: 0,
            response_bytes: 0,
            last_command: String::new(),
        }
    }

    fn record(&mut self, peer: &str, command: &str, response: &Response) {
        if self.last_command != command {
            println!("[>] REMOTE REQUEST");
            println!("    Peer          : {peer}");
            println!("    Command       : {command}");
            if response.success {
                println!("[+] REMOTE RESPONSE");
                println!("    Status        : OK");
            } else {
                println!("[-] REMOTE RESPONSE");
                println!("    Status        : ERROR");
            }
            println!("    Text bytes    : {}", response.message.len());
            println!("    Data bytes    : {}", response.data.len());
            command.clone_into(&mut self.last_command);
        }

        self.requests += 1;
        self.response_bytes = self
            .response_bytes
            .saturating_add(response.message.len().saturating_add(response.data.len()) as u64);
        let elapsed = self.window_started.elapsed();
        if elapsed >= Duration::from_secs(1) {
            println!("[i] REMOTE IO");
            println!("    Peer          : {peer}");
            println!(
                "    Rate          : {:.1} request/s",
                self.requests as f64 / elapsed.as_secs_f64()
            );
            println!("    Response bytes: {}", self.response_bytes);
            println!(
                "    Last command  : {}",
                if self.last_command.is_empty() {
                    "<none>"
                } else {
                    &self.last_command
                }
            );
            self.window_started = Instant::now();
            self.requests = 0;
            self.response_bytes = 0;
        }
    }
}

pub fn run(driver: Ksld, kernel_dtb: u64, ram_size: u64, offsets: Offsets) -> Result<(), String> {
    let listener = TcpListener::bind((Ipv4Addr::UNSPECIFIED, TCP_PORT))
        .map_err(|error| format!("bind TCP 0.0.0.0:{TCP_PORT}: {error}"))?;
    let discovery = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, DISCOVERY_PORT))
        .map_err(|error| format!("bind UDP discovery 0.0.0.0:{DISCOVERY_PORT}: {error}"))?;
    let _ = discovery.set_broadcast(true);
    start_discovery(discovery);

    let kernel = locate_system_process(&driver, kernel_dtb)?;
    println!("[+] SERVER");
    println!("    Kernel base   : 0x{:016X}", kernel.base);
    println!("    System EPROCESS: 0x{:016X}", kernel.system_eprocess);
    println!("    UDP discovery : 0.0.0.0:{DISCOVERY_PORT}");
    println!("    TCP data      : 0.0.0.0:{TCP_PORT}");
    println!("    Protocol      : read-only, direct TCP");
    print_disconnected("waiting for laptop");

    let mut state = ServerState {
        driver,
        kernel_dtb,
        ram_size,
        offsets,
        kernel,
        process_cache: HashMap::new(),
        translation_caches: HashMap::new(),
        kernel_translation_cache: TranslationCache::default(),
        kernel_cache_started: Instant::now(),
    };

    for incoming in listener.incoming() {
        let stream = match incoming {
            Ok(stream) => stream,
            Err(error) => {
                eprintln!("[-] SERVER ERROR");
                eprintln!("    Operation     : accept TCP client");
                eprintln!("    Message       : {error}");
                continue;
            }
        };
        let peer = stream
            .peer_addr()
            .map(|address| address.to_string())
            .unwrap_or_else(|_| "unknown peer".to_string());

        match SecureChannel::accept(stream) {
            Ok(mut channel) => {
                println!("[+] CONNECTION");
                println!("    Status        : CONNECTED");
                println!("    Peer          : {peer}");
                println!("    Transport     : persistent TCP");
                if let Err(error) = handle_client(&mut state, &mut channel, &peer) {
                    print_disconnected(&format!("{peer}: {error}"));
                } else {
                    print_disconnected(&format!("{peer} closed connection"));
                }
            }
            Err(error) => {
                eprintln!("[-] CONNECTION");
                eprintln!("    Status        : REJECTED");
                eprintln!("    Peer          : {peer}");
                eprintln!("    Message       : {error}");
            }
        }
    }
    Ok(())
}

fn start_discovery(socket: UdpSocket) {
    thread::spawn(move || {
        let mut packet = [0u8; 256];
        loop {
            match socket.recv_from(&mut packet) {
                Ok((size, source)) => {
                    let Some(nonce) = verify_discovery_request(&packet[..size]) else {
                        continue;
                    };
                    let offer = create_discovery_offer(nonce);
                    if let Err(error) = socket.send_to(&offer, source) {
                        if error.kind() != std::io::ErrorKind::ConnectionReset {
                            eprintln!("[-] discovery reply to {source} failed: {error}");
                        }
                    }
                }
                Err(error) => {
                    if error.kind() == std::io::ErrorKind::ConnectionReset {
                        continue;
                    }
                    eprintln!("[-] discovery receive failed: {error}");
                    thread::sleep(Duration::from_millis(50));
                }
            }
        }
    });
}

fn handle_client(
    state: &mut ServerState,
    channel: &mut SecureChannel,
    peer: &str,
) -> Result<(), String> {
    let mut traffic = TrafficStats::new();
    loop {
        let request = channel.receive_request()?;
        let (response, label) = match request {
            Request::Command(args) => {
                let label = args.join(" ");
                let response = state.execute(&args, false).unwrap_or_else(Response::error);
                (response, label)
            }
            Request::MemoryRead { target, spans } => {
                let response = state
                    .execute_memory_read(target, &spans)
                    .unwrap_or_else(Response::error);
                (response, "typed memory read".to_string())
            }
        };
        traffic.record(peer, &label, &response);
        channel.send_response(&response)?;
    }
}

impl ServerState {
    fn execute_memory_read(
        &mut self,
        target: ReadTarget,
        spans: &[poor_dma_server::lan_protocol::ReadSpan],
    ) -> Result<Response, String> {
        let selector = match target {
            ReadTarget::Kernel => None,
            ReadTarget::ProcessName(name) => Some(ProcessSelector::Name(name)),
            ReadTarget::ProcessPid(pid) => Some(ProcessSelector::Pid(pid)),
        };
        let require_kernel = selector.is_none();
        let mut results = Vec::with_capacity(spans.len());

        let fast = match &selector {
            Some(selector)
                if spans
                    .iter()
                    .all(|span| is_user_address(span.address)) =>
            {
                let resolved = self.resolve_process(selector)?;
                let cache = self
                    .translation_caches
                    .entry(resolved.dtb)
                    .or_default()
                    .clone();
                Some((resolved.dtb, cache))
            }
            _ => None,
        };
        for span in spans {
            let size = span.size as usize;
            if let Some((dtb, cache)) = &fast
                && let Ok(memory) = VirtualMemory::new_cached(&self.driver, *dtb, cache.clone())
                && let Ok(data) = memory.read(span.address, size)
            {
                results.push(data);
                continue;
            }
            let response = self.read_virtual(
                selector.as_ref(),
                span.address,
                size,
                require_kernel,
                true,
            )?;
            results.push(response.data);
        }
        Ok(Response::data(
            String::new(),
            encode_read_results(&results)?,
        ))
    }

    fn execute(&mut self, remote_args: &[String], compact: bool) -> Result<Response, String> {
        let mut args = Vec::with_capacity(remote_args.len() + 1);
        args.push("poor_dma_server(remote)".to_string());
        args.extend(remote_args.iter().cloned());
        let command = cli::parse(&args)?;

        match command {
            Command::Serve => Err("server mode cannot be invoked through LAN".to_string()),
            Command::InspectSystem => {
                let processes = self.discover_processes()?;
                let system = processes
                    .first()
                    .ok_or_else(|| "validated process list is empty".to_string())?;
                Ok(Response::text(output::format_process(system, None)))
            }
            Command::ListProcesses => {
                let processes = self.discover_processes()?;
                Ok(Response::text(output::format_processes(&processes)))
            }
            Command::Modules { selector } => {
                let resolved = self.resolve_process(&selector)?;
                Ok(Response::text(output::format_process_modules(
                    &resolved.process,
                    resolved.dtb,
                    &resolved.modules,
                )))
            }
            Command::ProcessBase { selector } => {
                let resolved = self.resolve_process(&selector)?;
                let module = resolved
                    .modules
                    .first()
                    .ok_or_else(|| "validated loader list is empty".to_string())?;
                Ok(Response::text(output::format_process_modules(
                    &resolved.process,
                    resolved.dtb,
                    [module],
                )))
            }
            Command::ProcessModule {
                selector,
                module_name,
            } => {
                let resolved = self.resolve_process(&selector)?;
                let matches = resolved
                    .modules
                    .iter()
                    .filter(|module| module.name.eq_ignore_ascii_case(&module_name))
                    .collect::<Vec<_>>();
                if matches.is_empty() {
                    return Err(format!(
                        "module {module_name:?} not found in {}",
                        resolved.process.image_name
                    ));
                }
                Ok(Response::text(output::format_process_modules(
                    &resolved.process,
                    resolved.dtb,
                    matches,
                )))
            }
            Command::FixCr3 { selector } => {
                let (matches, system_dtb) = self.find_selected_process(&selector)?;
                let (process, dtb, modules) =
                    self.resolve_first_usable(&selector, matches, system_dtb, true)?;
                let resolved = ResolvedProcess {
                    process,
                    dtb,
                    modules,
                };
                self.cache_resolved(&selector, resolved.clone());
                Ok(Response::text(output::format_process_modules(
                    &resolved.process,
                    resolved.dtb,
                    &resolved.modules,
                )))
            }
            Command::ReadKernel { va, size } => self.read_virtual(None, va, size, true, compact),
            Command::ReadProcess { selector, va, size } => {
                self.read_virtual(Some(&selector), va, size, false, compact)
            }
            Command::ReadVirtual { selector, va, size } => {
                self.read_virtual(selector.as_ref(), va, size, false, compact)
            }
        }
    }

    fn discover_processes(&self) -> Result<Vec<ProcessInfo>, String> {
        enumerate_processes(
            &self.driver,
            self.kernel_dtb,
            self.kernel.system_eprocess,
            self.kernel.base,
            self.kernel.size,
            self.offsets,
        )
    }

    fn find_selected_process(
        &self,
        selector: &ProcessSelector,
    ) -> Result<(Vec<ProcessInfo>, u64), String> {
        let processes = self.discover_processes()?;
        let system_dtb = processes
            .first()
            .ok_or_else(|| "validated process list is empty".to_string())?
            .kernel_dtb;
        let matches = find_processes(&processes, selector);
        if matches.is_empty() {
            return Err(format!("process not found: {selector:?}"));
        }
        Ok((matches, system_dtb))
    }

    fn resolve_first_usable(
        &self,
        selector: &ProcessSelector,
        matches: Vec<ProcessInfo>,
        system_dtb: u64,
        via_pfn: bool,
    ) -> Result<(ProcessInfo, u64, Vec<ModuleInfo>), String> {
        let single = matches.len() == 1;
        let mut usable = Vec::new();
        let mut failures = Vec::new();
        for process in matches {
            let enumerate = if via_pfn {
                enumerate_modules_via_pfn
            } else {
                enumerate_modules
            };
            match enumerate(
                &self.driver,
                &process,
                system_dtb,
                self.ram_size,
                self.kernel.mm_get_virtual_for_physical,
                self.offsets,
            ) {
                Ok((dtb, modules)) => usable.push((process, dtb, modules)),
                Err(error) => failures.push((process.pid, error)),
            }
        }

        match usable.len() {
            1 => Ok(usable.pop().expect("exactly one")),
            0 => {

                let (_, first) = failures
                    .into_iter()
                    .next()
                    .ok_or_else(|| format!("process not found: {selector:?}"))?;
                if single {
                    Err(first)
                } else {
                    Err(format!(
                        "no process matching {selector:?} has a resolvable address space; the \
                         first said: {first}"
                    ))
                }
            }
            _ => Err(ambiguous(
                &usable
                    .into_iter()
                    .map(|(process, _, _)| process)
                    .collect::<Vec<_>>(),
            )),
        }
    }

    fn resolve_process(&mut self, selector: &ProcessSelector) -> Result<ResolvedProcess, String> {
        let cache_key = selector_key(selector);
        if let Some(cached) = self.process_cache.get(&cache_key) {
            if cached.last_validation.elapsed() < CACHE_VALIDATION_INTERVAL {
                return Ok(cached.resolved.clone());
            }
            let resolved = cached.resolved.clone();
            if self.validate_cached_process(&resolved).is_ok() {
                self.translation_caches.remove(&resolved.dtb);
                if let Some(cached) = self.process_cache.get_mut(&cache_key) {
                    cached.last_validation = Instant::now();
                }
                return Ok(resolved);
            }
            self.translation_caches.remove(&resolved.dtb);
            self.process_cache.remove(&cache_key);
        }

        let (matches, system_dtb) = self.find_selected_process(selector)?;
        let (process, dtb, modules) =
            self.resolve_first_usable(selector, matches, system_dtb, false)?;
        let resolved = ResolvedProcess {
            process,
            dtb,
            modules,
        };
        self.cache_resolved(selector, resolved.clone());
        Ok(resolved)
    }

    fn cache_resolved(&mut self, selector: &ProcessSelector, resolved: ResolvedProcess) {
        let previous = self.process_cache.insert(
            selector_key(selector),
            CachedProcess {
                resolved,
                last_validation: Instant::now(),
            },
        );
        if let Some(previous) = previous {
            self.translation_caches.remove(&previous.resolved.dtb);
        }
    }

    fn validate_cached_process(&self, resolved: &ResolvedProcess) -> Result<(), String> {
        let kernel_memory = VirtualMemory::new(&self.driver, self.kernel_dtb)?;
        let pid = kernel_memory.read_u64(checked_field(
            resolved.process.eprocess,
            self.offsets.eprocess_unique_process_id,
            "EPROCESS.UniqueProcessId",
        )?)?;
        if pid != u64::from(resolved.process.pid) {
            return Err("cached EPROCESS PID changed".to_string());
        }
        let image_bytes = kernel_memory.read(
            checked_field(
                resolved.process.eprocess,
                self.offsets.eprocess_image_file_name,
                "EPROCESS.ImageFileName",
            )?,
            IMAGE_FILE_NAME_LENGTH,
        )?;
        let end = image_bytes
            .iter()
            .position(|&byte| byte == 0)
            .unwrap_or(image_bytes.len());
        if !String::from_utf8_lossy(&image_bytes[..end])
            .eq_ignore_ascii_case(&resolved.process.image_name)
        {
            return Err("cached EPROCESS image name changed".to_string());
        }

        let main = resolved
            .modules
            .first()
            .ok_or_else(|| "cached loader list is empty".to_string())?;
        let process_memory = VirtualMemory::new(&self.driver, resolved.dtb)?;
        let image_base = process_memory.read_u64(checked_field(
            resolved.process.peb,
            self.offsets.peb_image_base_address,
            "cached PEB.ImageBaseAddress",
        )?)?;
        if image_base != main.base {
            return Err(format!(
                "cached PEB image base changed: 0x{image_base:X} != 0x{:X}",
                main.base
            ));
        }
        let ldr = process_memory.read_u64(checked_field(
            resolved.process.peb,
            self.offsets.peb_ldr,
            "cached PEB.Ldr",
        )?)?;
        if !is_user_address(ldr) {
            return Err(format!("cached PEB contains invalid Ldr 0x{ldr:X}"));
        }
        let initialized = process_memory.read_u8(checked_field(
            ldr,
            self.offsets.peb_ldr_initialized,
            "cached PEB_LDR_DATA.Initialized",
        )?)?;
        if initialized == 0 {
            return Err("cached PEB_LDR_DATA is not initialized".to_string());
        }
        Ok(())
    }

    fn read_virtual(
        &mut self,
        selector: Option<&ProcessSelector>,
        va: u64,
        size: usize,
        require_kernel: bool,
        compact: bool,
    ) -> Result<Response, String> {
        let end = va
            .checked_add(size.saturating_sub(1) as u64)
            .ok_or_else(|| "virtual-address range overflow".to_string())?;

        if is_kernel_address(va) && is_kernel_address(end) {
            if self.kernel_cache_started.elapsed() >= CACHE_VALIDATION_INTERVAL {
                self.kernel_translation_cache.clear();
                self.kernel_cache_started = Instant::now();
            }
            let memory = VirtualMemory::new_cached(
                &self.driver,
                self.kernel_dtb,
                self.kernel_translation_cache.clone(),
            )?;
            let data = memory.read(va, size)?;
            return Ok(Response::data(
                if compact {
                    String::new()
                } else {
                    output::format_read(
                        "KERNEL",
                        va,
                        end,
                        size,
                        self.kernel_dtb,
                        None,
                        Some("KslD CPU CR3"),
                    )
                },
                data,
            ));
        }
        if require_kernel {
            return Err(format!(
                "address range 0x{va:X}-0x{end:X} is not a canonical x64 kernel range"
            ));
        }

        if is_user_address(va) && is_user_address(end) {
            let selector = selector.ok_or_else(|| {
                "user virtual address requires process context: use <process> <va> [size]"
                    .to_string()
            })?;
            let resolved = self.resolve_process(selector)?;
            let translation_cache = self
                .translation_caches
                .entry(resolved.dtb)
                .or_default()
                .clone();
            let memory =
                VirtualMemory::new_cached(&self.driver, resolved.dtb, translation_cache.clone())?;
            match memory.read(va, size) {
                Ok(data) => Ok(Response::data(
                    if compact {
                        String::new()
                    } else {
                        output::format_read(
                            "USER",
                            va,
                            end,
                            size,
                            resolved.dtb,
                            Some(&resolved.process),
                            Some("validated process DTB"),
                        )
                    },
                    data,
                )),
                Err(first_error) => {
                    translation_cache.clear();
                    let retry_memory =
                        VirtualMemory::new_cached(&self.driver, resolved.dtb, translation_cache)?;
                    if let Ok(data) = retry_memory.read(va, size) {
                        return Ok(Response::data(
                            if compact {
                                String::new()
                            } else {
                                output::format_read(
                                    "USER",
                                    va,
                                    end,
                                    size,
                                    resolved.dtb,
                                    Some(&resolved.process),
                                    Some("validated process DTB; translation cache refreshed"),
                                )
                            },
                            data,
                        ));
                    }
                    if self.validate_cached_process(&resolved).is_ok() {
                        return Err(first_error);
                    }
                    self.process_cache.remove(&selector_key(selector));
                    let refreshed = self.resolve_process(selector)?;
                    let memory = VirtualMemory::new(&self.driver, refreshed.dtb)?;
                    let data = memory.read(va, size).map_err(|second_error| {
                        format!(
                            "read failed before and after process refresh: {first_error}; {second_error}"
                        )
                    })?;
                    Ok(Response::data(
                        if compact {
                            String::new()
                        } else {
                            output::format_read(
                                "USER",
                                va,
                                end,
                                size,
                                refreshed.dtb,
                                Some(&refreshed.process),
                                Some("refreshed validated process DTB"),
                            )
                        },
                        data,
                    ))
                }
            }
        } else {
            Err(format!(
                "VA range 0x{va:X}-0x{end:X} is noncanonical, below minimum user VA, or crosses user/kernel ranges"
            ))
        }
    }
}

fn selector_key(selector: &ProcessSelector) -> String {
    match selector {
        ProcessSelector::Pid(pid) => format!("pid:{pid}"),
        ProcessSelector::Name(name) => format!("name:{}", name.to_ascii_lowercase()),
    }
}

fn print_disconnected(reason: &str) {
    println!("[-] CONNECTION");
    println!("    Status        : DISCONNECTED");
    println!("    Reason        : {reason}");
}
