mod cli;
mod driver;
mod memory;
mod offsets;
mod output;
mod privilege;
mod server;
mod windows;
mod drop_driver;

use cli::Command;
use driver::{KSLD_PROTOCOL_VERSION, Ksld};
use memory::{PFN_MASK, VirtualMemory, is_kernel_address, is_user_address};
use offsets::{Offsets, require_supported_build};
use privilege::{enable_debug_privilege, require_administrator};
use drop_driver::{replace_driver, set_allowed_process, start_service, stop_service,};
use windows::{
    kernel::{KernelIdentity, locate_system_process, resolve_system_dtb},
    loader::{ModuleInfo, enumerate_modules, enumerate_modules_via_pfn},
    process::{ProcessInfo, ProcessSelector, enumerate_processes, find_process},
};

struct ResolvedProcess {
    process: ProcessInfo,
    dtb: u64,
    modules: Vec<ModuleInfo>,
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let command = cli::parse(&args).unwrap_or_else(|error| {
        eprintln!("[-] ERROR");
        eprintln!("    Message       : {error}");
        cli::usage(&args[0]);
        std::process::exit(2);
    });

    println!("[+] STARTUP");
    require_administrator().unwrap_or_else(|error| fatal(error));
    println!("    Administrator : elevated");

    let profile = require_supported_build().unwrap_or_else(|error| fatal(error));
    let offsets = profile.offsets;
    println!(
        "    Windows build : {} x64 ({})",
        profile.build, profile.release
    );
    println!("    Offset profile: {} accepted", profile.build);

    stop_service("KslD").unwrap_or_else(|error| fatal(error));
    println!("    Service       : KslD stopped");

    replace_driver().unwrap_or_else(|error| fatal(error));
    println!("    Driver        : Dropped into System32\\drivers\\wd\\KslD.sys");

    set_allowed_process("KslD").unwrap_or_else(|error| fatal(error));
    println!("    Registry      : AllowedProcessName updated");

    start_service("KslD").unwrap_or_else(|error| fatal(error));
    println!("    Service       : KslD started");

    enable_debug_privilege().unwrap_or_else(|error| fatal(error));
    println!("    Privilege     : SeDebugPrivilege enabled");

    let driver = Ksld::open().unwrap_or_else(|error| {
        eprintln!("[-] ERROR");
        eprintln!("    Operation     : open \\\\.\\KslD");
        eprintln!("    GetLastError  : {error}");
        eprintln!("    Hint          : ensure KslD service is installed and running");
        std::process::exit(1);
    });
    println!("    Driver        : \\\\.\\KslD opened");

    let driver_version = driver.get_version().unwrap_or_else(|error| fatal(error));
    if driver_version != KSLD_PROTOCOL_VERSION {
        fatal(format!(
            "unsupported KslD protocol 0x{driver_version:X}; expected 0x{KSLD_PROTOCOL_VERSION:X}"
        ));
    }
    println!("    Protocol      : KslD 0x{driver_version:X} accepted");

    let cpu = driver.get_cpu_state().unwrap_or_else(|error| fatal(error));
    let cpu_dtb = cpu.cr3 & PFN_MASK;
    let bootstrap_kernel =
        locate_system_process(&driver, cpu_dtb).unwrap_or_else(|error| fatal(error));
    let kernel_dtb = resolve_system_dtb(
        &driver,
        cpu_dtb,
        cpu.ram_size,
        bootstrap_kernel.system_eprocess,
        offsets,
    )
    .unwrap_or_else(|error| fatal(error));
    println!("    CPU CR3       : 0x{:016X}", cpu.cr3);
    println!("    Kernel DTB    : 0x{kernel_dtb:016X}");
    println!("    Physical RAM  : 0x{:016X}", cpu.ram_size);

    match command {
        Command::Serve => server::run(driver, kernel_dtb, cpu.ram_size, offsets)
            .unwrap_or_else(|error| fatal(error)),
        Command::InspectSystem => inspect_system(&driver, kernel_dtb, offsets),
        Command::ListProcesses => {
            let (_, processes) = discover_processes(&driver, kernel_dtb, offsets);
            print!("{}", output::format_processes(&processes));
        }
        Command::Modules { selector } => {
            let resolved =
                resolve_selected_process(&driver, kernel_dtb, cpu.ram_size, offsets, &selector);
            print!(
                "{}",
                output::format_process_modules(&resolved.process, resolved.dtb, &resolved.modules)
            );
        }
        Command::ProcessBase { selector } => {
            let resolved =
                resolve_selected_process(&driver, kernel_dtb, cpu.ram_size, offsets, &selector);
            let main = resolved
                .modules
                .first()
                .expect("validated loader list must contain main module");
            print!(
                "{}",
                output::format_process_modules(&resolved.process, resolved.dtb, [main])
            );
        }
        Command::ProcessModule {
            selector,
            module_name,
        } => {
            let resolved =
                resolve_selected_process(&driver, kernel_dtb, cpu.ram_size, offsets, &selector);
            let matches = resolved
                .modules
                .iter()
                .filter(|module| module.name.eq_ignore_ascii_case(&module_name))
                .collect::<Vec<_>>();
            if matches.is_empty() {
                fatal(format!(
                    "module {module_name:?} not found in {}",
                    resolved.process.image_name
                ));
            }
            print!(
                "{}",
                output::format_process_modules(&resolved.process, resolved.dtb, matches)
            );
        }
        Command::FixCr3 { selector } => {
            let (process, system_dtb, mm_get_virtual_for_physical) =
                find_selected_process(&driver, kernel_dtb, offsets, &selector);
            let (used_dtb, modules) = enumerate_modules_via_pfn(
                &driver,
                &process,
                system_dtb,
                cpu.ram_size,
                mm_get_virtual_for_physical,
                offsets,
            )
            .unwrap_or_else(|error| fatal(error));
            print!(
                "{}",
                output::format_process_modules(&process, used_dtb, &modules)
            );
        }
        Command::ReadKernel { va, size } => {
            if !is_kernel_address(va) {
                fatal(format!("address 0x{va:X} is not a canonical x64 kernel VA"));
            }
            let memory = VirtualMemory::new(&driver, kernel_dtb)
                .unwrap_or_else(|error| fatal(error))
                .traced(true);
            let data = memory.read(va, size).unwrap_or_else(|error| fatal(error));
            print_data(&data);
        }
        Command::ReadProcess { selector, va, size } => {
            read_virtual_auto(
                &driver,
                kernel_dtb,
                cpu.ram_size,
                offsets,
                Some(&selector),
                va,
                size,
            );
        }
        Command::ReadVirtual { selector, va, size } => {
            read_virtual_auto(
                &driver,
                kernel_dtb,
                cpu.ram_size,
                offsets,
                selector.as_ref(),
                va,
                size,
            );
        }
    }
}

fn discover_processes(
    driver: &Ksld,
    kernel_dtb: u64,
    offsets: Offsets,
) -> (KernelIdentity, Vec<ProcessInfo>) {
    let kernel = locate_system_process(driver, kernel_dtb).unwrap_or_else(|error| fatal(error));
    println!("[+] KERNEL");
    println!("    Image base    : 0x{:016X}", kernel.base);
    println!("    Image size    : 0x{:X}", kernel.size);
    println!(
        "    PsInitialSystemProcess : 0x{:016X}",
        kernel.ps_initial_system_process
    );
    println!(
        "    MmGetVirtualForPhysical: 0x{:016X}",
        kernel.mm_get_virtual_for_physical
    );
    println!(
        "    System EPROCESS        : 0x{:016X}",
        kernel.system_eprocess
    );

    let processes = enumerate_processes(
        driver,
        kernel_dtb,
        kernel.system_eprocess,
        kernel.base,
        kernel.size,
        offsets,
    )
    .unwrap_or_else(|error| fatal(error));
    (kernel, processes)
}

fn find_selected_process(
    driver: &Ksld,
    kernel_dtb: u64,
    offsets: Offsets,
    selector: &ProcessSelector,
) -> (ProcessInfo, u64, u64) {
    let (kernel, processes) = discover_processes(driver, kernel_dtb, offsets);
    let system_dtb = processes
        .first()
        .expect("validated process list must contain System")
        .kernel_dtb;
    let process = find_process(&processes, selector).unwrap_or_else(|error| fatal(error));
    (process, system_dtb, kernel.mm_get_virtual_for_physical)
}

fn resolve_selected_process(
    driver: &Ksld,
    kernel_dtb: u64,
    ram_size: u64,
    offsets: Offsets,
    selector: &ProcessSelector,
) -> ResolvedProcess {
    let (process, system_dtb, mm_get_virtual_for_physical) =
        find_selected_process(driver, kernel_dtb, offsets, selector);
    let (dtb, modules) = enumerate_modules(
        driver,
        &process,
        system_dtb,
        ram_size,
        mm_get_virtual_for_physical,
        offsets,
    )
    .unwrap_or_else(|error| fatal(error));
    ResolvedProcess {
        process,
        dtb,
        modules,
    }
}

fn read_virtual_auto(
    driver: &Ksld,
    kernel_dtb: u64,
    ram_size: u64,
    offsets: Offsets,
    selector: Option<&ProcessSelector>,
    va: u64,
    size: usize,
) {
    let end = va
        .checked_add(size.saturating_sub(1) as u64)
        .unwrap_or_else(|| fatal("virtual-address range overflow"));

    if is_kernel_address(va) && is_kernel_address(end) {
        print!(
            "{}",
            output::format_read(
                "KERNEL",
                va,
                end,
                size,
                kernel_dtb,
                None,
                Some("KslD CPU CR3"),
            )
        );
        let memory = VirtualMemory::new(driver, kernel_dtb)
            .unwrap_or_else(|error| fatal(error))
            .traced(true);
        let data = memory.read(va, size).unwrap_or_else(|error| fatal(error));
        print_data(&data);
        return;
    }

    if is_user_address(va) && is_user_address(end) {
        let selector = selector.unwrap_or_else(|| {
            fatal("user virtual address requires process context: use <process> <va> [size]")
        });
        let resolved = resolve_selected_process(driver, kernel_dtb, ram_size, offsets, selector);
        let note = if let Some(module) = resolved.modules.iter().find(|module| {
            module
                .base
                .checked_add(u64::from(module.size))
                .is_some_and(|module_end| va >= module.base && end < module_end)
        }) {
            format!("validated process DTB; module {}", module.name)
        } else {
            "validated process DTB; outside loaded-image ranges".to_string()
        };
        print!(
            "{}",
            output::format_read(
                "USER",
                va,
                end,
                size,
                resolved.dtb,
                Some(&resolved.process),
                Some(&note),
            )
        );

        let memory = VirtualMemory::new(driver, resolved.dtb)
            .unwrap_or_else(|error| fatal(error))
            .traced(true);
        let data = memory.read(va, size).unwrap_or_else(|error| fatal(error));
        print_data(&data);
        return;
    }

    fatal(format!(
        "VA range 0x{va:X}-0x{end:X} is noncanonical, below minimum user VA, or crosses user/kernel ranges"
    ));
}

fn inspect_system(driver: &Ksld, kernel_dtb: u64, offsets: Offsets) {
    let (_, processes) = discover_processes(driver, kernel_dtb, offsets);
    let system = processes
        .first()
        .expect("validated process list must contain System");
    print!("{}", output::format_process(system, None));
}

fn print_data(data: &[u8]) {
    println!("[+] DATA");
    println!("    Bytes         : {}", data.len());
    if !data.is_empty() && data.len() <= 8 {
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

fn fatal(error: impl std::fmt::Display) -> ! {
    eprintln!("[-] ERROR");
    eprintln!("    Message       : {error}");
    std::process::exit(1);
}
