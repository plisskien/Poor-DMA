use std::collections::HashSet;

use crate::{
    driver::Ksld,
    memory::{PFN_MASK, VirtualMemory, checked_field, is_kernel_address},
    offsets::Offsets,
};

const SYSTEM_PID: u32 = 4;

const IMAGE_FILE_NAME_LENGTH: usize = 15;

pub const IMAGE_FILE_NAME_MAX_CHARS: usize = IMAGE_FILE_NAME_LENGTH - 1;
const MAX_PROCESSES: usize = 65_536;

#[derive(Clone, Debug)]
pub struct ProcessInfo {
    pub eprocess: u64,
    pub pid: u32,
    pub image_name: String,
    pub kernel_dtb: u64,
    pub user_dtb: u64,
    pub peb: u64,
    pub wow64_process: u64,
}

#[derive(Clone, Debug)]
pub enum ProcessSelector {
    Pid(u32),
    Name(String),
}

impl ProcessSelector {
    pub fn parse(value: &str) -> Result<Self, String> {
        if let Some(pid) = value.strip_prefix("pid:") {
            return pid
                .parse::<u32>()
                .map(Self::Pid)
                .map_err(|_| format!("invalid PID selector: {value}"));
        }
        if !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit()) {
            return value
                .parse::<u32>()
                .map(Self::Pid)
                .map_err(|_| format!("invalid PID selector: {value}"));
        }
        if value.is_empty() {
            return Err("process name cannot be empty".to_string());
        }
        Ok(Self::Name(value.to_string()))
    }

    fn matches(&self, process: &ProcessInfo) -> bool {
        match self {
            Self::Pid(pid) => process.pid == *pid,
            Self::Name(name) => {
                if process.image_name.eq_ignore_ascii_case(name) {
                    return true;
                }
                let prefix: String = name.chars().take(IMAGE_FILE_NAME_MAX_CHARS).collect();
                name.chars().count() > IMAGE_FILE_NAME_MAX_CHARS
                    && process.image_name.eq_ignore_ascii_case(&prefix)
            }
        }
    }
}

pub fn enumerate_processes(
    driver: &Ksld,
    kernel_dtb: u64,
    system_eprocess: u64,
    kernel_base: u64,
    kernel_size: u64,
    offsets: Offsets,
) -> Result<Vec<ProcessInfo>, String> {
    let memory = VirtualMemory::new(driver, kernel_dtb)?;
    let kernel_end = kernel_base
        .checked_add(kernel_size)
        .ok_or_else(|| "ntoskrnl virtual-address range overflow".to_string())?;
    let system_link = checked_field(
        system_eprocess,
        offsets.eprocess_active_process_links,
        "System.ActiveProcessLinks",
    )?;

    let system = read_process(&memory, system_eprocess, offsets)?;
    if system.pid != SYSTEM_PID || !system.image_name.eq_ignore_ascii_case("System") {
        return Err(format!(
            "offset profile validation failed: PsInitialSystemProcess decoded as PID {} / {:?}",
            system.pid, system.image_name
        ));
    }

    let mut current_link = memory.read_u64(checked_field(
        system_link,
        offsets.list_entry_flink,
        "System.ActiveProcessLinks.Flink",
    )?)?;
    let mut seen_links = HashSet::new();
    let mut processes = vec![system];
    seen_links.insert(system_link);
    let mut process_list_head = None;

    while current_link != system_link {
        if processes.len() >= MAX_PROCESSES {
            return Err(format!(
                "active-process list exceeded safety limit {MAX_PROCESSES}"
            ));
        }
        if !is_kernel_address(current_link) || current_link & 7 != 0 {
            return Err(format!(
                "invalid ActiveProcessLinks pointer 0x{current_link:X}"
            ));
        }
        if !seen_links.insert(current_link) {
            return Err(format!(
                "active-process list formed a cycle away from PsActiveProcessHead at 0x{current_link:X}"
            ));
        }

        if (kernel_base..kernel_end).contains(&current_link) {
            if process_list_head.replace(current_link).is_some() {
                return Err(format!(
                    "encountered multiple process-list nodes inside ntoskrnl; latest = 0x{current_link:X}"
                ));
            }
        } else {
            let current_eprocess = current_link
                .checked_sub(offsets.eprocess_active_process_links)
                .ok_or_else(|| "ActiveProcessLinks containing-record underflow".to_string())?;
            processes.push(read_process(&memory, current_eprocess, offsets)?);
        }

        let next_link = memory.read_u64(checked_field(
            current_link,
            offsets.list_entry_flink,
            "ActiveProcessLinks.Flink",
        )?)?;
        if !is_kernel_address(next_link) || next_link & 7 != 0 {
            return Err(format!(
                "invalid ActiveProcessLinks.Flink 0x{next_link:X} at 0x{current_link:X}"
            ));
        }
        let next_blink = memory.read_u64(checked_field(
            next_link,
            offsets.list_entry_blink,
            "next ActiveProcessLinks.Blink",
        )?)?;
        if next_blink != current_link {
            return Err(format!(
                "process-list backlink mismatch: node 0x{current_link:X} -> 0x{next_link:X}, but next.Blink = 0x{next_blink:X}"
            ));
        }
        current_link = next_link;
    }

    let process_list_head = process_list_head.ok_or_else(|| {
        "active-process traversal did not encounter PsActiveProcessHead".to_string()
    })?;
    println!("[+] PsActiveProcessHead VA = 0x{process_list_head:X}");

    Ok(processes)
}

pub fn find_process(
    processes: &[ProcessInfo],
    selector: &ProcessSelector,
) -> Result<ProcessInfo, String> {
    match find_processes(processes, selector).as_slice() {
        [] => Err(format!("process not found: {selector:?}")),
        [process] => Ok(process.clone()),
        many => Err(ambiguous(many)),
    }
}

pub fn find_processes(processes: &[ProcessInfo], selector: &ProcessSelector) -> Vec<ProcessInfo> {
    processes
        .iter()
        .filter(|process| selector.matches(process))
        .cloned()
        .collect()
}

pub fn ambiguous(many: &[ProcessInfo]) -> String {
    let choices = many
        .iter()
        .map(|process| format!("{} (PID {})", process.image_name, process.pid))
        .collect::<Vec<_>>()
        .join(", ");
    format!("process selector is ambiguous: {choices}; use pid:<number>")
}

fn read_process(
    memory: &VirtualMemory<'_>,
    eprocess: u64,
    offsets: Offsets,
) -> Result<ProcessInfo, String> {
    if !is_kernel_address(eprocess) || eprocess & 7 != 0 {
        return Err(format!("invalid EPROCESS pointer 0x{eprocess:X}"));
    }

    let pid_raw = memory.read_u64(checked_field(
        eprocess,
        offsets.eprocess_unique_process_id,
        "EPROCESS.UniqueProcessId",
    )?)?;
    let pid = u32::try_from(pid_raw)
        .map_err(|_| format!("EPROCESS 0x{eprocess:X} has invalid PID 0x{pid_raw:X}"))?;

    let image_bytes = memory.read(
        checked_field(
            eprocess,
            offsets.eprocess_image_file_name,
            "EPROCESS.ImageFileName",
        )?,
        IMAGE_FILE_NAME_LENGTH,
    )?;
    let image_end = image_bytes
        .iter()
        .position(|&byte| byte == 0)
        .unwrap_or(image_bytes.len());
    let image_name = String::from_utf8_lossy(&image_bytes[..image_end]).into_owned();
    if image_name.is_empty()
        || !image_name
            .bytes()
            .all(|byte| byte.is_ascii_graphic() || byte == b' ')
    {
        return Err(format!(
            "EPROCESS 0x{eprocess:X} has invalid ImageFileName bytes"
        ));
    }

    let kernel_dtb = memory.read_u64(checked_field(
        eprocess,
        offsets.kprocess_directory_table_base,
        "KPROCESS.DirectoryTableBase",
    )?)? & PFN_MASK;
    let user_dtb = memory.read_u64(checked_field(
        eprocess,
        offsets.kprocess_user_directory_table_base,
        "KPROCESS.UserDirectoryTableBase",
    )?)? & PFN_MASK;
    let peb = memory.read_u64(checked_field(
        eprocess,
        offsets.eprocess_peb,
        "EPROCESS.Peb",
    )?)?;
    let wow64_process = memory.read_u64(checked_field(
        eprocess,
        offsets.eprocess_wow64_process,
        "EPROCESS.WoW64Process",
    )?)?;

    Ok(ProcessInfo {
        eprocess,
        pid,
        image_name,
        kernel_dtb,
        user_dtb,
        peb,
        wow64_process,
    })
}
