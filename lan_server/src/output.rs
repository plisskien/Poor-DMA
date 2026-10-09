use std::fmt::Write as _;

use crate::windows::{loader::ModuleInfo, process::ProcessInfo};

pub fn format_processes(processes: &[ProcessInfo]) -> String {
    let mut output = format!("[+] PROCESSES ({})\n", processes.len());
    output.push_str(
        "    PID       EPROCESS            KERNEL DTB          USER DTB            NAME\n",
    );
    output.push_str(
        "    --------  ------------------  ------------------  ------------------  ---------------\n",
    );
    for process in processes {
        writeln!(
            output,
            "    {:<8}  0x{:016X}  0x{:016X}  0x{:016X}  {}",
            process.pid, process.eprocess, process.kernel_dtb, process.user_dtb, process.image_name
        )
        .unwrap();
    }
    output
}

pub fn format_process(process: &ProcessInfo, validated_dtb: Option<u64>) -> String {
    let mut output = String::from("[+] PROCESS\n");
    writeln!(output, "    Name          : {}", process.image_name).unwrap();
    writeln!(output, "    PID           : {}", process.pid).unwrap();
    writeln!(output, "    EPROCESS      : 0x{:016X}", process.eprocess).unwrap();
    writeln!(output, "    Kernel DTB    : 0x{:016X}", process.kernel_dtb).unwrap();
    writeln!(output, "    User DTB      : 0x{:016X}", process.user_dtb).unwrap();
    writeln!(output, "    PEB           : 0x{:016X}", process.peb).unwrap();
    if let Some(dtb) = validated_dtb {
        writeln!(output, "    Validated DTB : 0x{dtb:016X}").unwrap();
    }
    output
}

pub fn format_process_modules<'a>(
    process: &ProcessInfo,
    validated_dtb: u64,
    modules: impl IntoIterator<Item = &'a ModuleInfo>,
) -> String {
    let modules = modules.into_iter().collect::<Vec<_>>();
    let mut output = format_process(process, Some(validated_dtb));
    writeln!(output, "[+] MODULES ({})", modules.len()).unwrap();
    output.push_str("    BASE                SIZE        NAME                              PATH\n");
    output.push_str("    ------------------  ----------  --------------------------------  ----\n");
    for module in modules {
        writeln!(
            output,
            "    0x{:016X}  0x{:08X}  {:<32}  {}",
            module.base, module.size, module.name, module.full_name
        )
        .unwrap();
    }
    output
}

pub fn format_read(
    space: &str,
    start: u64,
    end: u64,
    size: usize,
    dtb: u64,
    process: Option<&ProcessInfo>,
    note: Option<&str>,
) -> String {
    let mut output = String::from("[+] READ\n");
    writeln!(output, "    Space         : {space}").unwrap();
    writeln!(output, "    Range         : 0x{start:016X}-0x{end:016X}").unwrap();
    writeln!(output, "    Bytes         : {size}").unwrap();
    writeln!(output, "    DTB           : 0x{dtb:016X}").unwrap();
    if let Some(process) = process {
        writeln!(
            output,
            "    Process       : {} (PID {})",
            process.image_name, process.pid
        )
        .unwrap();
    }
    if let Some(note) = note {
        writeln!(output, "    Note          : {note}").unwrap();
    }
    output
}
