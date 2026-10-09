use crate::windows::process::ProcessSelector;

pub const MAX_READ_SIZE: usize = 16 * 1024 * 1024;

pub enum Command {
    Serve,
    InspectSystem,
    ListProcesses,
    Modules {
        selector: ProcessSelector,
    },
    ProcessBase {
        selector: ProcessSelector,
    },
    ProcessModule {
        selector: ProcessSelector,
        module_name: String,
    },
    FixCr3 {
        selector: ProcessSelector,
    },
    ReadVirtual {
        selector: Option<ProcessSelector>,
        va: u64,
        size: usize,
    },
    ReadKernel {
        va: u64,
        size: usize,
    },
    ReadProcess {
        selector: ProcessSelector,
        va: u64,
        size: usize,
    },
}

pub fn parse(args: &[String]) -> Result<Command, String> {
    match args.get(1).map(String::as_str) {
        None => Ok(Command::Serve),
        Some("system") if args.len() == 2 => Ok(Command::InspectSystem),
        Some("processes") if args.len() == 2 => Ok(Command::ListProcesses),
        Some("modules") if args.len() == 3 => Ok(Command::Modules {
            selector: ProcessSelector::parse(&args[2])?,
        }),
        Some("fixcr3") if args.len() == 3 => Ok(Command::FixCr3 {
            selector: ProcessSelector::parse(&args[2])?,
        }),
        Some("read-kernel") if (3..=4).contains(&args.len()) => Ok(Command::ReadKernel {
            va: parse_number(&args[2], "kernel virtual address")?,
            size: parse_size(args.get(3))?,
        }),
        Some("read-process") if (4..=5).contains(&args.len()) => Ok(Command::ReadProcess {
            selector: ProcessSelector::parse(&args[2])?,
            va: parse_number(&args[3], "process virtual address")?,
            size: parse_size(args.get(4))?,
        }),
        Some(value) if args.len() == 2 => match parse_number(value, "virtual address") {
            Ok(va) => Ok(Command::ReadVirtual {
                selector: None,
                va,
                size: 8,
            }),
            Err(_) => Ok(Command::ProcessBase {
                selector: ProcessSelector::parse(value)?,
            }),
        },
        Some(value) if args.len() == 3 => match parse_number(value, "virtual address") {
            Ok(va) => Ok(Command::ReadVirtual {
                selector: None,
                va,
                size: parse_size(args.get(2))?,
            }),
            Err(_) => {
                let selector = ProcessSelector::parse(value)?;
                match parse_number(&args[2], "process virtual address") {
                    Ok(va) => Ok(Command::ReadVirtual {
                        selector: Some(selector),
                        va,
                        size: 8,
                    }),
                    Err(_) if args[2].eq_ignore_ascii_case("all") => {
                        Ok(Command::Modules { selector })
                    }
                    Err(_) => Ok(Command::ProcessModule {
                        selector,
                        module_name: args[2].clone(),
                    }),
                }
            }
        },
        Some(value) if args.len() == 4 => {
            let selector = ProcessSelector::parse(value)?;
            Ok(Command::ReadVirtual {
                selector: Some(selector),
                va: parse_number(&args[2], "process virtual address")?,
                size: parse_size(args.get(3))?,
            })
        }
        _ => Err("invalid arguments".to_string()),
    }
}

pub fn usage(program: &str) {
    eprintln!("Usage:");
    eprintln!("  {program}                              start LAN read server");
    eprintln!("  {program} system                       inspect System EPROCESS");
    eprintln!("  {program} processes                    list active processes");
    eprintln!("  {program} modules <name|pid:N>         list process modules");
    eprintln!("  {program} fixcr3 <name|pid:N>          force PFN DTB recovery, then list modules");
    eprintln!("  {program} <process>                    print main image base");
    eprintln!("  {program} <process> <module>           print named module base");
    eprintln!("  {program} <process> all                print all module bases");
    eprintln!("  {program} <kernel-va> [size]          kernel virtual read via KslD CPU CR3");
    eprintln!("  {program} <process> <va> [size]        auto kernel/process virtual read");
    eprintln!("  {program} read-process <name|pid:N> <va> [size]");
    eprintln!("  {program} read-kernel <va> [size]");
}

fn parse_size(value: Option<&String>) -> Result<usize, String> {
    let value = match value {
        Some(value) => parse_number(value, "size")?,
        None => 8,
    };
    let size = usize::try_from(value).map_err(|_| "size does not fit in usize".to_string())?;
    if size == 0 || size > MAX_READ_SIZE {
        return Err(format!("size must be between 1 and {MAX_READ_SIZE} bytes"));
    }
    Ok(size)
}

fn parse_number(value: &str, name: &str) -> Result<u64, String> {
    let normalized = value.replace('_', "");
    let parsed = normalized
        .strip_prefix("0x")
        .or_else(|| normalized.strip_prefix("0X"))
        .map_or_else(
            || normalized.parse::<u64>(),
            |hex| u64::from_str_radix(hex, 16),
        );
    parsed.map_err(|_| format!("invalid {name}: {value}"))
}
