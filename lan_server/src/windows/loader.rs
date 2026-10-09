use std::collections::{HashSet, VecDeque};

use crate::{
    driver::Ksld,
    memory::{VirtualMemory, checked_field, is_user_address},
    offsets::Offsets,
};

use super::{
    dtb::discover_dtb_candidates,
    process::{IMAGE_FILE_NAME_MAX_CHARS, ProcessInfo},
};

const MAX_MODULES: usize = 512;
const MAX_LOADER_ENTRIES: usize = 4096;
const MAX_PATH_UTF16_BYTES: usize = 260 * 2;
const MAX_LDR_NAME_BYTES: usize = 0x1000;
const PEB64_READ_SIZE: usize = 0x20;
const PEB_LDR_DATA64_SIZE: usize = 0x40;
const LDR_MODULE64_SIZE: usize = 0x88;
const MAX_FAILURE_DETAILS: usize = 4;

#[derive(Clone, Debug)]
pub struct ModuleInfo {
    pub base: u64,
    pub size: u32,
    pub name: String,
    pub full_name: String,
}

pub fn enumerate_modules(
    driver: &Ksld,
    process: &ProcessInfo,
    system_dtb: u64,
    ram_size: u64,
    mm_get_virtual_for_physical: u64,
    offsets: Offsets,
) -> Result<(u64, Vec<ModuleInfo>), String> {
    enumerate_modules_impl(
        driver,
        process,
        system_dtb,
        ram_size,
        mm_get_virtual_for_physical,
        offsets,
        false,
    )
}

pub fn enumerate_modules_via_pfn(
    driver: &Ksld,
    process: &ProcessInfo,
    system_dtb: u64,
    ram_size: u64,
    mm_get_virtual_for_physical: u64,
    offsets: Offsets,
) -> Result<(u64, Vec<ModuleInfo>), String> {
    enumerate_modules_impl(
        driver,
        process,
        system_dtb,
        ram_size,
        mm_get_virtual_for_physical,
        offsets,
        true,
    )
}

fn enumerate_modules_impl(
    driver: &Ksld,
    process: &ProcessInfo,
    system_dtb: u64,
    ram_size: u64,
    mm_get_virtual_for_physical: u64,
    offsets: Offsets,
    force_pfn: bool,
) -> Result<(u64, Vec<ModuleInfo>), String> {
    if process.wow64_process != 0 {
        return Err(format!(
            "PID {} is WOW64; current x64 profiles support native x64 PEB/Ldr only",
            process.pid
        ));
    }
    if !is_user_address(process.peb) {
        return Err(format!(
            "PID {} has invalid or unavailable PEB 0x{:X}",
            process.pid, process.peb
        ));
    }

    let mut candidates = Vec::new();
    for dtb in [process.kernel_dtb, process.user_dtb] {
        if dtb != 0 && !candidates.contains(&dtb) {
            candidates.push(dtb);
        }
    }
    let mut failures = Vec::new();
    let mut direct_tried = 0usize;
    if !force_pfn {
        for &dtb in &candidates {
            direct_tried += 1;
            match enumerate_with_dtb(driver, process.peb, &process.image_name, dtb, offsets) {
                Ok(modules) => {
                    println!("[+] target DTB validated from EPROCESS: 0x{dtb:X}");
                    return Ok((dtb, modules));
                }
                Err(error) => failures.push(format!("DTB 0x{dtb:X}: {error}")),
            }
        }
        println!(
            "[+] EPROCESS DTB candidate(s) failed module validation; starting PFN FixCr3 recovery"
        );
    } else {
        println!(
            "[+] forced PFN FixCr3 mode; refreshing PFN candidates and merging target EPROCESS DTBs"
        );
    }
    let recovered = discover_dtb_candidates(
        driver,
        system_dtb,
        ram_size,
        mm_get_virtual_for_physical,
        offsets,
    )?;

    let mut recovery_candidates = Vec::new();
    if force_pfn {
        recovery_candidates.extend(candidates.iter().copied());
    }
    for dtb in recovered {
        if !recovery_candidates.contains(&dtb) {
            recovery_candidates.push(dtb);
        }
    }

    let mut recovered_tried = 0usize;
    for dtb in recovery_candidates {
        let from_eprocess = candidates.contains(&dtb);
        if !force_pfn && from_eprocess {
            continue;
        }
        if from_eprocess {
            direct_tried += 1;
        } else {
            recovered_tried += 1;
        }
        match enumerate_with_dtb(driver, process.peb, &process.image_name, dtb, offsets) {
            Ok(modules) => {
                if from_eprocess {
                    println!(
                        "[+] target DTB validated from EPROCESS after forced PFN refresh: 0x{dtb:X}"
                    );
                } else {
                    println!("[+] target DTB recovered from PFN candidate: 0x{dtb:X}");
                }
                return Ok((dtb, modules));
            }
            Err(error) if failures.len() < MAX_FAILURE_DETAILS => {
                failures.push(format!("DTB 0x{dtb:X}: {error}"));
            }
            Err(_) => {}
        }
    }

    let omitted = direct_tried
        .saturating_add(recovered_tried)
        .saturating_sub(failures.len());
    Err(format!(
        "no DTB validated for PID {}; tried {} EPROCESS and {recovered_tried} PFN candidate(s); first failures: {}{}",
        process.pid,
        direct_tried,
        failures.join("; "),
        if omitted == 0 {
            String::new()
        } else {
            format!("; {omitted} additional failure(s) omitted")
        }
    ))
}

fn enumerate_with_dtb(
    driver: &Ksld,
    peb: u64,
    verify_module: &str,
    dtb: u64,
    offsets: Offsets,
) -> Result<Vec<ModuleInfo>, String> {
    let first_memory = VirtualMemory::new(driver, dtb)?;
    let peb_data = first_memory
        .read(peb, PEB64_READ_SIZE)
        .map_err(|error| format!("PEB at 0x{peb:X}: {error}"))?;
    let image_base = read_u64_at(
        &peb_data,
        offset_usize(offsets.peb_image_base_address, "PEB.ImageBaseAddress")?,
        "PEB.ImageBaseAddress",
    )?;
    if !is_user_address(image_base) {
        return Err(format!("PEB contained invalid image base 0x{image_base:X}"));
    }

    let ldr = read_u64_at(
        &peb_data,
        offset_usize(offsets.peb_ldr, "PEB.Ldr")?,
        "PEB.Ldr",
    )?;
    if !is_user_address(ldr) {
        return Err(format!("PEB contained invalid Ldr pointer 0x{ldr:X}"));
    }

    let ldr_data = first_memory
        .read(ldr, PEB_LDR_DATA64_SIZE)
        .map_err(|error| format!("PEB_LDR_DATA at 0x{ldr:X}: {error}"))?;
    let ldr_length = read_u32_at(
        &ldr_data,
        offset_usize(offsets.peb_ldr_length, "PEB_LDR_DATA.Length")?,
        "PEB_LDR_DATA.Length",
    )?;
    let initialized = *ldr_data
        .get(offset_usize(
            offsets.peb_ldr_initialized,
            "PEB_LDR_DATA.Initialized",
        )?)
        .ok_or_else(|| "short PEB_LDR_DATA.Initialized read".to_string())?;
    if !(0x40..=0x1000).contains(&ldr_length) || initialized == 0 {
        return Err(format!(
            "invalid/uninitialized PEB_LDR_DATA: Length=0x{ldr_length:X}, Initialized={initialized}"
        ));
    }

    let second_memory = VirtualMemory::new(driver, dtb)?;
    let (raw_modules, unreadable_entries) =
        walk_ldr_module_graph(&first_memory, &second_memory, ldr, &ldr_data, offsets)?;
    let mut unavailable_strings = 0usize;
    let mut modules =
        materialize_module_names(&second_memory, raw_modules, &mut unavailable_strings);
    if modules.is_empty() {
        return Err("PEB loader lists yielded no valid modules".to_string());
    }

    let main_index = modules
        .iter()
        .position(|module| module.base == image_base)
        .ok_or_else(|| format!("no loader module matches PEB image base 0x{image_base:X}"))?;
    if main_index != 0 {
        modules.swap(0, main_index);
    }
    validate_main_module(&second_memory, image_base, verify_module, &mut modules[0])?;
    if modules.len() > 2 {
        modules[1..].sort_unstable_by_key(|module| module.base);
    }

    if unavailable_strings != 0 {
        println!(
            "[i] {unavailable_strings} loader string buffer(s) were unavailable; retained module addresses"
        );
    }
    if unreadable_entries != 0 {
        println!(
            "[i] omitted {unreadable_entries} unreadable loader entr{} after two passes",
            if unreadable_entries == 1 { "y" } else { "ies" }
        );
    }
    Ok(modules)
}

#[derive(Clone, Copy)]
struct UnicodeDescriptor {
    length: usize,
    maximum_length: usize,
    buffer: u64,
}

#[derive(Clone)]
struct RawModule {
    base: u64,
    size: u32,
    full_name: UnicodeDescriptor,
    base_name: UnicodeDescriptor,
}

fn walk_ldr_module_graph(
    first_memory: &VirtualMemory<'_>,
    second_memory: &VirtualMemory<'_>,
    ldr: u64,
    ldr_data: &[u8],
    offsets: Offsets,
) -> Result<(Vec<RawModule>, usize), String> {
    let lists = [
        (
            offsets.peb_ldr_in_load_order_module_list,
            offsets.ldr_entry_in_load_order_links,
            "InLoadOrderModuleList",
        ),
        (
            offsets.peb_ldr_in_memory_order_module_list,
            offsets.ldr_entry_in_memory_order_links,
            "InMemoryOrderModuleList",
        ),
        (
            offsets.peb_ldr_in_initialization_order_module_list,
            offsets.ldr_entry_in_initialization_order_links,
            "InInitializationOrderModuleList",
        ),
    ];
    let mut list_heads = HashSet::new();
    for &(head_offset, _, name) in &lists {
        list_heads.insert(checked_field(ldr, head_offset, name)?);
    }

    let mut all_entries = HashSet::new();
    let mut first_pass = VecDeque::new();
    for &(head_offset, link_offset, name) in &lists {
        let head_data_offset = offset_usize(head_offset, name)?;
        let flink = read_u64_at(ldr_data, head_data_offset, name)?;
        let blink_offset = head_data_offset
            .checked_add(offset_usize(offsets.list_entry_blink, "LIST_ENTRY.Blink")?)
            .ok_or_else(|| "loader list-head offset overflow".to_string())?;
        let blink = read_u64_at(ldr_data, blink_offset, name)?;
        queue_ldr_link(
            flink,
            link_offset,
            &list_heads,
            &mut all_entries,
            &mut first_pass,
        );
        queue_ldr_link(
            blink,
            link_offset,
            &list_heads,
            &mut all_entries,
            &mut first_pass,
        );
    }

    let mut second_pass = VecDeque::new();
    let mut module_bases = HashSet::new();
    let mut modules = Vec::new();
    let mut unreadable_entries = 0usize;
    let mut using_second_pass = false;
    while modules.len() < MAX_MODULES {
        let (entry, memory) = if using_second_pass {
            match second_pass.pop_front() {
                Some(entry) => (entry, second_memory),
                None if first_pass.is_empty() => break,
                None => {
                    using_second_pass = false;
                    continue;
                }
            }
        } else {
            match first_pass.pop_front() {
                Some(entry) => (entry, first_memory),
                None if second_pass.is_empty() => break,
                None => {
                    using_second_pass = true;
                    continue;
                }
            }
        };

        let (module, links) = match read_module_core(memory, entry, offsets) {
            Ok(value) => value,
            Err(_) if !using_second_pass => {
                second_pass.push_back(entry);
                continue;
            }
            Err(_) => {
                unreadable_entries += 1;
                continue;
            }
        };
        if !is_user_address(module.base)
            || module.base & 0xfff != 0
            || module.size == 0
            || module.size >= 0x4000_0000
            || module.base_name.length == 0
            || module.base_name.length >= MAX_LDR_NAME_BYTES
        {
            continue;
        }

        if module_bases.insert(module.base) {
            modules.push(module);
        }
        for (link, containing_offset) in links {
            queue_ldr_link(
                link,
                containing_offset,
                &list_heads,
                &mut all_entries,
                &mut first_pass,
            );
        }
    }
    Ok((modules, unreadable_entries))
}

fn queue_ldr_link(
    link: u64,
    containing_offset: u64,
    list_heads: &HashSet<u64>,
    all_entries: &mut HashSet<u64>,
    queue: &mut VecDeque<u64>,
) {
    if link == 0 || link & 7 != 0 || list_heads.contains(&link) {
        return;
    }
    let Some(entry) = link.checked_sub(containing_offset) else {
        return;
    };
    if !is_user_address(entry)
        || entry & 7 != 0
        || all_entries.len() >= MAX_LOADER_ENTRIES
        || !all_entries.insert(entry)
    {
        return;
    }
    queue.push_back(entry);
}

fn read_module_core(
    memory: &VirtualMemory<'_>,
    entry: u64,
    offsets: Offsets,
) -> Result<(RawModule, Vec<(u64, u64)>), String> {
    let data = memory
        .read(entry, LDR_MODULE64_SIZE)
        .map_err(|error| format!("LDR entry 0x{entry:X}: {error}"))?;
    let base = read_u64_at(
        &data,
        offset_usize(offsets.ldr_entry_dll_base, "LDR_MODULE64.BaseAddress")?,
        "LDR_MODULE64.BaseAddress",
    )?;
    let size = read_u32_at(
        &data,
        offset_usize(offsets.ldr_entry_size_of_image, "LDR_MODULE64.SizeOfImage")?,
        "LDR_MODULE64.SizeOfImage",
    )?;
    let full_name = read_unicode_descriptor_at(
        &data,
        offset_usize(offsets.ldr_entry_full_dll_name, "LDR_MODULE64.FullDllName")?,
        offsets,
        "LDR_MODULE64.FullDllName",
    )?;
    let base_name = read_unicode_descriptor_at(
        &data,
        offset_usize(offsets.ldr_entry_base_dll_name, "LDR_MODULE64.BaseDllName")?,
        offsets,
        "LDR_MODULE64.BaseDllName",
    )?;

    let mut links = Vec::with_capacity(6);
    for (list_offset, name) in [
        (
            offsets.ldr_entry_in_load_order_links,
            "LDR_MODULE64.InLoadOrderModuleList",
        ),
        (
            offsets.ldr_entry_in_memory_order_links,
            "LDR_MODULE64.InMemoryOrderModuleList",
        ),
        (
            offsets.ldr_entry_in_initialization_order_links,
            "LDR_MODULE64.InInitializationOrderModuleList",
        ),
    ] {
        let list_offset_usize = offset_usize(list_offset, name)?;
        links.push((read_u64_at(&data, list_offset_usize, name)?, list_offset));
        let blink_offset = list_offset_usize
            .checked_add(offset_usize(offsets.list_entry_blink, "LIST_ENTRY.Blink")?)
            .ok_or_else(|| "LDR_MODULE64 list offset overflow".to_string())?;
        links.push((read_u64_at(&data, blink_offset, name)?, list_offset));
    }

    Ok((
        RawModule {
            base,
            size,
            full_name,
            base_name,
        },
        links,
    ))
}

fn materialize_module_names(
    memory: &VirtualMemory<'_>,
    raw_modules: Vec<RawModule>,
    unavailable_strings: &mut usize,
) -> Vec<ModuleInfo> {
    raw_modules
        .into_iter()
        .map(|raw| {
            let mut full_name = read_loader_unicode(memory, raw.full_name).unwrap_or_else(|| {
                if raw.full_name.length != 0 {
                    *unavailable_strings += 1;
                }
                String::new()
            });
            let mut name = read_loader_unicode(memory, raw.base_name).unwrap_or_else(|| {
                *unavailable_strings += 1;
                String::new()
            });
            if name.is_empty() {
                name = full_name
                    .rsplit(['\\', '/'])
                    .next()
                    .unwrap_or_default()
                    .to_string();
            }
            if name.is_empty() {
                name = embedded_pe_module_name(memory, raw.base)
                    .unwrap_or_else(|| format!("_NA-0x{:x}.dll", raw.base));
            }
            if full_name.is_empty() {
                full_name.clone_from(&name);
            }
            ModuleInfo {
                base: raw.base,
                size: raw.size,
                name,
                full_name,
            }
        })
        .collect()
}

fn validate_main_module(
    memory: &VirtualMemory<'_>,
    image_base: u64,
    verify_module: &str,
    module: &mut ModuleInfo,
) -> Result<(), String> {
    if module.base != image_base {
        return Err(format!(
            "primary loader module base 0x{:X} differs from PEB image base 0x{image_base:X}",
            module.base
        ));
    }
    let name_available = !module.name.starts_with("_NA-0x");
    if name_available && !module_name_matches(verify_module, &module.name) {
        return Err(format!(
            "main loader module {:?} does not match target {:?}",
            module.name, verify_module
        ));
    }

    match read_pe_metadata(memory, image_base) {
        Ok(_) => {

            if !name_available {
                module.name = verify_module.to_string();
                module.full_name.clone_from(&module.name);
            }
        }
        Err(error) if is_nonresident_translation(&error) => {
            if !name_available {
                return Err(format!(
                    "main module name and PE header are both nonresident: {error}"
                ));
            }
        }
        Err(error) => {
            return Err(format!(
                "image base 0x{image_base:X} is not a valid PE image: {error}"
            ));
        }
    }
    Ok(())
}

fn is_nonresident_translation(error: &str) -> bool {
    error.contains("leaf PTE is not resident")
}

fn read_loader_unicode(
    memory: &VirtualMemory<'_>,
    descriptor: UnicodeDescriptor,
) -> Option<String> {
    if descriptor.length == 0 {
        return Some(String::new());
    }
    if descriptor.length & 1 != 0
        || descriptor.length > descriptor.maximum_length
        || !is_user_address(descriptor.buffer)
    {
        return None;
    }
    let read_size = descriptor.length.min(MAX_PATH_UTF16_BYTES) & !1;
    let bytes = memory.read(descriptor.buffer, read_size).ok()?;
    let utf16: Vec<u16> = bytes
        .chunks_exact(2)
        .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
        .take_while(|&code_unit| code_unit != 0)
        .collect();
    Some(String::from_utf16_lossy(&utf16))
}

fn module_name_matches(expected: &str, actual: &str) -> bool {
    if expected.eq_ignore_ascii_case(actual) {
        return true;
    }

    expected.chars().count() == IMAGE_FILE_NAME_MAX_CHARS
        && actual.chars().count() > IMAGE_FILE_NAME_MAX_CHARS
        && actual
            .chars()
            .take(IMAGE_FILE_NAME_MAX_CHARS)
            .collect::<String>()
            .eq_ignore_ascii_case(expected)
}

fn offset_usize(offset: u64, name: &str) -> Result<usize, String> {
    usize::try_from(offset).map_err(|_| format!("{name} offset 0x{offset:X} exceeds usize"))
}

fn read_u64_at(data: &[u8], offset: usize, name: &str) -> Result<u64, String> {
    let end = offset
        .checked_add(8)
        .ok_or_else(|| format!("{name} offset overflow"))?;
    let bytes = data
        .get(offset..end)
        .ok_or_else(|| format!("short {name} read"))?;
    Ok(u64::from_le_bytes(bytes.try_into().unwrap()))
}

fn read_u32_at(data: &[u8], offset: usize, name: &str) -> Result<u32, String> {
    let end = offset
        .checked_add(4)
        .ok_or_else(|| format!("{name} offset overflow"))?;
    let bytes = data
        .get(offset..end)
        .ok_or_else(|| format!("short {name} read"))?;
    Ok(u32::from_le_bytes(bytes.try_into().unwrap()))
}

fn read_u16_at(data: &[u8], offset: usize, name: &str) -> Result<u16, String> {
    let end = offset
        .checked_add(2)
        .ok_or_else(|| format!("{name} offset overflow"))?;
    let bytes = data
        .get(offset..end)
        .ok_or_else(|| format!("short {name} read"))?;
    Ok(u16::from_le_bytes(bytes.try_into().unwrap()))
}

fn read_unicode_descriptor_at(
    data: &[u8],
    base_offset: usize,
    offsets: Offsets,
    name: &str,
) -> Result<UnicodeDescriptor, String> {
    let length_offset = base_offset
        .checked_add(offset_usize(offsets.unicode_string_length, "UNICODE_STRING.Length")?)
        .ok_or_else(|| format!("{name}.Length offset overflow"))?;
    let length = read_u16_at(data, length_offset, &format!("{name}.Length"))? as usize;

    let max_len_offset = base_offset
        .checked_add(offset_usize(
            offsets.unicode_string_maximum_length,
            "UNICODE_STRING.MaximumLength",
        )?)
        .ok_or_else(|| format!("{name}.MaximumLength offset overflow"))?;
    let maximum_length =
        read_u16_at(data, max_len_offset, &format!("{name}.MaximumLength"))? as usize;

    let buffer_offset = base_offset
        .checked_add(offset_usize(offsets.unicode_string_buffer, "UNICODE_STRING.Buffer")?)
        .ok_or_else(|| format!("{name}.Buffer offset overflow"))?;
    let buffer = read_u64_at(data, buffer_offset, &format!("{name}.Buffer"))?;

    Ok(UnicodeDescriptor {
        length,
        maximum_length,
        buffer,
    })
}

fn read_pe_metadata(memory: &VirtualMemory<'_>, image_base: u64) -> Result<(), String> {
    let dos_data = memory.read(image_base, 0x40)?;
    if dos_data.len() < 0x40 || &dos_data[0..2] != b"MZ" {
        return Err("invalid DOS signature".to_string());
    }
    let e_lfanew = u32::from_le_bytes(dos_data[0x3c..0x40].try_into().unwrap());
    let nt_address = image_base
        .checked_add(e_lfanew as u64)
        .ok_or_else(|| "PE header address overflow".to_string())?;
    let nt_data = memory.read(nt_address, 0x18 + 0x70)?;
    if nt_data.len() < 4 || &nt_data[0..4] != b"PE\0\0" {
        return Err("invalid PE signature".to_string());
    }
    let magic = u16::from_le_bytes(nt_data[0x18..0x1a].try_into().unwrap());
    if magic != 0x20b {
        return Err("invalid PE32+ optional header magic".to_string());
    }
    Ok(())
}

fn embedded_pe_module_name(memory: &VirtualMemory<'_>, base: u64) -> Option<String> {
    let dos_data = memory.read(base, 0x40).ok()?;
    if dos_data.len() < 0x40 || &dos_data[0..2] != b"MZ" {
        return None;
    }
    let e_lfanew = u32::from_le_bytes(dos_data[0x3c..0x40].try_into().unwrap());
    let export_dir_offset = base
        .checked_add(e_lfanew as u64)?
        .checked_add(0x18 + 0x70)?;
    let export_rva_bytes = memory.read(export_dir_offset, 4).ok()?;
    let export_rva = u32::from_le_bytes(export_rva_bytes.try_into().unwrap());
    if export_rva == 0 {
        return None;
    }
    let name_rva_offset = base.checked_add(export_rva as u64)?.checked_add(0x0c)?;
    let name_rva_bytes = memory.read(name_rva_offset, 4).ok()?;
    let name_rva = u32::from_le_bytes(name_rva_bytes.try_into().unwrap());
    if name_rva == 0 {
        return None;
    }
    let name_bytes = memory.read(base.checked_add(name_rva as u64)?, 260).ok()?;
    let cstr: Vec<u8> = name_bytes.into_iter().take_while(|&b| b != 0).collect();
    String::from_utf8(cstr).ok()
}
