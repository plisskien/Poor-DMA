use std::collections::HashSet;

use crate::{
    driver::Ksld,
    memory::{PFN_MASK, VirtualMemory, is_kernel_address},
    offsets::Offsets,
};

const PAGE_SIZE: u64 = 0x1000;
const PFN_SCAN_CHUNK_BYTES: usize = 16 * 1024 * 1024;
const MMPFN_PAGE_LOCATION_ACTIVE: u8 = 6;
const MM_GET_VIRTUAL_FOR_PHYSICAL_SCAN_BYTES: usize = 0x80;
const MOV_R64_IMM64_SIZE: usize = 10;
const FOUR_GB: u64 = 0x1_0000_0000;
const FIRST_KERNEL_4GB_BASE: u64 = 0xffff_8000_0000_0000;
const LAST_KERNEL_4GB_BASE: u64 = 0xffff_ffff_0000_0000;
const PTE_QUALITY_THRESHOLD: usize = 32;

pub fn discover_dtb_candidates(
    driver: &Ksld,
    system_dtb: u64,
    ram_size: u64,
    mm_get_virtual_for_physical: u64,
    offsets: Offsets,
) -> Result<Vec<u64>, String> {
    let system_dtb = system_dtb & PFN_MASK;
    if system_dtb == 0 || ram_size == 0 {
        return Err(format!(
            "invalid PFN scan inputs: System DTB=0x{system_dtb:X}, RAM=0x{ram_size:X}"
        ));
    }

    let entry_size = usize::try_from(offsets.mmpfn_size)
        .map_err(|_| "_MMPFN size does not fit in usize".to_string())?;
    let pte_offset = usize::try_from(offsets.mmpfn_pte_address)
        .map_err(|_| "_MMPFN.PteAddress offset does not fit in usize".to_string())?;
    let location_offset = usize::try_from(offsets.mmpfn_page_location)
        .map_err(|_| "_MMPFN.PageLocation offset does not fit in usize".to_string())?;
    if entry_size == 0
        || pte_offset.checked_add(8).is_none_or(|end| end > entry_size)
        || location_offset >= entry_size
    {
        return Err("invalid _MMPFN offset profile".to_string());
    }

    let system_memory = VirtualMemory::new(driver, system_dtb)?;
    let mm_pfn_database = locate_mm_pfn_database(
        driver,
        &system_memory,
        system_dtb,
        mm_get_virtual_for_physical,
        offsets,
    )?;
    let system_pfn = system_dtb >> 12;
    let system_entry_va = mmpfn_address(system_pfn, mm_pfn_database, offsets)?;
    let system_entry = system_memory.read(system_entry_va, entry_size)?;
    let system_pte_address = read_u64(&system_entry, pte_offset)?;
    if system_pte_address == 0 {
        return Err(format!(
            "System _MMPFN entry at 0x{system_entry_va:X} has PteAddress = 0"
        ));
    }

    let scan_pfns = ram_size / PAGE_SIZE;
    let entries_per_chunk = PFN_SCAN_CHUNK_BYTES / entry_size;
    if entries_per_chunk == 0 {
        return Err("_MMPFN entry exceeds scan chunk".to_string());
    }

    println!(
        "[+] PFN DTB recovery: MmPfnDatabase=0x{:X}, System.PteAddress=0x{system_pte_address:X}",
        mm_pfn_database
    );
    println!(
        "[+] scanning up to {scan_pfns} _MMPFN entries using System-DTB translation and KslD physical reads"
    );

    let mut candidate_set = HashSet::new();
    let mut candidates = Vec::new();
    let mut start_pfn = 0u64;
    let mut next_progress = 10u64;

    while start_pfn < scan_pfns {
        let remaining = scan_pfns - start_pfn;
        let count = remaining.min(entries_per_chunk as u64);
        let request_size = usize::try_from(count)
            .ok()
            .and_then(|count| count.checked_mul(entry_size))
            .ok_or_else(|| "PFN scan chunk size overflow".to_string())?;
        let address = mmpfn_address(start_pfn, mm_pfn_database, offsets)?;

        let data = system_memory.read_zero_padded(address, request_size)?;

        let complete_entries = data.len() / entry_size;
        for index in 0..complete_entries {
            let entry = &data[index * entry_size..(index + 1) * entry_size];
            let pte_address = read_u64(entry, pte_offset)?;
            let page_location = entry[location_offset] & 0x7;
            if pte_address != system_pte_address || page_location != MMPFN_PAGE_LOCATION_ACTIVE {
                continue;
            }

            let pfn = start_pfn + index as u64;
            let dtb = pfn
                .checked_mul(PAGE_SIZE)
                .ok_or_else(|| "candidate DTB overflow".to_string())?;
            if candidate_set.insert(dtb)
                && let Ok(true) = validate_pml4(driver, dtb, ram_size.saturating_sub(1))
            {
                candidates.push(dtb);
            }
        }

        start_pfn = start_pfn
            .checked_add(complete_entries as u64)
            .ok_or_else(|| "PFN scan index overflow".to_string())?;
        let progress = start_pfn.saturating_mul(100) / scan_pfns;
        if progress >= next_progress {
            println!("[+] PFN scan {progress}%");
            next_progress = (progress / 10 + 1) * 10;
        }
    }

    println!(
        "[+] PFN scan produced {} DTB candidate(s)",
        candidates.len()
    );
    Ok(candidates)
}

fn locate_mm_pfn_database(
    driver: &Ksld,
    system_memory: &VirtualMemory<'_>,
    system_dtb: u64,
    mm_get_virtual_for_physical: u64,
    offsets: Offsets,
) -> Result<u64, String> {
    if !is_kernel_address(mm_get_virtual_for_physical) {
        return Err(format!(
            "invalid MmGetVirtualForPhysical VA 0x{mm_get_virtual_for_physical:X}"
        ));
    }

    let code = driver
        .kernel_read(
            mm_get_virtual_for_physical,
            MM_GET_VIRTUAL_FOR_PHYSICAL_SCAN_BYTES,
        )
        .or_else(|_| {
            system_memory.read(
                mm_get_virtual_for_physical,
                MM_GET_VIRTUAL_FOR_PHYSICAL_SCAN_BYTES,
            )
        })?;
    let mut checked = HashSet::new();

    for instruction in code.windows(MOV_R64_IMM64_SIZE) {
        let rex = instruction[0];
        let opcode = instruction[1];
        if !matches!(rex, 0x48 | 0x49) || !(0xb8..=0xbf).contains(&opcode) {
            continue;
        }

        let immediate = u64::from_le_bytes(instruction[2..10].try_into().unwrap());
        let Some(candidate) = immediate.checked_sub(offsets.mmpfn_pte_address) else {
            continue;
        };
        if !is_kernel_address(candidate)
            || candidate & 0xffff_ffff != 0
            || !checked.insert(candidate)
        {
            continue;
        }

        match verify_mm_pfn_database_candidate(system_memory, system_dtb, candidate, offsets) {
            Ok(pte_address) => {
                println!(
                    "[+] runtime MmPfnDatabase = 0x{candidate:X}; System.PteAddress = 0x{pte_address:X}"
                );
                return Ok(candidate);
            }
            Err(error) => {
                println!("[+] MmGetVirtualForPhysical candidate 0x{candidate:X} rejected: {error}");
            }
        }
    }

    println!("[+] searching mapped x64 kernel regions at 4 GiB boundaries for MmPfnDatabase");
    let mut candidate = FIRST_KERNEL_4GB_BASE;
    let mut candidate_count = 0u64;
    loop {
        candidate_count += 1;
        if checked.insert(candidate)
            && let Ok(pte_address) =
                verify_mm_pfn_database_candidate(system_memory, system_dtb, candidate, offsets)
        {
            println!(
                "[+] runtime MmPfnDatabase = 0x{candidate:X}; System.PteAddress = 0x{pte_address:X}"
            );
            return Ok(candidate);
        }

        if candidate == LAST_KERNEL_4GB_BASE {
            break;
        }
        candidate = candidate
            .checked_add(FOUR_GB)
            .ok_or_else(|| "MmPfnDatabase candidate range overflow".to_string())?;
    }

    Err(format!(
        "could not locate MmPfnDatabase: rejected MmGetVirtualForPhysical hints and {candidate_count} kernel 4-GiB candidates"
    ))
}

fn verify_mm_pfn_database_candidate(
    system_memory: &VirtualMemory<'_>,
    system_dtb: u64,
    candidate: u64,
    offsets: Offsets,
) -> Result<u64, String> {
    let system_pfn = system_dtb >> 12;
    let entry_va = mmpfn_address(system_pfn, candidate, offsets)?;
    let entry = system_memory
        .read(entry_va, offsets.mmpfn_size as usize)
        .map_err(|error| format!("System _MMPFN read at 0x{entry_va:X} failed: {error}"))?;
    let pte_address = read_u64(&entry, offsets.mmpfn_pte_address as usize)?;
    if !is_kernel_address(pte_address) || pte_address & 7 != 0 {
        return Err(format!("invalid System.PteAddress 0x{pte_address:X}"));
    }

    let pte_page = pte_address & !0xfff;
    let pa = system_memory
        .translate(pte_page)
        .map_err(|error| format!("System.PteAddress translation failed: {error}"))?;
    if pa & PFN_MASK != system_dtb {
        return Err(format!(
            "System.PteAddress translated to 0x{:X}, expected System DTB 0x{system_dtb:X}",
            pa & PFN_MASK
        ));
    }
    Ok(pte_address)
}

fn mmpfn_address(pfn: u64, mm_pfn_database: u64, offsets: Offsets) -> Result<u64, String> {
    let byte_offset = pfn
        .checked_mul(offsets.mmpfn_size)
        .ok_or_else(|| "_MMPFN index multiplication overflow".to_string())?;
    mm_pfn_database
        .checked_add(byte_offset)
        .ok_or_else(|| "_MMPFN virtual address overflow".to_string())
}

fn read_u64(data: &[u8], offset: usize) -> Result<u64, String> {
    let end = offset
        .checked_add(8)
        .ok_or_else(|| "u64 field offset overflow".to_string())?;
    let bytes = data
        .get(offset..end)
        .ok_or_else(|| "short _MMPFN field read".to_string())?;
    Ok(u64::from_le_bytes(bytes.try_into().unwrap()))
}

fn validate_pml4(driver: &Ksld, dtb: u64, pa_max: u64) -> Result<bool, String> {
    let page = driver.phys_read(dtb, PAGE_SIZE as usize)?;
    let pa_max = pa_max.max(u32::MAX as u64);
    let mut bad_entries = 0usize;
    let mut has_self_reference = false;

    for bytes in page.chunks_exact(8) {
        let entry = u64::from_le_bytes(bytes.try_into().unwrap());
        if entry & 1 != 0
            && entry & 0x0000_ffff_ffff_ffff > pa_max
            && entry & 0x80ff_ff00_0000_000f != 0x8000_0000_0000_000f
        {
            bad_entries += 1;
            if bad_entries > PTE_QUALITY_THRESHOLD {
                return Ok(false);
            }
        }
        if entry & PFN_MASK == dtb {
            has_self_reference = true;
        }
    }

    Ok(has_self_reference)
}
