use std::{mem, ptr};

use winapi::{
    ctypes::c_void,
    shared::minwindef::{DWORD, FALSE, HMODULE},
    um::{
        errhandlingapi::GetLastError,
        libloaderapi::{DONT_RESOLVE_DLL_REFERENCES, FreeLibrary, GetProcAddress, LoadLibraryExW},
        psapi::EnumDeviceDrivers,
        sysinfoapi::GetSystemDirectoryW,
        winnt::{
            IMAGE_DOS_HEADER, IMAGE_DOS_SIGNATURE, IMAGE_NT_HEADERS64,
            IMAGE_NT_OPTIONAL_HDR64_MAGIC, IMAGE_NT_SIGNATURE,
        },
    },
};

use crate::{
    driver::Ksld,
    memory::{PFN_MASK, VirtualMemory, checked_field, is_kernel_address},
    offsets::Offsets,
};

#[derive(Clone, Copy, Debug)]
pub struct KernelIdentity {
    pub base: u64,
    pub size: u64,
    pub ps_initial_system_process: u64,
    pub mm_get_virtual_for_physical: u64,
    pub system_eprocess: u64,
}

pub fn locate_system_process(driver: &Ksld, kernel_dtb: u64) -> Result<KernelIdentity, String> {
    let base = get_kernel_base_addr()?;
    let (ps_initial_system_process, size) =
        get_kernel_export_address(base, b"PsInitialSystemProcess\0")?;
    let (mm_get_virtual_for_physical, _) =
        get_kernel_export_address(base, b"MmGetVirtualForPhysical\0")?;
    let memory = VirtualMemory::new(driver, kernel_dtb)?;
    let system_eprocess = memory
        .read_u64(ps_initial_system_process)
        .or_else(|translation_error| {
            kernel_read_u64(driver, ps_initial_system_process).map_err(|virtual_error| {
                format!(
                    "PsInitialSystemProcess bootstrap failed through CPU CR3 ({translation_error}) and KslD kernel read ({virtual_error})"
                )
            })
        })?;

    if !crate::memory::is_kernel_address(system_eprocess) {
        return Err(format!(
            "PsInitialSystemProcess contained invalid pointer 0x{system_eprocess:X}"
        ));
    }

    Ok(KernelIdentity {
        base,
        size,
        ps_initial_system_process,
        mm_get_virtual_for_physical,
        system_eprocess,
    })
}

pub fn resolve_system_dtb(
    driver: &Ksld,
    bootstrap_dtb: u64,
    ram_size: u64,
    system_eprocess: u64,
    offsets: Offsets,
) -> Result<u64, String> {
    let directory_table_base = checked_field(
        system_eprocess,
        offsets.kprocess_directory_table_base,
        "System.KPROCESS.DirectoryTableBase",
    )?;
    let dtb = kernel_read_u64(driver, directory_table_base)
        .or_else(|_| VirtualMemory::new(driver, bootstrap_dtb)?.read_u64(directory_table_base))?
        & PFN_MASK;
    if dtb == 0 || dtb >= ram_size {
        return Err(format!(
            "System DirectoryTableBase is outside physical RAM: DTB=0x{dtb:X}, RAM=0x{ram_size:X}"
        ));
    }

    let memory = VirtualMemory::new(driver, dtb)?;
    let pid = memory.read_u64(checked_field(
        system_eprocess,
        offsets.eprocess_unique_process_id,
        "System.EPROCESS.UniqueProcessId",
    )?)?;
    let image = memory.read(
        checked_field(
            system_eprocess,
            offsets.eprocess_image_file_name,
            "System.EPROCESS.ImageFileName",
        )?,
        6,
    )?;
    if pid != 4 || !image.starts_with(b"System") {
        return Err(format!(
            "System DTB 0x{dtb:X} failed identity validation: PID=0x{pid:X}, image={image:02X?}"
        ));
    }
    Ok(dtb)
}

fn kernel_read_u64(driver: &Ksld, address: u64) -> Result<u64, String> {
    if !is_kernel_address(address) {
        return Err(format!("invalid kernel pointer 0x{address:X}"));
    }
    let bytes = driver.kernel_read(address, 8)?;
    Ok(u64::from_le_bytes(bytes[..8].try_into().unwrap()))
}

fn get_kernel_base_addr() -> Result<u64, String> {
    let mut drivers: [*mut c_void; 1024] = [ptr::null_mut(); 1024];
    let capacity = mem::size_of_val(&drivers);
    let mut bytes_needed: DWORD = 0;
    let ok =
        unsafe { EnumDeviceDrivers(drivers.as_mut_ptr(), capacity as DWORD, &mut bytes_needed) };
    if ok == FALSE {
        return Err(format!(
            "EnumDeviceDrivers failed, GetLastError = {}",
            unsafe { GetLastError() }
        ));
    }
    if bytes_needed == 0 || bytes_needed as usize > capacity {
        return Err(format!(
            "EnumDeviceDrivers returned invalid required size {bytes_needed}"
        ));
    }

    let kernel_base = drivers[0] as usize as u64;
    if kernel_base == 0 {
        return Err(
            "EnumDeviceDrivers returned a null kernel base; Windows 11 24H2/25H2 requires SeDebugPrivilege to be enabled"
                .to_string(),
        );
    }
    Ok(kernel_base)
}

fn get_system_directory() -> Result<Vec<u16>, String> {
    let mut path = vec![0u16; 32_768];
    let length = unsafe { GetSystemDirectoryW(path.as_mut_ptr(), path.len() as u32) } as usize;
    if length == 0 {
        return Err(format!(
            "GetSystemDirectoryW failed, GetLastError = {}",
            unsafe { GetLastError() }
        ));
    }
    if length >= path.len() {
        return Err("system-directory path exceeded buffer".to_string());
    }
    path.truncate(length);
    Ok(path)
}

fn get_kernel_export_address(kernel_base: u64, export_name: &[u8]) -> Result<(u64, u64), String> {
    if export_name.last() != Some(&0) {
        return Err("export name must be NUL-terminated".to_string());
    }

    let mut image_path = get_system_directory()?;
    image_path.extend("\\ntoskrnl.exe".encode_utf16());
    image_path.push(0);

    let image = unsafe {
        LoadLibraryExW(
            image_path.as_ptr(),
            ptr::null_mut(),
            DONT_RESOLVE_DLL_REFERENCES,
        )
    };
    if image.is_null() {
        return Err(format!(
            "LoadLibraryExW(ntoskrnl.exe) failed, GetLastError = {}",
            unsafe { GetLastError() }
        ));
    }

    let result = (|| {
        let image_size = get_local_image_size(image)?;
        let local_export = unsafe { GetProcAddress(image, export_name.as_ptr() as *const i8) };
        if local_export.is_null() {
            let name = String::from_utf8_lossy(&export_name[..export_name.len() - 1]);
            return Err(format!(
                "GetProcAddress({name}) failed, GetLastError = {}",
                unsafe { GetLastError() }
            ));
        }
        let rva = (local_export as usize as u64)
            .checked_sub(image as usize as u64)
            .ok_or_else(|| "kernel export address precedes local image base".to_string())?;
        let address = kernel_base
            .checked_add(rva)
            .ok_or_else(|| "rebased kernel export address overflow".to_string())?;
        Ok((address, image_size))
    })();

    unsafe { FreeLibrary(image) };
    result
}

fn get_local_image_size(image: HMODULE) -> Result<u64, String> {
    let dos = unsafe { &*(image as *const IMAGE_DOS_HEADER) };
    if dos.e_magic != IMAGE_DOS_SIGNATURE {
        return Err("local ntoskrnl image has invalid DOS signature".to_string());
    }

    let nt_offset = usize::try_from(dos.e_lfanew)
        .map_err(|_| "local ntoskrnl image has negative PE offset".to_string())?;
    let nt_address = (image as usize)
        .checked_add(nt_offset)
        .ok_or_else(|| "local ntoskrnl PE address overflow".to_string())?;
    let nt = unsafe { &*(nt_address as *const IMAGE_NT_HEADERS64) };
    if nt.Signature != IMAGE_NT_SIGNATURE
        || nt.OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC
    {
        return Err("local ntoskrnl image has invalid PE32+ headers".to_string());
    }

    let size = u64::from(nt.OptionalHeader.SizeOfImage);
    if size == 0 {
        return Err("local ntoskrnl image has zero SizeOfImage".to_string());
    }
    Ok(size)
}
