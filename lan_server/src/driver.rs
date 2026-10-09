use std::{mem, ptr};

use winapi::{
    ctypes::c_void,
    shared::minwindef::{DWORD, FALSE},
    um::{
        errhandlingapi::GetLastError,
        fileapi::{CreateFileW, OPEN_EXISTING},
        handleapi::{CloseHandle, INVALID_HANDLE_VALUE},
        ioapiset::DeviceIoControl,
        winnt::{FILE_SHARE_READ, FILE_SHARE_WRITE, GENERIC_READ, GENERIC_WRITE},
    },
};

const KSLD_IOCTL: DWORD = 0x222044;
const SUB_VERSION: u32 = 0;
const SUB_GET_CPU_REGISTERS: u32 = 2;
const SUB_MM_COPY: u32 = 12;
const DIR_PHYSICAL: u32 = 1;
const DIR_VIRTUAL: u32 = 2;
pub const KSLD_PROTOCOL_VERSION: u16 = 0x104;
const CURRENT_CPU: u32 = u32::MAX;
const CPU_REGISTERS_SIZE: usize = 0x1c0;

#[repr(C)]
#[derive(Clone, Copy)]
struct KslInput {
    sub_command: u32,
    reserved: u32,
    address: u64,
    size: u64,
    direction: u32,
    padding: u32,
}

const _: () = assert!(mem::size_of::<KslInput>() == 32);

#[repr(C)]
#[derive(Clone, Copy)]
struct KslRegistersInput {
    sub_command: u32,
    cpu: u32,
}

const _: () = assert!(mem::size_of::<KslRegistersInput>() == 8);

pub struct Ksld {
    handle: *mut c_void,
}

pub struct CpuState {
    pub cr3: u64,
    pub ram_size: u64,
}

impl Ksld {
    pub fn open() -> Result<Self, DWORD> {
        let name: Vec<u16> = "\\\\.\\KslD\0".encode_utf16().collect();
        let handle = unsafe {
            CreateFileW(
                name.as_ptr(),
                GENERIC_READ | GENERIC_WRITE,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                ptr::null_mut(),
                OPEN_EXISTING,
                0,
                ptr::null_mut(),
            )
        };

        if handle == INVALID_HANDLE_VALUE {
            Err(unsafe { GetLastError() })
        } else {
            Ok(Self { handle })
        }
    }

    pub fn get_version(&self) -> Result<u16, String> {
        let mut input = SUB_VERSION;
        let mut output = [0u8; mem::size_of::<u16>()];
        let mut bytes_returned: DWORD = 0;

        let ok = unsafe {
            DeviceIoControl(
                self.handle,
                KSLD_IOCTL,
                &mut input as *mut u32 as *mut c_void,
                mem::size_of::<u32>() as DWORD,
                output.as_mut_ptr() as *mut c_void,
                output.len() as DWORD,
                &mut bytes_returned,
                ptr::null_mut(),
            )
        };
        if ok == FALSE {
            return Err(format!(
                "KslD version query failed, GetLastError = {}",
                unsafe { GetLastError() }
            ));
        }
        if bytes_returned != output.len() as DWORD {
            return Err(format!(
                "KslD version query returned {bytes_returned} bytes; expected {}",
                output.len()
            ));
        }

        Ok(u16::from_le_bytes(output))
    }

    pub fn get_cpu_state(&self) -> Result<CpuState, String> {
        let input = KslRegistersInput {
            sub_command: SUB_GET_CPU_REGISTERS,
            cpu: CURRENT_CPU,
        };
        let mut output = vec![0u8; CPU_REGISTERS_SIZE];
        let mut bytes_returned: DWORD = 0;

        let ok = unsafe {
            DeviceIoControl(
                self.handle,
                KSLD_IOCTL,
                &input as *const KslRegistersInput as *mut c_void,
                mem::size_of::<KslRegistersInput>() as DWORD,
                output.as_mut_ptr() as *mut c_void,
                output.len() as DWORD,
                &mut bytes_returned,
                ptr::null_mut(),
            )
        };

        if ok == FALSE {
            return Err(format!(
                "CPU-register IOCTL failed, GetLastError = {}",
                unsafe { GetLastError() }
            ));
        }

        let returned = bytes_returned as usize;
        if !(16..=output.len()).contains(&returned) {
            return Err(format!(
                "CPU-register IOCTL returned invalid length {returned}; expected at most {}",
                output.len()
            ));
        }

        let mut cr3 = None;
        let mut ram_size = None;
        for record in output[..returned].chunks_exact(16) {
            let name_end = record[..8].iter().position(|&byte| byte == 0).unwrap_or(8);
            let value = u64::from_le_bytes(record[8..16].try_into().unwrap());
            if record[..name_end].eq_ignore_ascii_case(b"cr3") {
                cr3 = Some(value);
            } else if record[..name_end].eq_ignore_ascii_case(b"ramsize") {
                ram_size = Some(value);
            }
        }

        let cr3 = cr3.ok_or_else(|| {
            format!("driver returned {returned} register bytes, but no CR3 record was present")
        })?;
        let ram_size = ram_size.ok_or_else(|| {
            format!("driver returned {returned} register bytes, but no ramsize record was present")
        })?;
        if cr3 == 0 || ram_size == 0 || ram_size & 0xfff != 0 {
            return Err(format!(
                "driver returned invalid CPU state: CR3=0x{cr3:X}, ramsize=0x{ram_size:X}"
            ));
        }
        Ok(CpuState { cr3, ram_size })
    }

    pub fn phys_read(&self, address: u64, size: usize) -> Result<Vec<u8>, String> {
        self.mm_copy(address, size, DIR_PHYSICAL, "physical")
    }

    pub fn kernel_read(&self, address: u64, size: usize) -> Result<Vec<u8>, String> {
        self.mm_copy(address, size, DIR_VIRTUAL, "kernel virtual")
    }

    fn mm_copy(
        &self,
        address: u64,
        size: usize,
        direction: u32,
        kind: &str,
    ) -> Result<Vec<u8>, String> {
        let output = self.mm_copy_inner(address, size, direction, kind)?;
        if output.len() < size {
            return Err(format!(
                "short {kind} read at 0x{address:X}: requested {size}, received {}",
                output.len()
            ));
        }
        Ok(output)
    }

    fn mm_copy_inner(
        &self,
        address: u64,
        size: usize,
        direction: u32,
        kind: &str,
    ) -> Result<Vec<u8>, String> {
        let input = KslInput {
            sub_command: SUB_MM_COPY,
            reserved: 0,
            address,
            size: size as u64,
            direction,
            padding: 0,
        };

        let buffer_size = size
            .checked_add(256)
            .ok_or_else(|| "requested read size overflow".to_string())?
            .max(4096);
        if buffer_size > DWORD::MAX as usize {
            return Err("requested read is too large for DeviceIoControl".to_string());
        }

        let mut output = vec![0u8; buffer_size];
        let mut bytes_returned: DWORD = 0;
        let ok = unsafe {
            DeviceIoControl(
                self.handle,
                KSLD_IOCTL,
                &input as *const KslInput as *mut c_void,
                mem::size_of::<KslInput>() as DWORD,
                output.as_mut_ptr() as *mut c_void,
                output.len() as DWORD,
                &mut bytes_returned,
                ptr::null_mut(),
            )
        };

        if ok == FALSE {
            return Err(format!(
                "{kind}-read IOCTL failed at 0x{address:X}, GetLastError = {}",
                unsafe { GetLastError() }
            ));
        }
        if bytes_returned as usize > output.len() {
            return Err(format!(
                "{kind}-read IOCTL returned invalid length {bytes_returned}; buffer is {} bytes",
                output.len()
            ));
        }

        output.truncate(bytes_returned as usize);
        Ok(output)
    }
}

impl Drop for Ksld {
    fn drop(&mut self) {
        unsafe { CloseHandle(self.handle) };
    }
}
