use std::{mem, ptr};

use winapi::{
    ctypes::c_void,
    shared::{
        minwindef::FALSE,
        winerror::{ERROR_NOT_ALL_ASSIGNED, ERROR_SUCCESS},
    },
    um::{
        errhandlingapi::{GetLastError, SetLastError},
        handleapi::CloseHandle,
        processthreadsapi::{GetCurrentProcess, OpenProcessToken},
        securitybaseapi::{AdjustTokenPrivileges, GetTokenInformation},
        winbase::LookupPrivilegeValueW,
        winnt::{
            HANDLE, LUID, LUID_AND_ATTRIBUTES, SE_PRIVILEGE_ENABLED, TOKEN_ADJUST_PRIVILEGES,
            TOKEN_ELEVATION, TOKEN_PRIVILEGES, TOKEN_QUERY, TokenElevation,
        },
    },
};

struct OwnedHandle(HANDLE);

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        unsafe { CloseHandle(self.0) };
    }
}

fn open_current_process_token(access: u32) -> Result<OwnedHandle, String> {
    let mut raw_token = ptr::null_mut();
    let opened = unsafe { OpenProcessToken(GetCurrentProcess(), access, &mut raw_token) };
    if opened == FALSE {
        return Err(format!(
            "OpenProcessToken failed, GetLastError = {}",
            unsafe { GetLastError() }
        ));
    }
    Ok(OwnedHandle(raw_token))
}

pub fn require_administrator() -> Result<(), String> {
    let token = open_current_process_token(TOKEN_QUERY)?;
    let mut elevation: TOKEN_ELEVATION = unsafe { mem::zeroed() };
    let mut returned = 0u32;
    let queried = unsafe {
        GetTokenInformation(
            token.0,
            TokenElevation,
            (&mut elevation as *mut TOKEN_ELEVATION).cast::<c_void>(),
            mem::size_of::<TOKEN_ELEVATION>() as u32,
            &mut returned,
        )
    };
    if queried == FALSE {
        return Err(format!(
            "GetTokenInformation(TokenElevation) failed, GetLastError = {}",
            unsafe { GetLastError() }
        ));
    }
    if returned < mem::size_of::<TOKEN_ELEVATION>() as u32 {
        return Err(format!(
            "GetTokenInformation(TokenElevation) returned only {returned} byte(s)"
        ));
    }
    if elevation.TokenIsElevated == 0 {
        return Err(
            "administrator elevation required; restart this program with Run as administrator"
                .to_string(),
        );
    }
    Ok(())
}

pub fn enable_debug_privilege() -> Result<(), String> {
    let token = open_current_process_token(TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY)?;

    let name: Vec<u16> = "SeDebugPrivilege\0".encode_utf16().collect();
    let mut luid: LUID = unsafe { mem::zeroed() };
    if unsafe { LookupPrivilegeValueW(ptr::null(), name.as_ptr(), &mut luid) } == FALSE {
        return Err(format!(
            "LookupPrivilegeValueW(SeDebugPrivilege) failed, GetLastError = {}",
            unsafe { GetLastError() }
        ));
    }

    let mut privileges = TOKEN_PRIVILEGES {
        PrivilegeCount: 1,
        Privileges: [LUID_AND_ATTRIBUTES {
            Luid: luid,
            Attributes: SE_PRIVILEGE_ENABLED,
        }],
    };
    unsafe { SetLastError(ERROR_SUCCESS) };
    let adjusted = unsafe {
        AdjustTokenPrivileges(
            token.0,
            FALSE,
            &mut privileges,
            0,
            ptr::null_mut(),
            ptr::null_mut(),
        )
    };
    if adjusted == FALSE {
        return Err(format!(
            "AdjustTokenPrivileges failed, GetLastError = {}",
            unsafe { GetLastError() }
        ));
    }

    let status = unsafe { GetLastError() };
    if status == ERROR_NOT_ALL_ASSIGNED {
        return Err(
            "SeDebugPrivilege is not present in this token; run from an elevated administrator session"
                .to_string(),
        );
    }
    if status != ERROR_SUCCESS {
        return Err(format!(
            "AdjustTokenPrivileges reported GetLastError = {status}"
        ));
    }
    Ok(())
}
