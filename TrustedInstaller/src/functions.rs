use std::env;
use std::ffi::{CStr, OsString};
use std::fs::File;
use std::io::Error;
use std::io::ErrorKind;
use std::mem::size_of;
use std::mem;
use std::os::windows::ffi::OsStrExt;
use std::ptr::null_mut;
use widestring::U16CString;
use winapi::shared::minwindef::{DWORD, FALSE};
use winapi::shared::ntdef::NULL;
use winapi::um::errhandlingapi::GetLastError;
use winapi::um::handleapi::{CloseHandle, INVALID_HANDLE_VALUE};
use winapi::um::processthreadsapi::{OpenProcess, GetCurrentProcess, OpenProcessToken};
use winapi::um::securitybaseapi::AdjustTokenPrivileges;
use winapi::um::shellapi::ShellExecuteW;
use winapi::um::tlhelp32::{CreateToolhelp32Snapshot, Process32First, Process32Next, TH32CS_SNAPPROCESS, PROCESSENTRY32};
use winapi::um::winbase::{FormatMessageW, LookupPrivilegeValueW, FORMAT_MESSAGE_FROM_SYSTEM, FORMAT_MESSAGE_IGNORE_INSERTS};
use winapi::um::winnt::{
    PROCESS_QUERY_INFORMATION, 
    PROCESS_CREATE_PROCESS, 
    PROCESS_DUP_HANDLE, 
    PROCESS_SET_INFORMATION,
    TOKEN_ADJUST_PRIVILEGES, 
    SE_PRIVILEGE_ENABLED, 
    TOKEN_PRIVILEGES};
use winapi::um::winnt::{HANDLE, LPCWSTR};
use winapi::um::winsvc::{
    OpenSCManagerW, 
    QueryServiceStatus, 
    StartServiceW, 
    OpenServiceW,
    SERVICE_QUERY_STATUS, 
    SERVICE_RUNNING, 
    SERVICE_START, 
    SERVICE_STOP, 
    SERVICE_USER_DEFINED_CONTROL,
    SC_MANAGER_CONNECT};
use winapi::um::winsvc::SC_HANDLE;
use winapi::um::winuser::SW_NORMAL;
use winapi::shared::winerror::ERROR_NO_MORE_FILES;

const TI_SERVICE_NAME: &str = "TrustedInstaller";
const TI_EXECUTABLE_NAME: &str = "trustedinstaller.exe";


pub fn enable_se_debug_privilege() -> Result<(), String> {
    let mut token_handle: HANDLE = null_mut();
    unsafe {
        if OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &mut token_handle) == 0 {
            return Err(format!("[-] OpenProcessToken failed: {}", GetLastError()));
        }
    }

    unsafe {
        // Lookup the LUID for "SeDebugPrivilege".
        use std::ptr;
        let mut luid = mem::zeroed();
        let mut tp: TOKEN_PRIVILEGES = mem::zeroed();
        let privilege_name = widestring::U16CString::from_str("SeDebugPrivilege").unwrap();
        if LookupPrivilegeValueW(ptr::null(), privilege_name.as_ptr(), &mut luid) == 0 {
            return Err(format!("[-] Failed to lookup privilege value. Error: {}", GetLastError()));
        }

        // Adjust the token privileges to enable SeDebugPrivilege
        tp.PrivilegeCount = 1;
        tp.Privileges[0].Luid = luid;
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

        if AdjustTokenPrivileges(token_handle, FALSE, &mut tp, mem::size_of::<TOKEN_PRIVILEGES>() as DWORD, null_mut(), null_mut()) == 0 {
            return Err(format!("AdjustTokenPrivileges failed: {}", GetLastError()));
        }
    }

    Ok(())
}


fn open_sc_manager(desired_access: DWORD) -> Result<SC_HANDLE, DWORD> {
    let sc_manager_handle = unsafe { OpenSCManagerW(null_mut(), null_mut(), desired_access) };
    if sc_manager_handle.is_null() {
        Err(unsafe { GetLastError() })
    } else {
        Ok(sc_manager_handle)
    }
}


pub fn open_service(sc_manager_handle: SC_HANDLE, service_name: &str) -> Result<SC_HANDLE, DWORD> {
    let service_name_wstr = U16CString::from_str(service_name).unwrap();
    let service_handle = unsafe {
        OpenServiceW(
            sc_manager_handle,
            service_name_wstr.as_ptr(),
            SERVICE_QUERY_STATUS | SERVICE_START | SERVICE_STOP | SERVICE_USER_DEFINED_CONTROL,
        )
    };
    if service_handle.is_null() {
        Err(unsafe { GetLastError() })
    } else {
        Ok(service_handle)
    }
}


fn query_service_status(service_handle: SC_HANDLE) -> Result<DWORD, DWORD> {
    let mut service_status = unsafe { std::mem::zeroed() };
    let result = unsafe { QueryServiceStatus(service_handle, &mut service_status) };
    if result == 0 {
        Err(unsafe { GetLastError() })
    } else {
        Ok(service_status.dwCurrentState)
    }
}


fn start_service(service_handle: SC_HANDLE) -> Result<(), DWORD> {
    let result = unsafe { StartServiceW(service_handle, 0, null_mut()) };
    if result == 0 {
        Err(unsafe { GetLastError() })
    } else {
        Ok(())
    }
}


pub fn check_trusted_installer_running() -> Result<bool, ErrorKind> {
    let sc_manager_handle = open_sc_manager(SC_MANAGER_CONNECT).unwrap();
    let service_handle: SC_HANDLE = open_service(sc_manager_handle, TI_SERVICE_NAME).unwrap();
    
    // Query service status
    let status = query_service_status(service_handle).unwrap();
    if status != SERVICE_RUNNING {
        // Start the service
        match start_service(service_handle) {
            Ok(_) => println!("[+] Service 'TrustedInstaller' started successfully."),
            Err(error) => {
                println!("[-] Failed to start service '{}'. Error: {}", TI_SERVICE_NAME, error);
                std::process::exit(0);
            }
        }
    }
    else {
        println!("[+] Service 'TrustedInstaller' is already running");
    }

    Ok(true)
}


pub fn get_trusted_installer_pid() -> Result<DWORD, String> {
    unsafe {
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if snapshot == INVALID_HANDLE_VALUE {
            return Err(format!("[-] Failed to create snapshot (CreateToolhelp32Snapshot). Error: {}", GetLastError()));
        }

        // Initialize the PROCESSENTRY32 structure
        let mut process_entry: PROCESSENTRY32 = std::mem::zeroed();
        process_entry.dwSize = size_of::<PROCESSENTRY32>() as DWORD;

        if Process32First(snapshot, &mut process_entry) == 0 {
            CloseHandle(snapshot);
            return Err(format!("[-] Failed to iterate over processes (Process32First). Error: {}", GetLastError()));
        }

        // Iterate over all processes
        loop {
            let process_name_cstr = CStr::from_ptr(process_entry.szExeFile.as_ptr());
            if process_name_cstr.to_str().unwrap().eq_ignore_ascii_case(TI_EXECUTABLE_NAME) {
                CloseHandle(snapshot);
                return Ok(process_entry.th32ProcessID);
            }

            if Process32Next(snapshot, &mut process_entry) == FALSE {
                if Error::last_os_error().raw_os_error().unwrap() == ERROR_NO_MORE_FILES as i32 {
                    break;
                }
                CloseHandle(snapshot);
                return Err(format!("[-] Cannot find {} in running process list. Error: {}", TI_EXECUTABLE_NAME, GetLastError()));
            }
        }
        
        CloseHandle(snapshot);
        return Err(format!("[-] Cannot find {} in running process list. Error: {}", TI_EXECUTABLE_NAME, GetLastError()));
    }
}


pub fn check_if_admin() -> bool {
    match File::open("\\\\.\\PHYSICALDRIVE0") {
        Ok(file) => {
            drop(file); // Close the file
            true
        },
        Err(err) => match err.kind() {
            ErrorKind::PermissionDenied => false,
            _ => false,
        },
    }
}



pub fn elevate() -> Result<(), Box<dyn std::error::Error>> {
    let verb = OsString::from("runas");
    let exe = env::current_exe()?;
    let cwd = env::current_dir()?;
    let args: OsString = env::args().skip(1).collect::<Vec<_>>().join(" ").into();

    let verb_wide: Vec<u16> = verb.encode_wide().chain(Some(0)).collect();
    let exe_wide: Vec<u16> = exe.clone().into_os_string().encode_wide().chain(Some(0)).collect();
    let cwd_wide: Vec<u16> = cwd.clone().into_os_string().encode_wide().chain(Some(0)).collect();
    let args_wide: Vec<u16> = args.encode_wide().chain(Some(0)).collect();
    
    // Check if null terminator is correctly added
    let verb_ptr: LPCWSTR = verb_wide.as_ptr();
    let exe_ptr: LPCWSTR = exe_wide.as_ptr();
    let cwd_ptr: LPCWSTR = cwd_wide.as_ptr();
    let args_ptr: LPCWSTR = args_wide.as_ptr();
    let show_cmd: i32 = SW_NORMAL as i32;

    let result = unsafe {
        ShellExecuteW(
            NULL as *mut _,
            verb_ptr,
            exe_ptr,
            args_ptr,
            cwd_ptr,
            show_cmd,
        )
    };

    if result as isize <= 32 {
        let mut buffer: [u16; 256] = [0; 256];
        unsafe {
            FormatMessageW(
                FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
                null_mut(),
                result as u32,
                0,
                buffer.as_mut_ptr(),
                buffer.len() as u32,
                null_mut(),
            );
        }
        Err(Box::new(std::io::Error::last_os_error()))
    } else {
        std::process::exit(0);
    }
}


pub fn open_process(pid: u32) -> Result<HANDLE, DWORD> {
    unsafe {
        let handle = OpenProcess(
            PROCESS_QUERY_INFORMATION | PROCESS_CREATE_PROCESS | PROCESS_DUP_HANDLE | PROCESS_SET_INFORMATION,
            1,
            pid,
        );
        if handle.is_null() {
            eprintln!("[-] Failed to open process.");
            Err(GetLastError())
        } else {
            Ok(handle)
        }
    }
}