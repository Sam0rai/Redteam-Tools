use std::ffi::OsStr;
use std::iter::once;
use std::mem::{size_of, zeroed};
use std::os::windows::ffi::OsStrExt;
use std::ptr::null_mut;
use winapi::ctypes::c_void;
use winapi::shared::minwindef::LPVOID;
use winapi::um::errhandlingapi::GetLastError;
use winapi::um::handleapi::{CloseHandle, INVALID_HANDLE_VALUE};
use winapi::um::processthreadsapi::{
    CreateProcessW, 
    DeleteProcThreadAttributeList, 
    InitializeProcThreadAttributeList,
    UpdateProcThreadAttribute,
    PROCESS_INFORMATION,
    PROC_THREAD_ATTRIBUTE_LIST};
use winapi::um::winbase::{STARTUPINFOEXW, EXTENDED_STARTUPINFO_PRESENT, CREATE_NEW_CONSOLE};
use winapi::um::winnt::HANDLE;


mod functions;

const PROC_THREAD_ATTRIBUTE_PARENT_PROCESS: usize = 0x00020000;

fn run_as_trusted_installer(path: &str, args: &[&str]) -> Result<(), String> {
    // Check if the tool is running under the security context of an admin.
    // If not - try to elevate it to admin by opening a new process with admin rights (will trigger a UAC prompt). 
    if !functions::check_if_admin() {
        println!("[+] Not running as admin. Will try to elevate privileges.");
        let elevate_result = functions::elevate();
        match elevate_result{
            Ok(()) => {
                println!("[+] Running as admin");
            }
            Err(e) => {
                return Err(format!("[-] Cannot elevate Privileges to admin: {}", e));
            }
        }
    }

    // Under admin security context, we have the 'SeDebugPrivilege' privilege, but by default- it's disabled.
    // Therefore, we need to enable it.
    functions::enable_se_debug_privilege().map_err(|e| format!("[-] Cannot enable 'SeDebugPrivilege': {}", e))?;
    println!("[+] Enabled 'SeDebugPrivilege'.");

    // Check if the TrustedInstaller service is running. If it isn't- try to start it.
    functions::check_trusted_installer_running().map_err(|e| format!("[-] TrustedInstaller service is not running: {}", e))?;
    
    // Get the pid of the "TrustedInstaller" process.
    let ti_pid_result = functions::get_trusted_installer_pid();

    match ti_pid_result {
        Ok(trusted_installer_pid) => println!("[+] Found TrustedInstaller.exe pid: {}", trusted_installer_pid),
        Err(_e) => {
            return Err(format!("Error getting TrustedInstaller.exe pid: {}", unsafe { GetLastError() }));
        }
    }

    // Open the TrustedInstaller process to acquire its handle (with sufficient privileges).
    let handle = functions::open_process(ti_pid_result.unwrap());
    if handle.unwrap() as *mut c_void == INVALID_HANDLE_VALUE {
        return Err(format!("[-] Invalid handle after open process attempt. Error: {}", unsafe { GetLastError() }));
    }
    
    // First call to get the correct size
    let mut attr_list_size: usize = 0;
    unsafe {
        InitializeProcThreadAttributeList(null_mut(), 1, 0, &mut attr_list_size);
    }
    
    // Allocate the attribute list with the correct size
    let mut attr_list: Vec<u8> = vec![0; attr_list_size];
    let attr_list_ptr = attr_list.as_mut_ptr() as *mut PROC_THREAD_ATTRIBUTE_LIST;

    // Set up the STARTUPINFOEX structure
    let mut startup_info_ex: STARTUPINFOEXW = unsafe { std::mem::MaybeUninit::zeroed().assume_init() }; //unsafe { std::mem::zeroed() };
    startup_info_ex.StartupInfo.cb = std::mem::size_of::<STARTUPINFOEXW>() as u32;
    startup_info_ex.lpAttributeList = attr_list_ptr;

    // Initialize and update the attribute list
    unsafe {
        if InitializeProcThreadAttributeList(attr_list_ptr, 1, 0, &mut attr_list_size) == 0 {
            return Err(format!("[-] Failed to initialize process attribute list: {}", std::io::Error::last_os_error()));
        }
        if UpdateProcThreadAttribute(
            startup_info_ex.lpAttributeList,
            0,
            PROC_THREAD_ATTRIBUTE_PARENT_PROCESS,
            &handle.unwrap() as *const _ as LPVOID,
            std::mem::size_of::<HANDLE>(),
            null_mut(),
            null_mut(),
        ) == 0 {
            DeleteProcThreadAttributeList(attr_list_ptr);
            return Err(format!("[-] Failed to update process attribute list: {}", std::io::Error::last_os_error()));
        }
    }

    let mut pi: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };
    let command = OsStr::new(path)
        .encode_wide()
        .chain(once(0))
        .collect::<Vec<u16>>();

    let mut args_wide = args.iter()
        .flat_map(|arg| OsStr::new(arg).encode_wide().chain(once(0)))
        .collect::<Vec<u16>>();
    
     // Open the new process
     unsafe {
        // Setup STARTUPINFOEX structure for extended startup information
        let mut startup_info: STARTUPINFOEXW = zeroed();
        startup_info.StartupInfo.cb = size_of::<STARTUPINFOEXW>() as u32;
        
        // Create an attribute list for setting the parent process
        let mut attribute_list_size: usize = 0;
        InitializeProcThreadAttributeList(null_mut(), 1, 0, &mut attribute_list_size as *mut _);
        let mut attribute_list = vec![0u8; attribute_list_size];
        if InitializeProcThreadAttributeList(attribute_list.as_mut_ptr() as *mut _, 1, 0, &mut attribute_list_size as *mut _) == 0 {
            return Err(format!("[-] Failed to initialize thread attribute list. Error: {}", GetLastError()));
        }

        // Set the parent process attribute (TrustedInstaller handle)
        if UpdateProcThreadAttribute(
            attribute_list.as_mut_ptr() as *mut _, 
            0, 
            PROC_THREAD_ATTRIBUTE_PARENT_PROCESS,
            &handle.unwrap() as *const _ as *mut _,
            size_of::<HANDLE>(),
            null_mut(),
            null_mut()
        ) == 0 {
            return Err(format!("Failed to update thread attribute. Error: {}", GetLastError()));
        }

        // Attach the attribute list to the STARTUPINFOEXW structure
        startup_info.lpAttributeList = attribute_list.as_mut_ptr() as *mut _;

        let success = CreateProcessW(
                command.as_ptr(),
                args_wide.as_mut_ptr(),
                null_mut(),
                null_mut(),
                false as i32,
                EXTENDED_STARTUPINFO_PRESENT | CREATE_NEW_CONSOLE,
                null_mut(),
                null_mut(),
                &mut startup_info_ex.StartupInfo,
                &mut pi,
            );

        // Check if process creation succeeded
        if success == 0 {
            return Err(format!("[-] Failed to create new process: {}", GetLastError()));
        }

        CloseHandle(handle.unwrap());
    }

    Ok(())
}

fn main() {
    if let Err(e) = run_as_trusted_installer("c:\\Windows\\System32\\cmd.exe", &["/k", "start", "cmd.exe"]) {
        panic!("Panic Error: {}", e);
    }
}