use std::fmt::{Debug, Display};
use winapi::ctypes::*;
use winapi::um::memoryapi::*;
use winapi::um::processthreadsapi::*;
use winapi::um::winnt::{ MEM_COMMIT, MEM_RELEASE, PAGE_EXECUTE_READWRITE };
use winapi::shared::ntstatus::{ STATUS_BUFFER_TOO_SMALL, STATUS_INFO_LENGTH_MISMATCH };
use winapi::shared::ntdef::*;
use ntapi::ntexapi::*;

#[derive(Debug, Clone, PartialEq)]
pub enum WinProcListError {
    CouldNotGetProcInfo(i32),
    BufferSizeTooSmall(usize, usize),
}
impl Display for WinProcListError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            WinProcListError::CouldNotGetProcInfo(status) => write!(f, "Could not get process information. Status: 0x{:X}", status),
            WinProcListError::BufferSizeTooSmall(alloc_size, req_size) => write!(f, "Buffer size too small. You need at least {} bytes, but only allocated {} bytes.", req_size, alloc_size),
        }
    }
}

#[derive(Debug)]
pub struct ProcInfo {
    pub image_name: String,
    pub unique_process_id: u32,
    pub handle_count: u32,
    pub session_id: u32,
    pub peak_virtual_size: usize,
    pub virtual_size: usize,
    pub peak_working_set_size: usize,
    pub quota_paged_pool_usage: usize,
    pub quota_non_paged_pool_usage: usize,
    pub pagefile_usage: usize,
    pub peak_pagefile_usage: usize,
    pub private_page_count: usize,
}

#[derive(Debug)]
pub struct WinProcList {
    pub proc_list: Vec<ProcInfo>,
}

struct BufferStruct {
    base_address: *mut c_void,
    alloc_size: usize,
}

pub fn get() -> Result<WinProcList, WinProcListError> {
    let buffer = get_system_processes_info()?;
    let list_vec = get_proc_list(buffer.base_address);
    vfree(buffer.base_address, buffer.alloc_size);
    Ok(WinProcList { proc_list: list_vec })
}

// 現在動作中のすべてのプロセス情報を取得
// SystemProcessInformation を buffer に取得
fn get_system_processes_info() -> Result<BufferStruct, WinProcListError> {
    let mut base_address = std::ptr::null_mut();

    // プロセス情報を取得
    // SystemProcessInformation : 各プロセスの情報（オプション定数）
    // base_address             : 格納先
    // buffer_size              : 格納先のサイズ
    // &mut buffer_size         : 実際に取得したサイズ
    let mut buffer_size: u32 = 1024;
    let mut status;
    loop {
        unsafe {
            base_address = valloc(buffer_size as usize);
            status = NtQuerySystemInformation(SystemProcessInformation, base_address, buffer_size as u32, &mut buffer_size as *mut u32);
        }
        if NT_ERROR(status) {
            if status == STATUS_INFO_LENGTH_MISMATCH || status == STATUS_BUFFER_TOO_SMALL {
                vfree(base_address, buffer_size as usize);
            }
            else {
                return Err(WinProcListError::CouldNotGetProcInfo(status));
            }
        }
        else {
            break;
        }
    }

    return Ok(BufferStruct {
        base_address: base_address,
        alloc_size: buffer_size as usize,
    });
}

fn get_proc_list(base_address: *mut c_void) -> Vec<ProcInfo> {
    let mut system_process_information = read_proc_info(base_address as isize);
    let mut next_address = base_address as isize;
    let mut proc_list: Vec<ProcInfo> = Vec::new();

    loop {
        next_address += system_process_information.NextEntryOffset as isize;
        system_process_information = read_proc_info(next_address);

        let proc_info: ProcInfo = ProcInfo {
            image_name: get_str_from_mem(system_process_information.ImageName.Buffer as *mut c_void, 0, system_process_information.ImageName.Length as usize),
            unique_process_id: system_process_information.UniqueProcessId as u32,
            handle_count: system_process_information.HandleCount,
            session_id: system_process_information.SessionId,
            peak_virtual_size: system_process_information.PeakVirtualSize,
            virtual_size: system_process_information.VirtualSize,
            peak_working_set_size: system_process_information.PeakWorkingSetSize,
            quota_paged_pool_usage: system_process_information.QuotaPagedPoolUsage,
            quota_non_paged_pool_usage: system_process_information.QuotaNonPagedPoolUsage,
            pagefile_usage: system_process_information.PagefileUsage,
            peak_pagefile_usage: system_process_information.PeakPagefileUsage,
            private_page_count: system_process_information.PrivatePageCount,
        };

        proc_list.push(proc_info);

        if system_process_information.NextEntryOffset == 0 {
            break;
        }
    }

    proc_list
}

// プロセス一つ分の情報を取得
fn read_proc_info(next_address: isize) -> SYSTEM_PROCESS_INFORMATION {
    unsafe {
        let mut system_process_info: SYSTEM_PROCESS_INFORMATION = std::mem::zeroed();

        // base_address の該当オフセット値から SYSTEM_PROCESS_INFORMATION 構造体の情報をプロセス1つ分取得
        ReadProcessMemory(
            GetCurrentProcess(), next_address as *const c_void, &mut system_process_info as *mut _ as *mut c_void, 
            std::mem::size_of::<SYSTEM_PROCESS_INFORMATION>() as usize, std::ptr::null_mut()
        );

        system_process_info
    }
}

fn get_str_from_mem(base_address: *mut c_void, offset: usize, size: usize) -> String {
    let mut vec: Vec<u16> = vec![0; size];
    unsafe {
        ReadProcessMemory(
            GetCurrentProcess(), (base_address as usize + offset) as *const c_void, vec.as_mut_ptr() as *mut c_void, 
            size, std::ptr::null_mut()
        );
    }

    String::from_utf16_lossy(&vec).trim_matches(char::from(0)).to_string()
}

fn valloc(buffer_size: usize) -> *mut c_void {
    unsafe {
        VirtualAlloc(std::ptr::null_mut(), buffer_size, MEM_COMMIT, PAGE_EXECUTE_READWRITE)
    }
}

fn vfree(addr: *mut c_void, buffer_size: usize) {
    if addr != std::ptr::null_mut() {
        unsafe {
            VirtualFree(addr, buffer_size, MEM_RELEASE);
        }
    }
}

pub fn get_proc_info_by_pid(pid: u32) -> Result<Option<ProcInfo>, WinProcListError> {
    let buffer = get_system_processes_info()?;
    let mut system_process_information = read_proc_info(buffer.base_address as isize);
    let mut next_address = buffer.base_address as isize;

    loop {
        next_address += system_process_information.NextEntryOffset as isize;
        system_process_information = read_proc_info(next_address);

        if system_process_information.UniqueProcessId as u32 != pid {
            if system_process_information.NextEntryOffset == 0 {
                break;
            }
            continue;
        }

        let proc_info: ProcInfo = ProcInfo {
            image_name: get_str_from_mem(system_process_information.ImageName.Buffer as *mut c_void, 0, system_process_information.ImageName.Length as usize),
            unique_process_id: system_process_information.UniqueProcessId as u32,
            handle_count: system_process_information.HandleCount,
            session_id: system_process_information.SessionId,
            peak_virtual_size: system_process_information.PeakVirtualSize,
            virtual_size: system_process_information.VirtualSize,
            peak_working_set_size: system_process_information.PeakWorkingSetSize,
            quota_paged_pool_usage: system_process_information.QuotaPagedPoolUsage,
            quota_non_paged_pool_usage: system_process_information.QuotaNonPagedPoolUsage,
            pagefile_usage: system_process_information.PagefileUsage,
            peak_pagefile_usage: system_process_information.PeakPagefileUsage,
            private_page_count: system_process_information.PrivatePageCount,
        };

        vfree(buffer.base_address, buffer.alloc_size);
        return Ok(Some(proc_info));
    }

    vfree(buffer.base_address, buffer.alloc_size);
    Ok(None)
}
