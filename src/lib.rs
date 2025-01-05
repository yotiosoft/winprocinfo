use std::fmt::{Debug, Display};
use winapi::ctypes::*;
use winapi::um::memoryapi::*;
use winapi::um::processthreadsapi::*;
use winapi::um::winnt::{ MEM_COMMIT, MEM_RELEASE, PAGE_EXECUTE_READWRITE };
use winapi::shared::ntdef::*;
use ntapi::ntexapi::*;

#[derive(Debug, Clone, PartialEq)]
pub enum WinProcListError {
    CouldNotGetProcInfo,
    BufferSizeTooSmall(usize, usize),
}
impl Display for WinProcListError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            WinProcListError::CouldNotGetProcInfo => write!(f, "Could not get process information."),
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
    base_address: *mut c_void,
    pub proc_list: Vec<ProcInfo>,
    pub alloc_size: usize,
}

impl WinProcList {
    pub fn new() -> WinProcList {
        WinProcList {
            base_address: std::ptr::null_mut(),
            proc_list: Vec::new(),
            alloc_size: 0,
        }
    }

    pub fn get(&mut self, buffer_size: usize) -> Result<(), WinProcListError> {
        // if self.proc_list is set already, free the memory
        if self.base_address != std::ptr::null_mut() {
            self.free_mem(self.base_address, self.alloc_size);
            self.base_address = std::ptr::null_mut();
            self.proc_list.clear();
            self.alloc_size = 0;
        }

        let addr = self.get_system_processes_info(buffer_size)?;
        self.alloc_size = buffer_size;

        if addr == std::ptr::null_mut() {
            return Err(WinProcListError::CouldNotGetProcInfo);
        }
        else {
            self.base_address = addr;
            self.proc_list = self.get_proc_list();

            return Ok(());
        }
    }

    // 現在動作中のすべてのプロセス情報を取得
    // SystemProcessInformation を buffer に取得
    fn get_system_processes_info(&self, mut buffer_size: usize) -> Result<*mut c_void, WinProcListError> {
        let before_buffer_size = buffer_size;
        let base_address;
        unsafe {
            base_address = VirtualAlloc(std::ptr::null_mut(), buffer_size, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
        }

        // プロセス情報を取得
        // SystemProcessInformation : 各プロセスの情報（オプション定数）
        // base_address             : 格納先
        // buffer_size              : 格納先のサイズ
        // &mut buffer_size         : 実際に取得したサイズ
        let mut buffer_size_u32 = buffer_size as u32;
        let status;
        unsafe {
            status = NtQuerySystemInformation(SystemProcessInformation, base_address, buffer_size_u32, &mut buffer_size_u32);
        }
        if buffer_size_u32 != buffer_size as u32 {
            buffer_size = buffer_size_u32 as usize;
        }
        if NT_ERROR(status) {
            self.free_mem(base_address, before_buffer_size);
            if before_buffer_size < buffer_size {
                return Err(WinProcListError::BufferSizeTooSmall(before_buffer_size, buffer_size));
            }
            return Err(WinProcListError::CouldNotGetProcInfo);
        }

        return Ok(base_address);
    }

    fn get_proc_list(&self) -> Vec<ProcInfo> {
        let mut system_process_information = self.get_proc_info(self.base_address as isize);
        let mut next_address = self.base_address as isize;
        let mut proc_list: Vec<ProcInfo> = Vec::new();

        loop {
            next_address += system_process_information.NextEntryOffset as isize;
            system_process_information = self.get_proc_info(next_address);

            let proc_info: ProcInfo = ProcInfo {
                image_name: self.get_str_from_mem(system_process_information.ImageName.Buffer as *mut c_void, 0, system_process_information.ImageName.Length as usize),
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
    fn get_proc_info(&self, next_address: isize) -> SYSTEM_PROCESS_INFORMATION {
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

    fn get_str_from_mem(&self, base_address: *mut c_void, offset: usize, size: usize) -> String {
        let mut vec: Vec<u16> = vec![0; size];
        unsafe {
            ReadProcessMemory(
                GetCurrentProcess(), (base_address as usize + offset) as *const c_void, vec.as_mut_ptr() as *mut c_void, 
                size, std::ptr::null_mut()
            );
        }

        let str = String::from_utf16_lossy(&vec).trim_matches(char::from(0)).to_string();

        str
    }

    fn free_mem(&self, addr: *mut c_void, buffer_size: usize) {
        if addr != std::ptr::null_mut() {
            unsafe {
                VirtualFree(addr, buffer_size, MEM_RELEASE);
            }
        }
    }
}

impl Drop for WinProcList {
    fn drop(&mut self) {
        self.free_mem(self.base_address, self.alloc_size);
    }
}
