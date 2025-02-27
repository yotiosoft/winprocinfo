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

pub struct ProcInfo {
    pub next_entry_offset: u32,
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
    pub number_of_threads: u32,
    pub working_set_private_size: LargeInteger,
    pub hard_fault_count: u32,
    pub number_of_threads_high_watermark: u32,
    pub cycle_time: u64,
    pub create_time: LargeInteger,
    pub user_time: LargeInteger,
    pub kernel_time: LargeInteger,
    pub base_priority: i32,
    pub inherited_from_unique_process_id: *mut c_void,
    pub unique_process_key: usize,
    pub page_fault_count: u32,
    pub working_set_size: usize,
    pub quota_peak_paged_pool_usage: usize,
    pub quota_peak_non_paged_pool_usage: usize,
    pub read_operation_count: LargeInteger,
    pub write_operation_count: LargeInteger,
    pub other_operation_count: LargeInteger,
    pub read_transfer_count: LargeInteger,
    pub write_transfer_count: LargeInteger,
    pub other_transfer_count: LargeInteger,
    pub threads: Vec<ThreadInfo>,
}
impl ProcInfo {
    pub fn set(raw_proc_info_buffer: &BufferStruct) -> ProcInfo {
        let raw_proc_info = raw_proc_info_buffer.base_address as *const SYSTEM_PROCESS_INFORMATION;
        let raw_proc_info = unsafe { *raw_proc_info };

        println!("ptr: {:x}", raw_proc_info.Threads.as_ptr() as *const c_void as usize);
        println!("PID: {}", raw_proc_info.UniqueProcessId as u32);
        let mut number_of_threads = raw_proc_info.NumberOfThreads;
        if raw_proc_info.UniqueProcessId as u32 == 4 {
            number_of_threads = 0;
        }
        ProcInfo {
            next_entry_offset: raw_proc_info.NextEntryOffset,
            image_name: get_str_from_mem(raw_proc_info.ImageName.Buffer as *mut c_void, 0, raw_proc_info.ImageName.Length as usize),
            unique_process_id: raw_proc_info.UniqueProcessId as u32,
            handle_count: raw_proc_info.HandleCount,
            session_id: raw_proc_info.SessionId,
            peak_virtual_size: raw_proc_info.PeakVirtualSize,
            virtual_size: raw_proc_info.VirtualSize,
            peak_working_set_size: raw_proc_info.PeakWorkingSetSize,
            quota_paged_pool_usage: raw_proc_info.QuotaPagedPoolUsage,
            quota_non_paged_pool_usage: raw_proc_info.QuotaNonPagedPoolUsage,
            pagefile_usage: raw_proc_info.PagefileUsage,
            peak_pagefile_usage: raw_proc_info.PeakPagefileUsage,
            private_page_count: raw_proc_info.PrivatePageCount,
            number_of_threads: raw_proc_info.NumberOfThreads,
            working_set_private_size: LargeInteger::set(&raw_proc_info.WorkingSetPrivateSize),
            hard_fault_count: raw_proc_info.HardFaultCount,
            number_of_threads_high_watermark: raw_proc_info.NumberOfThreadsHighWatermark,
            cycle_time: raw_proc_info.CycleTime,
            create_time: LargeInteger::set(&raw_proc_info.CreateTime),
            user_time: LargeInteger::set(&raw_proc_info.UserTime),
            kernel_time: LargeInteger::set(&raw_proc_info.KernelTime),
            base_priority: raw_proc_info.BasePriority,
            inherited_from_unique_process_id: raw_proc_info.InheritedFromUniqueProcessId,
            unique_process_key: raw_proc_info.UniqueProcessKey,
            page_fault_count: raw_proc_info.PageFaultCount,
            working_set_size: raw_proc_info.WorkingSetSize,
            quota_peak_paged_pool_usage: raw_proc_info.QuotaPeakPagedPoolUsage,
            quota_peak_non_paged_pool_usage: raw_proc_info.QuotaPeakNonPagedPoolUsage,
            read_operation_count: LargeInteger::set(&raw_proc_info.ReadOperationCount),
            write_operation_count: LargeInteger::set(&raw_proc_info.WriteOperationCount),
            other_operation_count: LargeInteger::set(&raw_proc_info.OtherOperationCount),
            read_transfer_count: LargeInteger::set(&raw_proc_info.ReadTransferCount),
            write_transfer_count: LargeInteger::set(&raw_proc_info.WriteTransferCount),
            other_transfer_count: LargeInteger::set(&raw_proc_info.OtherTransferCount),
            threads: get_thread_info_vec(raw_proc_info.Threads.as_ptr() as *const c_void, number_of_threads),
        }
    }
}

pub struct ThreadInfo {
    pub kernel_time: LargeInteger,
    pub user_time: LargeInteger,
    pub create_time: LargeInteger,
    pub wait_time: u32,
    pub start_address: *mut c_void,
    pub priority: i32,
    pub base_priority: i32,
    pub context_switches: u32,
    pub thread_state: u32,
    pub wait_reason: u32,
    pub client_id: ClientID,
}
impl ThreadInfo {
    pub fn set(thread_info: &SYSTEM_THREAD_INFORMATION) -> ThreadInfo {
        ThreadInfo {
            kernel_time: LargeInteger::set(&thread_info.KernelTime),
            user_time: LargeInteger::set(&thread_info.UserTime),
            create_time: LargeInteger::set(&thread_info.CreateTime),
            wait_time: thread_info.WaitTime,
            start_address: thread_info.StartAddress,
            priority: thread_info.Priority,
            base_priority: thread_info.BasePriority,
            context_switches: thread_info.ContextSwitches,
            thread_state: thread_info.ThreadState,
            wait_reason: thread_info.WaitReason,
            client_id: ClientID::set(&thread_info.ClientId),
        }
    }
}

fn get_thread_info_vec(thread_ptr: *const c_void, number_of_threads: u32) -> Vec<ThreadInfo> {
    let thread_array_base = thread_ptr as usize;
    let mut thread_info_vec: Vec<ThreadInfo> = Vec::new();
    for i in 0..number_of_threads as usize {
        println!("i = {}, {} ptr:{:x}", i, number_of_threads, thread_array_base + i * std::mem::size_of::<SYSTEM_THREAD_INFORMATION>());
        let thread_info_ptr = (thread_array_base + i * std::mem::size_of::<SYSTEM_THREAD_INFORMATION>()) as *const SYSTEM_THREAD_INFORMATION;
        let thread_info = unsafe { *thread_info_ptr };
        let thread_info = ThreadInfo::set(&thread_info);
        println!("thread_info: {}", thread_info.kernel_time.to_u64());
        thread_info_vec.push(thread_info);
    }
    thread_info_vec
}

pub struct ClientID {
    pub unique_process_id: *mut c_void,
    pub unique_thread_id: *mut c_void,
}
impl ClientID {
    pub fn set(raw_client_id: &ntapi::ntapi_base::CLIENT_ID) -> ClientID {
        ClientID {
            unique_process_id: raw_client_id.UniqueProcess,
            unique_thread_id: raw_client_id.UniqueThread,
        }
    }
}

pub struct LargeInteger {
    pub low_part: u32,
    pub high_part: i32,
}
impl LargeInteger {
    pub fn set(raw_large_integer: &winapi::shared::ntdef::LARGE_INTEGER) -> LargeInteger {
        let mut large_integer = LargeInteger {
            low_part: 0,
            high_part: 0,
        };
        read_process_memory(raw_large_integer as *const _ as *mut c_void, &mut large_integer as *mut _ as *mut c_void, std::mem::size_of::<LargeInteger>());
        large_integer
    }
    pub fn to_u64(&self) -> u64 {
        self.low_part as u64 | (self.high_part as u64) << 32
    }
}

struct BufferStruct {
    base_address: *mut c_void,
    alloc_size: usize,
}
impl Drop for BufferStruct {
    fn drop(&mut self) {
        println!("drop: {:x}", self.base_address as usize);
        vfree(self.base_address, self.alloc_size);
    }
}
impl BufferStruct {
    fn alloc(size: usize) -> BufferStruct {
        BufferStruct {
            base_address: valloc(size),
            alloc_size: size,
        }
    }
}

pub struct WinProcList {
    pub proc_list: Vec<ProcInfo>,
}

pub fn get() -> Result<WinProcList, WinProcListError> {
    let buffer = get_system_processes_info()?;
    let list_vec = get_proc_list(buffer.base_address);
    Ok(WinProcList { proc_list: list_vec })
}

impl WinProcList {
    pub fn search_by_pid(&self, pid: u32) -> Option<&ProcInfo> {
        self.proc_list.iter().find(|&x| x.unique_process_id == pid)
    }

    pub fn search_by_name(&self, name: &str) -> Option<Vec<&ProcInfo>> {
        let mut vec: Vec<&ProcInfo> = Vec::new();
        for proc in self.proc_list.iter() {
            if proc.image_name == name {
                vec.push(proc);
            }
        }
        if vec.is_empty() {
            None
        }
        else {
            Some(vec)
        }
    }

    pub fn get_name_by_pid(&self, pid: u32) -> Option<&String> {
        self.proc_list.iter().find(|&x| x.unique_process_id == pid).map(|x| &x.image_name)
    }

    pub fn get_pids_by_name(&self, name: &str) -> Option<Vec<u32>> {
        let mut vec: Vec<u32> = Vec::new();
        for proc in self.proc_list.iter() {
            if proc.image_name == name {
                vec.push(proc.unique_process_id);
            }
        }
        if vec.is_empty() {
            None
        }
        else {
            Some(vec)
        }
    }
}

pub fn get_proc_info_by_pid(pid: u32) -> Result<Option<ProcInfo>, WinProcListError> {
    let buffer = get_system_processes_info()?;
    let mut next_address = buffer.base_address as isize;

    loop {
        let system_process_information_buffer = read_proc_info(next_address as *mut c_void);
        if system_process_information_buffer.alloc_size == 0 {
            break;
        }

        let entry_pid = unsafe { (system_process_information_buffer.base_address as *const SYSTEM_PROCESS_INFORMATION).read().UniqueProcessId as u32 };
        if entry_pid != pid {
            next_address += system_process_information_buffer.alloc_size as isize;
            continue;
        }

        let proc_info: ProcInfo = ProcInfo::set(&system_process_information_buffer);

        return Ok(Some(proc_info));
    }

    Ok(None)
}

// 現在動作中のすべてのプロセス情報を取得
// SystemProcessInformation を buffer に取得
fn get_system_processes_info() -> Result<BufferStruct, WinProcListError> {
    // プロセス情報を取得
    // SystemProcessInformation : 各プロセスの情報（オプション定数）
    // base_address             : 格納先
    // buffer_size              : 格納先のサイズ
    // &mut buffer_size         : 実際に取得したサイズ
    let mut buffer_size: u32 = 1024;
    let mut status;
    loop {
        println!("buffer alloc: {}", buffer_size);
        let buffer = BufferStruct::alloc(buffer_size as usize);
        status = unsafe {
            NtQuerySystemInformation(SystemProcessInformation, buffer.base_address, buffer_size as u32, &mut buffer_size as *mut u32)
        };
        if NT_ERROR(status) {
            if status != STATUS_INFO_LENGTH_MISMATCH && status != STATUS_BUFFER_TOO_SMALL {
                return Err(WinProcListError::CouldNotGetProcInfo(status));
            }
        }
        else {
            println!("buffer_size: {}", buffer_size);
            return Ok(buffer);
        }
    }
}

fn get_proc_list(base_address: *mut c_void) -> Vec<ProcInfo> {
    let mut next_address = base_address as isize;
    let mut proc_list: Vec<ProcInfo> = Vec::new();

    loop {
        println!("before read_proc_info: {:x}", next_address);
        let system_process_information_buffer = read_proc_info(next_address as *mut c_void);
        println!("after");
        if system_process_information_buffer.alloc_size == 0 {
            break;
        }

        let proc_info: ProcInfo = ProcInfo::set(&system_process_information_buffer);
        println!("proc_info: {}", proc_info.image_name);
        proc_list.push(proc_info);

        next_address += system_process_information_buffer.alloc_size as isize;
    }

    proc_list
}

// プロセス一つ分の情報を取得
fn read_proc_info(next_address: *mut c_void) -> BufferStruct {
    let next_entry_offset = unsafe { (next_address as *const SYSTEM_PROCESS_INFORMATION).read().NextEntryOffset };
    let number_of_threads = unsafe { (next_address as *const SYSTEM_PROCESS_INFORMATION).read().NumberOfThreads };
    let unique_process_id = unsafe { (next_address as *const SYSTEM_PROCESS_INFORMATION).read().UniqueProcessId };
    println!("PID: {}", unique_process_id as u32);
    println!("SYSTEM_PROCESS_INFORMATION size: {}", std::mem::size_of::<SYSTEM_PROCESS_INFORMATION>());
    println!("SYSTEM_THREAD_INFORMATION size: {}", std::mem::size_of::<SYSTEM_THREAD_INFORMATION>());
    println!("next_entry_offset * SYSTEM_THREAD_INFORMATION size: {}", std::mem::size_of::<SYSTEM_THREAD_INFORMATION>() * number_of_threads as usize);
    println!("number_of_threads: {}", number_of_threads);
    let mut system_process_info_buffer = BufferStruct::alloc(next_entry_offset as usize);
    if next_entry_offset == 0 {
        return system_process_info_buffer;
    }

    println!("next_entry_offset: {} next_address: {:?} base-address: {:?} alloc-size: {}", next_entry_offset, next_address, system_process_info_buffer.base_address, system_process_info_buffer.alloc_size);
    // base_address の該当オフセット値から SYSTEM_PROCESS_INFORMATION 構造体の情報をプロセス1つ分取得
    //read_process_memory(next_address, &mut system_process_info_buffer.base_address as *mut _ as *mut c_void, system_process_info_buffer.alloc_size);
    system_process_info_buffer.base_address = next_address;
    println!("base_address: {:x}", system_process_info_buffer.base_address as usize);
    system_process_info_buffer
}

fn get_str_from_mem(base_address: *mut c_void, offset: usize, size: usize) -> String {
    let mut vec: Vec<u16> = vec![0; size];
    read_process_memory((base_address as usize + offset) as *mut c_void, vec.as_mut_ptr() as *mut c_void, size);
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

fn read_process_memory(base_address: *mut c_void, buffer: *mut c_void, buffer_size: usize) {
    unsafe {
        ReadProcessMemory(
            GetCurrentProcess(), base_address, buffer, buffer_size, std::ptr::null_mut()
        );
    }
}
