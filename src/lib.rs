use std::fmt::{Debug, Display};
use std::ptr;
use winapi::ctypes::*;
use winapi::um::memoryapi::*;
use winapi::um::processthreadsapi::*;
use winapi::um::winnt::{ MEM_COMMIT, MEM_RELEASE, PAGE_EXECUTE_READWRITE };
use winapi::shared::ntstatus::{ STATUS_BUFFER_TOO_SMALL, STATUS_INFO_LENGTH_MISMATCH };
use winapi::shared::ntdef::*;
use ntapi::ntexapi::*;

/// An enumeration representing possible errors that can occur while obtaining process information.
#[derive(Debug, Clone, PartialEq)]
pub enum WinProcInfoError {
    /// Could not obtain process information.
    CouldNotGetProcInfo(i32),
    /// The buffer size was too small to hold the process information.
    BufferSizeTooSmall(usize, usize),
}

impl Display for WinProcInfoError {
    /// Formats the error message for displaying.
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            WinProcInfoError::CouldNotGetProcInfo(status) => write!(f, "Could not get process information. Status: 0x{:X}", status),
            WinProcInfoError::BufferSizeTooSmall(alloc_size, req_size) => write!(f, "Buffer size too small. You need at least {} bytes, but only allocated {} bytes.", req_size, alloc_size),
        }
    }
}

/// A struct representing the information of a process.
/// Each member variable corresponds to the member variables of the SYSTEM_PROCESS_INFORMATION structure in the ntapi crate.
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
    /// Sets the process information from the given raw process information buffer.
    fn from(raw_proc_info_buffer: &BufferStruct) -> ProcInfo {
        let raw_proc_info = raw_proc_info_buffer.base_address as *const SYSTEM_PROCESS_INFORMATION;
        let raw_proc_info = unsafe { *raw_proc_info };

        let number_of_threads = raw_proc_info.NumberOfThreads;
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
            working_set_private_size: LargeInteger::from(&raw_proc_info.WorkingSetPrivateSize),
            hard_fault_count: raw_proc_info.HardFaultCount,
            number_of_threads_high_watermark: raw_proc_info.NumberOfThreadsHighWatermark,
            cycle_time: raw_proc_info.CycleTime,
            create_time: LargeInteger::from(&raw_proc_info.CreateTime),
            user_time: LargeInteger::from(&raw_proc_info.UserTime),
            kernel_time: LargeInteger::from(&raw_proc_info.KernelTime),
            base_priority: raw_proc_info.BasePriority,
            inherited_from_unique_process_id: raw_proc_info.InheritedFromUniqueProcessId,
            unique_process_key: raw_proc_info.UniqueProcessKey,
            page_fault_count: raw_proc_info.PageFaultCount,
            working_set_size: raw_proc_info.WorkingSetSize,
            quota_peak_paged_pool_usage: raw_proc_info.QuotaPeakPagedPoolUsage,
            quota_peak_non_paged_pool_usage: raw_proc_info.QuotaPeakNonPagedPoolUsage,
            read_operation_count: LargeInteger::from(&raw_proc_info.ReadOperationCount),
            write_operation_count: LargeInteger::from(&raw_proc_info.WriteOperationCount),
            other_operation_count: LargeInteger::from(&raw_proc_info.OtherOperationCount),
            read_transfer_count: LargeInteger::from(&raw_proc_info.ReadTransferCount),
            write_transfer_count: LargeInteger::from(&raw_proc_info.WriteTransferCount),
            other_transfer_count: LargeInteger::from(&raw_proc_info.OtherTransferCount),
            threads: get_thread_info_vec(&raw_proc_info_buffer, number_of_threads),
        }
    }

    /// Converts the ProcInfo struct to the SYSTEM_PROCESS_INFORMATION struct used by ntapi.
    pub fn to_ntapi(&self) -> SYSTEM_PROCESS_INFORMATION {
        SYSTEM_PROCESS_INFORMATION {
            NextEntryOffset: self.next_entry_offset,
            ImageName: UNICODE_STRING {
                Length: self.image_name.len() as u16 * 2,
                MaximumLength: self.image_name.len() as u16 * 2,
                Buffer: {
                    let mut buffer: Vec<u16> = self.image_name.encode_utf16().collect();
                    buffer.push(0);
                    buffer.as_mut_ptr()
                }
            },
            UniqueProcessId: self.unique_process_id as *mut c_void,
            HandleCount: self.handle_count,
            SessionId: self.session_id,
            PeakVirtualSize: self.peak_virtual_size,
            VirtualSize: self.virtual_size,
            PeakWorkingSetSize: self.peak_working_set_size,
            QuotaPagedPoolUsage: self.quota_paged_pool_usage,
            QuotaNonPagedPoolUsage: self.quota_non_paged_pool_usage,
            PagefileUsage: self.pagefile_usage,
            PeakPagefileUsage: self.peak_pagefile_usage,
            PrivatePageCount: self.private_page_count,
            NumberOfThreads: self.number_of_threads,
            WorkingSetPrivateSize: self.working_set_private_size.to_ntapi(),
            HardFaultCount: self.hard_fault_count,
            NumberOfThreadsHighWatermark: self.number_of_threads_high_watermark,
            CycleTime: self.cycle_time,
            CreateTime: self.create_time.to_ntapi(),
            UserTime: self.user_time.to_ntapi(),
            KernelTime: self.kernel_time.to_ntapi(),
            BasePriority: self.base_priority,
            InheritedFromUniqueProcessId: self.inherited_from_unique_process_id,
            UniqueProcessKey: self.unique_process_key,
            PageFaultCount: self.page_fault_count,
            WorkingSetSize: self.working_set_size,
            QuotaPeakPagedPoolUsage: self.quota_peak_paged_pool_usage,
            QuotaPeakNonPagedPoolUsage: self.quota_peak_non_paged_pool_usage,
            ReadOperationCount: self.read_operation_count.to_ntapi(),
            WriteOperationCount: self.write_operation_count.to_ntapi(),
            OtherOperationCount: self.other_operation_count.to_ntapi(),
            ReadTransferCount: self.read_transfer_count.to_ntapi(),
            WriteTransferCount: self.write_transfer_count.to_ntapi(),
            OtherTransferCount: self.other_transfer_count.to_ntapi(),
            Threads: [self.threads[0].to_ntapi(); 1],
        }
    }
}

/// A struct representing the information of a thread.
/// Each member variable corresponds to the member variables of the SYSTEM_THREAD_INFORMATION structure in the ntapi crate.
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
    /// Sets the thread information from the given SYSTEM_THREAD_INFORMATION.
    pub fn from(thread_info: &SYSTEM_THREAD_INFORMATION) -> ThreadInfo {
        ThreadInfo {
            kernel_time: LargeInteger::from(&thread_info.KernelTime),
            user_time: LargeInteger::from(&thread_info.UserTime),
            create_time: LargeInteger::from(&thread_info.CreateTime),
            wait_time: thread_info.WaitTime,
            start_address: thread_info.StartAddress,
            priority: thread_info.Priority,
            base_priority: thread_info.BasePriority,
            context_switches: thread_info.ContextSwitches,
            thread_state: thread_info.ThreadState,
            wait_reason: thread_info.WaitReason,
            client_id: ClientID::from(&thread_info.ClientId),
        }
    }

    /// Converts the ThreadInfo struct to the SYSTEM_THREAD_INFORMATION struct used by ntapi.
    pub fn to_ntapi(&self) -> SYSTEM_THREAD_INFORMATION {
        SYSTEM_THREAD_INFORMATION {
            KernelTime: self.kernel_time.to_ntapi(),
            UserTime: self.user_time.to_ntapi(),
            CreateTime: self.create_time.to_ntapi(),
            WaitTime: self.wait_time,
            StartAddress: self.start_address,
            Priority: self.priority,
            BasePriority: self.base_priority,
            ContextSwitches: self.context_switches,
            ThreadState: self.thread_state,
            WaitReason: self.wait_reason,
            ClientId: ntapi::ntapi_base::CLIENT_ID {
                UniqueProcess: self.client_id.unique_process_id,
                UniqueThread: self.client_id.unique_thread_id,
            },
        }
    }
}

/// Retrieves a vector of ThreadInfo from the given process information buffer.
fn get_thread_info_vec(proc_info_buffer: &BufferStruct, number_of_threads: u32) -> Vec<ThreadInfo> {
    let thread_array_base = proc_info_buffer.base_address as usize + std::mem::size_of::<SYSTEM_PROCESS_INFORMATION>() - std::mem::size_of::<SYSTEM_THREAD_INFORMATION>();
    unsafe { 
        std::slice::from_raw_parts(thread_array_base as *const SYSTEM_THREAD_INFORMATION, number_of_threads as usize)
            .iter()
            .map(|x| ThreadInfo::from(x)).collect() 
    }
}

/// A struct representing the client ID, including unique process and thread IDs.
pub struct ClientID {
    pub unique_process_id: *mut c_void,
    pub unique_thread_id: *mut c_void,
}

impl ClientID {
    /// Sets the client ID from the given CLIENT_ID struct.
    pub fn from(raw_client_id: &ntapi::ntapi_base::CLIENT_ID) -> ClientID {
        ClientID {
            unique_process_id: raw_client_id.UniqueProcess,
            unique_thread_id: raw_client_id.UniqueThread,
        }
    }
}

/// A struct representing a large integer, including low and high parts.
pub struct LargeInteger {
    pub low_part: u32,
    pub high_part: i32,
}

impl LargeInteger {
    /// Sets the large integer from the given LARGE_INTEGER struct.
    pub fn from(raw_large_integer: &winapi::shared::ntdef::LARGE_INTEGER) -> LargeInteger {
        unsafe {  ptr::read_unaligned(raw_large_integer as *const _ as *const LargeInteger) }
    }

    /// Converts the large integer to a 64-bit unsigned integer.
    pub fn to_u64(&self) -> u64 {
        self.low_part as u64 | (self.high_part as u64) << 32
    }

    /// Converts the LargeInteger struct to the LARGE_INTEGER struct used by ntapi.
    pub fn to_ntapi(&self) -> winapi::shared::ntdef::LARGE_INTEGER {
        unsafe { ptr::read_unaligned(self as *const _ as *const winapi::shared::ntdef::LARGE_INTEGER) }
    }
}

/// A struct representing a buffer, including its base address and allocation size.
struct BufferStruct {
    base_address: *mut c_void,
    alloc_size: usize,
    with_valloc: bool,
}

impl Drop for BufferStruct {
    /// Frees the allocated memory if valloc was used.
    fn drop(&mut self) {
        if self.with_valloc {
            if self.base_address != std::ptr::null_mut() {
                vfree(self.base_address, self.alloc_size);
            }
        }
    }
}

impl BufferStruct {
    /// Allocates memory for the buffer.
    fn alloc(size: usize) -> BufferStruct {
        BufferStruct {
            base_address: valloc(size),
            alloc_size: size,
            with_valloc: true,
        }
    }

    /// Creates a buffer with the given base address and size without using valloc.
    fn with(base_address: *mut c_void, size: usize) -> BufferStruct {
        BufferStruct {
            base_address: base_address,
            alloc_size: size,
            with_valloc: false,
        }
    }
}

/// A struct representing a list of processes.
pub struct WinProcList {
    pub proc_list: Vec<ProcInfo>,
}

/// Retrieves the list of processes.
/// 
/// # Returns
/// 
/// * `Result<WinProcList, WinProcInfoError>` - A result containing either the WinProcList struct or a WinProcInfoError.
pub fn get_list() -> Result<WinProcList, WinProcInfoError> {
    let buffer = get_system_processes_info()?;
    let list_vec = get_proc_list(buffer.base_address);
    Ok(WinProcList { proc_list: list_vec })
}

impl WinProcList {
    /// Searches for a process by its PID.
    /// 
    /// # Arguments
    /// 
    /// * `pid` - The PID of the process to search for.
    /// 
    /// # Returns
    /// 
    /// * `Option<&ProcInfo>` - An option containing the ProcInfo struct if found.
    pub fn search_by_pid(&self, pid: u32) -> Option<&ProcInfo> {
        self.proc_list.iter().find(|&x| x.unique_process_id == pid)
    }

    /// Searches for processes by their name.
    /// 
    /// # Arguments
    /// 
    /// * `name` - The name of the processes to search for.
    /// 
    /// # Returns
    /// 
    /// * `Vec<&ProcInfo>` - A vector containing the ProcInfo structs of the processes found.
    pub fn search_by_name(&self, name: &str) -> Vec<&ProcInfo> {
        let mut vec: Vec<&ProcInfo> = Vec::new();
        for proc in self.proc_list.iter() {
            if proc.image_name == name {
                vec.push(proc);
            }
        }
        vec
    }

    /// Gets the name of a process by its PID.
    /// 
    /// # Arguments
    /// 
    /// * `pid` - The PID of the process.
    /// 
    /// # Returns
    /// 
    /// * `Option<&String>` - An option containing the name of the process if found.
    pub fn get_name_by_pid(&self, pid: u32) -> Option<&String> {
        self.proc_list.iter().find(|&x| x.unique_process_id == pid).map(|x| &x.image_name)
    }

    /// Gets the PIDs of processes by their name.
    /// 
    /// # Arguments
    /// 
    /// * `name` - The name of the processes.
    /// 
    /// # Returns
    /// 
    /// * `Option<Vec<u32>>` - An option containing a vector of PIDs of the processes found.
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

/// Retrieves the information of a process by its PID.
/// 
/// # Arguments
/// 
/// * `pid` - The PID of the process.
/// 
/// # Returns
/// 
/// * `Result<Option<ProcInfo>, WinProcInfoError>` - A result containing either an option with the ProcInfo struct or a WinProcInfoError.
pub fn get_proc_info_by_pid(pid: u32) -> Result<Option<ProcInfo>, WinProcInfoError> {
    let buffer = get_system_processes_info()?;
    let mut next_address = buffer.base_address as isize;

    loop {
        let system_process_information_buffer = read_proc_info(next_address as *mut c_void);

        let entry_pid = unsafe { (system_process_information_buffer.base_address as *const SYSTEM_PROCESS_INFORMATION).read().UniqueProcessId as u32 };
        if entry_pid != pid {
            if system_process_information_buffer.alloc_size == 0 {
                break;
            }
            next_address += system_process_information_buffer.alloc_size as isize;
            continue;
        }

        let proc_info: ProcInfo = ProcInfo::from(&system_process_information_buffer);

        return Ok(Some(proc_info));
    }

    Ok(None)
}

/// Retrieves the information of all currently running processes.
/// 
/// This function queries the system for process information and stores it in a buffer.
/// 
/// # Returns
/// 
/// * `Result<BufferStruct, WinProcInfoError>` - A result containing either the BufferStruct with process information or a WinProcInfoError.
fn get_system_processes_info() -> Result<BufferStruct, WinProcInfoError> {
    let mut buffer_size: u32 = 1024;
    let mut status;
    loop {
        let buffer = BufferStruct::alloc(buffer_size as usize);
        status = unsafe {
            NtQuerySystemInformation(SystemProcessInformation, buffer.base_address, buffer_size as u32, &mut buffer_size as *mut u32)
        };
        if NT_ERROR(status) {
            if status != STATUS_INFO_LENGTH_MISMATCH && status != STATUS_BUFFER_TOO_SMALL {
                return Err(WinProcInfoError::CouldNotGetProcInfo(status));
            }
        }
        else {
            return Ok(buffer);
        }
    }
}

/// Retrieves a list of process information from the given base address.
/// 
/// # Arguments
/// 
/// * `base_address` - The base address from which to retrieve process information.
/// 
/// # Returns
/// 
/// * `Vec<ProcInfo>` - A vector containing the information of all processes.
fn get_proc_list(base_address: *mut c_void) -> Vec<ProcInfo> {
    let mut next_address = base_address as isize;
    let mut proc_list: Vec<ProcInfo> = Vec::new();

    loop {
        let system_process_information_buffer = read_proc_info(next_address as *mut c_void);
        let proc_info: ProcInfo = ProcInfo::from(&system_process_information_buffer);
        proc_list.push(proc_info);

        if system_process_information_buffer.alloc_size == 0 {
            break;
        }

        next_address += system_process_information_buffer.alloc_size as isize;
    }

    proc_list
}

/// Retrieves the information of a single process from the given address.
/// 
/// # Arguments
/// 
/// * `next_address` - The address from which to retrieve the process information.
/// 
/// # Returns
/// 
/// * `BufferStruct` - A buffer containing the process information.
fn read_proc_info(next_address: *mut c_void) -> BufferStruct {
    let next_entry_offset = unsafe { (next_address as *const SYSTEM_PROCESS_INFORMATION).read().NextEntryOffset };
    
    let mut system_process_info_buffer = BufferStruct::with(next_address, next_entry_offset as usize);
    if next_entry_offset == 0 {
        return system_process_info_buffer;
    }

    system_process_info_buffer.base_address = next_address;
    system_process_info_buffer
}

/// Reads a string from memory.
/// 
/// # Arguments
/// 
/// * `base_address` - The base address from which to read the string.
/// * `offset` - The offset from the base address.
/// * `size` - The size of the string.
/// 
/// # Returns
/// 
/// * `String` - The string read from memory.
fn get_str_from_mem(base_address: *mut c_void, offset: usize, size: usize) -> String {
    let mut vec: Vec<u16> = vec![0; size];
    read_process_memory((base_address as usize + offset) as *mut c_void, vec.as_mut_ptr() as *mut c_void, size);
    String::from_utf16_lossy(&vec).trim_matches(char::from(0)).to_string()
}

/// Allocates memory for a buffer.
/// 
/// # Arguments
/// 
/// * `buffer_size` - The size of the buffer to allocate.
/// 
/// # Returns
/// 
/// * `*mut c_void` - A pointer to the allocated memory.
fn valloc(buffer_size: usize) -> *mut c_void {
    unsafe {
        VirtualAlloc(std::ptr::null_mut(), buffer_size, MEM_COMMIT, PAGE_EXECUTE_READWRITE)
    }
}

/// Frees the allocated memory.
/// 
/// # Arguments
/// 
/// * `addr` - The address of the memory to free.
/// * `buffer_size` - The size of the memory to free.
fn vfree(addr: *mut c_void, buffer_size: usize) {
    if addr != std::ptr::null_mut() {
        unsafe {
            VirtualFree(addr, buffer_size, MEM_RELEASE);
        }
    }
}

/// Reads the memory of a process.
/// 
/// # Arguments
/// 
/// * `base_address` - The base address from which to read.
/// * `buffer` - The buffer to store the read data.
/// * `buffer_size` - The size of the buffer.
fn read_process_memory(base_address: *mut c_void, buffer: *mut c_void, buffer_size: usize) {
    unsafe {
        ReadProcessMemory(
            GetCurrentProcess(), base_address, buffer, buffer_size, std::ptr::null_mut()
        );
    }
}
