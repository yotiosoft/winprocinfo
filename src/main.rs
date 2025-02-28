use winprocinfo;

fn print_proc_header() {
    println!("{:<25} {:<10} {:<10} {:<10} {:<15} {:<15} {:<15} {:<10} {:<10}",
        "ImageName", "PID", "Handles", "SessionId", "VirtualSize", "PagefileUsage", "PrivatePages", "Priority", "Threads");
    println!("{:-<125}", "");
}

fn print_thread_header() {
    println!("    {:<10} {:<15} {:<15} {:<20} {:<10} {:<15} {:<10}", "TID", "KernelTime", "UserTime", "CreateTime", "WaitTime", "ContextSwitches", "Priority");
    println!("    {:-<121}", "");
}

fn print_proc_info(proc: &winprocinfo::ProcInfo) {
    print_proc_header();
    println!("{:<25} {:<10} {:<10} {:<10} {:<15} {:<15} {:<15} {:<10} {:<10}",
        proc.image_name,
        proc.unique_process_id,
        proc.handle_count,
        proc.session_id,
        proc.virtual_size,
        proc.pagefile_usage,
        proc.private_page_count,
        proc.base_priority,
        proc.number_of_threads
    );
    
    if !proc.threads.is_empty() {
        print_thread_header();
        for thread in &proc.threads {
            println!("    {:<10} {:<15} {:<15} {:<20} {:<10} {:<15} {:<10}",
                thread.client_id.unique_thread_id as u32,
                thread.kernel_time.to_u64(),
                thread.user_time.to_u64(),
                thread.create_time.to_u64(),
                thread.wait_time,
                thread.context_switches,
                thread.priority
            );
        }
    }
    println!("{:-<125}", "");
}

fn main() -> Result<(), String> {
    let win_proc_list = winprocinfo::get().map_err(|e| e.to_string())?;
    
    for proc in win_proc_list.proc_list.iter() {
        print_proc_info(proc);
    }

    println!("\n{:=<125}", "");
    
    let pid = std::process::id();
    println!("\nSearch by this process id: {}", pid);
    if let Some(proc) = win_proc_list.search_by_pid(pid) {
        print_proc_info(proc);
    } else {
        println!("Process not found.");
    }

    println!("\n{:=<125}", "");
    
    let name = std::env::current_exe().map_err(|e| e.to_string())?;
    let name = name.file_name().ok_or("Invalid file name.")?.to_str().ok_or("Invalid file name.")?;
    println!("\nSearch by process name: {}", name);
    let procs = win_proc_list.search_by_name(name);
    if procs.is_empty() {
        println!("Process not found.");
    }
    else {
        for proc in procs.iter() {
            print_proc_info(proc);
        }
    }

    println!("\n{:=<125}", "");
    
    println!("\nGet PID by process name: {}", name);
    if let Some(pids) = win_proc_list.get_pids_by_name(name) {
        for pid in pids.iter() {
            println!("PID: {}", pid);
        }
    } else {
        println!("Process not found.");
    }

    println!("\n{:=<125}", "");
    
    println!("\nGet process name by PID: {}", pid);
    if let Some(name) = win_proc_list.get_name_by_pid(pid) {
        println!("Process name: {}", name);
    } else {
        println!("Process not found.");
    }

    println!("\n{:=<125}", "");
    
    println!("\nGet process info by PID: {}", pid);
    if let Some(proc) = winprocinfo::get_proc_info_by_pid(pid).map_err(|e| e.to_string())? {
        print_proc_info(&proc);
        let proc_name = proc.to_ntapi().ImageName;
        println!("len: {} buf: {:?}", proc_name.Length, proc_name.Buffer);
        let proc_name = get_str_from_mem(proc_name.Buffer as *mut c_void, 0, proc_name.Length as usize);
        println!("Process name: {:?}", proc_name);
        let raw_val = proc.to_ntapi().Threads[0].CreateTime;
        let val = LargeInteger::from(&raw_val);
        println!("TID 1 create time: {:?}", val.to_u64());
    } else {
        println!("Process not found.");
    }
    
    Ok(())
}




use winapi::ctypes::c_void;
use winapi::ctypes::*;
use winapi::um::memoryapi::*;
use winapi::um::processthreadsapi::*;
use winapi::um::winnt::{ MEM_COMMIT, MEM_RELEASE, PAGE_EXECUTE_READWRITE };
use winapi::shared::ntstatus::{ STATUS_BUFFER_TOO_SMALL, STATUS_INFO_LENGTH_MISMATCH };
use winapi::shared::ntdef::*;
use ntapi::ntexapi::*;
use winprocinfo::LargeInteger;
fn get_str_from_mem(base_address: *mut c_void, offset: usize, size: usize) -> String {
    let mut vec: Vec<u16> = vec![0; size];
    read_process_memory((base_address as usize + offset) as *mut c_void, vec.as_mut_ptr() as *mut c_void, size);
    String::from_utf16_lossy(&vec).trim_matches(char::from(0)).to_string()
}
fn read_process_memory(base_address: *mut c_void, buffer: *mut c_void, buffer_size: usize) {
    unsafe {
        ReadProcessMemory(
            GetCurrentProcess(), base_address, buffer, buffer_size, std::ptr::null_mut()
        );
    }
}
