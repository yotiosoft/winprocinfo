use winproclist;

fn print_proc_info(proc: &winproclist::ProcInfo) {
    println!("======");
    println!("ImageName: {}", proc.image_name);
    println!("PID: {}", proc.unique_process_id);
    println!("HandleCount: {}", proc.handle_count);
    println!("SessionId: {}", proc.session_id);
    println!("PeakVirtualSize: {}", proc.peak_virtual_size);
    println!("VirtualSize: {}", proc.virtual_size);
    println!("PeakWorkingSetSize: {}", proc.peak_working_set_size);
    println!("QuotaPagedPoolUsage: {}", proc.quota_paged_pool_usage);
    println!("QuotaNonPagedPoolUsage: {}", proc.quota_non_paged_pool_usage);
    println!("PagefileUsage: {}", proc.pagefile_usage);
    println!("PeakPagefileUsage: {}", proc.peak_pagefile_usage);
    println!("PrivatePageCount: {}", proc.private_page_count);
    println!("ThreadCount: {}", proc.number_of_threads);
    for thread in proc.threads.iter() {
        println!("Thread:");
        println!("  KernelTime: {}", thread.kernel_time.to_u64());
        println!("  UserTime: {}", thread.user_time.to_u64());
        println!("  CreateTime: {}", thread.create_time.to_u64());
        println!("  WaitTime: {}", thread.wait_time);
        println!("  ContextSwitches: {}", thread.context_switches);
        println!("  Priority: {}", thread.priority);
        println!("  BasePriority: {}", thread.base_priority);
    }
    println!("======");
}

fn main() -> Result<(), String> {
    // Print all processes.
    println!("--------------------------------------------------");
    println!("All processes:");
    let win_proc_list = winproclist::get().map_err(|e| e.to_string())?;
    for proc in win_proc_list.proc_list.iter() {
        print_proc_info(proc);
    }
    println!("--------------------------------------------------");

    // Search by this process id.
    let pid = std::process::id();
    println!("--------------------------------------------------");
    println!("Current process: {}", pid);
    println!("search_by_pid: {}", pid);
    let proc = win_proc_list.search_by_pid(pid);
    if let Some(proc) = proc {
        print_proc_info(proc);
    }
    else {
        println!("Current process not found.");
    }
    println!("--------------------------------------------------");

    // Search by this process name.
    let name = "winproclist.exe";
    println!("--------------------------------------------------");
    println!("search_by_name: WinProcList");
    let procs = win_proc_list.search_by_name(name);
    if let Some(procs) = procs {
        for proc in procs.iter() {
            print_proc_info(proc);
        }
    }
    else {
        println!("Process not found.");
    }
    println!("--------------------------------------------------");

    // Get pid by this process name.
    println!("--------------------------------------------------");
    println!("get_pids_by_name: WinProcList");
    let pids = win_proc_list.get_pids_by_name(name);
    if let Some(pids) = pids {
        for pid in pids.iter() {
            println!("PID: {}", pid);
        }
    }
    else {
        println!("Process not found.");
    }
    println!("--------------------------------------------------");

    // Get process name by this process id.
    println!("--------------------------------------------------");
    println!("get_name_by_pid: {}", pid);
    let name = win_proc_list.get_name_by_pid(pid);
    if let Some(name) = name {
        println!("Process name: {}", name);
    }
    else {
        println!("Process not found.");
    }
    println!("--------------------------------------------------");

    // Get process info by this process id.
    let pid = std::process::id();
    println!("--------------------------------------------------");
    println!("Current process: {}", pid);
    println!("Get from get_proc_info_by_pid");
    let proc = winproclist::get_proc_info_by_pid(pid).map_err(|e| e.to_string())?;
    if let Some(proc) = proc {
        print_proc_info(&proc);
    }
    else {
        println!("Current process not found.");
    }
    println!("--------------------------------------------------");

    Ok(())
}
