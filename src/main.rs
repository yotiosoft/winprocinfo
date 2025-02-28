use winproclist;

fn print_proc_header() {
    println!("{:<25} {:<10} {:<10} {:<10} {:<15} {:<15} {:<15} {:<10} {:<10}",
        "ImageName", "PID", "Handles", "SessionId", "VirtualSize", "PagefileUsage", "PrivatePages", "Priority", "Threads");
    println!("{:-<125}", "");
}

fn print_thread_header() {
    println!("    {:<10} {:<15} {:<15} {:<20} {:<10} {:<15} {:<10}", "TID", "KernelTime", "UserTime", "CreateTime", "WaitTime", "ContextSwitches", "Priority");
    println!("    {:-<121}", "");
}

fn print_proc_info(proc: &winproclist::ProcInfo) {
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
    let win_proc_list = winproclist::get().map_err(|e| e.to_string())?;
    
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
    if let Some(proc) = winproclist::get_proc_info_by_pid(pid).map_err(|e| e.to_string())? {
        print_proc_info(&proc);
    } else {
        println!("Process not found.");
    }
    
    Ok(())
}
