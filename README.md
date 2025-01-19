# WinProcList

WinProcList is a simple library to list all running processes on Windows.  
WinProcList uses a Windows API method ``NtQuerySystemInformation`` with the information class ``SystemProcessInformation`` to get the list of running processes.

## Installation

Add the following to your ``Cargo.toml``:

```toml
[dependencies]
winproclist = "0.1.0"
```

Or you can use the following command:

```bash
cargo add winproclist
```

## Usage

WinProcList needs to be initialized with the size of the buffer to store the list of running processes.  
The size of the buffer must be greater than whose size of the list of running processes.  
If the size of the buffer is less than the size of the list of running processes, the ``get`` method will return an error ``WinProcListError::BufferSizeTooSmall``.

To get all information about running processes, you can use the following code:

```rust
use winproclist;

fn main() -> Result<(), String> {
    let mut win_proc_list = winproclist::WinProcList::new();
    win_proc_list.get(0x500000).map_err(|e| e.to_string())?;
    println!("alloc_size: {}", win_proc_list.alloc_size);

    for proc in win_proc_list.proc_list.iter() {
        println!("--------------------------------------------------");
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
        println!("--------------------------------------------------");
    }
    Ok(())
}
```

All information about running processes is stored in the ``WinProcList`` struct.
