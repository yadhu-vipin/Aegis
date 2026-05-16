use std::process::Command;
use std::os::windows::process::CommandExt;
use winapi::um::winbase::CREATE_NO_WINDOW;
use winapi::um::processthreadsapi::{GetProcessTimes, GetExitCodeProcess};
use winapi::um::winnt::HANDLE;
use std::ptr;

pub fn start_behavioral_scan(file_path: &str) -> std::io::Result<()> {
    let sandbox_path = "C:\\Aegis\\quarantine\\sandbox_exec.exe";
    std::fs::rename(file_path, sandbox_path)?;

    // Start the process in the "Bubble"
    let mut child = Command::new(sandbox_path)
        .creation_flags(CREATE_NO_WINDOW) 
        .spawn()?;

    let pid = child.id();
    
    // Convert Process ID to a Windows Handle to use WinAPI
    let handle = child.as_raw_handle() as HANDLE;

    println!("[Aegis] Sandbox active. PID: {}. Scanning for behavioral anomalies...", pid);

    // Monitoring Loop
    let mut suspicious_score = 0;
    
    // Give the malware 5 seconds to "show its true colors"
    for _ in 0..5 {
        if let Some(score_increase) = check_process_vitals(handle) {
            suspicious_score += score_increase;
        }
        std::thread::sleep(std::time::Duration::from_secs(1));
    }

    // Kill the process after analysis
    let _ = child.kill();

    if suspicious_score > 10 {
        return Err(std::io::Error::new(std::io::ErrorKind::Other, "Behavioral Threat Detected"));
    }

    Ok(())
}

fn check_process_vitals(handle: HANDLE) -> Option<i32> {
    let mut exit_code: u32 = 0;
    unsafe {
        GetExitCodeProcess(handle, &mut exit_code);
    }

    // If the process crashed or was terminated abnormally, it's suspicious
    if exit_code != 259 { // 259 means STILL_ACTIVE
         return Some(5);
    }
    
    None
}