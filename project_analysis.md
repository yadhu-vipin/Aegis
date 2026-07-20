# Aegis Project Analysis

## File Structure & Contents

```
Aegis/
├── AegisExtension/          # Chrome Extension to intercept downloads
│   ├── manifest.json        # Extension manifest configures permissions
│   ├── background.js        # Cancels browser downloads, sends details to Host
│   └── com.aegis.sandbox.json # Native messaging configuration
│
├── aegis/                   # Rust Backend Native Messaging Host
│   ├── Cargo.toml           # Backend dependencies (tokio, reqwest, winapi)
│   └── src/
│       ├── main.rs          # Manages IPC stream, handles download & quarantine
│       ├── scanner.rs       # Verifies magic bytes, flags Trojan mismatches
│       └── hcs.rs           # Behavioral sandbox (Windows HCS/API monitoring)
│
└── URL/                     # Machine Learning Component
    ├── train.ipynb          # Jupyter notebook for model training
    ├── newtrain.ipynb       # Jupyter notebook for model training
    └── url_gen_*.pt         # PyTorch weights for URL generation/classification
```

---

## Key Issues

1. **Platform Lock (Windows APIs on Linux)**
   * `aegis/Cargo.toml` specifies `winapi` dependency.
   * [hcs.rs](file:///home/yadhu/Documents/Aegis/aegis/src/hcs.rs) imports `std::os::windows::process::CommandExt` and calls WinAPI functions (`CREATE_NO_WINDOW`, `GetExitCodeProcess`).
   * **Result:** Compilation fails on Linux.

2. **Undefined Function Call**
   * [main.rs](file:///home/yadhu/Documents/Aegis/aegis/src/main.rs#L57) calls `scanner::deep_forensic_scan(&chunk, &request.filename, is_first)`.
   * **Result:** Compilation fails because [scanner.rs](file:///home/yadhu/Documents/Aegis/aegis/src/scanner.rs) only defines `scan_file` and `detect_dangerous_intent`.

3. **Hardcoded Windows Paths**
   * Quarantine paths in `main.rs` (`C:\Aegis\quarantine\scan.tmp`) and `hcs.rs` (`C:\Aegis\quarantine\sandbox_exec.exe`) are Windows-specific and will fail on Linux.

---

## Suggested Fixes

1. **Linux compatibility or cross-platform abstraction:**
   * Abstract sandbox/execution layer in [hcs.rs](file:///home/yadhu/Documents/Aegis/aegis/src/hcs.rs) using conditional compilation (`#[cfg(target_os = "windows")]` and `#[cfg(target_os = "linux")]`).
   * Replace Windows `winapi` with Linux-equivalent sandboxing or process monitoring (e.g. `nix`, `libc`, or namespaces).

2. **Reconcile Scanner logic:**
   * Merge or map `deep_forensic_scan` inside `main.rs` to call `scan_file` (which validates headers/extensions) and `detect_dangerous_intent` (which inspects the contents).

3. **Dynamic Paths:**
   * Replace hardcoded Windows paths with standard temporary directory utilities (e.g., using Rust's `std::env::temp_dir()`).
