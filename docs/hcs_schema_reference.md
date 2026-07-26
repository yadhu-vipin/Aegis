# Windows HCS Schema Reference & API Integration Guide

This document references the Windows Host Compute Service (HCS) v2 schema used in `aegis-host/src/sandbox/windows_hcs.rs`.

---

## 1. HCS v2 Container Configuration Schema

When `windows_hcs.rs` invokes `HcsCreateComputeSystem`, it passes a JSON configuration matching the HCS v2 schema:

```json
{
  "SchemaVersion": {
    "Major": 2,
    "Minor": 1
  },
  "Owner": "aegis-host",
  "GuestOs": {
    "HostName": "aegis-sandbox"
  },
  "Storage": {
    "Layers": [
      {
        "Id": "00000000-0000-0000-0000-000000000000",
        "Path": "C:\\ProgramData\\Microsoft\\Windows\\Images\\NanoServer"
      }
    ],
    "ScratchVhd": {
      "Path": "C:\\Users\\...\\AppData\\Local\\Temp\\aegis_scratch_UUID.vhdx",
      "CreateInstead": true,
      "SizeInGB": 2
    }
  },
  "Networking": {},
  "Processor": {
    "Count": 1
  },
  "Memory": {
    "SizeInMB": 512
  }
}
```

---

## 2. Windows HCS API Reference Calls

| HCS API Function | Module / Crate Feature | Purpose in Aegis |
|---|---|---|
| `HcsCreateComputeSystem` | `Win32_System_HostComputeSystem` | Allocates and initializes the guest container compute system |
| `HcsStartComputeSystem` | `Win32_System_HostComputeSystem` | Boots the container with the scratch VHDX layer |
| `HcsCreateProcess` | `Win32_System_HostComputeSystem` | Executes the quarantined binary inside guest container space |
| `HcsGetComputeSystemProperties` | `Win32_System_HostComputeSystem` | Queries guest state, memory stats, and exit status |
| `HcsTerminateComputeSystem` | `Win32_System_HostComputeSystem` | Forcefully halts container execution upon timeout or completion |
| `HcsCloseComputeSystem` | `Win32_System_HostComputeSystem` | Releases OS handle for compute system |

---

## 3. Manual Verification Checklist for Windows 11 Deployment

When testing on a real Windows 11 host:
1. Ensure **Containers** and **Hyper-V** optional features are enabled (`Enable-WindowsOptionalFeature -Online -FeatureName Containers, Microsoft-Hyper-V`).
2. Verify base container layer exists at configured path (e.g. NanoServer or ServerCore base image).
3. Run `cargo build --release` under `x86_64-pc-windows-msvc` toolchain.
4. Execute `scripts/install_native_host.ps1` to create registry key under `HKCU:\Software\Google\Chrome\NativeMessagingHosts\com.aegis.sandbox`.
5. Trigger download of an `.exe` disguised as `.jpg` in Chrome to confirm HCS container creation in Task Manager / Hyper-V Manager.
