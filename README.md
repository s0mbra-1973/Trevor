<div align="center">


---

<img src="https://github.com/wyrtensi/TrevorWy/blob/main/TrevorWy/Trevor.bmp" alt="TrevorWy">
<img width="960" height="640" alt="image" src="https://github.com/user-attachments/assets/b176f4c5-473f-4122-914f-e1a66611ba06" />

</div>

---

<div align="center">

ＦＵＬＬ ＯＰＥＮ－ＳＯＵＲＣＥ

</div>

<div align="center">

## Stealth DLL Injector — Manual Mapping + NT API Stealth Layer — Wy Edition

</div>

<div align="center">

![Platform](https://img.shields.io/badge/Platform-Windows%20x64-blue)
![Static Badge](https://img.shields.io/badge/STEALTH_NT_API-blue)
![Static Badge](https://img.shields.io/badge/XOR_TRANSIT_ENCRYPTION-blue)
![Static Badge](https://img.shields.io/badge/ANTI--FORENSIC_CLEANUP-blue)
![Static Badge](https://img.shields.io/badge/HANDLE_HIJACKING-blue)
![Static Badge](https://img.shields.io/badge/FULL_OPEN_SOURCE-blue)
![Static Badge](https://img.shields.io/badge/FULL_MALWARE_FREE-blue)

![Version](https://img.shields.io/badge/Version-6.0--Wy-red)

![Static Badge](https://img.shields.io/badge/License-Massachusetts%20Institute%20of%20Technology%20(MIT)-blue)

</div>

---

## 🙏 Thanks & Credits

> **This project is a fork of [ＴＲＥ▼ＯＲ５ by s0mbra-1973](https://github.com/s0mbra-1973/Trevor), now evolved into TRE▼OR Wy.**
>
> Huge thanks to **s0mbra-1973** and **BLaCKaSS** for creating the original ＴＲＥ▼ＯＲ Injector — the foundation that made all of these improvements possible. The original manual-mapping engine, UI design, and architecture were excellent work. This fork builds on that solid base with stealth hardening, encryption, anti-forensics, handle hijacking, Fluent Design UI, and quality-of-life improvements.
>
> Originally inspired by [TheCruZ/Simple-Manual-Map-Injector](https://github.com/TheCruZ/Simple-Manual-Map-Injector).

---

## 📌 Overview

**ＴＲＥ▼ＯＲ Wy** is a heavily improved fork of the original ＴＲＥ▼ＯＲ５ injector. It uses **NT API syscalls** instead of hooked Win32 functions, **XOR encrypts DLL sections in transit**, and **overwrites all injection artifacts with random bytes** — making it significantly harder for anti-cheat engines to detect while providing a polished user experience.

---

## ⚙️ How It Works

The injection process follows a modular pipeline:

```
┌─────────────────────────────────────────────────────────────┐
│  1. PROCESS ACCESS                                          │
│     NtOpenProcess (stealth) → Handle Hijacking fallback     │
├─────────────────────────────────────────────────────────────┤
│  2. MEMORY ALLOCATION                                       │
│     NtAllocateVirtualMemory as PAGE_READWRITE               │
├─────────────────────────────────────────────────────────────┤
│  3. PE HEADERS + SECTIONS WRITE                             │
│     Headers written plain → Sections XOR-encrypted in       │
│     local buffer → NtWriteVirtualMemory → Upgrade to RWX   │
├─────────────────────────────────────────────────────────────┤
│  4. SHELLCODE DEPLOYMENT                                    │
│     Shellcode allocated (RWX) → XOR decrypts sections       │
│     in-place → Resolves imports → Calls DllMain             │
├─────────────────────────────────────────────────────────────┤
│  5. ANTI-FORENSIC CLEANUP                                   │
│     PE headers → random bytes │ Shellcode → random bytes    │
│     Mapping data → random bytes │ Self-erase via            │
│     RtlZeroMemory │ Section protections adjusted            │
└─────────────────────────────────────────────────────────────┘
```

### Process Access Strategy

The injector uses a 3-step escalation strategy for acquiring a process handle:

1. **NtOpenProcess** with minimum rights (`PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ | PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION`)
2. **NtOpenProcess** with `PROCESS_ALL_ACCESS` (fallback)
3. **Handle Hijacking** — scans the system handle table via `NtQuerySystemInformation(SystemExtendedHandleInformation)`, finds process handles held by system services (`services.exe`, `svchost.exe`, `explorer.exe`, etc.), duplicates them via `NtDuplicateObject`, and optionally escalates access rights

### Watch & Early Injection

For anti-cheat-protected games, the **Watch mode** (`⏱ Watch`) polls for the target process to start, then injects **immediately** (~400ms after detection) — before the anti-cheat driver initializes.

---

## 🔥 What Changed From the Original (v5 → v6 Wy)

### ️ NT API Stealth Layer
- All injection operations use direct NT API calls resolved dynamically from `ntdll.dll`:
  - `NtAllocateVirtualMemory`, `NtWriteVirtualMemory`, `NtReadVirtualMemory`
  - `NtFreeVirtualMemory`, `NtProtectVirtualMemory`
  - `NtCreateThreadEx`, `NtWaitForSingleObject`
  - `NtOpenProcess`, `NtQuerySystemInformation`, `NtDuplicateObject`
- Win32 fallback if any NT API fails to resolve

### 🔓 Handle Hijacking
- Scans system handle table for existing process handles held by system services
- Duplicates and optionally escalates access rights
- Bypasses anti-cheat process protection that blocks `OpenProcess`

### 🔐 XOR Transit Encryption
- Random 1-byte XOR key per session
- DLL sections encrypted in local buffer before `NtWriteVirtualMemory`
- Shellcode decrypts sections in-place inside the target process
- Headers written plain for shellcode parsing, then overwritten with random bytes

### 🧹 Anti-Forensic Cleanup
- PE headers, shellcode, and mapping data overwritten with **random bytes** (not zeroes)
- Shellcode self-erases `MANUAL_MAPPING_DATA` via `RtlZeroMemory`
- Section protections adjusted to match PE characteristics

### ⏱️ Watch & Early Injection
- Process watcher thread monitors for target process startup
- Injects ~400ms after process detection, before anti-cheat loads
- Fully automatic — select process name, click Watch, start the game

### 🎯 Exe Rename on Launch
- Executable renames itself to `svc_XXXXXXXX.exe` (8 random alphanumeric chars)
- Defeats process-name-based detection rules

---

## 🔑 Key Features

| Feature | Description |
|---------|-------------|
| **NT API Stealth** | Bypasses user-mode hooks by calling ntdll directly |
| **Manual Mapping** | No `LoadLibrary` — DLL never appears in module lists |
| **Handle Hijacking** | Duplicates system process handles when `OpenProcess` is blocked |
| **XOR Transit** | Sections encrypted during write, decrypted in-place by shellcode |
| **Anti-Forensic** | Headers + artifacts overwritten with random bytes, then freed |
| **Self-Erase** | Shellcode zeros its own mapping data after DllMain returns |
| **Anti-Timing** | Random delay before shellcode execution |
| **Watch Mode** | Early injection before anti-cheat initializes |
| **SEH Support** | Handles exception directories via `RtlAddFunctionTable` |
| **Architecture Check** | Validates DLL matches target process (x64/x86) |
| **Privilege Escalation** | Auto-enables `SeDebugPrivilege` |
| **Drag & Drop** | Drop `.dll` files directly onto the window |
| **Session Persistence** | Remembers last process + DLL in `Injector.ini` |

---

## 📥 Installation & Usage

### Prerequisites
- **Windows 10/11 (x64)**
- **Microsoft Visual Studio 2022** (for compilation)
- **Administrator privileges** (required for injection)

### 🛠️ Compilation
1. Open `trevorwy.sln` in Visual Studio 2022
2. Select **Release | x64**
3. Build → Build Solution (`Ctrl+Shift+B`)
4. Output: `x64\Release\trevorwy.exe`

### 🚀 Usage

#### Standard Injection
1. **Start your target application** (game, etc.)
2. **Right-click** `trevorwy.exe` → **Run as Administrator**
3. **Select the target process** from the dropdown (or click ↻ Refresh)
4. **Browse for a DLL** or drag-and-drop it onto the window
5. Click **⚡ INJECT** and confirm
6. Wait for the green `✔ INJECTION SUCCESSFUL` message
7. The injector auto-closes after 5 seconds

#### Early Injection (Watch Mode)
1. **Right-click** `trevorwy.exe` → **Run as Administrator**
2. **Type or select the target process name** (e.g., `app.exe`)
3. **Select your DLL** via Browse or drag-and-drop
4. Click **⏱ Watch**
5. **Start the game** — injection happens automatically on existing name match, ~400ms after process creation

---

### ⚠️ Warnings & Limitations

- **Anti-cheat detection**: NT API stealth + manual mapping + handle hijacking significantly reduce detection risk, but no method is 100% undetectable. Kernel-level anti-cheats (e.g., Vanguard, EAC) may still detect.
- **x64 only**: This build targets 64-bit processes. The x86 configuration has known compatibility issues with x64-only API types.
- **DLL stability**: Some DLLs may crash if they rely on certain load-time features not handled by manual mapping.
- **Windows Defender**: Will flag this as suspicious due to `NtAllocateVirtualMemory`, `NtCreateThreadEx`, shellcode injection, and import table manipulation. Add an exclusion for the folder if you trust the code.
- **I am not responsible** for any damage, account bans, or other consequences of using this tool.

### 🛡️ Windows Defender Exclusion
1. Go to **Settings → Windows Security → Virus & Threat Protection → Manage Settings → Exclusions**
2. Add the folder containing `trevorwy.exe`
3. This prevents Defender from quarantining the injector

---

### 📜 MIT License

<div align="center">

![Static Badge](https://img.shields.io/badge/License-Massachusetts%20Institute%20of%20Technology%20(MIT)-orange)

</div>

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

---

<div align="center">

### 📌 Credits

**Original ＴＲＥ▼ＯＲ Injector** by **[s0mbra-1973](https://github.com/s0mbra-1973)** & **BLaCKaSS**

**Wy Edition** improvements by **Wyrtensi**

Stealth improvements, NT API layer, XOR transit encryption, handle hijacking, anti-forensic cleanup, and bug fixes by the community.

Originally inspired by [TheCruZ/Simple-Manual-Map-Injector](https://github.com/TheCruZ/Simple-Manual-Map-Injector)

</div>
