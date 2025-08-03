<div align="center">
  
![Visitors](https://api.visitorbadge.io/api/visitors?path=https%3A%2F%2Fgithub.com%2Fs0mbra-1973%2FTrevor&label=Counter%20Strike%202%20Cheaters%20Interested%20in%20this%20Injector%3A&labelColor=%23ff8a65&countColor=%23263759)

  <img src="https://i.ibb.co/TBcf6F6z/Trevor-Injector.jpg" alt="Trevor Injector">


# TREVOR Injector v3
![Version](https://img.shields.io/badge/Version-4%20in%20development-orange?style=flat-square)
### Simple & Secure GUI .DLL Injection Tool for Windows 11 for the game Counter Strike 2

![Static Badge](https://img.shields.io/badge/VALVE_ANTICHEAT_VAC3_PROOF-orange)
![Static Badge](https://img.shields.io/badge/FULL_OPEN_SOURCE-green)
![Static Badge](https://img.shields.io/badge/FULL_C%2B%2B-blue)
![Static Badge](https://img.shields.io/badge/FULL_MALWARE_FREE-green)
![Version](https://img.shields.io/badge/Version-3.0-blue)
![Platform](https://img.shields.io/badge/Platform-Windows(x86/x64)-green)
![Static Badge](https://img.shields.io/badge/License-Massachusetts%20Institute%20of%20Technology%20(MIT)-orange)


</div>

## 📌 Overview

- TREVOR Injector is a sophisticated, and easy to use, .DLLs injection tool that uses manual mapping to load .DLLs into target processes (CS2.exe) without relying on LoadLibrary.
- It supports x86 and x64 processes, includes SEH (Structured Exception Handling) support, and cleans up traces after injection for stealth.
- This injector has been specifically designed and adapted for use with Daniel Kuprinski's "Osiris.dll" library, although you can probably inject other .dlls (Osiris.dll is a safe product, be careful with other .dlls of dubious origin).

## 🔑 Key Features

- ✅ VAC3 Proof 
- ✅ Manual Mapping – Bypasses LoadLibrary for stealthier injection
- ✅ Multi-Architecture Support – Works on both 32-bit and 64-bit processes
- ✅ SEH Support – Handles exception directories for stable execution
- ✅ Clean Injection – Removes PE headers & unnecessary sections post-injection
- ✅ Process Privilege Escalation – Automatically enables SE_DEBUG privilege
- ✅ Error Handling – Detailed error messages for debugging

## ⚙️ Technical Details

### 🔧 How It Works

#### Manual Mapping Process

    Reads the target DLL into memory
    Allocates memory in the target process
    Relocates imports, applies base relocations, and handles TLS callbacks
    Executes the DLL's entry point (DllMain)

#### Post-Injection Cleanup

    Optionally removes PE headers
    Cleans unnecessary sections (.pdata, .rsrc, .reloc)
    Adjusts memory protections for stealth

#### Shellcode Execution

    Uses a custom shellcode stub to perform the injection
    Handles exception directories for stability

## 📥 Installation & Usage

### Prerequisites

    Windows 7/10/11 (x86 or x64)
    Visual Studio 2022 (for compilation)
    Administrator privileges (for debugging rights)

### 🛠️ Compilation

    Open the project in Visual Studio
    Build in Release mode (x86 or x64, depending on target)

### 🚀 Usage:

RUN TrevorV3.exe as Administrator, select the .dll file to inject, Press Inject button.

## 📋 Step-by-Step Instructions for Beginners:

1. **Run Counter Strike 2**:
   - The CS2 game must be running and in the main menu, not in a match. 

2. **Download de Latest Release of Trevor Injector**:
   - Download and extract from https://github.com/s0mbra-1973/Trevor/archive/refs/heads/main.zip
   - Compile it with Microsoft Visual Studio or similar.
  
3. **Run TrevorV3.exe as Administrator, select the .dll file to inject, Press Inject button.**



## ⚠️ Is it completely 100% undetectable by Valve's VAC3 Anti-cheat?

Like everything in life, you're never 100% secure. Valve spends millions of dollars preventing the use of cheats.
That said, I've been using it for months without any issues or detections, but it all depends largely on the .DLL you inject.
Osiris.dll (https://github.com/danielkrupinski/Osiris) doesn't cause any problems or get detected, at least for now.

## ⚠️ Why Windows 11 Detects It as a Virus

TrevorV3.exe is a DLL injector that uses manual mapping techniques to inject a dynamic link library (DLL) into the memory space of another process. This type of code is often flagged as malicious by antivirus software, including Microsoft Defender on Windows 11, due to the techniques it employs, such as process memory manipulation, shellcode injection, and remote thread creation, which are common in malware, even though they can also be used for legitimate purposes.

### Suspicious Techniques:
- The use of functions like VirtualAllocEx, WriteProcessMemory, and CreateRemoteThread is typical in malware injectors, triggering Microsoft Defender's heuristic detection.
- Shellcode and manipulation of import tables or relocations may be interpreted as attempts to hide malicious code.
- Temporarily disabling certain memory sections or cleaning PE headers is also considered suspicious behavior.

## ⚠️ How to Validate TrevorV3.exe in Windows 11

To make Windows 11 (and Microsoft Defender) consider TrevorV3.exe or Osiris.dll safe, you can follow these steps:

### Temporarily Disable Real-Time Protection:

- TrevorV3.exe is safe and you’re using it in a controlled environment:
    - Go to Settings > Update & Security > Windows Security > Virus & Threat Protection > Manage Settings.
    - Temporarily disable Real-time protection.
    - Run TrevorV3.exe. 
    - Re-enable real-time protection immediately afterward.
    - Caution: This is not a permanent solution, as it disables protection for all files, which can be risky.

- Add an Exception in Microsoft Defender:
    - If you plan to use this program repeatedly:
    - Go to Windows Security > Virus & Threat Protection > Manage Settings > Exclusions.
    - Add an exclusion for the folder containing the executable or the specific file. (TrevorV3.exe & Osiris.dll)
    - This tells Defender to ignore your program.
    - Caution: Ensure the file is safe before excluding it, as this prevents Defender from scanning it.

## ⚠️ Warning & Limitations

- Anti-Cheat Detection: Manual mapping is stealthier than LoadLibrary, but some anti-cheats may still detect it.
- I am not responsible for any type of damage that may cause to your systems, potential Steam account loss or any other problem you may have.
- 32/64-bit Mismatch: You cannot inject a 64-bit DLL into a 32-bit process (or vice versa).
- Stability: Some DLLs may crash if they rely on certain load-time features.

## 📜 License

This project is licensed under the MIT License.

## 📌 Credits

Developed by s0mbra (June 2025)

This injector is designed and tested for use with Osiris.dll: https://github.com/danielkrupinski/Osiris created by Daniel Krupiński https://github.com/danielkrupinski

Project inspired by https://github.com/TheCruZ/Simple-Manual-Map-Injector
