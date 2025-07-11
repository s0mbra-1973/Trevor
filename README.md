# TREVOR V2 | Simple & Secure GUI .DLL Injector for CS2 | VAC3 Proof

![alt text](https://i.ibb.co/TBcf6F6z/Trevor-Injector.jpg "TREVOR .DLL Injector (for Osiris.dll)")

GUI .DLL Injection Tool for Windows 11 for the game Counter Strike 2

![Version](https://img.shields.io/badge/Version-2.0-blue)
![Platform](https://img.shields.io/badge/Platform-Windows%2520(x86/x64)-green)
![License](https://img.shields.io/badge/License-MIT-orange)

## 📌 Overview

- TREVOR Injector is a sophisticated, and easy to use, .DLLs injection tool that uses manual mapping to load .DLLs into target processes without relying on LoadLibrary.
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

RUN TrevorV2.exe, select the .dll file to inject, Press Inject button.

## 📋 Step-by-Step Instructions for Beginners:

1. **Run Counter Strike 2**:
   - The CS2 game must be running and in the main menu, not in a match. 

2. **Download de Latest Release of Trevor Injector**:
   - Download and extract from https://github.com/s0mbra-1973/Trevor/releases/download/untagged-ce6217dba9d963ccc905/TrevorV2.zip
  
3. **Run TrevorV2.exe as Administrator, select the .dll file to inject, Press Inject button.

   - A version of Osiris.dll compiled on June, 2025, is included in the TrevorV2.zip file. However, it is recommended that you compile a more up-to-date version following the instructions in its official repository: https://github.com/danielkrupinski/Osiris

## ⚠️ Why Windows 11 Detects It as a Virus

TrevorV2.exe d is a DLL injector that uses manual mapping techniques to inject a dynamic link library (DLL) into the memory space of another process. This type of code is often flagged as malicious by antivirus software, including Microsoft Defender on Windows 11, due to the techniques it employs, such as process memory manipulation, shellcode injection, and remote thread creation, which are common in malware, even though they can also be used for legitimate purposes.

### Suspicious Techniques:
- The use of functions like VirtualAllocEx, WriteProcessMemory, and CreateRemoteThread is typical in malware injectors, triggering Microsoft Defender's heuristic detection.
- Shellcode and manipulation of import tables or relocations may be interpreted as attempts to hide malicious code.
- Temporarily disabling certain memory sections or cleaning PE headers is also considered suspicious behavior.

## ⚠️ How to Validate TrevorV2.exe in Windows 11

To make Windows 11 (and Microsoft Defender) consider TrevorV2.exe or Osiris.dll safe, you can follow these steps:

### Temporarily Disable Real-Time Protection:

- TrevorV2.exe is safe and you’re using it in a controlled environment:
    - Go to Settings > Update & Security > Windows Security > Virus & Threat Protection > Manage Settings.
    - Temporarily disable Real-time protection.
    - Run TrevorV2.exe. 
    - Re-enable real-time protection immediately afterward.
    - Caution: This is not a permanent solution, as it disables protection for all files, which can be risky.

- Add an Exception in Microsoft Defender:
    - If you plan to use this program repeatedly:
    - Go to Windows Security > Virus & Threat Protection > Manage Settings > Exclusions.
    - Add an exclusion for the folder containing the executable or the specific file. (TrevorV2.exe & Osiris.dll)
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

Project inspired by https://github.com/H-zz-H69/cs2-injector
