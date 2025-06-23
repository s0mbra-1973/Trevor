# TREVOR Injector (for CS2 and "Osiris.dll") (June 2025)

![alt text](https://i.ibb.co/TBcf6F6z/Trevor-Injector.jpg "TREVOR .DLL Injector (for Osiris.dll)")

Advanced Manual .DLL Injection Tool for Windows 11 for the game Counter Strike 2

![Version](https://img.shields.io/badge/Version-1.0-blue)
![Platform](https://img.shields.io/badge/Platform-Windows%2520(x86/x64)-green)
![License](https://img.shields.io/badge/License-MIT-orange)

## 📌 Overview

- TREVOR Injector is a sophisticated DLL injection tool that uses manual mapping to load DLLs into target processes without relying on LoadLibrary.
- It supports x86 and x64 processes, includes SEH (Structured Exception Handling) support, and cleans up traces after injection for stealth.
- This injector has been specifically designed and adapted for use with Daniel Kuprinski's "Osiris.dll" library, although you can probably inject other .dlls (Osiris.dll is a safe product, be careful with other .dlls of dubious origin).

## 🔑 Key Features

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

Basic Syntax (As Administrator): Trevor.exe Osiris.dll cs2.exe

## 📋 Step-by-Step Instructions for Beginners:
1. **Run Counter Strike 2**:
   - The CS2 game must be running and in the main menu, not in a match. 

2. **Donwload de Latest Release of Trevor Injector**:
   - Donwload and extract from https://github.com/s0mbra-1973/Trevor/releases/download/Trevor/Trevor.zip
  
3. **Open the Command Prompt as Administrator**:
   - Press `Win + S`, type `cmd`, right-click on "Command Prompt," and select "Run as administrator." This is required because the injector needs administrator privileges to enable `SE_DEBUG` privilege.
   - You’ll see a window with a title like "Administrator: Command Prompt."

4. **Navigate to the Injector’s Folder**:
   - Use the `cd` command to go to the folder where `Trevor.exe` is located.
   - Remember that the .dll library, in this case "Osiris.dll," must be in that same folder.
   - A version of Osiris.dll compiled on June 23, 2025, is included in the Trevor.zip file. However, it is recommended that you compile a more up-to-date version following the instructions in its official repository: https://github.com/danielkrupinski/Osiris

## ⚠️ Warning & Limitations

- Anti-Cheat Detection: Manual mapping is stealthier than LoadLibrary, but some anti-cheats (e.g., BattlEye, EAC) may still detect it.
- I am not responsible for any type of damage that may cause to your systems, potential Steam account loss or any other problem you may have.
- 32/64-bit Mismatch: You cannot inject a 64-bit DLL into a 32-bit process (or vice versa).
- Stability: Some DLLs may crash if they rely on certain load-time features.

## 📜 License

This project is licensed under the MIT License.

## 📌 Credits

Developed by s0mbra (June 2025)

This injector is designed and tested for use with Osiris.dll: https://github.com/danielkrupinski/Osiris created by Daniel Krupiński https://github.com/danielkrupinski

Project inspired by https://github.com/H-zz-H69/cs2-injector
