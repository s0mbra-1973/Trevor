#include <Windows.h>
#include <winnt.h>
#include <TlHelp32.h>
#include <fstream>
#include <thread>
#include <chrono>
#include <string>
#include <iostream>
#include <vector>
#include <locale>
#include <codecvt>

using namespace std;

#if defined(_MSC_VER) && (_MSC_VER >= 1900)
#define NOEXCEPT noexcept
#else
#define NOEXCEPT
#endif

using f_LoadLibraryA = HINSTANCE(WINAPI*)(LPCSTR lpLibFilename);
using f_GetProcAddress = FARPROC(WINAPI*)(HMODULE hModule, LPCSTR lpProcName);
using f_DLL_ENTRY_POINT = BOOL(WINAPI*)(void* hDll, DWORD dwReason, void* pReserved);
using f_RtlAddFunctionTable = BOOLEAN(WINAPI*)(PRUNTIME_FUNCTION FunctionTable, DWORD EntryCount, DWORD64 BaseAddress);

struct MANUAL_MAPPING_DATA {
    f_LoadLibraryA pLoadLibraryA;
    f_GetProcAddress pGetProcAddress;
    f_RtlAddFunctionTable pRtlAddFunctionTable;
    BYTE* pBase;
    HINSTANCE hMod;
    DWORD dwReason;
    LPVOID lpReserved;
    BOOL bSEHSupport;
};

class HandleGuard {
    HANDLE m_handle;
public:
    explicit HandleGuard(HANDLE h = nullptr) : m_handle(h) {}
    ~HandleGuard() { if (m_handle && m_handle != INVALID_HANDLE_VALUE) CloseHandle(m_handle); }
    HandleGuard(const HandleGuard&) = delete;
    HandleGuard& operator=(const HandleGuard&) = delete;
    HANDLE get() const { return m_handle; }
    operator HANDLE() const { return m_handle; }
    void reset(HANDLE h = nullptr) {
        if (m_handle && m_handle != INVALID_HANDLE_VALUE) CloseHandle(m_handle);
        m_handle = h;
    }
};

void SetConsoleColor(int color) {
    SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), color);
}

void TypewriterEffect(const string& message, int delay_ms = 20) {
    for (char c : message) {
        cout << c << flush;
        this_thread::sleep_for(chrono::milliseconds(delay_ms));
    }
}

// Architecture check functions
BOOL Is64BitWindows() {
    SYSTEM_INFO si;
    GetNativeSystemInfo(&si);
    return (si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64);
}

BOOL Is64BitProcess(HANDLE hProcess, PBOOL isWow64) {
    if (!Is64BitWindows()) {
        *isWow64 = FALSE;
        return TRUE;
    }
    return IsWow64Process(hProcess, isWow64);
}

bool IsCorrectArchitecture(HANDLE hProcess) {
    if (!Is64BitWindows()) return true;

    BOOL isTargetWow64 = FALSE;
    if (!Is64BitProcess(hProcess, &isTargetWow64)) {
        SetConsoleColor(12);
        cout << "[-] Error checking architecture: 0x" << hex << GetLastError() << endl;
        return false;
    }

    BOOL isHostWow64 = FALSE;
    Is64BitProcess(GetCurrentProcess(), &isHostWow64);

    return isTargetWow64 == isHostWow64;
}

DWORD GetPIDByName(const wstring& name) {
    PROCESSENTRY32W entry = { sizeof(PROCESSENTRY32W) };
    HandleGuard snapshot(CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0));
    if (snapshot.get() == INVALID_HANDLE_VALUE) return 0;

    if (Process32FirstW(snapshot, &entry)) {
        do {
            if (_wcsicmp(entry.szExeFile, name.c_str()) == 0)
                return entry.th32ProcessID;
        } while (Process32NextW(snapshot, &entry));
    }
    return 0;
}

#define RELOC_FLAG(RelInfo) ((RelInfo >> 0x0C) == IMAGE_REL_BASED_DIR64)

#pragma runtime_checks("", off)
#pragma optimize("", off)
void __stdcall Shellcode(MANUAL_MAPPING_DATA* pData) {
    if (!pData) {
        if (pData) pData->hMod = reinterpret_cast<HINSTANCE>(0x404040);
        return;
    }

    BYTE* pBase = pData->pBase;
    IMAGE_DOS_HEADER* pDosHeader = reinterpret_cast<IMAGE_DOS_HEADER*>(pBase);
    IMAGE_NT_HEADERS* pNtHeaders = reinterpret_cast<IMAGE_NT_HEADERS*>(pBase + pDosHeader->e_lfanew);
    IMAGE_OPTIONAL_HEADER* pOptionalHeader = &pNtHeaders->OptionalHeader;

    auto pLoadLibrary = pData->pLoadLibraryA;
    auto pGetProcAddress = pData->pGetProcAddress;
    auto pRtlAddFunctionTable = pData->pRtlAddFunctionTable;
    auto DllEntry = reinterpret_cast<f_DLL_ENTRY_POINT>(pBase + pOptionalHeader->AddressOfEntryPoint);

    uintptr_t delta = reinterpret_cast<uintptr_t>(pBase) - pOptionalHeader->ImageBase;
    if (delta != 0 && pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size) {
        auto* pRelocData = reinterpret_cast<IMAGE_BASE_RELOCATION*>(pBase + pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
        auto* pRelocEnd = reinterpret_cast<IMAGE_BASE_RELOCATION*>(reinterpret_cast<BYTE*>(pRelocData) + pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size);
        while (pRelocData < pRelocEnd && pRelocData->SizeOfBlock) {
            UINT count = (pRelocData->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
            WORD* pRelativeInfo = reinterpret_cast<WORD*>(pRelocData + 1);
            for (UINT i = 0; i < count; ++i, ++pRelativeInfo) {
                if (RELOC_FLAG(*pRelativeInfo)) {
                    uintptr_t* pPatch = reinterpret_cast<uintptr_t*>(pBase + pRelocData->VirtualAddress + ((*pRelativeInfo) & 0xFFF));
                    *pPatch += static_cast<uintptr_t>(delta);
                }
            }
            pRelocData = reinterpret_cast<IMAGE_BASE_RELOCATION*>(reinterpret_cast<BYTE*>(pRelocData) + pRelocData->SizeOfBlock);
        }
    }

    if (pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size) {
        auto* pImportDesc = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(pBase + pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
        while (pImportDesc->Name) {
            char* szMod = reinterpret_cast<char*>(pBase + pImportDesc->Name);
            HINSTANCE hDll = pLoadLibrary(szMod);
            ULONG_PTR* pThunkRef = reinterpret_cast<ULONG_PTR*>(pBase + pImportDesc->OriginalFirstThunk);
            ULONG_PTR* pFuncRef = reinterpret_cast<ULONG_PTR*>(pBase + pImportDesc->FirstThunk);
            if (!pThunkRef) pThunkRef = pFuncRef;
            for (; *pThunkRef; ++pThunkRef, ++pFuncRef) {
                if (IMAGE_SNAP_BY_ORDINAL(*pThunkRef)) {
                    *pFuncRef = reinterpret_cast<ULONG_PTR>(pGetProcAddress(hDll, reinterpret_cast<char*>(*pThunkRef & 0xFFFF)));
                }
                else {
                    auto* pImport = reinterpret_cast<IMAGE_IMPORT_BY_NAME*>(pBase + *pThunkRef);
                    *pFuncRef = reinterpret_cast<ULONG_PTR>(pGetProcAddress(hDll, pImport->Name));
                }
            }
            ++pImportDesc;
        }
    }

    if (pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size) {
        auto* pTls = reinterpret_cast<IMAGE_TLS_DIRECTORY*>(pBase + pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress);
        auto* pCallback = reinterpret_cast<PIMAGE_TLS_CALLBACK*>(pTls->AddressOfCallBacks);
        while (pCallback && *pCallback) {
            (*pCallback)(pBase, DLL_PROCESS_ATTACH, nullptr);
            ++pCallback;
        }
    }

    bool bExceptionSupportFailed = false;
    if (pData->bSEHSupport && pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].Size) {
        auto* pExceptionTable = reinterpret_cast<PRUNTIME_FUNCTION>(pBase + pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].VirtualAddress);
        DWORD entryCount = pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].Size / sizeof(RUNTIME_FUNCTION);
        if (!pRtlAddFunctionTable(pExceptionTable, entryCount, reinterpret_cast<DWORD64>(pBase))) {
            bExceptionSupportFailed = true;
        }
    }

    DllEntry(pBase, pData->dwReason, pData->lpReserved);
    pData->hMod = bExceptionSupportFailed ? reinterpret_cast<HINSTANCE>(0x505050) : reinterpret_cast<HINSTANCE>(pBase);
}
#pragma optimize("", on)
#pragma runtime_checks("", restore)

vector<BYTE> LoadDLL(const wstring& dllPath) {
    ifstream file(dllPath, ios::binary | ios::ate);
    if (!file.is_open())
        throw runtime_error("Could not open DLL file");
    auto fileSize = file.tellg();
    if (fileSize < 0x1000) {
        file.close();
        throw runtime_error("Invalid DLL file size");
    }
    vector<BYTE> dllData(static_cast<size_t>(fileSize));
    file.seekg(0, ios::beg);
    file.read(reinterpret_cast<char*>(dllData.data()), fileSize);
    file.close();
    return dllData;
}

bool ManualMapDLL(HANDLE hProcess, BYTE* pSourceData, SIZE_T fileSize, bool cleanHeader = true,
    bool cleanUnneededSections = true, bool adjustProtections = true, bool sehSupport = true,
    DWORD reason = DLL_PROCESS_ATTACH, LPVOID reserved = nullptr) {

    system("chcp 65001 >NUL");
    SetConsoleColor(10);
    TypewriterEffect("[+] Welcome to TREVOR Injector v1.0 2025!\n");

    IMAGE_DOS_HEADER* pDosHeader = reinterpret_cast<IMAGE_DOS_HEADER*>(pSourceData);
    if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        SetConsoleColor(12);
        cout << "[-] Invalid file (no MZ signature)\n";
        return false;
    }

    IMAGE_NT_HEADERS* pNtHeaders = reinterpret_cast<IMAGE_NT_HEADERS*>(pSourceData + pDosHeader->e_lfanew);
    IMAGE_OPTIONAL_HEADER* pOptionalHeader = &pNtHeaders->OptionalHeader;
    IMAGE_FILE_HEADER* pFileHeader = &pNtHeaders->FileHeader;

#ifdef _WIN64
    if (pFileHeader->Machine != IMAGE_FILE_MACHINE_AMD64) {
#else
    if (pFileHeader->Machine != IMAGE_FILE_MACHINE_I386) {
#endif
        SetConsoleColor(12);
        cout << "[-] Invalid file architecture\n";
        return false;
    }

    cout << "[+] Valid file\n";

    BYTE* pTargetBase = reinterpret_cast<BYTE*>(VirtualAllocEx(hProcess, nullptr, pOptionalHeader->SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
    if (!pTargetBase) {
        SetConsoleColor(12);
        cout << "[-] Error allocating process memory: 0x" << hex << GetLastError() << endl;
        return false;
    }

    DWORD oldProtect = 0;
    if (!VirtualProtectEx(hProcess, pTargetBase, pOptionalHeader->SizeOfImage, PAGE_EXECUTE_READWRITE, &oldProtect)) {
        SetConsoleColor(12);
        cout << "[-] Error setting memory protection: 0x" << hex << GetLastError() << endl;
        VirtualFreeEx(hProcess, pTargetBase, 0, MEM_RELEASE);
        return false;
    }

    MANUAL_MAPPING_DATA mappingData = { 0 };
    mappingData.pLoadLibraryA = LoadLibraryA;
    mappingData.pGetProcAddress = GetProcAddress;
    mappingData.pRtlAddFunctionTable = reinterpret_cast<f_RtlAddFunctionTable>(GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "RtlAddFunctionTable"));
    mappingData.pBase = pTargetBase;
    mappingData.dwReason = reason;
    mappingData.lpReserved = reserved;
    mappingData.bSEHSupport = sehSupport;

    if (!WriteProcessMemory(hProcess, pTargetBase, pSourceData, 0x1000, nullptr)) {
        SetConsoleColor(12);
        cout << "[-] Error writing PE header: 0x" << hex << GetLastError() << endl;
        VirtualFreeEx(hProcess, pTargetBase, 0, MEM_RELEASE);
        return false;
    }

    IMAGE_SECTION_HEADER* pSectionHeader = IMAGE_FIRST_SECTION(pNtHeaders);
    for (UINT i = 0; i < pFileHeader->NumberOfSections; ++i, ++pSectionHeader) {
        if (pSectionHeader->SizeOfRawData) {
            if (!WriteProcessMemory(hProcess, pTargetBase + pSectionHeader->VirtualAddress,
                pSourceData + pSectionHeader->PointerToRawData, pSectionHeader->SizeOfRawData, nullptr)) {
                SetConsoleColor(12);
                cout << "[-] Error mapping section: 0x" << hex << GetLastError() << endl;
                VirtualFreeEx(hProcess, pTargetBase, 0, MEM_RELEASE);
                return false;
            }
        }
    }

    BYTE* pMappingDataAlloc = reinterpret_cast<BYTE*>(VirtualAllocEx(hProcess, nullptr, sizeof(MANUAL_MAPPING_DATA), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
    if (!pMappingDataAlloc) {
        SetConsoleColor(12);
        cout << "[-] Error allocating mapping data memory: 0x" << hex << GetLastError() << endl;
        VirtualFreeEx(hProcess, pTargetBase, 0, MEM_RELEASE);
        return false;
    }

    if (!WriteProcessMemory(hProcess, pMappingDataAlloc, &mappingData, sizeof(MANUAL_MAPPING_DATA), nullptr)) {
        SetConsoleColor(12);
        cout << "[-] Error writing mapping data: 0x" << hex << GetLastError() << endl;
        VirtualFreeEx(hProcess, pTargetBase, 0, MEM_RELEASE);
        VirtualFreeEx(hProcess, pMappingDataAlloc, 0, MEM_RELEASE);
        return false;
    }

    void* pShellcode = VirtualAllocEx(hProcess, nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!pShellcode) {
        SetConsoleColor(12);
        cout << "[-] Error allocating shellcode memory: 0x" << hex << GetLastError() << endl;
        VirtualFreeEx(hProcess, pTargetBase, 0, MEM_RELEASE);
        VirtualFreeEx(hProcess, pMappingDataAlloc, 0, MEM_RELEASE);
        return false;
    }

    if (!WriteProcessMemory(hProcess, pShellcode, Shellcode, 0x1000, nullptr)) {
        SetConsoleColor(12);
        cout << "[-] Error writing shellcode: 0x" << hex << GetLastError() << endl;
        VirtualFreeEx(hProcess, pTargetBase, 0, MEM_RELEASE);
        VirtualFreeEx(hProcess, pMappingDataAlloc, 0, MEM_RELEASE);
        VirtualFreeEx(hProcess, pShellcode, 0, MEM_RELEASE);
        return false;
    }

    HandleGuard hThread(CreateRemoteThread(hProcess, nullptr, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(pShellcode), pMappingDataAlloc, 0, nullptr));
    if (!hThread) {
        SetConsoleColor(12);
        cout << "[-] Error creating remote thread: 0x" << hex << GetLastError() << endl;
        VirtualFreeEx(hProcess, pTargetBase, 0, MEM_RELEASE);
        VirtualFreeEx(hProcess, pMappingDataAlloc, 0, MEM_RELEASE);
        VirtualFreeEx(hProcess, pShellcode, 0, MEM_RELEASE);
        return false;
    }

    SetConsoleColor(10);
    cout << "[+] Injection completed successfully\n";

    HINSTANCE hModule = nullptr;
    while (!hModule) {
        DWORD exitCode = 0;
        GetExitCodeProcess(hProcess, &exitCode);
        if (exitCode != STILL_ACTIVE) {
            SetConsoleColor(12);
            cout << "[-] Target process terminated, exit code: " << dec << exitCode << endl;
            return false;
        }

        MANUAL_MAPPING_DATA data = { 0 };
        ReadProcessMemory(hProcess, pMappingDataAlloc, &data, sizeof(data), nullptr);
        hModule = data.hMod;

        if (hModule == reinterpret_cast<HINSTANCE>(0x404040)) {
            SetConsoleColor(12);
            cout << "[-] Mapping pointer error\n";
            VirtualFreeEx(hProcess, pTargetBase, 0, MEM_RELEASE);
            VirtualFreeEx(hProcess, pMappingDataAlloc, 0, MEM_RELEASE);
            VirtualFreeEx(hProcess, pShellcode, 0, MEM_RELEASE);
            return false;
        }
        else if (hModule == reinterpret_cast<HINSTANCE>(0x505050)) {
            SetConsoleColor(14);
            cout << "[!] Warning: Exception support failed\n";
        }
        this_thread::sleep_for(chrono::milliseconds(10));
    }

    vector<BYTE> cleanBuffer(1024 * 1024, 0);

    if (cleanHeader) {
        if (!WriteProcessMemory(hProcess, pTargetBase, cleanBuffer.data(), 0x1000, nullptr))
            SetConsoleColor(14), cout << "[!] Warning: Could not clean PE header\n";
    }

    if (cleanUnneededSections) {
        pSectionHeader = IMAGE_FIRST_SECTION(pNtHeaders);
        for (UINT i = 0; i < pFileHeader->NumberOfSections; ++i, ++pSectionHeader) {
            if (pSectionHeader->Misc.VirtualSize) {
                bool isUnneededSection = (sehSupport ? false : strcmp(reinterpret_cast<char*>(pSectionHeader->Name), ".pdata") == 0) ||
                    strcmp(reinterpret_cast<char*>(pSectionHeader->Name), ".rsrc") == 0 ||
                    strcmp(reinterpret_cast<char*>(pSectionHeader->Name), ".reloc") == 0;
                if (isUnneededSection) {
                    SetConsoleColor(14);
                    cout << "[!] Removing section: " << pSectionHeader->Name << endl;
                    if (!WriteProcessMemory(hProcess, pTargetBase + pSectionHeader->VirtualAddress, cleanBuffer.data(), pSectionHeader->Misc.VirtualSize, nullptr))
                        cout << "[-] Error cleaning section " << pSectionHeader->Name << ": 0x" << hex << GetLastError() << endl;
                }
            }
        }
    }

    if (adjustProtections) {
        pSectionHeader = IMAGE_FIRST_SECTION(pNtHeaders);
        for (UINT i = 0; i < pFileHeader->NumberOfSections; ++i, ++pSectionHeader) {
            if (pSectionHeader->Misc.VirtualSize) {
                DWORD newProtect = PAGE_READONLY;
                if (pSectionHeader->Characteristics & IMAGE_SCN_MEM_WRITE)
                    newProtect = PAGE_READWRITE;
                else if (pSectionHeader->Characteristics & IMAGE_SCN_MEM_EXECUTE)
                    newProtect = PAGE_EXECUTE_READ;

                DWORD oldProtect = 0;
                if (!VirtualProtectEx(hProcess, pTargetBase + pSectionHeader->VirtualAddress, pSectionHeader->Misc.VirtualSize, newProtect, &oldProtect))
                    SetConsoleColor(12), cout << "[-] Error setting section " << pSectionHeader->Name << " as 0x" << hex << newProtect << endl;
                else
                    SetConsoleColor(14), cout << "[!] Section " << pSectionHeader->Name << " set as 0x" << hex << newProtect << endl;
            }
        }
        DWORD oldProtect = 0;
        if (!VirtualProtectEx(hProcess, pTargetBase, IMAGE_FIRST_SECTION(pNtHeaders)->VirtualAddress, PAGE_READONLY, &oldProtect))
            SetConsoleColor(12), cout << "[-] Error setting header protection: 0x" << hex << GetLastError() << endl;
    }

    if (!WriteProcessMemory(hProcess, pShellcode, cleanBuffer.data(), 0x1000, nullptr))
        SetConsoleColor(14), cout << "[!] Warning: Could not clean shellcode\n";
    if (!VirtualFreeEx(hProcess, pShellcode, 0, MEM_RELEASE))
        SetConsoleColor(14), cout << "[!] Warning: Could not free shellcode memory\n";
    if (!VirtualFreeEx(hProcess, pMappingDataAlloc, 0, MEM_RELEASE))
        SetConsoleColor(14), cout << "[!] Warning: Could not free mapping data memory\n";

    return true;
    }

int wmain(int argc, wchar_t* argv[]) {
    try {
        locale::global(locale(""));
        wcout.imbue(locale());

        wstring dllPath;
        DWORD pid = 0;

        if (argc == 3) {
            dllPath = argv[1];
            pid = GetPIDByName(argv[2]);
        }
        else if (argc == 2) {
            dllPath = argv[1];
            wcout << L"[-] Process not specified. Enter process name: ";
            wstring processName;
            getline(wcin, processName);
            pid = GetPIDByName(processName);
        }
        else {
            SetConsoleColor(12);
            wcout << L"Usage: injector.exe <dll_path> <process_name>\n";
            system("pause");
            return -1;
        }

        if (pid == 0) {
            SetConsoleColor(12);
            wcout << L"[-] Process not found\n";
            system("pause");
            return -2;
        }

        wcout << L"[+] Injecting into process with PID: " << pid << endl;

        HandleGuard hToken;
        HANDLE hTokenTemp = nullptr;
        if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hTokenTemp)) {
            hToken.reset(hTokenTemp);
            TOKEN_PRIVILEGES privileges = { 0 };
            privileges.PrivilegeCount = 1;
            privileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
            if (LookupPrivilegeValue(nullptr, SE_DEBUG_NAME, &privileges.Privileges[0].Luid))
                AdjustTokenPrivileges(hToken, FALSE, &privileges, 0, nullptr, nullptr);
        }

        HandleGuard hProcess(OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid));
        if (!hProcess) {
            SetConsoleColor(12);
            wcout << L"[-] Error opening process: 0x" << hex << GetLastError() << endl;
            system("pause");
            return -3;
        }

        if (!IsCorrectArchitecture(hProcess)) {
            SetConsoleColor(12);
            wcout << L"[-] Process architecture not compatible\n";
            system("pause");
            return -4;
        }

        vector<BYTE> dllData;
        try {
            dllData = LoadDLL(dllPath);
        }
        catch (const exception& e) {
            SetConsoleColor(12);
            wcout << L"[-] Error loading DLL: " << e.what() << endl;
            system("pause");
            return -5;
        }

        wcout << L"[+] Injecting DLL...\n";
        if (!ManualMapDLL(hProcess, dllData.data(), dllData.size())) {
            SetConsoleColor(12);
            wcout << L"[-] Error during injection\n";
            system("pause");
            return -6;
        }

        SetConsoleColor(10);
        wcout << L"[+] Injection complete. Created by s0mbra (c) 2025\n";
    }
    catch (const exception& e) {
        SetConsoleColor(12);
        wcout << L"[-] Unexpected error: " << e.what() << endl;
        return -99;
    }

    system("pause");
    return 0;
}
