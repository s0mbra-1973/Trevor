#include "resource.h"
#include <Windows.h>
#include <winnt.h>
#include <TlHelp32.h>
#include <fstream>
#include <thread>
#include <chrono>
#include <string>
#include <vector>
#include <locale>
#include <codecvt>
#include <Mmsystem.h>
#include <Richedit.h>
#include <CommCtrl.h>
#include <Shlwapi.h>
#include <random>
#include <ctime>
#include <iomanip>
#include <sstream>
#pragma comment(lib, "winmm.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "gdi32.lib")
#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "msimg32.lib")

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

// Function declarations
string XorDecrypt(const string& input, char key);
string GetObfuscatedString(const string& str);
wstring GetCurrentTimestamp();
void UpdateStatus(const wstring& message, COLORREF color);
void LogToMemory(const wstring& message);

// Global variables
HWND g_hwndMain;
HWND g_hwndStatus;
HWND g_hwndBrowseButton;
HWND g_hwndInjectButton;
HWND g_hwndProgressBar;
wstring g_dllPath;
vector<wstring> g_logBuffer;
bool g_enableLogging = false;
const string obfuscatedProcessName = GetObfuscatedString("cs2.exe");
const string obfuscatedNtdll = GetObfuscatedString("ntdll.dll");

string XorDecrypt(const string& input, char key) {
    string output = input;
    for (char& c : output) c ^= key;
    return output;
}

string GetObfuscatedString(const string& str) {
    const char key = 0x55;
    string obfuscated = str;
    for (char& c : obfuscated) c ^= key;
    return obfuscated;
}

void InitializeLogging() {
    wstring configPath = L"Injector.ini";
    if (GetFileAttributesW(configPath.c_str()) != INVALID_FILE_ATTRIBUTES) {
        g_enableLogging = GetPrivateProfileIntW(L"Settings", L"EnableLogging", 0, configPath.c_str()) != 0;
    }
}

void LogToMemory(const wstring& message) {
    if (!g_enableLogging) return;
    wstring timestampedMessage = L"[" + GetCurrentTimestamp() + L"] " + message;
    g_logBuffer.push_back(timestampedMessage);
}

void PlaySuccessSound() {
    PlaySound(MAKEINTRESOURCE(IDR_TREVOR_WAV), GetModuleHandle(NULL), SND_RESOURCE | SND_ASYNC);
}

void PlayErrorSound() {
    PlaySound(TEXT("SystemHand"), NULL, SND_ALIAS | SND_ASYNC);
}

wstring GetCurrentTimestamp() {
    auto now = chrono::system_clock::now();
    auto time = chrono::system_clock::to_time_t(now);
    tm local_time;
    localtime_s(&local_time, &time);
    wstringstream wss;
    wss << std::put_time(&local_time, L"%Y-%m-%d %H:%M:%S")
        << L"." << std::setfill(L'0') << std::setw(3)
        << (chrono::duration_cast<chrono::milliseconds>(now.time_since_epoch()) % 1000).count();
    return wss.str();
}

void UpdateStatus(const wstring& message, COLORREF color) {
    wstring timestampedMessage = L"[" + GetCurrentTimestamp() + L"] " + message;
    int len = GetWindowTextLengthW(g_hwndStatus) + 1;
    vector<wchar_t> buffer(len);
    GetWindowTextW(g_hwndStatus, buffer.data(), len);
    wstring currentText(buffer.data());
    currentText = currentText.substr(0, currentText.find_last_not_of(L"\r\n") + 1);
    wstring newText = currentText.empty() ? timestampedMessage : currentText + L"\r\n" + timestampedMessage;
    SetWindowTextW(g_hwndStatus, newText.c_str());
    CHARFORMATW cf = { sizeof(CHARFORMATW) };
    cf.dwMask = CFM_COLOR;
    cf.crTextColor = RGB(0, 255, 0);
    SendMessageW(g_hwndStatus, EM_SETCHARFORMAT, SCF_ALL, (LPARAM)&cf);
    SendMessageW(g_hwndStatus, EM_SETSEL, (WPARAM)-1, (LPARAM)-1);
    SendMessageW(g_hwndStatus, EM_SCROLLCARET, 0, 0);
    SendMessageW(g_hwndStatus, WM_VSCROLL, SB_BOTTOM, 0);
    InvalidateRect(g_hwndStatus, NULL, TRUE);
    UpdateWindow(g_hwndStatus);
    LogToMemory(timestampedMessage);
}

bool IsRunAsAdmin() {
    BOOL isAdmin = FALSE;
    PSID adminGroup = nullptr;
    SID_IDENTIFIER_AUTHORITY ntAuthority = SECURITY_NT_AUTHORITY;
    if (AllocateAndInitializeSid(&ntAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &adminGroup)) {
        CheckTokenMembership(NULL, adminGroup, &isAdmin);
        FreeSid(adminGroup);
    }
    return isAdmin;
}

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
        UpdateStatus(L"[-] Error checking process architecture", RGB(0, 255, 0));
        PlayErrorSound();
        return false;
    }
    BOOL isHostWow64 = FALSE;
    Is64BitProcess(GetCurrentProcess(), &isHostWow64);
    return isTargetWow64 == isHostWow64;
}

bool CheckDLLArchitecture(const vector<BYTE>& dllData, HANDLE hProcess) {
    if (dllData.size() < sizeof(IMAGE_DOS_HEADER)) {
        UpdateStatus(L"[-] Invalid DLL data size for architecture check", RGB(0, 255, 0));
        return false;
    }
    const BYTE* rawData = dllData.data();
    IMAGE_DOS_HEADER* pDosHeader = reinterpret_cast<IMAGE_DOS_HEADER*>(const_cast<BYTE*>(rawData));
    if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        UpdateStatus(L"[-] Invalid DLL (no MZ signature)", RGB(0, 255, 0));
        return false;
    }
    if (static_cast<SIZE_T>(pDosHeader->e_lfanew) + sizeof(IMAGE_NT_HEADERS) > dllData.size()) {
        UpdateStatus(L"[-] Invalid NT headers offset in DLL", RGB(0, 255, 0));
        return false;
    }
    IMAGE_NT_HEADERS* pNtHeaders = reinterpret_cast<IMAGE_NT_HEADERS*>(const_cast<BYTE*>(rawData + pDosHeader->e_lfanew));
    if (pNtHeaders->Signature != IMAGE_NT_SIGNATURE) {
        UpdateStatus(L"[-] Invalid NT signature in DLL", RGB(0, 255, 0));
        return false;
    }
    BOOL isProcessWow64 = FALSE;
    if (!Is64BitProcess(hProcess, &isProcessWow64)) {
        UpdateStatus(L"[-] Error checking process architecture for DLL validation", RGB(0, 255, 0));
        return false;
    }
    bool isProcess64Bit = !isProcessWow64 && Is64BitWindows();
#ifdef _WIN64
    bool isDLL64Bit = pNtHeaders->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64;
#else
    bool isDLL64Bit = pNtHeaders->FileHeader.Machine == IMAGE_FILE_MACHINE_I386;
#endif
    if (isDLL64Bit != isProcess64Bit) {
        UpdateStatus(L"[-] DLL architecture does not match process architecture", RGB(0, 255, 0));
        return false;
    }
    UpdateStatus(L"[+] DLL architecture verified", RGB(0, 255, 0));
    return true;
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

bool ValidateDLLPath(const wstring& dllPath) {
    if (dllPath.length() > 260) {
        UpdateStatus(L"[-] DLL path too long", RGB(0, 255, 0));
        return false;
    }
    if (dllPath.find(L"..\\") != wstring::npos || dllPath.find(L"/") != wstring::npos || dllPath.find(L"\\") == 0) {
        UpdateStatus(L"[-] Invalid characters in DLL path", RGB(0, 255, 0));
        return false;
    }
    if (PathFileExistsW(dllPath.c_str()) == FALSE) {
        UpdateStatus(L"[-] DLL file does not exist", RGB(0, 255, 0));
        return false;
    }
    return true;
}

#define RELOC_FLAG(RelInfo) ((RelInfo >> 0x0C) == IMAGE_REL_BASED_DIR64)

#pragma runtime_checks("", off)
#pragma optimize("", off)
void __stdcall Shellcode(MANUAL_MAPPING_DATA* pData) {
    if (!pData) return;
    BYTE* pBase = pData->pBase;
    if (!pBase) {
        pData->hMod = reinterpret_cast<HINSTANCE>(0x404040);
        return;
    }
    IMAGE_DOS_HEADER* pDosHeader = reinterpret_cast<IMAGE_DOS_HEADER*>(pBase);
    if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        pData->hMod = reinterpret_cast<HINSTANCE>(0x404040);
        return;
    }
    IMAGE_NT_HEADERS* pNtHeaders = reinterpret_cast<IMAGE_NT_HEADERS*>(pBase + pDosHeader->e_lfanew);
    if (pNtHeaders->Signature != IMAGE_NT_SIGNATURE) {
        pData->hMod = reinterpret_cast<HINSTANCE>(0x404040);
        return;
    }
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
            if (!hDll) {
                pData->hMod = reinterpret_cast<HINSTANCE>(0x404040);
                return;
            }
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
                if (!*pFuncRef) {
                    pData->hMod = reinterpret_cast<HINSTANCE>(0x404040);
                    return;
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
    if (!DllEntry(pBase, pData->dwReason, pData->lpReserved)) {
        pData->hMod = reinterpret_cast<HINSTANCE>(0x404040);
        return;
    }
    pData->hMod = bExceptionSupportFailed ? reinterpret_cast<HINSTANCE>(0x505050) : reinterpret_cast<HINSTANCE>(pBase);
}
#pragma optimize("", on)
#pragma runtime_checks("", restore)

vector<BYTE> LoadDLL(const wstring& dllPath) {
    if (!ValidateDLLPath(dllPath)) {
        UpdateStatus(L"[-] Invalid DLL path", RGB(0, 255, 0));
        throw runtime_error("Invalid DLL path");
    }
    ifstream file(dllPath, ios::binary | ios::ate);
    if (!file.is_open()) {
        UpdateStatus(L"[-] Could not open DLL file", RGB(0, 255, 0));
        throw runtime_error("Could not open DLL file");
    }
    auto fileSize = file.tellg();
    if (fileSize < 0x1000) {
        file.close();
        UpdateStatus(L"[-] Invalid DLL file size", RGB(0, 255, 0));
        throw runtime_error("Invalid DLL file size");
    }
    vector<BYTE> dllData(static_cast<size_t>(fileSize));
    file.seekg(0, ios::beg);
    file.read(reinterpret_cast<char*>(dllData.data()), fileSize);
    file.close();
    return dllData;
}

bool ValidatePEHeaders(BYTE* pSourceData, SIZE_T fileSize, wstring& errorMsg) {
    if (!pSourceData || fileSize < sizeof(IMAGE_DOS_HEADER)) {
        errorMsg = L"[-] Invalid source data size";
        return false;
    }
    IMAGE_DOS_HEADER* pDosHeader = reinterpret_cast<IMAGE_DOS_HEADER*>(pSourceData);
    if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        errorMsg = L"[-] Invalid file (no MZ signature)";
        return false;
    }
    if (static_cast<SIZE_T>(pDosHeader->e_lfanew) + sizeof(IMAGE_NT_HEADERS) > fileSize) {
        errorMsg = L"[-] Invalid NT headers offset";
        return false;
    }
    IMAGE_NT_HEADERS* pNtHeaders = reinterpret_cast<IMAGE_NT_HEADERS*>(pSourceData + pDosHeader->e_lfanew);
    if (pNtHeaders->Signature != IMAGE_NT_SIGNATURE) {
        errorMsg = L"[-] Invalid NT signature";
        return false;
    }
#ifdef _WIN64
    if (pNtHeaders->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64) {
#else
    if (pNtHeaders->FileHeader.Machine != IMAGE_FILE_MACHINE_I386) {
#endif
        errorMsg = L"[-] Invalid file architecture";
        return false;
    }
    errorMsg = L"[+] Valid PE file detected";
    return true;
    }

BYTE* AllocateProcessMemory(HANDLE hProcess, SIZE_T size, DWORD & oldProtect, wstring & errorMsg) {
    BYTE* pTargetBase = reinterpret_cast<BYTE*>(VirtualAllocEx(hProcess, nullptr, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
    if (!pTargetBase) {
        errorMsg = L"[-] Error allocating process memory, code: 0x" + to_wstring(GetLastError());
        return nullptr;
    }
    if (!VirtualProtectEx(hProcess, pTargetBase, size, PAGE_EXECUTE_READWRITE, &oldProtect)) {
        errorMsg = L"[-] Error setting memory protection, code: 0x" + to_wstring(GetLastError());
        VirtualFreeEx(hProcess, pTargetBase, 0, MEM_RELEASE);
        return nullptr;
    }
    errorMsg = L"[+] Memory allocated and protection set";
    return pTargetBase;
}

bool WritePEHeaders(HANDLE hProcess, BYTE * pTargetBase, BYTE * pSourceData, wstring & errorMsg) {
    if (!WriteProcessMemory(hProcess, pTargetBase, pSourceData, 0x1000, nullptr)) {
        errorMsg = L"[-] Error writing PE header, code: 0x" + to_wstring(GetLastError());
        return false;
    }
    errorMsg = L"[+] PE header written";
    return true;
}

bool WriteSections(HANDLE hProcess, BYTE * pTargetBase, BYTE * pSourceData, IMAGE_NT_HEADERS * pNtHeaders, wstring & errorMsg) {
    IMAGE_SECTION_HEADER* pSectionHeader = IMAGE_FIRST_SECTION(pNtHeaders);
    for (UINT i = 0; i < pNtHeaders->FileHeader.NumberOfSections; ++i, ++pSectionHeader) {
        if (pSectionHeader->SizeOfRawData) {
            if (static_cast<SIZE_T>(pSectionHeader->PointerToRawData) + pSectionHeader->SizeOfRawData > pNtHeaders->OptionalHeader.SizeOfImage) {
                errorMsg = L"[-] Invalid section data for " + wstring(pSectionHeader->Name, pSectionHeader->Name + 8);
                return false;
            }
            if (!WriteProcessMemory(hProcess, pTargetBase + pSectionHeader->VirtualAddress,
                pSourceData + pSectionHeader->PointerToRawData, pSectionHeader->SizeOfRawData, nullptr)) {
                errorMsg = L"[-] Error mapping section " + wstring(pSectionHeader->Name, pSectionHeader->Name + 8) + L", code: 0x" + to_wstring(GetLastError());
                return false;
            }
            errorMsg = L"[+] Section mapped: " + wstring(pSectionHeader->Name, pSectionHeader->Name + 8);
            UpdateStatus(errorMsg, RGB(0, 255, 0));
        }
    }
    return true;
}

BYTE* AllocateMappingData(HANDLE hProcess, const MANUAL_MAPPING_DATA & mappingData, wstring & errorMsg) {
    BYTE* pMappingDataAlloc = reinterpret_cast<BYTE*>(VirtualAllocEx(hProcess, nullptr, sizeof(MANUAL_MAPPING_DATA), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
    if (!pMappingDataAlloc) {
        errorMsg = L"[-] Error allocating mapping data memory, code: 0x" + to_wstring(GetLastError());
        return nullptr;
    }
    if (!WriteProcessMemory(hProcess, pMappingDataAlloc, &mappingData, sizeof(MANUAL_MAPPING_DATA), nullptr)) {
        errorMsg = L"[-] Error writing mapping data, code: 0x" + to_wstring(GetLastError());
        VirtualFreeEx(hProcess, pMappingDataAlloc, 0, MEM_RELEASE);
        return nullptr;
    }
    errorMsg = L"[+] Mapping data memory allocated and written";
    return pMappingDataAlloc;
}

void* AllocateAndWriteShellcode(HANDLE hProcess, wstring & errorMsg) {
    void* pShellcode = VirtualAllocEx(hProcess, nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!pShellcode) {
        errorMsg = L"[-] Error allocating shellcode memory, code: 0x" + to_wstring(GetLastError());
        return nullptr;
    }
    if (!WriteProcessMemory(hProcess, pShellcode, Shellcode, 0x1000, nullptr)) {
        errorMsg = L"[-] Error writing shellcode, code: 0x" + to_wstring(GetLastError());
        VirtualFreeEx(hProcess, pShellcode, 0, MEM_RELEASE);
        return nullptr;
    }
    errorMsg = L"[+] Shellcode memory allocated and written";
    return pShellcode;
}

bool ExecuteShellcode(HANDLE hProcess, void* pShellcode, BYTE * pMappingDataAlloc, wstring & errorMsg) {
    HandleGuard hThread(CreateRemoteThread(hProcess, nullptr, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(pShellcode), pMappingDataAlloc, 0, nullptr));
    if (!hThread) {
        errorMsg = L"[-] Error creating remote thread, code: 0x" + to_wstring(GetLastError());
        return false;
    }
    errorMsg = L"[+] Remote thread created";
    return true;
}

bool WaitForInjection(HANDLE hProcess, BYTE * pMappingDataAlloc, HINSTANCE & hModule, wstring & errorMsg) {
    hModule = nullptr;
    random_device rd;
    mt19937 gen(rd());
    uniform_int_distribution<> dis(5, 15);
    while (!hModule) {
        DWORD exitCode = 0;
        if (!GetExitCodeProcess(hProcess, &exitCode) || exitCode != STILL_ACTIVE) {
            errorMsg = L"[-] Target process terminated, exit code: " + to_wstring(exitCode);
            return false;
        }
        MANUAL_MAPPING_DATA data = { 0 };
        if (!ReadProcessMemory(hProcess, pMappingDataAlloc, &data, sizeof(data), nullptr)) {
            errorMsg = L"[-] Error reading mapping data, code: 0x" + to_wstring(GetLastError());
            return false;
        }
        hModule = data.hMod;
        if (hModule == reinterpret_cast<HINSTANCE>(0x404040)) {
            errorMsg = L"[-] Mapping pointer error";
            return false;
        }
        else if (hModule == reinterpret_cast<HINSTANCE>(0x505050)) {
            errorMsg = L"[!] Warning: Exception support failed";
            UpdateStatus(errorMsg, RGB(0, 255, 0));
        }
        this_thread::sleep_for(chrono::milliseconds(dis(gen)));
    }
    errorMsg = L"[+] DLL module loaded successfully";
    return true;
}

bool CleanAndProtectMemory(HANDLE hProcess, BYTE * pTargetBase, IMAGE_NT_HEADERS * pNtHeaders, void* pShellcode, BYTE * pMappingDataAlloc, bool cleanHeader, bool cleanUnneededSections, bool adjustProtections, bool sehSupport, wstring & errorMsg) {
    vector<BYTE> cleanBuffer(1024 * 1024, 0);
    if (cleanHeader) {
        if (!WriteProcessMemory(hProcess, pTargetBase, cleanBuffer.data(), 0x1000, nullptr)) {
            UpdateStatus(L"[!] Warning: Could not clean PE header", RGB(0, 255, 0));
        }
        else {
            UpdateStatus(L"[+] PE header cleaned", RGB(0, 255, 0));
        }
    }
    if (cleanUnneededSections) {
        IMAGE_SECTION_HEADER* pSectionHeader = IMAGE_FIRST_SECTION(pNtHeaders);
        for (UINT i = 0; i < pNtHeaders->FileHeader.NumberOfSections; ++i, ++pSectionHeader) {
            if (pSectionHeader->Misc.VirtualSize) {
                bool isUnneededSection = (sehSupport ? false : strcmp(reinterpret_cast<char*>(pSectionHeader->Name), ".pdata") == 0) ||
                    strcmp(reinterpret_cast<char*>(pSectionHeader->Name), ".rsrc") == 0 ||
                    strcmp(reinterpret_cast<char*>(pSectionHeader->Name), ".reloc") == 0;
                if (isUnneededSection) {
                    wstring sectionName(pSectionHeader->Name, pSectionHeader->Name + 8);
                    UpdateStatus(L"[!] Removing section: " + sectionName, RGB(0, 255, 0));
                    if (!WriteProcessMemory(hProcess, pTargetBase + pSectionHeader->VirtualAddress, cleanBuffer.data(), pSectionHeader->Misc.VirtualSize, nullptr)) {
                        UpdateStatus(L"[-] Error cleaning section " + sectionName + L", code: 0x" + to_wstring(GetLastError()), RGB(0, 255, 0));
                    }
                    else {
                        UpdateStatus(L"[+] Section cleaned: " + sectionName, RGB(0, 255, 0));
                    }
                }
            }
        }
    }
    if (adjustProtections) {
        IMAGE_SECTION_HEADER* pSectionHeader = IMAGE_FIRST_SECTION(pNtHeaders);
        for (UINT i = 0; i < pNtHeaders->FileHeader.NumberOfSections; ++i, ++pSectionHeader) {
            if (pSectionHeader->Misc.VirtualSize) {
                DWORD newProtect = PAGE_READONLY;
                if (pSectionHeader->Characteristics & IMAGE_SCN_MEM_WRITE)
                    newProtect = PAGE_READWRITE;
                else if (pSectionHeader->Characteristics & IMAGE_SCN_MEM_EXECUTE)
                    newProtect = PAGE_EXECUTE_READ;
                DWORD oldProtect = 0;
                wstring sectionName(pSectionHeader->Name, pSectionHeader->Name + 8);
                if (!VirtualProtectEx(hProcess, pTargetBase + pSectionHeader->VirtualAddress, pSectionHeader->Misc.VirtualSize, newProtect, &oldProtect)) {
                    UpdateStatus(L"[-] Error setting section " + sectionName + L" protection to 0x" + to_wstring(newProtect), RGB(0, 255, 0));
                }
                else {
                    UpdateStatus(L"[+] Section " + sectionName + L" protection set to 0x" + to_wstring(newProtect), RGB(0, 255, 0));
                }
            }
        }
        DWORD oldProtect = 0;
        if (!VirtualProtectEx(hProcess, pTargetBase, IMAGE_FIRST_SECTION(pNtHeaders)->VirtualAddress, PAGE_READONLY, &oldProtect)) {
            UpdateStatus(L"[-] Error setting header protection, code: 0x" + to_wstring(GetLastError()), RGB(0, 255, 0));
        }
        else {
            UpdateStatus(L"[+] Header protection set", RGB(0, 255, 0));
        }
    }
    random_device rd;
    mt19937 gen(rd());
    uniform_int_distribution<> dis(0, 255);
    vector<BYTE> randomBuffer(0x1000);
    for (auto& byte : randomBuffer) byte = static_cast<BYTE>(dis(gen));
    if (!WriteProcessMemory(hProcess, pShellcode, randomBuffer.data(), 0x1000, nullptr)) {
        UpdateStatus(L"[!] Warning: Could not overwrite shellcode", RGB(0, 255, 0));
    }
    else {
        UpdateStatus(L"[+] Shellcode overwritten with random data", RGB(0, 255, 0));
    }
    if (!VirtualFreeEx(hProcess, pShellcode, 0, MEM_RELEASE)) {
        UpdateStatus(L"[!] Warning: Could not free shellcode memory, code: 0x" + to_wstring(GetLastError()), RGB(0, 255, 0));
    }
    else {
        UpdateStatus(L"[+] Shellcode memory freed", RGB(0, 255, 0));
    }
    if (!VirtualFreeEx(hProcess, pMappingDataAlloc, 0, MEM_RELEASE)) {
        UpdateStatus(L"[!] Warning: Could not free mapping data memory, code: 0x" + to_wstring(GetLastError()), RGB(0, 255, 0));
    }
    else {
        UpdateStatus(L"[+] Mapping data memory freed", RGB(0, 255, 0));
    }
    errorMsg = L"[+] Injection process completed successfully";
    return true;
}

bool ManualMapDLL(HANDLE hProcess, BYTE * pSourceData, SIZE_T fileSize, bool cleanHeader = true,
    bool cleanUnneededSections = true, bool adjustProtections = true, bool sehSupport = true,
    DWORD reason = DLL_PROCESS_ATTACH, LPVOID reserved = nullptr) {
    auto startTime = chrono::high_resolution_clock::now();
    UpdateStatus(L"[+] Initializing injection process...", RGB(0, 255, 0));
    SendMessage(g_hwndProgressBar, PBM_SETRANGE, 0, MAKELPARAM(0, 100));
    SendMessage(g_hwndProgressBar, PBM_SETSTEP, (WPARAM)10, 0);
    SendMessage(g_hwndProgressBar, PBM_SETSTATE, PBST_NORMAL, 0);
    SendMessage(g_hwndProgressBar, PBM_SETPOS, 0, 0);

    random_device rd;
    mt19937 gen(rd());
    uniform_int_distribution<> dis(5, 15);

    wstring errorMsg;
    if (!ValidatePEHeaders(pSourceData, fileSize, errorMsg)) {
        UpdateStatus(errorMsg, RGB(0, 255, 0));
        PlayErrorSound();
        SendMessage(g_hwndProgressBar, PBM_SETSTATE, PBST_ERROR, 0);
        return false;
    }
    UpdateStatus(errorMsg, RGB(0, 255, 0));
    SendMessage(g_hwndProgressBar, PBM_STEPIT, 0, 0);
    this_thread::sleep_for(chrono::milliseconds(dis(gen)));

    IMAGE_NT_HEADERS* pNtHeaders = reinterpret_cast<IMAGE_NT_HEADERS*>(pSourceData + reinterpret_cast<IMAGE_DOS_HEADER*>(pSourceData)->e_lfanew);
    DWORD oldProtect = 0;
    BYTE* pTargetBase = AllocateProcessMemory(hProcess, pNtHeaders->OptionalHeader.SizeOfImage, oldProtect, errorMsg);
    if (!pTargetBase) {
        UpdateStatus(errorMsg, RGB(0, 255, 0));
        PlayErrorSound();
        SendMessage(g_hwndProgressBar, PBM_SETSTATE, PBST_ERROR, 0);
        return false;
    }
    UpdateStatus(errorMsg, RGB(0, 255, 0));
    SendMessage(g_hwndProgressBar, PBM_STEPIT, 0, 0);
    this_thread::sleep_for(chrono::milliseconds(dis(gen)));

    if (!WritePEHeaders(hProcess, pTargetBase, pSourceData, errorMsg)) {
        UpdateStatus(errorMsg, RGB(0, 255, 0));
        VirtualFreeEx(hProcess, pTargetBase, 0, MEM_RELEASE);
        PlayErrorSound();
        SendMessage(g_hwndProgressBar, PBM_SETSTATE, PBST_ERROR, 0);
        return false;
    }
    UpdateStatus(errorMsg, RGB(0, 255, 0));
    SendMessage(g_hwndProgressBar, PBM_STEPIT, 0, 0);
    this_thread::sleep_for(chrono::milliseconds(dis(gen)));

    if (!WriteSections(hProcess, pTargetBase, pSourceData, pNtHeaders, errorMsg)) {
        UpdateStatus(errorMsg, RGB(0, 255, 0));
        VirtualFreeEx(hProcess, pTargetBase, 0, MEM_RELEASE);
        PlayErrorSound();
        SendMessage(g_hwndProgressBar, PBM_SETSTATE, PBST_ERROR, 0);
        return false;
    }
    SendMessage(g_hwndProgressBar, PBM_STEPIT, 0, 0);
    this_thread::sleep_for(chrono::milliseconds(dis(gen)));

    MANUAL_MAPPING_DATA mappingData = { 0 };
    mappingData.pLoadLibraryA = LoadLibraryA;
    mappingData.pGetProcAddress = GetProcAddress;
    string ntdllName = XorDecrypt(obfuscatedNtdll, 0x55);
    HMODULE hNtdll = GetModuleHandleA(ntdllName.c_str());
    if (!hNtdll) {
        UpdateStatus(L"[-] Error getting handle to module, code: 0x" + to_wstring(GetLastError()), RGB(0, 255, 0));
        VirtualFreeEx(hProcess, pTargetBase, 0, MEM_RELEASE);
        PlayErrorSound();
        SendMessage(g_hwndProgressBar, PBM_SETSTATE, PBST_ERROR, 0);
        return false;
    }
    mappingData.pRtlAddFunctionTable = reinterpret_cast<f_RtlAddFunctionTable>(GetProcAddress(hNtdll, "RtlAddFunctionTable"));
    mappingData.pBase = pTargetBase;
    mappingData.dwReason = reason;
    mappingData.lpReserved = reserved;
    mappingData.bSEHSupport = sehSupport;
    BYTE* pMappingDataAlloc = AllocateMappingData(hProcess, mappingData, errorMsg);
    if (!pMappingDataAlloc) {
        UpdateStatus(errorMsg, RGB(0, 255, 0));
        VirtualFreeEx(hProcess, pTargetBase, 0, MEM_RELEASE);
        PlayErrorSound();
        SendMessage(g_hwndProgressBar, PBM_SETSTATE, PBST_ERROR, 0);
        return false;
    }
    UpdateStatus(errorMsg, RGB(0, 255, 0));
    SendMessage(g_hwndProgressBar, PBM_STEPIT, 0, 0);
    this_thread::sleep_for(chrono::milliseconds(dis(gen)));

    void* pShellcode = AllocateAndWriteShellcode(hProcess, errorMsg);
    if (!pShellcode) {
        UpdateStatus(errorMsg, RGB(0, 255, 0));
        VirtualFreeEx(hProcess, pTargetBase, 0, MEM_RELEASE);
        VirtualFreeEx(hProcess, pMappingDataAlloc, 0, MEM_RELEASE);
        PlayErrorSound();
        SendMessage(g_hwndProgressBar, PBM_SETSTATE, PBST_ERROR, 0);
        return false;
    }
    UpdateStatus(errorMsg, RGB(0, 255, 0));
    SendMessage(g_hwndProgressBar, PBM_STEPIT, 0, 0);
    this_thread::sleep_for(chrono::milliseconds(dis(gen)));

    if (!ExecuteShellcode(hProcess, pShellcode, pMappingDataAlloc, errorMsg)) {
        UpdateStatus(errorMsg, RGB(0, 255, 0));
        VirtualFreeEx(hProcess, pTargetBase, 0, MEM_RELEASE);
        VirtualFreeEx(hProcess, pMappingDataAlloc, 0, MEM_RELEASE);
        VirtualFreeEx(hProcess, pShellcode, 0, MEM_RELEASE);
        PlayErrorSound();
        SendMessage(g_hwndProgressBar, PBM_SETSTATE, PBST_ERROR, 0);
        return false;
    }
    UpdateStatus(errorMsg, RGB(0, 255, 0));
    SendMessage(g_hwndProgressBar, PBM_STEPIT, 0, 0);
    this_thread::sleep_for(chrono::milliseconds(dis(gen)));

    HINSTANCE hModule = nullptr;
    if (!WaitForInjection(hProcess, pMappingDataAlloc, hModule, errorMsg)) {
        UpdateStatus(errorMsg, RGB(0, 255, 0));
        VirtualFreeEx(hProcess, pTargetBase, 0, MEM_RELEASE);
        VirtualFreeEx(hProcess, pMappingDataAlloc, 0, MEM_RELEASE);
        VirtualFreeEx(hProcess, pShellcode, 0, MEM_RELEASE);
        PlayErrorSound();
        SendMessage(g_hwndProgressBar, PBM_SETSTATE, PBST_ERROR, 0);
        return false;
    }
    UpdateStatus(errorMsg, RGB(0, 255, 0));
    SendMessage(g_hwndProgressBar, PBM_STEPIT, 0, 0);
    this_thread::sleep_for(chrono::milliseconds(dis(gen)));

    if (!CleanAndProtectMemory(hProcess, pTargetBase, pNtHeaders, pShellcode, pMappingDataAlloc, cleanHeader, cleanUnneededSections, adjustProtections, sehSupport, errorMsg)) {
        UpdateStatus(errorMsg, RGB(0, 255, 0));
        PlayErrorSound();
        SendMessage(g_hwndProgressBar, PBM_SETSTATE, PBST_ERROR, 0);
        return false;
    }
    UpdateStatus(errorMsg, RGB(0, 255, 0));
    SendMessage(g_hwndProgressBar, PBM_STEPIT, 0, 0);
    this_thread::sleep_for(chrono::milliseconds(dis(gen)));

    auto endTime = chrono::high_resolution_clock::now();
    auto durationMs = chrono::duration_cast<chrono::milliseconds>(endTime - startTime).count();
    double durationSec = durationMs / 1000.0;
    wstringstream durationStream;
    durationStream << fixed << setprecision(3) << durationSec;
    UpdateStatus(L"[+] Injection completed in " + durationStream.str() + L" seconds", RGB(0, 255, 0));
    SendMessage(g_hwndProgressBar, PBM_SETPOS, 100, 0);
    SendMessage(g_hwndProgressBar, PBM_SETSTATE, PBST_NORMAL, 0);
    return true;
}

LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    static HFONT hFontTitle = CreateFontW(24, 0, 0, 0, FW_BOLD, FALSE, FALSE, FALSE, DEFAULT_CHARSET, OUT_DEFAULT_PRECIS,
        CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE, L"Segoe UI");
    static HFONT hFontButton = CreateFontW(20, 0, 0, 0, FW_BOLD, FALSE, FALSE, FALSE, DEFAULT_CHARSET, OUT_DEFAULT_PRECIS,
        CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE, L"Segoe UI");
    static HFONT hFontStatus = CreateFontW(18, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE, DEFAULT_CHARSET, OUT_DEFAULT_PRECIS,
        CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE, L"Segoe UI");
    static HFONT hFontFooter = CreateFontW(14, 0, 0, 0, FW_BOLD, FALSE, FALSE, FALSE, DEFAULT_CHARSET, OUT_DEFAULT_PRECIS,
        CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE, L"Segoe UI");
    static HBITMAP hBitmap = nullptr;
    static HBRUSH hBackgroundBrush = CreateSolidBrush(RGB(223, 204, 174));
    static HBRUSH hStatusBrush = CreateSolidBrush(RGB(0, 0, 0));

    switch (msg) {
    case WM_CREATE: {
        INITCOMMONCONTROLSEX icex = { sizeof(INITCOMMONCONTROLSEX), ICC_STANDARD_CLASSES | ICC_PROGRESS_CLASS };
        InitCommonControlsEx(&icex);
        SetClassLongPtr(hwnd, GCLP_HBRBACKGROUND, (LONG_PTR)hBackgroundBrush);
        hBitmap = (HBITMAP)LoadImageW(GetModuleHandle(NULL), MAKEINTRESOURCE(IDB_TREVOR_BMP), IMAGE_BITMAP, 0, 0, 0);
        if (!hBitmap) {
            DWORD error = GetLastError();
            wstring errorMsg = L"[-] Error loading bitmap, code: 0x" + to_wstring(error);
            UpdateStatus(errorMsg, RGB(0, 255, 0));
            PlayErrorSound();
        }
        HWND hImage = CreateWindowW(L"STATIC", NULL, WS_VISIBLE | WS_CHILD | SS_BITMAP | SS_CENTERIMAGE,
            (800 - 200) / 2, 20, 200, 234, hwnd, NULL, NULL, NULL);
        if (hBitmap) {
            SendMessage(hImage, STM_SETIMAGE, IMAGE_BITMAP, (LPARAM)hBitmap);
        }
        HWND hTitle = CreateWindowW(L"STATIC", L"Simple and Secure Counter Strike 2 .DLL Injector | By s0mbra",
            WS_VISIBLE | WS_CHILD | SS_CENTER, 50, 274, 700, 50, hwnd, NULL, NULL, NULL);
        SendMessage(hTitle, WM_SETFONT, (WPARAM)hFontTitle, TRUE);
        g_hwndBrowseButton = CreateWindowW(L"BUTTON", L"Select .DLL to Inject...", WS_VISIBLE | WS_CHILD | BS_PUSHBUTTON | BS_FLAT,
            150, 334, 200, 50, hwnd, (HMENU)1, NULL, NULL);
        SendMessage(g_hwndBrowseButton, WM_SETFONT, (WPARAM)hFontButton, TRUE);
        g_hwndInjectButton = CreateWindowW(L"BUTTON", L"INJECT !", WS_VISIBLE | WS_CHILD | BS_PUSHBUTTON | BS_FLAT,
            450, 334, 200, 50, hwnd, (HMENU)2, NULL, NULL);
        SendMessage(g_hwndInjectButton, WM_SETFONT, (WPARAM)hFontButton, TRUE);
        g_hwndProgressBar = CreateWindowW(PROGRESS_CLASSW, NULL, WS_VISIBLE | WS_CHILD | PBS_SMOOTH,
            50, 394, 700, 20, hwnd, NULL, NULL, NULL);
        g_hwndStatus = CreateWindowExW(0, L"EDIT", L"Status: Ready to select DLL\r\n", WS_VISIBLE | WS_CHILD | WS_VSCROLL | ES_MULTILINE | ES_READONLY,
            50, 434, 700, 240, hwnd, NULL, NULL, NULL);
        SendMessage(g_hwndStatus, WM_SETFONT, (WPARAM)hFontStatus, TRUE);
        CHARFORMATW cf = { sizeof(CHARFORMATW) };
        cf.dwMask = CFM_COLOR;
        cf.crTextColor = RGB(0, 255, 0);
        SendMessageW(g_hwndStatus, EM_SETCHARFORMAT, SCF_ALL, (LPARAM)&cf);
        HWND hFooter = CreateWindowW(L"STATIC", L"Use this tool at your own risk. The source code is public and can be reviewed at: https://github.com/s0mbra-1973/Trevor",
            WS_VISIBLE | WS_CHILD | SS_CENTER, 50, 684, 700, 40, hwnd, (HMENU)3, NULL, NULL);
        SendMessage(hFooter, WM_SETFONT, (WPARAM)hFontFooter, TRUE);
        InitializeLogging();
        break;
    }
    case WM_CTLCOLORSTATIC: {
        HDC hdc = (HDC)wParam;
        HWND hCtrl = (HWND)lParam;
        if (hCtrl == GetDlgItem(hwnd, 3)) { // Footer control with ID 3
            SetTextColor(hdc, RGB(255, 0, 0)); // Red color for footer
            SetBkColor(hdc, RGB(223, 204, 174));
            return (LRESULT)hBackgroundBrush;
        }
        SetTextColor(hdc, RGB(0, 0, 0));
        SetBkColor(hdc, RGB(223, 204, 174));
        return (LRESULT)hBackgroundBrush;
    }
    case WM_CTLCOLOREDIT: {
        HDC hdc = (HDC)wParam;
        SetTextColor(hdc, RGB(0, 255, 0));
        SetBkColor(hdc, RGB(0, 0, 0));
        return (LRESULT)hStatusBrush;
    }
    case WM_CTLCOLORBTN: {
        HDC hdc = (HDC)wParam;
        SetTextColor(hdc, RGB(255, 255, 255));
        SetBkColor(hdc, RGB(100, 149, 237));
        return (LRESULT)CreateSolidBrush(RGB(100, 149, 237));
    }
    case WM_PAINT: {
        PAINTSTRUCT ps;
        HDC hdc = BeginPaint(hwnd, &ps);
        FillRect(hdc, &ps.rcPaint, hBackgroundBrush);
        EndPaint(hwnd, &ps);
        break;
    }
    case WM_TIMER: {
        if (wParam == 1) { // Timer ID 1 for auto-close
            KillTimer(hwnd, 1);
            PostMessage(hwnd, WM_CLOSE, 0, 0);
        }
        break;
    }
    case WM_COMMAND: {
        if (LOWORD(wParam) == 1) {
            OPENFILENAMEW ofn = { 0 };
            wchar_t szFile[260] = { 0 };
            ofn.lStructSize = sizeof(ofn);
            ofn.hwndOwner = hwnd;
            ofn.lpstrFile = szFile;
            ofn.nMaxFile = sizeof(szFile) / sizeof(*szFile);
            ofn.lpstrFilter = L"DLL Files\0*.dll\0All\0*.*\0";
            ofn.nFilterIndex = 1;
            ofn.Flags = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST;
            if (GetOpenFileNameW(&ofn)) {
                g_dllPath = szFile;
                if (!ValidateDLLPath(g_dllPath)) {
                    g_dllPath.clear();
                    PlayErrorSound();
                    return 0;
                }
                wstring status = L"[+] DLL selected: " + g_dllPath;
                UpdateStatus(status, RGB(0, 255, 0));
            }
        }
        else if (LOWORD(wParam) == 2) {
            if (!IsRunAsAdmin()) {
                MessageBoxW(hwnd, L"Injector MUST be run as Administrator.", L"Error", MB_OK | MB_ICONERROR);
                PlayErrorSound();
                UpdateStatus(L"[-] Application MUST be run as administrator", RGB(0, 255, 0));
                return 0;
            }
            if (g_dllPath.empty()) {
                UpdateStatus(L"[-] Please select a DLL file first", RGB(0, 255, 0));
                PlayErrorSound();
                return 0;
            }
            wstring processName = wstring(XorDecrypt(obfuscatedProcessName, 0x55).begin(), XorDecrypt(obfuscatedProcessName, 0x55).end());
            DWORD pid = GetPIDByName(processName);
            if (pid == 0) {
                UpdateStatus(L"[-] Target process not found. START THE GAME!", RGB(0, 255, 0));
                PlayErrorSound();
                return 0;
            }
            wstring pidStatus = L"[+] Injecting into target process (PID: " + to_wstring(pid) + L")";
            UpdateStatus(pidStatus, RGB(0, 255, 0));
            HandleGuard hToken;
            HANDLE hTokenTemp = nullptr;
            if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hTokenTemp)) {
                hToken.reset(hTokenTemp);
                TOKEN_PRIVILEGES privileges = { 0 };
                privileges.PrivilegeCount = 1;
                privileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
                if (LookupPrivilegeValue(nullptr, SE_DEBUG_NAME, &privileges.Privileges[0].Luid)) {
                    AdjustTokenPrivileges(hToken, FALSE, &privileges, 0, nullptr, nullptr);
                    UpdateStatus(L"[+] Debug privileges enabled", RGB(0, 255, 0));
                }
                else {
                    UpdateStatus(L"[!] Warning: Could not enable debug privileges, code: 0x" + to_wstring(GetLastError()), RGB(0, 255, 0));
                }
            }
            else {
                UpdateStatus(L"[!] Warning: Could not open process token, code: 0x" + to_wstring(GetLastError()), RGB(0, 255, 0));
            }
            HandleGuard hProcess(OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid));
            if (!hProcess) {
                UpdateStatus(L"[-] Error opening target process, code: 0x" + to_wstring(GetLastError()), RGB(0, 255, 0));
                PlayErrorSound();
                return 0;
            }
            UpdateStatus(L"[+] Target process opened successfully", RGB(0, 255, 0));
            if (!IsCorrectArchitecture(hProcess)) {
                UpdateStatus(L"[-] Target process architecture not compatible", RGB(0, 255, 0));
                PlayErrorSound();
                return 0;
            }
            UpdateStatus(L"[+] Target process architecture verified", RGB(0, 255, 0));
            vector<BYTE> dllData;
            try {
                dllData = LoadDLL(g_dllPath);
                UpdateStatus(L"[+] DLL file loaded successfully", RGB(0, 255, 0));
            }
            catch (const exception& e) {
                wstring error = L"[-] Error loading DLL: " + wstring(e.what(), e.what() + strlen(e.what()));
                UpdateStatus(error, RGB(0, 255, 0));
                PlayErrorSound();
                return 0;
            }
            if (!CheckDLLArchitecture(dllData, hProcess)) {
                PlayErrorSound();
                return 0;
            }
            UpdateStatus(L"[+] Starting DLL injection process...", RGB(0, 255, 0));
            if (!ManualMapDLL(hProcess, dllData.data(), dllData.size())) {
                UpdateStatus(L"[-] Error during injection", RGB(0, 255, 0));
                PlayErrorSound();
                return 0;
            }
            UpdateStatus(L"[+] INJECTION COMPLETED SUCCESSFULLY! Created by s0mbra (c) 2025", RGB(0, 255, 0));
            PlaySuccessSound();
            // Set a timer to close the window after 5 seconds
            SetTimer(hwnd, 1, 5000, NULL);
        }
        break;
    }
    case WM_DESTROY:
        if (hBitmap) DeleteObject(hBitmap);
        DeleteObject(hFontTitle);
        DeleteObject(hFontButton);
        DeleteObject(hFontStatus);
        DeleteObject(hFontFooter);
        DeleteObject(hBackgroundBrush);
        DeleteObject(hStatusBrush);
        PostQuitMessage(0);
        break;
    default:
        return DefWindowProc(hwnd, msg, wParam, lParam);
    }
    return 0;
}

int WINAPI wWinMain(_In_ HINSTANCE hInstance, _In_opt_ HINSTANCE hPrevInstance, _In_ LPWSTR lpCmdLine, _In_ int nCmdShow) {
    // Randomize executable name
    random_device rd;
    mt19937 gen(rd());
    string chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    uniform_int_distribution<int> dis(0, static_cast<int>(chars.size() - 1));
    wstring randomStr;
    for (int i = 0; i < 4; ++i) {
        randomStr += static_cast<wchar_t>(chars[dis(gen)]);
    }
    wstring exeName = L"Trevor4_" + randomStr + L".exe";
    wchar_t currentExePath[MAX_PATH];
    GetModuleFileNameW(NULL, currentExePath, MAX_PATH);
    wstring newExePath = wstring(currentExePath);
    size_t lastSlash = newExePath.find_last_of(L"\\");
    if (lastSlash != wstring::npos) {
        newExePath = newExePath.substr(0, lastSlash + 1) + exeName;
    }
    else {
        newExePath = exeName;
    }
    MoveFileW(currentExePath, newExePath.c_str());

    if (!IsRunAsAdmin()) {
        MessageBoxW(NULL, L"Injector MUST be run as Administrator.", L"Error", MB_OK | MB_ICONERROR);
        return -1;
    }
    HICON hIcon = (HICON)LoadImageW(hInstance, MAKEINTRESOURCE(IDI_TREVOR_ICON), IMAGE_ICON, 0, 0, LR_DEFAULTSIZE);
    if (!hIcon) {
        DWORD error = GetLastError();
        wstring errorMsg = L"[-] Error loading icon, code: 0x" + to_wstring(error);
        MessageBoxW(NULL, errorMsg.c_str(), L"Error", MB_OK | MB_ICONERROR);
    }
    WNDCLASSW wc = { 0 };
    wc.lpfnWndProc = WndProc;
    wc.hInstance = hInstance;
    wc.lpszClassName = L"InjectorWindowClass";
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    RegisterClassW(&wc);
    RECT rc = { 0, 0, 800, 754 };
    AdjustWindowRect(&rc, WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX, FALSE);
    int windowWidth = rc.right - rc.left;
    int windowHeight = rc.bottom - rc.top;
    int screenWidth = GetSystemMetrics(SM_CXSCREEN);
    int screenHeight = GetSystemMetrics(SM_CYSCREEN);
    int posX = (screenWidth - windowWidth) / 2;
    int posY = (screenHeight - windowHeight) / 2;
    g_hwndMain = CreateWindowW(L"InjectorWindowClass", L"Trevor Injector 4",
        WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX,
        posX, posY, windowWidth, windowHeight, NULL, NULL, hInstance, NULL);
    if (!g_hwndMain) {
        if (hIcon) DestroyIcon(hIcon);
        MessageBoxW(NULL, L"Error creating window.", L"Error", MB_OK | MB_ICONERROR);
        return -1;
    }
    if (hIcon) {
        SendMessage(g_hwndMain, WM_SETICON, ICON_BIG, (LPARAM)hIcon);
        SendMessage(g_hwndMain, WM_SETICON, ICON_SMALL, (LPARAM)hIcon);
    }
    ShowWindow(g_hwndMain, nCmdShow);
    UpdateWindow(g_hwndMain);
    MSG msg = { 0 };
    while (GetMessage(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }
    if (hIcon) DestroyIcon(hIcon);
    return (int)msg.wParam;
}