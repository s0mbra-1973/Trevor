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

class InjectorContext {
public:
    HWND hwndMain = nullptr;
    HWND hwndStatus = nullptr;
    HWND hwndBrowseButton = nullptr;
    HWND hwndInjectButton = nullptr;
    HWND hwndProgressBar = nullptr;
    HWND hwndProcessCombo = nullptr;
    HWND hwndRefreshButton = nullptr;
    HWND hwndProcessLabel = nullptr;
    HWND hwndDllLabel = nullptr;
    wstring dllPath;
    vector<wstring> logBuffer;
    bool enableLogging = false;
    wstring processName;
    const char* ntdllName;
    const char kXorKey;

    InjectorContext() : processName(L""), ntdllName("ntdll.dll"), kXorKey(GenerateXorKey()) {
        InitializeLogging();
    }

    bool ValidateDLLPath(const wstring& dllPath);

private:
    static char GenerateXorKey() {
        random_device rd;
        mt19937 gen(rd());
        uniform_int_distribution<> dis(1, 255);
        return static_cast<char>(dis(gen));
    }

    void InitializeLogging() {
        wstring configPath = L"Injector.ini";
        if (GetFileAttributesW(configPath.c_str()) != INVALID_FILE_ATTRIBUTES) {
            enableLogging = GetPrivateProfileIntW(L"Settings", L"EnableLogging", 0, configPath.c_str()) != 0;
            wchar_t buffer[260] = { 0 };
            if (GetPrivateProfileStringW(L"Settings", L"LastProcess", L"", buffer, 260, configPath.c_str())) {
                processName = buffer;
            }
            if (GetPrivateProfileStringW(L"Settings", L"LastDLL", L"", buffer, 260, configPath.c_str())) {
                dllPath = buffer;
                if (!ValidateDLLPath(dllPath)) {
                    dllPath.clear();
                }
            }
        }
    }
};

wstring GetCurrentTimestamp() {
    auto now = chrono::system_clock::now();
    auto time = chrono::system_clock::to_time_t(now);
    tm local_time;
    localtime_s(&local_time, &time);
    wstringstream wss;
    wss << put_time(&local_time, L"%Y-%m-%d %H:%M:%S")
        << L"." << setfill(L'0') << setw(3)
        << (chrono::duration_cast<chrono::milliseconds>(now.time_since_epoch()) % 1000).count();
    return wss.str();
}

void LogToMemory(InjectorContext& ctx, const wstring& message) {
    if (!ctx.enableLogging) return;
    wstring timestampedMessage = L"[" + GetCurrentTimestamp() + L"] " + message;
    ctx.logBuffer.push_back(timestampedMessage);
}

void PlaySuccessSound() {
    PlaySound(MAKEINTRESOURCE(IDR_TREVOR_WAV), GetModuleHandle(NULL), SND_RESOURCE | SND_ASYNC);
}

void PlayErrorSound() {
    PlaySound(TEXT("SystemHand"), NULL, SND_ALIAS | SND_ASYNC);
}

void LogErrorAndStatus(InjectorContext& ctx, const wstring& message, COLORREF color, bool isError) {
    wstring timestampedMessage = L"[" + GetCurrentTimestamp() + L"] " + message;
    LRESULT len = SendMessageW(ctx.hwndStatus, WM_GETTEXTLENGTH, 0, 0) + 1;
    vector<wchar_t> buffer(len);
    SendMessageW(ctx.hwndStatus, WM_GETTEXT, len, (LPARAM)buffer.data());
    wstring currentText(buffer.data());
    currentText = currentText.substr(0, currentText.find_last_not_of(L"\r\n") + 1);
    wstring newText = currentText.empty() ? timestampedMessage : currentText + L"\r\n" + timestampedMessage;
    SendMessageW(ctx.hwndStatus, WM_SETTEXT, 0, (LPARAM)newText.c_str());
    CHARFORMATW cf = { sizeof(CHARFORMATW) };
    cf.dwMask = CFM_COLOR;
    cf.crTextColor = color;
    SendMessageW(ctx.hwndStatus, EM_SETCHARFORMAT, SCF_ALL, (LPARAM)&cf);
    SendMessageW(ctx.hwndStatus, EM_SETSEL, (WPARAM)-1, (LPARAM)-1);
    SendMessageW(ctx.hwndStatus, EM_SCROLLCARET, 0, 0);
    SendMessageW(ctx.hwndStatus, WM_VSCROLL, SB_BOTTOM, 0);
    InvalidateRect(ctx.hwndStatus, NULL, TRUE);
    UpdateWindow(ctx.hwndStatus);
    LogToMemory(ctx, timestampedMessage);
    if (isError) {
        PlayErrorSound();
    }
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
        return false;
    }
    BOOL isHostWow64 = FALSE;
    Is64BitProcess(GetCurrentProcess(), &isHostWow64);
    return isTargetWow64 == isHostWow64;
}

bool CheckDLLArchitecture(InjectorContext& ctx, const vector<BYTE>& dllData, HANDLE hProcess) {
    try {
        if (dllData.size() < sizeof(IMAGE_DOS_HEADER)) {
            LogErrorAndStatus(ctx, L"[-] Invalid DLL data size for architecture check", RGB(255, 0, 0), true);
            return false;
        }
        const BYTE* rawData = dllData.data();
        IMAGE_DOS_HEADER* pDosHeader = reinterpret_cast<IMAGE_DOS_HEADER*>(const_cast<BYTE*>(rawData));
        if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
            LogErrorAndStatus(ctx, L"[-] Invalid DLL (no MZ signature)", RGB(255, 0, 0), true);
            return false;
        }
        if (static_cast<SIZE_T>(pDosHeader->e_lfanew) + sizeof(IMAGE_NT_HEADERS) > dllData.size() || pDosHeader->e_lfanew < 0) {
            LogErrorAndStatus(ctx, L"[-] Invalid NT headers offset in DLL", RGB(255, 0, 0), true);
            return false;
        }
        IMAGE_NT_HEADERS* pNtHeaders = reinterpret_cast<IMAGE_NT_HEADERS*>(const_cast<BYTE*>(rawData + pDosHeader->e_lfanew));
        if (pNtHeaders->Signature != IMAGE_NT_SIGNATURE) {
            LogErrorAndStatus(ctx, L"[-] Invalid NT signature in DLL", RGB(255, 0, 0), true);
            return false;
        }
        BOOL isProcessWow64 = FALSE;
        if (!Is64BitProcess(hProcess, &isProcessWow64)) {
            LogErrorAndStatus(ctx, L"[-] Error checking process architecture for DLL validation", RGB(255, 0, 0), true);
            return false;
        }
        bool isProcess64Bit = !isProcessWow64 && Is64BitWindows();
#ifdef _WIN64
        bool isDLL64Bit = pNtHeaders->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64;
#else
        bool isDLL64Bit = pNtHeaders->FileHeader.Machine == IMAGE_FILE_MACHINE_I386;
#endif
        if (isDLL64Bit != isProcess64Bit) {
            LogErrorAndStatus(ctx, L"[-] DLL architecture does not match process architecture", RGB(255, 0, 0), true);
            return false;
        }
        LogErrorAndStatus(ctx, L"[+] DLL architecture verified", RGB(0, 255, 0), false);
        return true;
    }
    catch (const exception& e) {
        wstring error = L"[-] Exception in CheckDLLArchitecture: " + wstring(e.what(), e.what() + strlen(e.what()));
        LogErrorAndStatus(ctx, error, RGB(255, 0, 0), true);
        return false;
    }
}

DWORD GetPIDByName(InjectorContext& ctx, const wstring& name) {
    HandleGuard snapshot(CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0));
    if (snapshot.get() == INVALID_HANDLE_VALUE) {
        DWORD error = GetLastError();
        LogErrorAndStatus(ctx, L"[-] Failed to create process snapshot, error code: 0x" + to_wstring(error), RGB(255, 0, 0), true);
        return 0;
    }
    PROCESSENTRY32W entry = { sizeof(PROCESSENTRY32W) };
    if (!Process32FirstW(snapshot, &entry)) {
        DWORD error = GetLastError();
        LogErrorAndStatus(ctx, L"[-] Failed to enumerate first process, error code: 0x" + to_wstring(error), RGB(255, 0, 0), true);
        return 0;
    }
    wstring lowerName = name;
    transform(lowerName.begin(), lowerName.end(), lowerName.begin(), ::towlower);
    wstring foundProcesses;
    do {
        wstring exeName(entry.szExeFile);
        transform(exeName.begin(), exeName.end(), exeName.begin(), ::towlower);
        if (exeName == lowerName) {
            LogErrorAndStatus(ctx, L"[+] Found process: " + wstring(entry.szExeFile) + L" (PID: " + to_wstring(entry.th32ProcessID) + L")", RGB(0, 255, 0), false);
            return entry.th32ProcessID;
        }
        foundProcesses += wstring(entry.szExeFile) + L", ";
    } while (Process32NextW(snapshot, &entry));
    LogErrorAndStatus(ctx, L"[-] Process not found: " + name + L". Processes scanned: " + foundProcesses, RGB(255, 0, 0), true);
    return 0;
}

bool InjectorContext::ValidateDLLPath(const wstring& dllPath) {
    if (dllPath.length() > 260) {
        LogErrorAndStatus(*this, L"[-] DLL path too long", RGB(255, 0, 0), true);
        return false;
    }
    if (dllPath.find(L"..\\") != wstring::npos || dllPath.find(L"/") != wstring::npos || dllPath.find(L"\\") == 0) {
        LogErrorAndStatus(*this, L"[-] Invalid characters in DLL path", RGB(255, 0, 0), true);
        return false;
    }
    if (PathFileExistsW(dllPath.c_str()) == FALSE) {
        LogErrorAndStatus(*this, L"[-] DLL file does not exist", RGB(255, 0, 0), true);
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

vector<BYTE> LoadDLL(InjectorContext& ctx, const wstring& dllPath) {
    try {
        if (!ctx.ValidateDLLPath(dllPath)) {
            throw runtime_error("Invalid DLL path");
        }
        ifstream file(dllPath, ios::binary | ios::ate);
        if (!file.is_open()) {
            LogErrorAndStatus(ctx, L"[-] Could not open DLL file", RGB(255, 0, 0), true);
            throw runtime_error("Could not open DLL file");
        }
        auto fileSize = file.tellg();
        if (fileSize < 0x1000) {
            file.close();
            LogErrorAndStatus(ctx, L"[-] Invalid DLL file size", RGB(255, 0, 0), true);
            throw runtime_error("Invalid DLL file size");
        }
        vector<BYTE> dllData(static_cast<size_t>(fileSize));
        file.seekg(0, ios::beg);
        file.read(reinterpret_cast<char*>(dllData.data()), fileSize);
        file.close();
        return dllData;
    }
    catch (const exception& e) {
        wstring error = L"[-] Exception in LoadDLL: " + wstring(e.what(), e.what() + strlen(e.what()));
        LogErrorAndStatus(ctx, error, RGB(255, 0, 0), true);
        throw;
    }
}

bool ValidatePEHeaders(InjectorContext& ctx, const BYTE* pSourceData, SIZE_T fileSize, wstring& errorMsg) {
    try {
        if (!pSourceData || fileSize < sizeof(IMAGE_DOS_HEADER)) {
            errorMsg = L"[-] Invalid source data size";
            return false;
        }
        IMAGE_DOS_HEADER* pDosHeader = reinterpret_cast<IMAGE_DOS_HEADER*>(const_cast<BYTE*>(pSourceData));
        if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
            errorMsg = L"[-] Invalid file (no MZ signature)";
            return false;
        }
        if (pDosHeader->e_lfanew < 0 || static_cast<SIZE_T>(pDosHeader->e_lfanew) + sizeof(IMAGE_NT_HEADERS) > fileSize) {
            errorMsg = L"[-] Invalid NT headers offset";
            return false;
        }
        IMAGE_NT_HEADERS* pNtHeaders = reinterpret_cast<IMAGE_NT_HEADERS*>(const_cast<BYTE*>(pSourceData + pDosHeader->e_lfanew));
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
    catch (const exception& e) {
        errorMsg = L"[-] Exception in ValidatePEHeaders: " + wstring(e.what(), e.what() + strlen(e.what()));
        return false;
    }
    }

BYTE* AllocateProcessMemory(InjectorContext & ctx, HANDLE hProcess, SIZE_T size, DWORD & oldProtect, wstring & errorMsg) {
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

bool WritePEHeaders(InjectorContext & ctx, HANDLE hProcess, BYTE * pTargetBase, const BYTE * pSourceData, wstring & errorMsg) {
    IMAGE_DOS_HEADER* pDosHeader = reinterpret_cast<IMAGE_DOS_HEADER*>(const_cast<BYTE*>(pSourceData));
    IMAGE_NT_HEADERS* pNtHeaders = reinterpret_cast<IMAGE_NT_HEADERS*>(const_cast<BYTE*>(pSourceData + pDosHeader->e_lfanew));
    SIZE_T bytesWritten = 0;
    if (!WriteProcessMemory(hProcess, pTargetBase, pSourceData, pNtHeaders->OptionalHeader.SizeOfHeaders, &bytesWritten) ||
        bytesWritten != pNtHeaders->OptionalHeader.SizeOfHeaders) {
        errorMsg = L"[-] Error writing PE headers, code: 0x" + to_wstring(GetLastError());
        return false;
    }
    errorMsg = L"[+] PE headers written successfully";
    return true;
}

bool WriteSections(InjectorContext & ctx, HANDLE hProcess, BYTE * pTargetBase, const BYTE * pSourceData, IMAGE_NT_HEADERS * pNtHeaders, wstring & errorMsg) {
    IMAGE_SECTION_HEADER* pSectionHeader = IMAGE_FIRST_SECTION(pNtHeaders);
    SIZE_T bytesWritten = 0;
    for (WORD i = 0; i < pNtHeaders->FileHeader.NumberOfSections; ++i) {
        if (pSectionHeader[i].SizeOfRawData) {
            if (!WriteProcessMemory(hProcess, pTargetBase + pSectionHeader[i].VirtualAddress,
                pSourceData + pSectionHeader[i].PointerToRawData,
                pSectionHeader[i].SizeOfRawData, &bytesWritten) ||
                bytesWritten != pSectionHeader[i].SizeOfRawData) {
                errorMsg = L"[-] Error writing section " + to_wstring(i) + L", code: 0x" + to_wstring(GetLastError());
                return false;
            }
        }
    }
    errorMsg = L"[+] All sections written successfully";
    return true;
}

BYTE* AllocateMappingData(InjectorContext & ctx, HANDLE hProcess, const MANUAL_MAPPING_DATA & mappingData, wstring & errorMsg) {
    BYTE* pMappingDataAlloc = reinterpret_cast<BYTE*>(VirtualAllocEx(hProcess, nullptr, sizeof(MANUAL_MAPPING_DATA),
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
    if (!pMappingDataAlloc) {
        errorMsg = L"[-] Error allocating mapping data, code: 0x" + to_wstring(GetLastError());
        return nullptr;
    }
    SIZE_T bytesWritten = 0;
    if (!WriteProcessMemory(hProcess, pMappingDataAlloc, &mappingData, sizeof(MANUAL_MAPPING_DATA), &bytesWritten) ||
        bytesWritten != sizeof(MANUAL_MAPPING_DATA)) {
        errorMsg = L"[-] Error writing mapping data, code: 0x" + to_wstring(GetLastError());
        VirtualFreeEx(hProcess, pMappingDataAlloc, 0, MEM_RELEASE);
        return nullptr;
    }
    errorMsg = L"[+] Mapping data allocated and written";
    return pMappingDataAlloc;
}

void* AllocateAndWriteShellcode(InjectorContext & ctx, HANDLE hProcess, wstring & errorMsg) {
    void* pShellcode = VirtualAllocEx(hProcess, nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!pShellcode) {
        errorMsg = L"[-] Error allocating shellcode memory, code: 0x" + to_wstring(GetLastError());
        return nullptr;
    }
    SIZE_T bytesWritten = 0;
    if (!WriteProcessMemory(hProcess, pShellcode, Shellcode, 4096, &bytesWritten) || bytesWritten != 4096) {
        errorMsg = L"[-] Error writing shellcode, code: 0x" + to_wstring(GetLastError());
        VirtualFreeEx(hProcess, pShellcode, 0, MEM_RELEASE);
        return nullptr;
    }
    errorMsg = L"[+] Shellcode allocated and written";
    return pShellcode;
}

bool ExecuteShellcode(InjectorContext & ctx, HANDLE hProcess, void* pShellcode, BYTE * pMappingData, wstring & errorMsg) {
    HANDLE hThread = CreateRemoteThread(hProcess, nullptr, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(pShellcode),
        pMappingData, 0, nullptr);
    if (!hThread) {
        errorMsg = L"[-] Error creating remote thread, code: 0x" + to_wstring(GetLastError());
        return false;
    }
    CloseHandle(hThread);
    errorMsg = L"[+] Remote thread created for shellcode execution";
    return true;
}

bool WaitForInjection(InjectorContext & ctx, HANDLE hProcess, BYTE * pMappingData, HINSTANCE & hModule, wstring & errorMsg) {
    random_device rd;
    mt19937 gen(rd());
    uniform_int_distribution<> dis(5, 15);
    for (int i = 0; i < 100; ++i) {
        SIZE_T bytesRead = 0;
        HINSTANCE tempModule;
        if (!ReadProcessMemory(hProcess, pMappingData + offsetof(MANUAL_MAPPING_DATA, hMod),
            &tempModule, sizeof(HINSTANCE), &bytesRead) || bytesRead != sizeof(HINSTANCE)) {
            errorMsg = L"[-] Error reading module handle, code: 0x" + to_wstring(GetLastError());
            return false;
        }
        if (tempModule != nullptr) {
            hModule = tempModule;
            if (hModule == reinterpret_cast<HINSTANCE>(0x404040)) {
                errorMsg = L"[-] Injection failed (shellcode returned error)";
                return false;
            }
            if (hModule == reinterpret_cast<HINSTANCE>(0x505050)) {
                errorMsg = L"[!] Injection completed but SEH support failed";
                hModule = reinterpret_cast<HINSTANCE>(pMappingData);
                return true;
            }
            errorMsg = L"[+] Injection successful, module handle retrieved";
            return true;
        }
        this_thread::sleep_for(chrono::milliseconds(dis(gen)));
    }
    errorMsg = L"[-] Injection timed out";
    return false;
}

bool CleanAndProtectMemory(InjectorContext & ctx, HANDLE hProcess, BYTE * pTargetBase, IMAGE_NT_HEADERS * pNtHeaders,
    void* pShellcode, BYTE * pMappingData, bool cleanHeader, bool cleanUnneededSections,
    bool adjustProtections, bool sehSupport, wstring & errorMsg) {
    random_device rd;
    mt19937 gen(rd());
    uniform_int_distribution<> dis(5, 15);
    if (cleanHeader) {
        BYTE cleanBuffer[0x1000] = { 0 };
        SIZE_T bytesWritten = 0;
        if (!WriteProcessMemory(hProcess, pTargetBase, cleanBuffer, pNtHeaders->OptionalHeader.SizeOfHeaders, &bytesWritten)) {
            errorMsg = L"[-] Error cleaning headers, code: 0x" + to_wstring(GetLastError());
            return false;
        }
    }
    if (cleanUnneededSections) {
        BYTE cleanBuffer[0x1000] = { 0 };
        IMAGE_SECTION_HEADER* pSectionHeader = IMAGE_FIRST_SECTION(pNtHeaders);
        SIZE_T bytesWritten = 0;
        for (WORD i = 0; i < pNtHeaders->FileHeader.NumberOfSections; ++i) {
            bool isExecutable = (pSectionHeader[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) != 0;
            bool isReadable = (pSectionHeader[i].Characteristics & IMAGE_SCN_MEM_READ) != 0;
            bool isWritable = (pSectionHeader[i].Characteristics & IMAGE_SCN_MEM_WRITE) != 0;
            if (!isExecutable && !isReadable && !isWritable) {
                if (pSectionHeader[i].SizeOfRawData) {
                    if (!WriteProcessMemory(hProcess, pTargetBase + pSectionHeader[i].VirtualAddress,
                        cleanBuffer, pSectionHeader[i].SizeOfRawData, &bytesWritten)) {
                        errorMsg = L"[-] Error cleaning section " + to_wstring(i) + L", code: 0x" + to_wstring(GetLastError());
                        return false;
                    }
                }
            }
        }
    }
    if (adjustProtections) {
        IMAGE_SECTION_HEADER* pSectionHeader = IMAGE_FIRST_SECTION(pNtHeaders);
        for (WORD i = 0; i < pNtHeaders->FileHeader.NumberOfSections; ++i) {
            DWORD oldProtect = 0;
            DWORD newProtect = 0;
            if (pSectionHeader[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) {
                newProtect = (pSectionHeader[i].Characteristics & IMAGE_SCN_MEM_WRITE) ?
                    PAGE_EXECUTE_READWRITE : PAGE_EXECUTE_READ;
            }
            else {
                newProtect = (pSectionHeader[i].Characteristics & IMAGE_SCN_MEM_WRITE) ?
                    PAGE_READWRITE : PAGE_READONLY;
            }
            if (pSectionHeader[i].SizeOfRawData) {
                if (!VirtualProtectEx(hProcess, pTargetBase + pSectionHeader[i].VirtualAddress,
                    pSectionHeader[i].SizeOfRawData, newProtect, &oldProtect)) {
                    errorMsg = L"[-] Error adjusting section protection " + to_wstring(i) + L", code: 0x" + to_wstring(GetLastError());
                    return false;
                }
            }
        }
    }
    if (pShellcode) {
        VirtualFreeEx(hProcess, pShellcode, 0, MEM_RELEASE);
    }
    if (pMappingData) {
        VirtualFreeEx(hProcess, pMappingData, 0, MEM_RELEASE);
    }
    errorMsg = L"[+] Memory cleaned and protections adjusted";
    return true;
}

bool AllocateAndWriteHeaders(InjectorContext & ctx, HANDLE hProcess, const BYTE * pSourceData, SIZE_T fileSize, BYTE * &pTargetBase, IMAGE_NT_HEADERS * &pNtHeaders, DWORD & oldProtect) {
    wstring errorMsg;
    if (!ValidatePEHeaders(ctx, pSourceData, fileSize, errorMsg)) {
        LogErrorAndStatus(ctx, errorMsg, RGB(255, 0, 0), true);
        SendMessage(ctx.hwndProgressBar, PBM_SETSTATE, PBST_ERROR, 0);
        return false;
    }
    LogErrorAndStatus(ctx, errorMsg, RGB(0, 255, 0), false);
    pNtHeaders = reinterpret_cast<IMAGE_NT_HEADERS*>(const_cast<BYTE*>(pSourceData + reinterpret_cast<IMAGE_DOS_HEADER*>(const_cast<BYTE*>(pSourceData))->e_lfanew));
    pTargetBase = AllocateProcessMemory(ctx, hProcess, pNtHeaders->OptionalHeader.SizeOfImage, oldProtect, errorMsg);
    if (!pTargetBase) {
        LogErrorAndStatus(ctx, errorMsg, RGB(255, 0, 0), true);
        SendMessage(ctx.hwndProgressBar, PBM_SETSTATE, PBST_ERROR, 0);
        return false;
    }
    LogErrorAndStatus(ctx, errorMsg, RGB(0, 255, 0), false);
    if (!WritePEHeaders(ctx, hProcess, pTargetBase, pSourceData, errorMsg)) {
        LogErrorAndStatus(ctx, errorMsg, RGB(255, 0, 0), true);
        VirtualFreeEx(hProcess, pTargetBase, 0, MEM_RELEASE);
        SendMessage(ctx.hwndProgressBar, PBM_SETSTATE, PBST_ERROR, 0);
        return false;
    }
    LogErrorAndStatus(ctx, errorMsg, RGB(0, 255, 0), false);
    return true;
}

bool WriteSectionsToMemory(InjectorContext & ctx, HANDLE hProcess, BYTE * pTargetBase, const BYTE * pSourceData, IMAGE_NT_HEADERS * pNtHeaders) {
    wstring errorMsg;
    if (!WriteSections(ctx, hProcess, pTargetBase, pSourceData, pNtHeaders, errorMsg)) {
        LogErrorAndStatus(ctx, errorMsg, RGB(255, 0, 0), true);
        VirtualFreeEx(hProcess, pTargetBase, 0, MEM_RELEASE);
        SendMessage(ctx.hwndProgressBar, PBM_SETSTATE, PBST_ERROR, 0);
        return false;
    }
    return true;
}

bool PrepareMappingData(InjectorContext & ctx, HANDLE hProcess, BYTE * pTargetBase, bool sehSupport, DWORD reason, LPVOID reserved, BYTE * &pMappingDataAlloc) {
    wstring errorMsg;
    MANUAL_MAPPING_DATA mappingData = { 0 };
    mappingData.pLoadLibraryA = LoadLibraryA;
    mappingData.pGetProcAddress = GetProcAddress;
    HMODULE hNtdll = GetModuleHandleA(ctx.ntdllName);
    if (!hNtdll) {
        LogErrorAndStatus(ctx, L"[-] Error getting handle to module, code: 0x" + to_wstring(GetLastError()), RGB(255, 0, 0), true);
        return false;
    }
    mappingData.pRtlAddFunctionTable = reinterpret_cast<f_RtlAddFunctionTable>(GetProcAddress(hNtdll, "RtlAddFunctionTable"));
    mappingData.pBase = pTargetBase;
    mappingData.dwReason = reason;
    mappingData.lpReserved = reserved;
    mappingData.bSEHSupport = sehSupport;
    pMappingDataAlloc = AllocateMappingData(ctx, hProcess, mappingData, errorMsg);
    if (!pMappingDataAlloc) {
        LogErrorAndStatus(ctx, errorMsg, RGB(255, 0, 0), true);
        return false;
    }
    LogErrorAndStatus(ctx, errorMsg, RGB(0, 255, 0), false);
    return true;
}

bool AllocateAndWriteShellcodeAndExecute(InjectorContext & ctx, HANDLE hProcess, BYTE * pMappingDataAlloc, void*& pShellcode) {
    wstring errorMsg;
    pShellcode = AllocateAndWriteShellcode(ctx, hProcess, errorMsg);
    if (!pShellcode) {
        LogErrorAndStatus(ctx, errorMsg, RGB(255, 0, 0), true);
        return false;
    }
    LogErrorAndStatus(ctx, errorMsg, RGB(0, 255, 0), false);
    if (!ExecuteShellcode(ctx, hProcess, pShellcode, pMappingDataAlloc, errorMsg)) {
        LogErrorAndStatus(ctx, errorMsg, RGB(255, 0, 0), true);
        return false;
    }
    LogErrorAndStatus(ctx, errorMsg, RGB(0, 255, 0), false);
    return true;
}

bool WaitAndCleanUp(InjectorContext & ctx, HANDLE hProcess, BYTE * pTargetBase, IMAGE_NT_HEADERS * pNtHeaders, void* pShellcode, BYTE * pMappingDataAlloc, bool cleanHeader, bool cleanUnneededSections, bool adjustProtections, bool sehSupport) {
    wstring errorMsg;
    HINSTANCE hModule = nullptr;
    if (!WaitForInjection(ctx, hProcess, pMappingDataAlloc, hModule, errorMsg)) {
        LogErrorAndStatus(ctx, errorMsg, RGB(255, 0, 0), true);
        return false;
    }
    LogErrorAndStatus(ctx, errorMsg, RGB(0, 255, 0), false);
    if (!CleanAndProtectMemory(ctx, hProcess, pTargetBase, pNtHeaders, pShellcode, pMappingDataAlloc, cleanHeader, cleanUnneededSections, adjustProtections, sehSupport, errorMsg)) {
        LogErrorAndStatus(ctx, errorMsg, RGB(255, 0, 0), true);
        return false;
    }
    LogErrorAndStatus(ctx, errorMsg, RGB(0, 255, 0), false);
    return true;
}

bool ManualMapDLL(InjectorContext & ctx, HANDLE hProcess, const BYTE * pSourceData, SIZE_T fileSize, bool cleanHeader,
    bool cleanUnneededSections, bool adjustProtections, bool sehSupport,
    DWORD reason, LPVOID reserved) {
    try {
        auto startTime = chrono::high_resolution_clock::now();
        LogErrorAndStatus(ctx, L"[+] Initializing injection process...", RGB(0, 255, 0), false);
        SendMessage(ctx.hwndProgressBar, PBM_SETRANGE, 0, MAKELPARAM(0, 100));
        SendMessage(ctx.hwndProgressBar, PBM_SETSTEP, (WPARAM)10, 0);
        SendMessage(ctx.hwndProgressBar, PBM_SETSTATE, PBST_NORMAL, 0);
        SendMessage(ctx.hwndProgressBar, PBM_SETPOS, 0, 0);

        random_device rd;
        mt19937 gen(rd());
        uniform_int_distribution<> dis(5, 15);

        BYTE* pTargetBase = nullptr;
        IMAGE_NT_HEADERS* pNtHeaders = nullptr;
        DWORD oldProtect = 0;
        if (!AllocateAndWriteHeaders(ctx, hProcess, pSourceData, fileSize, pTargetBase, pNtHeaders, oldProtect)) {
            return false;
        }
        SendMessage(ctx.hwndProgressBar, PBM_STEPIT, 0, 0);
        this_thread::sleep_for(chrono::milliseconds(dis(gen)));

        if (!WriteSectionsToMemory(ctx, hProcess, pTargetBase, pSourceData, pNtHeaders)) {
            VirtualFreeEx(hProcess, pTargetBase, 0, MEM_RELEASE);
            return false;
        }
        SendMessage(ctx.hwndProgressBar, PBM_STEPIT, 0, 0);
        this_thread::sleep_for(chrono::milliseconds(dis(gen)));

        BYTE* pMappingDataAlloc = nullptr;
        if (!PrepareMappingData(ctx, hProcess, pTargetBase, sehSupport, reason, reserved, pMappingDataAlloc)) {
            VirtualFreeEx(hProcess, pTargetBase, 0, MEM_RELEASE);
            return false;
        }
        SendMessage(ctx.hwndProgressBar, PBM_STEPIT, 0, 0);
        this_thread::sleep_for(chrono::milliseconds(dis(gen)));

        void* pShellcode = nullptr;
        if (!AllocateAndWriteShellcodeAndExecute(ctx, hProcess, pMappingDataAlloc, pShellcode)) {
            VirtualFreeEx(hProcess, pTargetBase, 0, MEM_RELEASE);
            VirtualFreeEx(hProcess, pMappingDataAlloc, 0, MEM_RELEASE);
            return false;
        }
        SendMessage(ctx.hwndProgressBar, PBM_STEPIT, 0, 0);
        this_thread::sleep_for(chrono::milliseconds(dis(gen)));

        if (!WaitAndCleanUp(ctx, hProcess, pTargetBase, pNtHeaders, pShellcode, pMappingDataAlloc, cleanHeader, cleanUnneededSections, adjustProtections, sehSupport)) {
            VirtualFreeEx(hProcess, pTargetBase, 0, MEM_RELEASE);
            VirtualFreeEx(hProcess, pMappingDataAlloc, 0, MEM_RELEASE);
            VirtualFreeEx(hProcess, pShellcode, 0, MEM_RELEASE);
            return false;
        }
        SendMessage(ctx.hwndProgressBar, PBM_STEPIT, 0, 0);
        this_thread::sleep_for(chrono::milliseconds(dis(gen)));

        auto endTime = chrono::high_resolution_clock::now();
        auto durationMs = chrono::duration_cast<chrono::milliseconds>(endTime - startTime).count();
        double durationSec = durationMs / 1000.0;
        wstringstream durationStream;
        durationStream << fixed << setprecision(3) << durationSec;
        LogErrorAndStatus(ctx, L"[+] Injection completed in " + durationStream.str() + L" seconds", RGB(0, 255, 0), false);
        SendMessage(ctx.hwndProgressBar, PBM_SETPOS, 100, 0);
        SendMessage(ctx.hwndProgressBar, PBM_SETSTATE, PBST_NORMAL, 0);
        return true;
    }
    catch (const exception& e) {
        wstring error = L"[-] Exception in ManualMapDLL: " + wstring(e.what(), e.what() + strlen(e.what()));
        LogErrorAndStatus(ctx, error, RGB(255, 0, 0), true);
        SendMessage(ctx.hwndProgressBar, PBM_SETSTATE, PBST_ERROR, 0);
        return false;
    }
}

LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    static InjectorContext ctx;
    static HFONT hFontTitle = CreateFontW(24, 0, 0, 0, FW_BOLD, FALSE, FALSE, FALSE, DEFAULT_CHARSET, OUT_DEFAULT_PRECIS,
        CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE, L"Segoe UI");
    static HFONT hFontButton = CreateFontW(18, 0, 0, 0, FW_BOLD, FALSE, FALSE, FALSE, DEFAULT_CHARSET, OUT_DEFAULT_PRECIS,
        CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE, L"Segoe UI");
    static HFONT hFontStatus = CreateFontW(18, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE, DEFAULT_CHARSET, OUT_DEFAULT_PRECIS,
        CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE, L"Segoe UI");
    static HFONT hFontFooter = CreateFontW(14, 0, 0, 0, FW_BOLD, FALSE, FALSE, FALSE, DEFAULT_CHARSET, OUT_DEFAULT_PRECIS,
        CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE, L"Segoe UI");
    static HBITMAP hBitmap = nullptr;
    static HBRUSH hBackgroundBrush = CreateSolidBrush(RGB(12, 16, 25));
    static HBRUSH hStatusBrush = CreateSolidBrush(RGB(0, 0, 0));

    switch (msg) {
    case WM_CREATE: {
        INITCOMMONCONTROLSEX icex = { sizeof(INITCOMMONCONTROLSEX), ICC_STANDARD_CLASSES | ICC_PROGRESS_CLASS };
        InitCommonControlsEx(&icex);
        SetClassLongPtr(hwnd, GCLP_HBRBACKGROUND, (LONG_PTR)hBackgroundBrush);
        hBitmap = (HBITMAP)LoadImageW(GetModuleHandle(NULL), MAKEINTRESOURCE(IDB_TREVOR_BMP), IMAGE_BITMAP, 0, 0, 0);
        if (!hBitmap) {
            DWORD error = GetLastError();
            LogErrorAndStatus(ctx, L"[-] Error loading bitmap, code: 0x" + to_wstring(error), RGB(255, 0, 0), true);
        }
        ctx.hwndMain = hwnd;
        HWND hImage = CreateWindowW(L"STATIC", NULL, WS_VISIBLE | WS_CHILD | SS_BITMAP | SS_CENTERIMAGE,
            (800 - 362) / 2, 20, 362, 55, hwnd, NULL, GetModuleHandle(NULL), NULL);
        if (hBitmap) {
            SendMessage(hImage, STM_SETIMAGE, IMAGE_BITMAP, (LPARAM)hBitmap);
        }
        HWND hTitle = CreateWindowW(L"STATIC", L"Simple and Secure .DLL Injector | By s0mbra",
            WS_VISIBLE | WS_CHILD | SS_CENTER, 50, 95, 700, 50, hwnd, NULL, GetModuleHandle(NULL), NULL);
        SendMessage(hTitle, WM_SETFONT, (WPARAM)hFontTitle, TRUE);
        ctx.hwndProcessLabel = CreateWindowW(L"STATIC", L"Selected Process: None", WS_VISIBLE | WS_CHILD | SS_CENTER,
            50, 125, 330, 20, hwnd, (HMENU)5, GetModuleHandle(NULL), NULL);
        SendMessage(ctx.hwndProcessLabel, WM_SETFONT, (WPARAM)hFontStatus, TRUE);
        ctx.hwndProcessCombo = CreateWindowW(L"COMBOBOX", NULL, WS_VISIBLE | WS_CHILD | CBS_DROPDOWNLIST | CBS_SORT | WS_VSCROLL,
            50, 155, 280, 200, hwnd, (HMENU)IDD_PROCESSSELECT, GetModuleHandle(NULL), NULL);
        SendMessage(ctx.hwndProcessCombo, WM_SETFONT, (WPARAM)hFontButton, TRUE);
        ctx.hwndRefreshButton = CreateWindowW(L"BUTTON", L"Refresh", WS_VISIBLE | WS_CHILD | BS_PUSHBUTTON | BS_FLAT,
            340, 155, 50, 30, hwnd, (HMENU)4, GetModuleHandle(NULL), NULL);
        SendMessage(ctx.hwndRefreshButton, WM_SETFONT, (WPARAM)hFontButton, TRUE);
        ctx.hwndDllLabel = CreateWindowW(L"STATIC", L"Selected DLL: None", WS_VISIBLE | WS_CHILD | SS_CENTER,
            400, 125, 300, 20, hwnd, (HMENU)6, GetModuleHandle(NULL), NULL);
        SendMessage(ctx.hwndDllLabel, WM_SETFONT, (WPARAM)hFontStatus, TRUE);
        ctx.hwndBrowseButton = CreateWindowW(L"BUTTON", L"Select .DLL...", WS_VISIBLE | WS_CHILD | BS_PUSHBUTTON | BS_FLAT,
            400, 155, 120, 30, hwnd, (HMENU)1, GetModuleHandle(NULL), NULL);
        SendMessage(ctx.hwndBrowseButton, WM_SETFONT, (WPARAM)hFontButton, TRUE);
        ctx.hwndInjectButton = CreateWindowW(L"BUTTON", L"INJECT !", WS_VISIBLE | WS_CHILD | BS_PUSHBUTTON | BS_FLAT,
            530, 155, 120, 30, hwnd, (HMENU)2, GetModuleHandle(NULL), NULL);
        SendMessage(ctx.hwndInjectButton, WM_SETFONT, (WPARAM)hFontButton, TRUE);
        ctx.hwndProgressBar = CreateWindowW(PROGRESS_CLASSW, NULL, WS_VISIBLE | WS_CHILD | PBS_SMOOTH,
            50, 205, 700, 20, hwnd, NULL, GetModuleHandle(NULL), NULL);
        ctx.hwndStatus = CreateWindowExW(0, L"EDIT", L"Status: Ready to select process and DLL\r\n", WS_VISIBLE | WS_CHILD | WS_VSCROLL | ES_MULTILINE | ES_READONLY,
            50, 245, 700, 240, hwnd, NULL, GetModuleHandle(NULL), NULL);
        SendMessage(ctx.hwndStatus, WM_SETFONT, (WPARAM)hFontStatus, TRUE);
        CHARFORMATW cf = { sizeof(CHARFORMATW) };
        cf.dwMask = CFM_COLOR;
        cf.crTextColor = RGB(0, 255, 0);
        SendMessageW(ctx.hwndStatus, EM_SETCHARFORMAT, SCF_ALL, (LPARAM)&cf);
        HWND hFooter = CreateWindowW(L"STATIC", L"Use this tool at your own risk. The source code is public and can be reviewed at: https://github.com/s0mbra-1973/Trevor",
            WS_VISIBLE | WS_CHILD | SS_CENTER, 50, 495, 700, 40, hwnd, (HMENU)3, GetModuleHandle(NULL), NULL);
        SendMessage(hFooter, WM_SETFONT, (WPARAM)hFontFooter, TRUE);
        HandleGuard snapshot(CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0));
        if (snapshot.get() == INVALID_HANDLE_VALUE) {
            LogErrorAndStatus(ctx, L"[-] Failed to load process list, please try refreshing", RGB(255, 0, 0), true);
            EnableWindow(ctx.hwndInjectButton, FALSE);
        }
        else {
            PROCESSENTRY32W entry = { sizeof(PROCESSENTRY32W) };
            if (Process32FirstW(snapshot, &entry)) {
                do {
                    wstring display = wstring(entry.szExeFile) + L" (PID: " + to_wstring(entry.th32ProcessID) + L")";
                    SendMessageW(ctx.hwndProcessCombo, CB_ADDSTRING, 0, (LPARAM)display.c_str());
                } while (Process32NextW(snapshot, &entry));
            }
            SendMessageW(ctx.hwndProcessCombo, CB_SETCURSEL, 0, 0);
            if (!ctx.processName.empty()) {
                wstring searchStr = ctx.processName + L" (PID: ";
                LRESULT index = SendMessageW(ctx.hwndProcessCombo, CB_FINDSTRING, (WPARAM)-1, (LPARAM)searchStr.c_str());
                if (index != CB_ERR) {
                    SendMessageW(ctx.hwndProcessCombo, CB_SETCURSEL, index, 0);
                    SetWindowTextW(ctx.hwndProcessLabel, (L"Selected Process: " + ctx.processName).c_str());
                }
            }
            if (!ctx.dllPath.empty()) {
                SetWindowTextW(ctx.hwndDllLabel, (L"Selected DLL: " + ctx.dllPath).c_str());
                LogErrorAndStatus(ctx, L"[+] Loaded last DLL: " + ctx.dllPath, RGB(0, 255, 0), false);
            }
            EnableWindow(ctx.hwndInjectButton, !ctx.processName.empty() && !ctx.dllPath.empty());
        }
        break;
    }
    case WM_CTLCOLORSTATIC: {
        HDC hdc = (HDC)wParam;
        HWND hCtrl = (HWND)lParam;
        if (hCtrl == ctx.hwndProcessLabel || hCtrl == ctx.hwndDllLabel || hCtrl == GetDlgItem(hwnd, 3)) {
            SetTextColor(hdc, RGB(255, 255, 255));
            SetBkColor(hdc, RGB(12, 16, 25));
            return (LRESULT)hBackgroundBrush;
        }
        SetTextColor(hdc, RGB(255, 255, 255));
        SetBkColor(hdc, RGB(12, 16, 25));
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
        if (wParam == 1) {
            KillTimer(hwnd, 1);
            PostMessage(hwnd, WM_CLOSE, 0, 0);
        }
        break;
    }
    case WM_COMMAND: {
        if (LOWORD(wParam) == 4) {
            SendMessageW(ctx.hwndProcessCombo, CB_RESETCONTENT, 0, 0);
            HandleGuard snapshot(CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0));
            if (snapshot.get() == INVALID_HANDLE_VALUE) {
                LogErrorAndStatus(ctx, L"[-] Failed to refresh process list", RGB(255, 0, 0), true);
                EnableWindow(ctx.hwndInjectButton, FALSE);
            }
            else {
                PROCESSENTRY32W entry = { sizeof(PROCESSENTRY32W) };
                if (Process32FirstW(snapshot, &entry)) {
                    do {
                        wstring display = wstring(entry.szExeFile) + L" (PID: " + to_wstring(entry.th32ProcessID) + L")";
                        SendMessageW(ctx.hwndProcessCombo, CB_ADDSTRING, 0, (LPARAM)display.c_str());
                    } while (Process32NextW(snapshot, &entry));
                }
                SendMessageW(ctx.hwndProcessCombo, CB_SETCURSEL, 0, 0);
                LogErrorAndStatus(ctx, L"[+] Process list refreshed", RGB(0, 255, 0), false);
                EnableWindow(ctx.hwndInjectButton, !ctx.processName.empty() && !ctx.dllPath.empty());
            }
        }
        else if (HIWORD(wParam) == CBN_SELCHANGE && LOWORD(wParam) == IDD_PROCESSSELECT) {
            LRESULT index = SendMessageW(ctx.hwndProcessCombo, CB_GETCURSEL, 0, 0);
            if (index != CB_ERR) {
                wchar_t buffer[260];
                SendMessageW(ctx.hwndProcessCombo, CB_GETLBTEXT, index, (LPARAM)buffer);
                wstring selected = buffer;
                size_t pos = selected.find(L" (PID:");
                if (pos != wstring::npos) {
                    ctx.processName = selected.substr(0, pos);
                    SetWindowTextW(ctx.hwndProcessLabel, (L"Selected Process: " + ctx.processName).c_str());
                    WritePrivateProfileStringW(L"Settings", L"LastProcess", ctx.processName.c_str(), L"Injector.ini");
                    LogErrorAndStatus(ctx, L"[+] Selected process: " + ctx.processName, RGB(0, 255, 0), false);
                    EnableWindow(ctx.hwndInjectButton, !ctx.processName.empty() && !ctx.dllPath.empty());
                }
            }
        }
        else if (LOWORD(wParam) == 1) {
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
                ctx.dllPath = szFile;
                if (!ctx.ValidateDLLPath(ctx.dllPath)) {
                    ctx.dllPath.clear();
                    SetWindowTextW(ctx.hwndDllLabel, L"Selected DLL: None");
                    EnableWindow(ctx.hwndInjectButton, FALSE);
                    return 0;
                }
                SetWindowTextW(ctx.hwndDllLabel, (L"Selected DLL: " + ctx.dllPath).c_str());
                WritePrivateProfileStringW(L"Settings", L"LastDLL", ctx.dllPath.c_str(), L"Injector.ini");
                wstring status = L"[+] DLL selected: " + ctx.dllPath;
                LogErrorAndStatus(ctx, status, RGB(0, 255, 0), false);
                EnableWindow(ctx.hwndInjectButton, !ctx.processName.empty() && !ctx.dllPath.empty());
            }
        }
        else if (LOWORD(wParam) == 2) {
            if (!IsRunAsAdmin()) {
                MessageBoxW(hwnd, L"ＴＲＥ▼ＯＲ５ Injector MUST be run as Administrator.", L"Error", MB_OK | MB_ICONERROR);
                LogErrorAndStatus(ctx, L"[-] Application MUST be run as administrator", RGB(255, 0, 0), true);
                return 0;
            }
            if (ctx.dllPath.empty()) {
                LogErrorAndStatus(ctx, L"[-] Please select a DLL file first", RGB(255, 0, 0), true);
                return 0;
            }
            if (ctx.processName.empty()) {
                LogErrorAndStatus(ctx, L"[-] Please select a process first", RGB(255, 0, 0), true);
                return 0;
            }
            wstring confirmMsg = L"Are you sure you want to inject\n" + ctx.dllPath + L"\ninto process: " + ctx.processName + L"?";
            if (MessageBoxW(hwnd, confirmMsg.c_str(), L"Confirm Injection", MB_YESNO | MB_ICONQUESTION) != IDYES) {
                LogErrorAndStatus(ctx, L"[*] Injection cancelled by user", RGB(255, 255, 0), false);
                return 0;
            }
            LogErrorAndStatus(ctx, L"[*] Searching for process: " + ctx.processName, RGB(255, 255, 0), false);
            DWORD pid = GetPIDByName(ctx, ctx.processName);
            if (pid == 0) {
                LogErrorAndStatus(ctx, L"[-] Target process not found. Ensure the process is running!", RGB(255, 0, 0), true);
                return 0;
            }
            wstring pidStatus = L"[+] Injecting into target process (PID: " + to_wstring(pid) + L")";
            LogErrorAndStatus(ctx, pidStatus, RGB(0, 255, 0), false);
            HandleGuard hToken;
            HANDLE hTokenTemp = nullptr;
            if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hTokenTemp)) {
                hToken.reset(hTokenTemp);
                TOKEN_PRIVILEGES privileges = { 0 };
                privileges.PrivilegeCount = 1;
                privileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
                if (LookupPrivilegeValue(nullptr, SE_DEBUG_NAME, &privileges.Privileges[0].Luid)) {
                    AdjustTokenPrivileges(hToken, FALSE, &privileges, 0, nullptr, nullptr);
                    LogErrorAndStatus(ctx, L"[+] Debug privileges enabled", RGB(0, 255, 0), false);
                }
                else {
                    LogErrorAndStatus(ctx, L"[!] Warning: Could not enable debug privileges, code: 0x" + to_wstring(GetLastError()), RGB(255, 255, 0), true);
                }
            }
            else {
                LogErrorAndStatus(ctx, L"[!] Warning: Could not open process token, code: 0x" + to_wstring(GetLastError()), RGB(255, 225, 0), true);
            }
            HandleGuard hProcess(OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid));
            if (!hProcess) {
                LogErrorAndStatus(ctx, L"[-] Error opening target process, code: 0x" + to_wstring(GetLastError()), RGB(255, 0, 0), true);
                return 0;
            }
            LogErrorAndStatus(ctx, L"[+] Target process opened successfully", RGB(0, 255, 0), false);
            if (!IsCorrectArchitecture(hProcess)) {
                LogErrorAndStatus(ctx, L"[-] Target process architecture not compatible", RGB(255, 0, 0), true);
                return 0;
            }
            LogErrorAndStatus(ctx, L"[+] Target process architecture verified", RGB(0, 255, 0), false);
            vector<BYTE> dllData;
            try {
                dllData = LoadDLL(ctx, ctx.dllPath);
                LogErrorAndStatus(ctx, L"[+] DLL file loaded successfully", RGB(0, 255, 0), false);
            }
            catch (const exception& e) {
                wstring error = L"[-] Error loading DLL: " + wstring(e.what(), e.what() + strlen(e.what()));
                LogErrorAndStatus(ctx, error, RGB(255, 0, 0), true);
                return 0;
            }
            if (!CheckDLLArchitecture(ctx, dllData, hProcess)) {
                return 0;
            }
            LogErrorAndStatus(ctx, L"[+] Starting DLL injection process...", RGB(0, 255, 0), false);
            if (!ManualMapDLL(ctx, hProcess, dllData.data(), dllData.size(), true, true, true, true, DLL_PROCESS_ATTACH, nullptr)) {
                LogErrorAndStatus(ctx, L"[-] Error during injection", RGB(255, 0, 0), true);
                return 0;
            }
            LogErrorAndStatus(ctx, L"[+] INJECTION COMPLETED SUCCESSFULLY! Created by s0mbra (c) 2025", RGB(0, 255, 0), false);
            PlaySuccessSound();
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
    random_device rd;
    mt19937 gen(rd());
    string chars = "$%&/=$abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    uniform_int_distribution<int> dis(0, static_cast<int>(chars.size() - 1));
    wstring randomStr;
    for (int i = 0; i < 4; ++i) {
        randomStr += static_cast<wchar_t>(chars[dis(gen)]);
    }
    wstring exeName = L"ＴＲＥ▼ＯＲ５_" + randomStr + L".exe";
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
        MessageBoxW(NULL, L"ＴＲＥ▼ＯＲ５ Injector MUST be run as Administrator.", L"Error", MB_OK | MB_ICONERROR);
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
    RECT rc = { 0, 0, 800, 565 };
    AdjustWindowRect(&rc, WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX, FALSE);
    int windowWidth = rc.right - rc.left;
    int windowHeight = rc.bottom - rc.top;
    int screenWidth = GetSystemMetrics(SM_CXSCREEN);
    int screenHeight = GetSystemMetrics(SM_CYSCREEN);
    int posX = (screenWidth - windowWidth) / 2;
    int posY = (screenHeight - windowHeight) / 2;
    HWND hwndMain = CreateWindowW(L"InjectorWindowClass", L"ＴＲＥ▼ＯＲ Injector ５",
        WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX,
        posX, posY, windowWidth, windowHeight, NULL, NULL, hInstance, NULL);
    if (!hwndMain) {
        if (hIcon) DestroyIcon(hIcon);
        MessageBoxW(NULL, L"Error creating window.", L"Error", MB_OK | MB_ICONERROR);
        return -1;
    }
    if (hIcon) {
        SendMessage(hwndMain, WM_SETICON, ICON_BIG, (LPARAM)hIcon);
        SendMessage(hwndMain, WM_SETICON, ICON_SMALL, (LPARAM)hIcon);
    }
    ShowWindow(hwndMain, nCmdShow);
    UpdateWindow(hwndMain);
    MSG msg = { 0 };
    while (GetMessage(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }
    if (hIcon) DestroyIcon(hIcon);
    return (int)msg.wParam;
}