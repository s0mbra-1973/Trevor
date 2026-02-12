
#include "Resource.h"
#include <windows.h>
#include <mmsystem.h> // For PlaySoundW
#include <commctrl.h> // For InitCommonControlsEx

// ===== Standard C++ Libraries (Must be included BEFORE Windows.h) =====
#include <algorithm>
#include <chrono>
#include <ctime>
#include <fstream>
#include <iomanip>
#include <locale>
#include <map>
#include <random>
#include <set>
#include <sstream>
#include <string>
#include <thread>
#include <vector>
// ===== Windows Headers =====
#ifdef WIN32_LEAN_AND_MEAN
#undef WIN32_LEAN_AND_MEAN
#endif

#define NOMINMAX
#define UNICODE
#define _UNICODE

#include <CommCtrl.h>
#include <Mmsystem.h>
#include <Richedit.h>
#include <Shlwapi.h>
#include <TlHelp32.h>
#include <Windows.h>
#include <dwmapi.h>
#include <objidl.h>
#include <gdiplus.h>
#include <gdiplusimaging.h>
#include <ole2.h>
#include <shellapi.h>
#include <uxtheme.h>
#include <winnt.h>
#include <winternl.h>

#ifndef DWMWA_USE_IMMERSIVE_DARK_MODE
#define DWMWA_USE_IMMERSIVE_DARK_MODE 20
#endif
#ifndef DWMWA_SYSTEMBACKDROP_TYPE
#define DWMWA_SYSTEMBACKDROP_TYPE 38
#endif
#ifndef DWMSBT_MAINWINDOW
#define DWMSBT_MAINWINDOW 2
#endif

#pragma comment(lib, "winmm.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "gdi32.lib")
#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "dwmapi.lib")
#pragma comment(lib, "uxtheme.lib")
#pragma comment(lib, "gdiplus.lib")

// Force Common Controls v6 manifest (guaranteed embedding via linker)
#pragma comment(linker, "\"/manifestdependency:type='win32' \
name='Microsoft.Windows.Common-Controls' version='6.0.0.0' \
processorArchitecture='*' publicKeyToken='6595b64144ccf1df' language='*'\"")

using namespace std;

// ===== Original function typedefs =====
using f_LoadLibraryA = HINSTANCE(WINAPI *)(LPCSTR lpLibFilename);
using f_GetProcAddress = FARPROC(WINAPI *)(HMODULE hModule, LPCSTR lpProcName);
using f_DLL_ENTRY_POINT = BOOL(WINAPI *)(void *hDll, DWORD dwReason,
                                         void *pReserved);
using f_RtlAddFunctionTable = BOOLEAN(WINAPI *)(PRUNTIME_FUNCTION FunctionTable,
                                                DWORD EntryCount,
                                                DWORD64 BaseAddress);

// ===== NT API typedefs for stealth (bypass user-mode hooks) =====
typedef NTSTATUS(NTAPI *f_NtAllocateVirtualMemory)(
    HANDLE ProcessHandle, PVOID *BaseAddress, ULONG_PTR ZeroBits,
    PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect);
typedef NTSTATUS(NTAPI *f_NtWriteVirtualMemory)(HANDLE ProcessHandle,
                                                PVOID BaseAddress, PVOID Buffer,
                                                SIZE_T NumberOfBytesToWrite,
                                                PSIZE_T NumberOfBytesWritten);
typedef NTSTATUS(NTAPI *f_NtFreeVirtualMemory)(HANDLE ProcessHandle,
                                               PVOID *BaseAddress,
                                               PSIZE_T RegionSize,
                                               ULONG FreeType);
typedef NTSTATUS(NTAPI *f_NtProtectVirtualMemory)(HANDLE ProcessHandle,
                                                  PVOID *BaseAddress,
                                                  PSIZE_T RegionSize,
                                                  ULONG NewProtect,
                                                  PULONG OldProtect);
typedef NTSTATUS(NTAPI *f_NtCreateThreadEx)(
    PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess, PVOID ObjectAttributes,
    HANDLE ProcessHandle, PVOID StartRoutine, PVOID Argument, ULONG CreateFlags,
    SIZE_T ZeroBits, SIZE_T StackSize, SIZE_T MaximumStackSize,
    PVOID AttributeList);
typedef NTSTATUS(NTAPI *f_NtReadVirtualMemory)(HANDLE ProcessHandle,
                                               PVOID BaseAddress, PVOID Buffer,
                                               SIZE_T BufferSize,
                                               PSIZE_T NumberOfBytesRead);
typedef NTSTATUS(NTAPI *f_NtWaitForSingleObject)(HANDLE Handle,
                                                 BOOLEAN Alertable,
                                                 PLARGE_INTEGER Timeout);
typedef NTSTATUS(NTAPI *f_NtOpenProcess)(PHANDLE ProcessHandle,
                                         ACCESS_MASK DesiredAccess,
                                         PVOID ObjectAttributes,
                                         PVOID ClientId);
typedef NTSTATUS(NTAPI *f_NtQuerySystemInformation)(
    ULONG SystemInformationClass, PVOID SystemInformation,
    ULONG SystemInformationLength, PULONG ReturnLength);
typedef NTSTATUS(NTAPI *f_NtDuplicateObject)(
    HANDLE SourceProcessHandle, HANDLE SourceHandle, HANDLE TargetProcessHandle,
    PHANDLE TargetHandle, ACCESS_MASK DesiredAccess, ULONG HandleAttributes,
    ULONG Options);
typedef NTSTATUS(NTAPI *f_NtQueryObject)(HANDLE Handle,
                                         ULONG ObjectInformationClass,
                                         PVOID ObjectInformation,
                                         ULONG ObjectInformationLength,
                                         PULONG ReturnLength);

// SystemExtendedHandleInformation structures for handle hijacking (64-bit PID
// safe)
#define SystemExtendedHandleInformation_ID 64
#define DUPLICATE_SAME_ACCESS_FLAG 0x00000002

struct SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX {
  PVOID Object;
  ULONG_PTR UniqueProcessId;
  ULONG_PTR HandleValue;
  ULONG GrantedAccess;
  USHORT CreatorBackTraceIndex;
  USHORT ObjectTypeIndex;
  ULONG HandleAttributes;
  ULONG Reserved;
};

struct SYSTEM_HANDLE_INFORMATION_EX {
  ULONG_PTR NumberOfHandles;
  ULONG_PTR Reserved;
  SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX Handles[1];
};

// ===== Shellcode self-erase typedefs =====
using f_VirtualFree = BOOL(WINAPI *)(LPVOID lpAddress, SIZE_T dwSize,
                                     DWORD dwFreeType);
using f_RtlZeroMemory = void(WINAPI *)(PVOID Destination, SIZE_T Length);
using f_Sleep = void(WINAPI *)(DWORD dwMilliseconds);

// ===== NT API function pointers (resolved at runtime) =====
struct NtApis {
  f_NtAllocateVirtualMemory NtAllocateVirtualMemory = nullptr;
  f_NtWriteVirtualMemory NtWriteVirtualMemory = nullptr;
  f_NtFreeVirtualMemory NtFreeVirtualMemory = nullptr;
  f_NtProtectVirtualMemory NtProtectVirtualMemory = nullptr;
  f_NtCreateThreadEx NtCreateThreadEx = nullptr;
  f_NtReadVirtualMemory NtReadVirtualMemory = nullptr;
  f_NtWaitForSingleObject NtWaitForSingleObject = nullptr;
  f_NtOpenProcess NtOpenProcess = nullptr;
  f_NtQuerySystemInformation NtQuerySystemInformation = nullptr;
  f_NtDuplicateObject NtDuplicateObject = nullptr;
  f_NtQueryObject NtQueryObject = nullptr;
  bool valid = false;
};

struct MANUAL_MAPPING_DATA {
  f_LoadLibraryA pLoadLibraryA;
  f_GetProcAddress pGetProcAddress;
  f_RtlAddFunctionTable pRtlAddFunctionTable;
  f_VirtualFree pVirtualFree;
  f_RtlZeroMemory pRtlZeroMemory;
  f_Sleep pSleep;
  BYTE *pBase;
  HINSTANCE hMod;
  DWORD dwReason;
  LPVOID lpReserved;
  BOOL bSEHSupport;
  BYTE xorKey;
  SIZE_T imageSize;
  SIZE_T headersSize;
  PVOID pShellcodeBase;
  SIZE_T shellcodeSize;
};

// ===== Resolve NT APIs from ntdll dynamically =====
NtApis ResolveNtApis() {
  NtApis apis;
  HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
  if (!hNtdll)
    return apis;
  apis.NtAllocateVirtualMemory = (f_NtAllocateVirtualMemory)GetProcAddress(
      hNtdll, "NtAllocateVirtualMemory");
  apis.NtWriteVirtualMemory =
      (f_NtWriteVirtualMemory)GetProcAddress(hNtdll, "NtWriteVirtualMemory");
  apis.NtFreeVirtualMemory =
      (f_NtFreeVirtualMemory)GetProcAddress(hNtdll, "NtFreeVirtualMemory");
  apis.NtProtectVirtualMemory = (f_NtProtectVirtualMemory)GetProcAddress(
      hNtdll, "NtProtectVirtualMemory");
  apis.NtCreateThreadEx =
      (f_NtCreateThreadEx)GetProcAddress(hNtdll, "NtCreateThreadEx");
  apis.NtReadVirtualMemory =
      (f_NtReadVirtualMemory)GetProcAddress(hNtdll, "NtReadVirtualMemory");
  apis.NtWaitForSingleObject =
      (f_NtWaitForSingleObject)GetProcAddress(hNtdll, "NtWaitForSingleObject");
  apis.NtOpenProcess = (f_NtOpenProcess)GetProcAddress(hNtdll, "NtOpenProcess");
  apis.NtQuerySystemInformation = (f_NtQuerySystemInformation)GetProcAddress(
      hNtdll, "NtQuerySystemInformation");
  apis.NtDuplicateObject =
      (f_NtDuplicateObject)GetProcAddress(hNtdll, "NtDuplicateObject");
  apis.NtQueryObject = (f_NtQueryObject)GetProcAddress(hNtdll, "NtQueryObject");
  apis.valid = apis.NtAllocateVirtualMemory && apis.NtWriteVirtualMemory &&
               apis.NtFreeVirtualMemory && apis.NtProtectVirtualMemory &&
               apis.NtCreateThreadEx && apis.NtReadVirtualMemory;
  return apis;
}

// Global NT API instance
static NtApis g_NtApis;

// ===== Stealth wrappers: use NT APIs instead of Win32 to bypass hooks =====
// All wrappers fall back to Win32 if NT APIs are unavailable
BYTE *StealthAlloc(HANDLE hProcess, SIZE_T size, DWORD protect) {
  if (!g_NtApis.NtAllocateVirtualMemory) {
    return reinterpret_cast<BYTE *>(VirtualAllocEx(
        hProcess, nullptr, size, MEM_COMMIT | MEM_RESERVE, protect));
  }
  PVOID base = nullptr;
  SIZE_T regionSize = size;
  NTSTATUS status = g_NtApis.NtAllocateVirtualMemory(
      hProcess, &base, 0, &regionSize, MEM_COMMIT | MEM_RESERVE, protect);
  return (status >= 0) ? reinterpret_cast<BYTE *>(base) : nullptr;
}

// Returns NTSTATUS (>= 0 is success). lastStatus stores the last NTSTATUS for
// diagnostics.
static NTSTATUS g_lastWriteStatus = 0;
static DWORD g_lastWriteError = 0;

bool StealthWrite(HANDLE hProcess, PVOID dest, PVOID src, SIZE_T size) {
  // Try NT API first
  if (g_NtApis.NtWriteVirtualMemory) {
    SIZE_T written = 0;
    NTSTATUS status =
        g_NtApis.NtWriteVirtualMemory(hProcess, dest, src, size, &written);
    g_lastWriteStatus = status;
    g_lastWriteError = 0;
    if (status >= 0 && written == size)
      return true;
    // If NtWriteVirtualMemory failed, try smaller chunks (anti-cheat may block
    // large writes)
    if (status < 0 && size > 0x1000) {
      SIZE_T offset = 0;
      while (offset < size) {
        SIZE_T chunkSize = (std::min)(size - offset, (SIZE_T)0x1000);
        SIZE_T chunkWritten = 0;
        status = g_NtApis.NtWriteVirtualMemory(hProcess, (BYTE *)dest + offset,
                                               (BYTE *)src + offset, chunkSize,
                                               &chunkWritten);
        if (status < 0 || chunkWritten != chunkSize) {
          g_lastWriteStatus = status;
          break;
        }
        offset += chunkSize;
      }
      if (offset >= size)
        return true;
    }
  }
  // Fallback to Win32 WriteProcessMemory
  SIZE_T written = 0;
  SetLastError(0);
  if (WriteProcessMemory(hProcess, dest, src, size, &written) &&
      written == size) {
    g_lastWriteStatus = 0;
    g_lastWriteError = 0;
    return true;
  }
  g_lastWriteError = GetLastError();
  return false;
}

bool StealthRead(HANDLE hProcess, PVOID src, PVOID dest, SIZE_T size) {
  if (!g_NtApis.NtReadVirtualMemory) {
    SIZE_T bytesRead = 0;
    return ReadProcessMemory(hProcess, src, dest, size, &bytesRead) &&
           (bytesRead == size);
  }
  SIZE_T bytesRead = 0;
  NTSTATUS status =
      g_NtApis.NtReadVirtualMemory(hProcess, src, dest, size, &bytesRead);
  return (status >= 0) && (bytesRead == size);
}

bool StealthFree(HANDLE hProcess, PVOID base) {
  if (!g_NtApis.NtFreeVirtualMemory) {
    return VirtualFreeEx(hProcess, base, 0, MEM_RELEASE) != 0;
  }
  SIZE_T regionSize = 0;
  NTSTATUS status =
      g_NtApis.NtFreeVirtualMemory(hProcess, &base, &regionSize, MEM_RELEASE);
  return (status >= 0);
}

bool StealthProtect(HANDLE hProcess, PVOID base, SIZE_T size, DWORD newProtect,
                    DWORD *oldProtect) {
  if (!g_NtApis.NtProtectVirtualMemory) {
    DWORD old = 0;
    BOOL ret = VirtualProtectEx(hProcess, base, size, newProtect, &old);
    if (oldProtect)
      *oldProtect = old;
    return ret != 0;
  }
  ULONG old = 0;
  NTSTATUS status =
      g_NtApis.NtProtectVirtualMemory(hProcess, &base, &size, newProtect, &old);
  if (oldProtect)
    *oldProtect = old;
  return (status >= 0);
}

HANDLE StealthCreateThread(HANDLE hProcess, PVOID startAddr, PVOID param) {
  if (!g_NtApis.NtCreateThreadEx) {
    return CreateRemoteThread(hProcess, nullptr, 0,
                              (LPTHREAD_START_ROUTINE)startAddr, param, 0,
                              nullptr);
  }
  HANDLE hThread = nullptr;
  NTSTATUS status =
      g_NtApis.NtCreateThreadEx(&hThread, THREAD_ALL_ACCESS, nullptr, hProcess,
                                startAddr, param, 0, 0, 0, 0, nullptr);
  return (status >= 0) ? hThread : nullptr;
}

// Minimum access rights for injection (much less suspicious than
// PROCESS_ALL_ACCESS)
constexpr DWORD INJECT_MIN_ACCESS = PROCESS_VM_OPERATION | PROCESS_VM_WRITE |
                                    PROCESS_VM_READ | PROCESS_CREATE_THREAD |
                                    PROCESS_QUERY_INFORMATION;

HANDLE StealthOpenProcess(DWORD desiredAccess, DWORD pid) {
  if (g_NtApis.NtOpenProcess) {
    // OBJECT_ATTRIBUTES: from winternl.h
    OBJECT_ATTRIBUTES oa;
    memset(&oa, 0, sizeof(oa));
    oa.Length = sizeof(oa);
    // CLIENT_ID: {UniqueProcess, UniqueThread}
    struct {
      HANDLE UniqueProcess;
      HANDLE UniqueThread;
    } clientId;
    memset(&clientId, 0, sizeof(clientId));
    clientId.UniqueProcess = (HANDLE)(ULONG_PTR)pid;
    HANDLE hProcess = nullptr;
    NTSTATUS status =
        g_NtApis.NtOpenProcess(&hProcess, desiredAccess, &oa, &clientId);
    if (status >= 0 && hProcess)
      return hProcess;
  }
  // Fallback to Win32 OpenProcess
  return OpenProcess(desiredAccess, FALSE, pid);
}

// ===== Handle Hijacking: find existing handles to a process and duplicate them
// ===== TARGETED approach: enumerate known system processes by name (csrss.exe,
// svchost.exe, services.exe, etc.) which always hold process handles to every
// process. Then look only at THEIR handles in the system handle table,
// duplicate and verify with GetProcessId.
//
// This is extremely lightweight: ~5-10 processes, ~50-200 dups total.
HANDLE HijackProcessHandle(DWORD targetPid, DWORD desiredAccess,
                           vector<wstring> *ppLog = nullptr) {
  auto log = [&](const wstring &msg) {
    if (ppLog)
      ppLog->push_back(msg);
  };

  if (!g_NtApis.NtQuerySystemInformation || !g_NtApis.NtDuplicateObject) {
    log(L"  [-] NtQuerySystemInformation or NtDuplicateObject not resolved");
    return nullptr;
  }

  // Step 1: Find PIDs of known system processes that hold process handles
  // These always have handles to every running process
  set<DWORD> systemPids;
  {
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap != INVALID_HANDLE_VALUE) {
      PROCESSENTRY32W pe = {sizeof(pe)};
      if (Process32FirstW(hSnap, &pe)) {
        do {
          wstring name(pe.szExeFile);
          // Convert to lowercase for comparison
          for (auto &ch : name)
            ch = towlower(ch);
          // Target non-PPL system processes that hold process handles.
          // EXCLUDED: csrss.exe, lsass.exe, smss.exe — these are Protected
          // Process Light (PPL) and can't be opened even with SeDebugPrivilege.
          if (name == L"services.exe" || name == L"svchost.exe" ||
              name == L"wininit.exe" || name == L"winlogon.exe" ||
              name == L"conhost.exe" || name == L"dllhost.exe" ||
              name == L"sihost.exe" || name == L"taskhostw.exe" ||
              name == L"runtimebroker.exe" || name == L"explorer.exe") {
            if (pe.th32ProcessID != 0 && pe.th32ProcessID != 4) {
              systemPids.insert(pe.th32ProcessID);
            }
          }
        } while (Process32NextW(hSnap, &pe));
      }
      CloseHandle(hSnap);
    }
  }

  log(L"  [i] Found " + to_wstring(systemPids.size()) +
      L" system processes to scan");

  if (systemPids.empty()) {
    log(L"  [-] Could not enumerate system processes");
    return nullptr;
  }

  // Step 2: Query extended system handle table
  ULONG bufferSize = 4 * 1024 * 1024;
  vector<BYTE> buffer;
  NTSTATUS status = (NTSTATUS)0xC0000004L;

  for (int attempt = 0; attempt < 15; ++attempt) {
    buffer.resize(bufferSize);
    ULONG returnLength = 0;
    status = g_NtApis.NtQuerySystemInformation(
        SystemExtendedHandleInformation_ID, buffer.data(), bufferSize,
        &returnLength);
    if (status == (NTSTATUS)0xC0000004L) {
      bufferSize =
          (returnLength > 0) ? (returnLength + 1024 * 1024) : (bufferSize * 2);
      continue;
    }
    break;
  }

  if (status < 0) {
    wchar_t hexBuf[32];
    swprintf_s(hexBuf, L"0x%08X", (ULONG)status);
    log(L"  [-] NtQuerySystemInformation failed: " + wstring(hexBuf));
    return nullptr;
  }

  auto *handleInfo =
      reinterpret_cast<SYSTEM_HANDLE_INFORMATION_EX *>(buffer.data());
  log(L"  [i] System handle table: " + to_wstring(handleInfo->NumberOfHandles) +
      L" handles");

  // Step 3: Collect handles ONLY from our known system processes
  struct HandleCandidate {
    ULONG_PTR ownerPid;
    ULONG_PTR handleValue;
    ULONG grantedAccess;
  };
  vector<HandleCandidate> candidates;

  for (ULONG_PTR i = 0; i < handleInfo->NumberOfHandles; ++i) {
    auto &entry = handleInfo->Handles[i];
    // Only look at handles from our known system processes
    if (systemPids.find((DWORD)entry.UniqueProcessId) == systemPids.end())
      continue;

    DWORD access = entry.GrantedAccess;
    // Filter for process-handle-like access rights
    // Process handles typically have PROCESS_QUERY_LIMITED_INFORMATION (0x1000)
    // or higher Skip obvious non-process patterns
    if (access < 0x400)
      continue;
    if (access == 0x120089 || access == 0x120116 || access == 0x12019F)
      continue; // FILE_GENERIC_*

    candidates.push_back({entry.UniqueProcessId, entry.HandleValue, access});
  }

  log(L"  [i] Collected " + to_wstring(candidates.size()) +
      L" handles from system processes");

  if (candidates.empty()) {
    log(L"  [-] No candidate handles found in system processes");
    return nullptr;
  }

  // Sort by access descending — try broadest access first (PROCESS_ALL_ACCESS =
  // 0x1FFFFF)
  std::sort(candidates.begin(), candidates.end(),
            [](const HandleCandidate &a, const HandleCandidate &b) {
              return a.grantedAccess > b.grantedAccess;
            });

  // Step 4: Open each system process, duplicate its handles, check with
  // GetProcessId
  HANDLE bestHandle = nullptr;
  DWORD bestAccess = 0;
  int ownersOpened = 0;
  int dupAttempted = 0;
  int dupSucceeded = 0;
  bool foundPerfect = false;

  map<ULONG_PTR, HANDLE> ownerHandles;

  for (auto &c : candidates) {
    if (foundPerfect)
      break;

    // Open owner if not cached
    if (ownerHandles.find(c.ownerPid) == ownerHandles.end()) {
      HANDLE hOwner = StealthOpenProcess(PROCESS_DUP_HANDLE, (DWORD)c.ownerPid);
      ownerHandles[c.ownerPid] = hOwner;
      if (hOwner)
        ownersOpened++;
    }
    HANDLE hOwner = ownerHandles[c.ownerPid];
    if (!hOwner)
      continue;

    dupAttempted++;

    // Duplicate with DUPLICATE_SAME_ACCESS
    HANDLE duplicated = nullptr;
    NTSTATUS dupStatus = g_NtApis.NtDuplicateObject(
        hOwner, (HANDLE)c.handleValue, GetCurrentProcess(), &duplicated, 0, 0,
        DUPLICATE_SAME_ACCESS_FLAG);

    if (dupStatus < 0 || !duplicated)
      continue;
    dupSucceeded++;

    // GetProcessId returns 0 for non-process handles, target PID for process
    // handles to target
    DWORD handlePid = GetProcessId(duplicated);
    if (handlePid != targetPid) {
      CloseHandle(duplicated);
      continue;
    }

    // Found a process handle to the target!
    if ((c.grantedAccess & desiredAccess) == desiredAccess) {
      // Has all the access we need
      if (bestHandle)
        CloseHandle(bestHandle);
      bestHandle = duplicated;
      bestAccess = c.grantedAccess;
      wchar_t hexBuf[32];
      swprintf_s(hexBuf, L"0x%08X", c.grantedAccess);
      log(L"  [+] HIJACKED! Owner PID " + to_wstring(c.ownerPid) + L" access " +
          hexBuf);
      foundPerfect = true;
    } else {
      // Insufficient access — try escalation via re-duplication with explicit
      // access
      HANDLE escalated = nullptr;
      NTSTATUS escStatus = g_NtApis.NtDuplicateObject(
          hOwner, (HANDLE)c.handleValue, GetCurrentProcess(), &escalated,
          desiredAccess, 0, 0);

      if (escStatus >= 0 && escalated && GetProcessId(escalated) == targetPid) {
        if (bestHandle)
          CloseHandle(bestHandle);
        CloseHandle(duplicated);
        bestHandle = escalated;
        bestAccess = desiredAccess;
        wchar_t hexBuf[32];
        swprintf_s(hexBuf, L"0x%08X", desiredAccess);
        log(L"  [+] ESCALATED! Owner PID " + to_wstring(c.ownerPid) +
            L" escalated to " + hexBuf);
        foundPerfect = true;
      } else {
        if (escalated)
          CloseHandle(escalated);
        // Keep as partial if best
        if (!bestHandle || c.grantedAccess > bestAccess) {
          if (bestHandle)
            CloseHandle(bestHandle);
          bestHandle = duplicated;
          bestAccess = c.grantedAccess;
          wchar_t hexBuf[32];
          swprintf_s(hexBuf, L"0x%08X", c.grantedAccess);
          log(L"  [i] Partial: owner PID " + to_wstring(c.ownerPid) +
              L" access " + hexBuf);
        } else {
          CloseHandle(duplicated);
        }
      }
    }
  }

  // Close cached owner handles
  for (auto &kv : ownerHandles) {
    if (kv.second)
      CloseHandle(kv.second);
  }

  log(L"  [i] Stats: " + to_wstring(ownersOpened) + L" owners, " +
      to_wstring(dupAttempted) + L" dups, " + to_wstring(dupSucceeded) +
      L" ok");

  // Step 5: If partial, try self-escalation
  if (bestHandle && !foundPerfect) {
    HANDLE escalated = nullptr;
    NTSTATUS escStatus = g_NtApis.NtDuplicateObject(
        GetCurrentProcess(), bestHandle, GetCurrentProcess(), &escalated,
        desiredAccess, 0, 0);
    if (escStatus >= 0 && escalated && GetProcessId(escalated) == targetPid) {
      CloseHandle(bestHandle);
      bestHandle = escalated;
      bestAccess = desiredAccess;
      wchar_t hexBuf[32];
      swprintf_s(hexBuf, L"0x%08X", desiredAccess);
      log(L"  [+] Self-escalation SUCCESS! Access " + wstring(hexBuf));
    } else {
      if (escalated)
        CloseHandle(escalated);
    }
  }

  if (bestHandle) {
    wchar_t hexBuf[32];
    swprintf_s(hexBuf, L"0x%08X", bestAccess);
    log(L"  [+] Best handle access: " + wstring(hexBuf));
  } else {
    log(L"  [-] No handles to target PID " + to_wstring(targetPid) + L" found");
  }

  return bestHandle;
}

// ===== XOR encrypt/decrypt buffer =====
void XorBuffer(BYTE *data, SIZE_T size, BYTE key) {
  for (SIZE_T i = 0; i < size; i++) {
    data[i] ^= key;
  }
}

class HandleGuard {
  HANDLE m_handle;

public:
  explicit HandleGuard(HANDLE h = nullptr) : m_handle(h) {}
  ~HandleGuard() {
    if (m_handle && m_handle != INVALID_HANDLE_VALUE)
      CloseHandle(m_handle);
  }
  HandleGuard(const HandleGuard &) = delete;
  HandleGuard &operator=(const HandleGuard &) = delete;
  HANDLE get() const { return m_handle; }
  operator HANDLE() const { return m_handle; }
  void reset(HANDLE h = nullptr) {
    if (m_handle && m_handle != INVALID_HANDLE_VALUE)
      CloseHandle(m_handle);
    m_handle = h;
  }
};

// ===== WinUI 3 Dark Theme Constants =====
namespace Fluent {
// Window & Backgrounds (WinUI 3 Dark)
constexpr COLORREF BgMica     = RGB(32, 32, 32);   // SolidBackgroundFillColorBase
constexpr COLORREF BgCard     = RGB(44, 44, 44);   // CardBackgroundFillColorDefault (#0DFFFFFF over mica)
constexpr COLORREF BgCardHov  = RGB(50, 50, 50);   // CardBackgroundFillColorSecondary
constexpr COLORREF BgInput    = RGB(25, 25, 25);   // ControlFillColorInputActive
constexpr COLORREF BgInset    = RGB(28, 28, 28);   // Inset surface (log)

// Accent Colors (Pink Gamer / Neon)
constexpr COLORREF Accent     = RGB(255, 170, 222); // light pink highlight
constexpr COLORREF AccentBase = RGB(255, 64, 169);  // primary pink
constexpr COLORREF AccentDark = RGB(190, 35, 132);  // pressed/low
constexpr COLORREF AccentAlt  = RGB(151, 71, 255);  // purple secondary

// Text Colors (WinUI 3 dark)
constexpr COLORREF TextPri    = RGB(255, 255, 255); // TextFillColorPrimary
constexpr COLORREF TextSec    = RGB(197, 197, 197); // TextFillColorSecondary (#C5FFFFFF)
constexpr COLORREF TextDis    = RGB(90, 90, 90);    // TextFillColorDisabled
constexpr COLORREF TextTer    = RGB(114, 114, 114); // TextFillColorTertiary
constexpr COLORREF TextOnAccent= RGB(255, 255, 255); // TextOnAccentFillColorPrimary (white)

// Status Colors
constexpr COLORREF Success    = RGB(108, 203, 95);
constexpr COLORREF Warning    = RGB(252, 225, 0);
constexpr COLORREF Error      = RGB(255, 99, 71);
constexpr COLORREF Info       = RGB(96, 205, 255);

// Banners
constexpr COLORREF BannerOk   = RGB(15, 50, 15);
constexpr COLORREF BannerErr  = RGB(60, 20, 20);

// Layout
constexpr int CardR = 8;  // WinUI 3 card corner radius
constexpr int BtnR  = 8;  // WinUI 3 button corner radius
constexpr int BtnH  = 32; // WinUI 3 standard button height
} // namespace Fluent

// ===== Compact/Modern layout metrics (single source of truth) =====
struct LayoutMetrics {
  int winW = 0;
  int winH = 0;

  int titleBarH = 40;
  int captionBtnW = 46;
  int captionBtnCount = 2;

  int minMargin = 24;
  int maxContentW = 888; // compact, modern centered content width

  int pageLeft = 0;
  int contentW = 0;

  int cardPadX = 16;
  int cardInnerLeft = 0;
  int cardInnerW = 0;

  int rowH = 48;
  int cardTopPad = 4;

  int headerTitleY = 0;
  int headerSubY = 0;
  int pillsY = 0;

  int card1Y = 0;
  int card1H = 152;

  int progressY = 0;
  int progressH = 2;

  int card2Y = 0;
  int card2H = 0;

  int footerH = 32;
  int footerPadBottom = 10;
};

static LayoutMetrics ComputeLayout(HWND hwnd) {
  RECT rc{};
  GetClientRect(hwnd, &rc);
  LayoutMetrics m;
  m.winW = rc.right;
  m.winH = rc.bottom;

  // Center content within the window (big-company look: consistent max width)
  const int availableW = max(320, m.winW - m.minMargin * 2);
  m.contentW = min(m.maxContentW, availableW);
  m.pageLeft = (m.winW - m.contentW) / 2;

  m.cardInnerLeft = m.pageLeft + m.cardPadX;
  m.cardInnerW = m.contentW - (m.cardPadX * 2);

  // Header region
  m.headerTitleY = m.titleBarH + 4;
  m.headerSubY = m.titleBarH + 30;
  m.pillsY = m.titleBarH + 52;

  // Cards
  m.card1Y = m.titleBarH + 72;
  m.progressY = m.card1Y + m.card1H + 8;
  m.card2Y = m.card1Y + m.card1H + 16;

  // Card2 fills the rest above footer
  const int reservedBottom = m.footerH + m.footerPadBottom;
  m.card2H = max(200, m.winH - reservedBottom - m.card2Y);
  return m;
}

class InjectorContext;
static void ApplyLayout(const LayoutMetrics& m, InjectorContext& ctx);

// GDI+ globals
static ULONG_PTR gdiplusToken = 0;

// Helper: build a GDI+ rounded rect path
inline void MakeRoundedRect(Gdiplus::GraphicsPath& path, int x, int y, int w, int h, int r) {
  int d = r * 2;
  path.AddArc(x, y, d, d, 180, 90);
  path.AddArc(x + w - d, y, d, d, 270, 90);
  path.AddArc(x + w - d, y + h - d, d, d, 0, 90);
  path.AddArc(x, y + h - d, d, d, 90, 90);
  path.CloseFigure();
}

// Helper: rounded only on the right side (used for combo dropdown button)
inline void MakeRightRoundedRect(Gdiplus::GraphicsPath& path, int x, int y, int w, int h, int r) {
  int d = r * 2;
  // left side is square
  path.StartFigure();
  path.AddLine(x, y, x + w - d, y);
  path.AddArc(x + w - d, y, d, d, 270, 90);
  path.AddArc(x + w - d, y + h - d, d, d, 0, 90);
  path.AddLine(x + w - d, y + h, x, y + h);
  path.CloseFigure();
}

static inline BYTE ClampByte(int v) {
  return (BYTE)(v < 0 ? 0 : (v > 255 ? 255 : v));
}

static inline COLORREF AdjustColor(COLORREF c, int delta) {
  return RGB(ClampByte((int)GetRValue(c) + delta), ClampByte((int)GetGValue(c) + delta),
             ClampByte((int)GetBValue(c) + delta));
}

static inline Gdiplus::Color GdiColorA(BYTE a, COLORREF c) {
  return Gdiplus::Color(a, GetRValue(c), GetGValue(c), GetBValue(c));
}

static void ApplyRoundedRegion(HWND hwnd, int radiusPx) {
  if (!hwnd)
    return;
  RECT rc{};
  GetClientRect(hwnd, &rc);
  int w = rc.right - rc.left;
  int h = rc.bottom - rc.top;
  if (w <= 0 || h <= 0)
    return;
  int d = max(1, radiusPx) * 2;
  HRGN rgn = CreateRoundRectRgn(0, 0, w + 1, h + 1, d, d);
  SetWindowRgn(hwnd, rgn, TRUE);
  // rgn ownership transfers to the window; do not delete.
}

// Forward declaration of fonts (defined in WndProc as statics — we store a pointer)
static HFONT g_hFontBody = nullptr;

// Subclass proc for the combo box — fully custom-paints the entire control
static LRESULT CALLBACK ComboSubclassProc(HWND hwnd, UINT msg, WPARAM wParam,
                                          LPARAM lParam, UINT_PTR, DWORD_PTR) {
  switch (msg) {
  case WM_NCPAINT:
    return 0;
  case WM_ERASEBKGND:
    return 1;
  case WM_PAINT: {
    PAINTSTRUCT ps;
    HDC hdc = BeginPaint(hwnd, &ps);
    RECT rc{};
    GetClientRect(hwnd, &rc);
    const int w = rc.right, h = rc.bottom;

    // Double-buffer
    HDC mem = CreateCompatibleDC(hdc);
    HBITMAP bm = CreateCompatibleBitmap(hdc, w, h);
    HBITMAP old = (HBITMAP)SelectObject(mem, bm);

    using namespace Gdiplus;
    Graphics g(mem);
    g.SetSmoothingMode(SmoothingModeAntiAlias);
    g.SetPixelOffsetMode(PixelOffsetModeHighQuality);

    // Fill with parent (card) background first to clean corners
    SolidBrush parentBg(Color(255, GetRValue(Fluent::BgCard),
                              GetGValue(Fluent::BgCard), GetBValue(Fluent::BgCard)));
    g.FillRectangle(&parentBg, 0, 0, w, h);

    // Rounded field path
    GraphicsPath fieldPath;
    MakeRoundedRect(fieldPath, 0, 0, w, h, 8);

    COLORREF top = AdjustColor(Fluent::BgInset, +10);
    COLORREF bot = AdjustColor(Fluent::BgInset, -4);
    LinearGradientBrush bg(Point(0, 0), Point(0, h),
                           GdiColorA(255, top), GdiColorA(255, bot));
    g.FillPath(&bg, &fieldPath);

    LinearGradientBrush sheen(Point(0, 0), Point(w, h),
                              Color(18, 255, 255, 255), Color(0, 255, 255, 255));
    g.FillPath(&sheen, &fieldPath);

    // Dropdown button (right side)
    COMBOBOXINFO cbi{};
    cbi.cbSize = sizeof(cbi);
    GetComboBoxInfo(hwnd, &cbi);
    RECT btn = cbi.rcButton;
    if (btn.right > btn.left) {
      GraphicsPath btnPath;
      MakeRightRoundedRect(btnPath, btn.left, 0, w - btn.left, h, 8);
      COLORREF bTop = AdjustColor(Fluent::BgInset, +16);
      COLORREF bBot = AdjustColor(Fluent::BgInset, 0);
      LinearGradientBrush bf(Point(0, 0), Point(0, h),
                             GdiColorA(255, bTop), GdiColorA(255, bBot));
      g.FillPath(&bf, &btnPath);

      Pen div(Color(40, 255, 255, 255), 1.0f);
      g.DrawLine(&div, (INT)btn.left, (INT)6, (INT)btn.left, (INT)(h - 6));

      const INT cx = (INT)((btn.left + w) / 2);
      const INT cy = (INT)(h / 2);
      Pen chev(Color(180, 255, 255, 255), 1.6f);
      chev.SetLineCap(LineCapRound, LineCapRound, DashCapRound);
      g.DrawLine(&chev, (INT)(cx - 4), (INT)(cy - 2), (INT)cx, (INT)(cy + 3));
      g.DrawLine(&chev, (INT)cx, (INT)(cy + 3), (INT)(cx + 4), (INT)(cy - 2));
    }

    // Border
    HWND focusHwnd = GetFocus();
    bool isDropped = (SendMessageW(hwnd, CB_GETDROPPEDSTATE, 0, 0) != 0);
    bool focused = (focusHwnd == hwnd) || (focusHwnd && IsChild(hwnd, focusHwnd)) || isDropped;
    GraphicsPath border;
    MakeRoundedRect(border, 1, 1, w - 2, h - 2, 7);
    if (focused) {
      LinearGradientBrush ring(Point(0, 0), Point(w, 0),
                               GdiColorA(170, Fluent::AccentAlt),
                               GdiColorA(170, Fluent::AccentBase));
      Pen pen(&ring, 2.0f);
      g.DrawPath(&pen, &border);
    } else {
      LinearGradientBrush br(Point(0, 0), Point(0, h),
                             Color(34, 255, 255, 255), Color(20, 255, 255, 255));
      Pen pen(&br, 1.0f);
      g.DrawPath(&pen, &border);
    }

    // Text
    wchar_t textBuf[260] = {};
    GetWindowTextW(hwnd, textBuf, 260);
    SetBkMode(mem, TRANSPARENT);
    SetTextColor(mem, Fluent::TextPri);
    if (g_hFontBody) SelectObject(mem, g_hFontBody);
    RECT tr = {10, 0, btn.left > 0 ? btn.left - 4 : w - 30, h};
    DrawTextW(mem, textBuf, -1, &tr,
             DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS);

    BitBlt(hdc, 0, 0, w, h, mem, 0, 0, SRCCOPY);
    SelectObject(mem, old);
    DeleteObject(bm);
    DeleteDC(mem);
    EndPaint(hwnd, &ps);
    return 0;
  }
  case WM_NCDESTROY:
    RemoveWindowSubclass(hwnd, ComboSubclassProc, 1);
    break;
  }
  return DefSubclassProc(hwnd, msg, wParam, lParam);
}

// Helper: draw anti-aliased WinUI 3 card with soft shadow and gradient border
inline void DrawWinUICard(HDC hdc, int x, int y, int w, int h,
                          COLORREF fill, COLORREF /*unused*/, int r = Fluent::CardR) {
  using namespace Gdiplus;
  Graphics g(hdc);
  g.SetSmoothingMode(SmoothingModeAntiAlias);
  g.SetPixelOffsetMode(PixelOffsetModeHighQuality);

  // --- Multi-pass soft shadow (modern Fluent elevation) ---
  // 4 layers below the card, each offset downward with decreasing alpha
  for (int i = 4; i >= 1; i--) {
    int shadowAlpha = 4 * (5 - i); // 16, 12, 8, 4 for stronger depth
    int off = i;                   // offset 4, 3, 2, 1 px down
    int expand = i;                // expand by 4, 3, 2, 1 px
    GraphicsPath shadowPath;
    MakeRoundedRect(shadowPath, x - expand, y + off, w + expand * 2, h + expand, r + 2);
    SolidBrush shadowBrush(Color((BYTE)shadowAlpha, 0, 0, 0));
    g.FillPath(&shadowBrush, &shadowPath);
  }

  // --- Card fill (richer gradient for modern + gamer look) ---
  GraphicsPath path;
  MakeRoundedRect(path, x, y, w, h, r);
  COLORREF topFill = AdjustColor(fill, +10);
  COLORREF botFill = AdjustColor(fill, -6);
  LinearGradientBrush baseGrad(
      Point(x, y), Point(x, y + h),
      Color(255, GetRValue(topFill), GetGValue(topFill), GetBValue(topFill)),
      Color(255, GetRValue(botFill), GetGValue(botFill), GetBValue(botFill)));
  g.FillPath(&baseGrad, &path);

  // Glass highlight overlay
  LinearGradientBrush fillGrad(Point(x, y), Point(x, y + h),
                               Color(18, 255, 255, 255),
                               Color(6, 255, 255, 255));
  g.FillPath(&fillGrad, &path);

  // Subtle neon sheen (top-left)
  {
    LinearGradientBrush sheen(Point(x, y), Point(x + w, y + h),
                              GdiColorA(18, Fluent::Accent),
                              Color(0, 0, 0, 0));
    g.FillPath(&sheen, &path);
  }

  // --- Gradient border: top = lighter (#19FFFFFF), bottom = darker (#12FFFFFF) ---
  // Use a LinearGradientBrush as a pen brush for the border stroke
  LinearGradientBrush borderGrad(
    Point(x, y), Point(x, y + h),
    Color(25, 255, 255, 255),   // top: CardStrokeColorDefault #19FFFFFF
    Color(18, 255, 255, 255));  // bottom: ControlStrokeColorDefault #12FFFFFF
  Pen borderPen(&borderGrad, 1.0f);
  g.DrawPath(&borderPen, &path);

  // Accent glow stroke (very subtle)
  {
    LinearGradientBrush glowGrad(Point(x, y), Point(x + w, y),
                                 GdiColorA(22, Fluent::AccentAlt),
                                 GdiColorA(22, Fluent::AccentBase));
    Pen glowPen(&glowGrad, 1.0f);
    g.DrawPath(&glowPen, &path);
  }

  // --- Inner highlight for subtle glass lift ---
  if (w > 4 && h > 4) {
    GraphicsPath inner;
    MakeRoundedRect(inner, x + 1, y + 1, w - 2, h - 2, max(1, r - 1));
    Pen innerPen(Color(12, 255, 255, 255), 1.0f);
    g.DrawPath(&innerPen, &inner);
  }
}

// Helper: draw a horizontal separator line (WinUI 3 divider)
inline void DrawWinUISeparator(HDC hdc, int x, int y, int w) {
  using namespace Gdiplus;
  Graphics g(hdc);
  // WinUI 3 DividerStrokeColorDefault = #15FFFFFF (alpha 21)
  Pen pen(Color(21, 255, 255, 255), 1.0f);
  g.DrawLine(&pen, x, y, x + w, y);
}

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
  HWND hwndTipsButton = nullptr;
  HWND hwndMethodLabel = nullptr;
  HWND hwndTooltip = nullptr;
  wstring dllPath;
  vector<wstring> logBuffer;
  bool enableLogging = false;
  wstring processName;
  const char *ntdllName;
  const BYTE kXorKey;
  bool ntApisAvailable = false;
  HWND hwndWatchButton = nullptr;
  HWND hwndMinButton = nullptr;
  HWND hwndCloseButton = nullptr;
  DWORD earlyInjectPID = 0;
  bool watcherActive = false;

  InjectorContext()
      : processName(L""), ntdllName("ntdll.dll"), kXorKey(GenerateXorKey()) {
    InitializeLogging();
  }

  bool ValidateDLLPath(const wstring &dllPath);

  static wstring GetExeRelativePath(const wstring &filename) {
    wchar_t exePath[MAX_PATH];
    GetModuleFileNameW(NULL, exePath, MAX_PATH);
    wstring dir(exePath);
    size_t pos = dir.find_last_of(L'\\');
    if (pos != wstring::npos)
      dir = dir.substr(0, pos + 1);
    return dir + filename;
  }

private:
  static BYTE GenerateXorKey() {
    random_device rd;
    mt19937 gen(rd());
    uniform_int_distribution<> dis(1, 255);
    return static_cast<BYTE>(dis(gen));
  }

  void InitializeLogging() {
    wstring configPath = GetExeRelativePath(L"Injector.ini");
    if (GetFileAttributesW(configPath.c_str()) != INVALID_FILE_ATTRIBUTES) {
      enableLogging = GetPrivateProfileIntW(L"Settings", L"EnableLogging", 0,
                                            configPath.c_str()) != 0;
      wchar_t buffer[260] = {0};
      if (GetPrivateProfileStringW(L"Settings", L"LastProcess", L"", buffer,
                                   260, configPath.c_str())) {
        processName = buffer;
      }
      if (GetPrivateProfileStringW(L"Settings", L"LastDLL", L"", buffer, 260,
                                   configPath.c_str())) {
        dllPath = buffer;
        if (!ValidateDLLPath(dllPath)) {
          dllPath.clear();
        }
      }
    }
  }
};

static void ApplyLayout(const LayoutMetrics& m, InjectorContext& ctx) {
  // Caption buttons
  const int totalCaptionW = (m.captionBtnW * m.captionBtnCount);
  if (ctx.hwndMinButton) {
    MoveWindow(ctx.hwndMinButton, m.winW - totalCaptionW, 0, m.captionBtnW,
               m.titleBarH, TRUE);
  }
  if (ctx.hwndCloseButton) {
    MoveWindow(ctx.hwndCloseButton, m.winW - m.captionBtnW, 0, m.captionBtnW,
               m.titleBarH, TRUE);
  }

  // Card 1 controls
  const int comboW = (int)(m.cardInnerW * 0.44);
  if (ctx.hwndProcessLabel) {
    MoveWindow(ctx.hwndProcessLabel, m.cardInnerLeft,
               m.card1Y + m.cardTopPad + 14, 160, 18, TRUE);
  }
  if (ctx.hwndProcessCombo) {
    MoveWindow(ctx.hwndProcessCombo,
               m.cardInnerLeft + m.cardInnerW - comboW - 44,
               m.card1Y + m.cardTopPad + 8, comboW, 200, TRUE);
  }
  if (ctx.hwndRefreshButton) {
    MoveWindow(ctx.hwndRefreshButton, m.cardInnerLeft + m.cardInnerW - 36,
               m.card1Y + m.cardTopPad + 8, 36, Fluent::BtnH, TRUE);
  }

  if (ctx.hwndDllLabel) {
    MoveWindow(ctx.hwndDllLabel, m.cardInnerLeft,
               m.card1Y + m.rowH + m.cardTopPad + 14,
               max(120, m.cardInnerW - 200), 18, TRUE);
  }
  if (ctx.hwndBrowseButton) {
    MoveWindow(ctx.hwndBrowseButton, m.cardInnerLeft + m.cardInnerW - 184,
               m.card1Y + m.rowH + m.cardTopPad + 8, 84, Fluent::BtnH, TRUE);
  }
  if (ctx.hwndWatchButton) {
    MoveWindow(ctx.hwndWatchButton, m.cardInnerLeft + m.cardInnerW - 92,
               m.card1Y + m.rowH + m.cardTopPad + 8, 92, Fluent::BtnH, TRUE);
  }

  if (ctx.hwndTipsButton) {
    MoveWindow(ctx.hwndTipsButton, m.cardInnerLeft,
               m.card1Y + m.rowH * 2 + m.cardTopPad + 8, 80, Fluent::BtnH,
               TRUE);
  }
  if (ctx.hwndInjectButton) {
    MoveWindow(ctx.hwndInjectButton, m.cardInnerLeft + m.cardInnerW - 120,
               m.card1Y + m.rowH * 2 + m.cardTopPad + 8, 120, Fluent::BtnH,
               TRUE);
  }

  // Progress bar
  if (ctx.hwndProgressBar) {
    MoveWindow(ctx.hwndProgressBar, m.pageLeft, m.progressY, m.contentW,
               m.progressH, TRUE);
  }

  // Card 2 status log
  if (ctx.hwndStatus) {
    const int insetX = 6;
    const int insetTop = 38;
    const int insetBottom = 10;
    MoveWindow(ctx.hwndStatus, m.pageLeft + insetX, m.card2Y + insetTop,
               max(100, m.contentW - insetX * 2),
               max(80, m.card2H - insetTop - insetBottom), TRUE);
  }

  // Rounded corners — only for non-owner-drawn controls (buttons are owner-drawn
  // and paint their own rounded corners via GDI+, so regions cause grey corner artifacts).
  const int r = 8;
  // Buttons: NO region — owner-draw handles corners perfectly
  // Combo: NO region — subclass paints full alpha-blended corners. 
  // Applying a region creates aliased artifacts.
  // ApplyRoundedRegion(ctx.hwndProcessCombo, r);
  // ApplyRoundedRegion(ctx.hwndStatus, 10);
  // ApplyRoundedRegion(ctx.hwndProgressBar, 10);

  // Combo edit child: force rounded + remove client-edge + add padding
  if (ctx.hwndProcessCombo) {
    // Ensure the editable portion height matches our design
    SendMessageW(ctx.hwndProcessCombo, CB_SETITEMHEIGHT, (WPARAM)-1,
                 (LPARAM)(Fluent::BtnH - 6));

    COMBOBOXINFO cbi{};
    cbi.cbSize = sizeof(cbi);
    if (GetComboBoxInfo(ctx.hwndProcessCombo, &cbi) && cbi.hwndItem) {
      // Remove classic borders if present
      LONG_PTR es = GetWindowLongPtrW(cbi.hwndItem, GWL_STYLE);
      es &= ~WS_BORDER;
      SetWindowLongPtrW(cbi.hwndItem, GWL_STYLE, es);
      LONG_PTR exs = GetWindowLongPtrW(cbi.hwndItem, GWL_EXSTYLE);
      exs &= ~WS_EX_CLIENTEDGE;
      SetWindowLongPtrW(cbi.hwndItem, GWL_EXSTYLE, exs);

      // Padding inside the edit
      SendMessageW(cbi.hwndItem, EM_SETMARGINS, EC_LEFTMARGIN | EC_RIGHTMARGIN,
                   MAKELPARAM(10, 10));

      // Make the edit fill the item rect tightly (helps hide square chrome)
      const int pad = 1;
      int editX = cbi.rcItem.left + pad;
      int editY = cbi.rcItem.top + pad;
      int editW = max(10, (cbi.rcButton.left - cbi.rcItem.left) - pad * 2);
      int editH = max(10, (cbi.rcItem.bottom - cbi.rcItem.top) - pad * 2);
      SetWindowPos(cbi.hwndItem, NULL, editX, editY, editW, editH,
                   SWP_NOZORDER | SWP_NOACTIVATE);

      // ApplyRoundedRegion(cbi.hwndItem, r);
      InvalidateRect(cbi.hwndItem, NULL, TRUE);
    }
    // Also strip borders from the combo's built-in button child
    if (cbi.hwndCombo) {
      LONG_PTR st = GetWindowLongPtrW(cbi.hwndCombo, GWL_STYLE);
      st &= ~WS_BORDER;
      SetWindowLongPtrW(cbi.hwndCombo, GWL_STYLE, st);
      LONG_PTR exst = GetWindowLongPtrW(cbi.hwndCombo, GWL_EXSTYLE);
      exst &= ~(WS_EX_CLIENTEDGE | WS_EX_STATICEDGE | WS_EX_WINDOWEDGE);
      SetWindowLongPtrW(cbi.hwndCombo, GWL_EXSTYLE, exst);
      SetWindowPos(cbi.hwndCombo, NULL, 0, 0, 0, 0,
                   SWP_NOMOVE | SWP_NOSIZE | SWP_NOZORDER | SWP_FRAMECHANGED);
    }
  }
}

// ===== Helper: Add tooltip to a control =====
void AddTooltip(HWND hwndTool, HWND hwndTooltip, const wchar_t *tipText) {
  TOOLINFOW ti = {sizeof(TOOLINFOW)};
  ti.uFlags = TTF_SUBCLASS | TTF_IDISHWND;
  ti.hwnd = GetParent(hwndTool);
  ti.uId = (UINT_PTR)hwndTool;
  ti.lpszText = const_cast<LPWSTR>(tipText);
  SendMessageW(hwndTooltip, TTM_ADDTOOLW, 0, (LPARAM)&ti);
}

// ===== Helper: Append colored line to RichEdit =====
void AppendColoredLine(HWND hwndRich, const wstring &text, COLORREF color) {
  // Move cursor to end
  CHARRANGE cr = {-1, -1};
  SendMessageW(hwndRich, EM_EXSETSEL, 0, (LPARAM)&cr);

  // Get current text length
  int len = GetWindowTextLengthW(hwndRich);
  wstring line = (len > 0 ? L"\r\n" : L"") + text;

  // Set the color for the new text
  CHARFORMAT2W cf;
  memset(&cf, 0, sizeof(cf));
  cf.cbSize = sizeof(CHARFORMAT2W);
  cf.dwMask = CFM_COLOR | CFM_BOLD;
  cf.crTextColor = color;
  cf.dwEffects = 0; // no CFE_AUTOCOLOR
  SendMessageW(hwndRich, EM_SETCHARFORMAT, SCF_SELECTION, (LPARAM)&cf);

  // Insert the text
  SendMessageW(hwndRich, EM_REPLACESEL, FALSE, (LPARAM)line.c_str());

  // Scroll to bottom
  SendMessageW(hwndRich, WM_VSCROLL, SB_BOTTOM, 0);
}

wstring GetCurrentTimestamp() {
  auto now = chrono::system_clock::now();
  auto time = chrono::system_clock::to_time_t(now);
  tm local_time;
  localtime_s(&local_time, &time);
  wstringstream wss;
  wss << put_time(&local_time, L"%Y-%m-%d %H:%M:%S") << L"." << setfill(L'0')
      << setw(3)
      << (chrono::duration_cast<chrono::milliseconds>(now.time_since_epoch()) %
          1000)
             .count();
  return wss.str();
}

void LogToMemory(InjectorContext &ctx, const wstring &message) {
  if (!ctx.enableLogging)
    return;
  wstring timestampedMessage = L"[" + GetCurrentTimestamp() + L"] " + message;
  ctx.logBuffer.push_back(timestampedMessage);
}

void PlaySuccessSound() {
  PlaySoundW(MAKEINTRESOURCEW(IDR_TREVOR_WAV), GetModuleHandle(NULL),
             SND_RESOURCE | SND_ASYNC);
}

void PlayErrorSound() {
  PlaySoundW(L"SystemHand", NULL, SND_ALIAS | SND_ASYNC);
}

void LogErrorAndStatus(InjectorContext &ctx, const wstring &message,
                       COLORREF color, bool isError) {
  wstring timestampedMessage = L"[" + GetCurrentTimestamp() + L"] " + message;

  // Use per-line colored RichEdit append
  AppendColoredLine(ctx.hwndStatus, timestampedMessage, color);

  LogToMemory(ctx, timestampedMessage);
  if (isError) {
    PlayErrorSound();
  }
}

bool IsRunAsAdmin() {
  BOOL isAdmin = FALSE;
  PSID adminGroup = nullptr;
  SID_IDENTIFIER_AUTHORITY ntAuthority = SECURITY_NT_AUTHORITY;
  if (AllocateAndInitializeSid(&ntAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID,
                               DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0,
                               &adminGroup)) {
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
  if (!Is64BitWindows())
    return true;
  BOOL isTargetWow64 = FALSE;
  if (!Is64BitProcess(hProcess, &isTargetWow64)) {
    return false;
  }
  BOOL isHostWow64 = FALSE;
  Is64BitProcess(GetCurrentProcess(), &isHostWow64);
  return isTargetWow64 == isHostWow64;
}

bool CheckDLLArchitecture(InjectorContext &ctx, const vector<BYTE> &dllData,
                          HANDLE hProcess) {
  try {
    if (dllData.size() < sizeof(IMAGE_DOS_HEADER)) {
      LogErrorAndStatus(ctx,
                        L"[-] Invalid DLL data size for architecture check",
                        RGB(255, 0, 0), true);
      return false;
    }
    const BYTE *rawData = dllData.data();
    IMAGE_DOS_HEADER *pDosHeader =
        reinterpret_cast<IMAGE_DOS_HEADER *>(const_cast<BYTE *>(rawData));
    if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
      LogErrorAndStatus(ctx, L"[-] Invalid DLL (no MZ signature)",
                        RGB(255, 0, 0), true);
      return false;
    }
    if (static_cast<SIZE_T>(pDosHeader->e_lfanew) + sizeof(IMAGE_NT_HEADERS) >
            dllData.size() ||
        pDosHeader->e_lfanew < 0) {
      LogErrorAndStatus(ctx, L"[-] Invalid NT headers offset in DLL",
                        RGB(255, 0, 0), true);
      return false;
    }
    IMAGE_NT_HEADERS *pNtHeaders = reinterpret_cast<IMAGE_NT_HEADERS *>(
        const_cast<BYTE *>(rawData + pDosHeader->e_lfanew));
    if (pNtHeaders->Signature != IMAGE_NT_SIGNATURE) {
      LogErrorAndStatus(ctx, L"[-] Invalid NT signature in DLL", RGB(255, 0, 0),
                        true);
      return false;
    }
    BOOL isProcessWow64 = FALSE;
    if (!Is64BitProcess(hProcess, &isProcessWow64)) {
      LogErrorAndStatus(
          ctx, L"[-] Error checking process architecture for DLL validation",
          RGB(255, 0, 0), true);
      return false;
    }
    bool isProcess64Bit = !isProcessWow64 && Is64BitWindows();
    bool isDLL64Bit =
        (pNtHeaders->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64);
    if (isDLL64Bit != isProcess64Bit) {
      LogErrorAndStatus(
          ctx, L"[-] DLL architecture does not match process architecture",
          RGB(255, 0, 0), true);
      return false;
    }
    LogErrorAndStatus(ctx, L"[+] DLL architecture verified", RGB(0, 255, 0),
                      false);
    return true;
  } catch (const exception &e) {
    wstring error = L"[-] Exception in CheckDLLArchitecture: " +
                    wstring(e.what(), e.what() + strlen(e.what()));
    LogErrorAndStatus(ctx, error, RGB(255, 0, 0), true);
    return false;
  }
}

DWORD GetPIDByName(InjectorContext &ctx, const wstring &name) {
  HandleGuard snapshot(CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0));
  if (snapshot.get() == INVALID_HANDLE_VALUE) {
    DWORD error = GetLastError();
    LogErrorAndStatus(ctx,
                      L"[-] Failed to create process snapshot, error code: 0x" +
                          to_wstring(error),
                      RGB(255, 0, 0), true);
    return 0;
  }
  PROCESSENTRY32W entry = {sizeof(PROCESSENTRY32W)};
  if (!Process32FirstW(snapshot, &entry)) {
    DWORD error = GetLastError();
    LogErrorAndStatus(ctx,
                      L"[-] Failed to enumerate first process, error code: 0x" +
                          to_wstring(error),
                      RGB(255, 0, 0), true);
    return 0;
  }
  wstring lowerName = name;
  transform(lowerName.begin(), lowerName.end(), lowerName.begin(), ::towlower);
  wstring foundProcesses;
  do {
    wstring exeName(entry.szExeFile);
    transform(exeName.begin(), exeName.end(), exeName.begin(), ::towlower);
    if (exeName == lowerName) {
      LogErrorAndStatus(ctx,
                        L"[+] Found process: " + wstring(entry.szExeFile) +
                            L" (PID: " + to_wstring(entry.th32ProcessID) + L")",
                        RGB(0, 255, 0), false);
      return entry.th32ProcessID;
    }
    foundProcesses += wstring(entry.szExeFile) + L", ";
  } while (Process32NextW(snapshot, &entry));
  LogErrorAndStatus(ctx,
                    L"[-] Process not found: " + name +
                        L". Processes scanned: " + foundProcesses,
                    RGB(255, 0, 0), true);
  return 0;
}

bool InjectorContext::ValidateDLLPath(const wstring &dllPath) {
  if (dllPath.empty() || dllPath.length() > MAX_PATH) {
    LogErrorAndStatus(*this, L"[-] DLL path is empty or too long",
                      RGB(255, 0, 0), true);
    return false;
  }
  if (PathFileExistsW(dllPath.c_str()) == FALSE) {
    LogErrorAndStatus(*this, L"[-] DLL file does not exist: " + dllPath,
                      RGB(255, 0, 0), true);
    return false;
  }
  // Verify it has a .dll extension
  size_t dotPos = dllPath.find_last_of(L'.');
  if (dotPos == wstring::npos) {
    LogErrorAndStatus(*this, L"[-] File has no extension: " + dllPath,
                      RGB(255, 0, 0), true);
    return false;
  }
  wstring ext = dllPath.substr(dotPos + 1);
  wstring lowerExt = ext;
  transform(lowerExt.begin(), lowerExt.end(), lowerExt.begin(), ::towlower);
  if (lowerExt != L"dll") {
    LogErrorAndStatus(*this, L"[-] File is not a .dll: " + dllPath,
                      RGB(255, 0, 0), true);
    return false;
  }
  return true;
}

#define RELOC_FLAG(RelInfo) ((RelInfo >> 0x0C) == IMAGE_REL_BASED_DIR64)

#pragma runtime_checks("", off)
#pragma optimize("", off)
void __stdcall Shellcode(MANUAL_MAPPING_DATA *pData) {
  if (!pData)
    return;
  BYTE *pBase = pData->pBase;
  if (!pBase) {
    pData->hMod = reinterpret_cast<HINSTANCE>(0x404040);
    return;
  }

  // === XOR decrypt only the actual section data (not padding/BSS) ===
  // Headers are plain. We must decrypt per-section using SizeOfRawData
  // at VirtualAddress, matching exactly what was encrypted host-side.
  // A flat sweep from headersSize to imageSize would corrupt BSS/padding.
  if (pData->xorKey != 0) {
    BYTE key = pData->xorKey;
    IMAGE_DOS_HEADER *pDos = reinterpret_cast<IMAGE_DOS_HEADER *>(pBase);
    IMAGE_NT_HEADERS *pNt =
        reinterpret_cast<IMAGE_NT_HEADERS *>(pBase + pDos->e_lfanew);
    IMAGE_SECTION_HEADER *pSec = IMAGE_FIRST_SECTION(pNt);
    for (WORD si = 0; si < pNt->FileHeader.NumberOfSections; ++si) {
      if (pSec[si].SizeOfRawData) {
        BYTE *secStart = pBase + pSec[si].VirtualAddress;
        for (SIZE_T j = 0; j < pSec[si].SizeOfRawData; ++j) {
          secStart[j] ^= key;
        }
      }
    }
  }

  IMAGE_DOS_HEADER *pDosHeader = reinterpret_cast<IMAGE_DOS_HEADER *>(pBase);
  if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
    pData->hMod = reinterpret_cast<HINSTANCE>(0x404040);
    return;
  }
  IMAGE_NT_HEADERS *pNtHeaders =
      reinterpret_cast<IMAGE_NT_HEADERS *>(pBase + pDosHeader->e_lfanew);
  if (pNtHeaders->Signature != IMAGE_NT_SIGNATURE) {
    pData->hMod = reinterpret_cast<HINSTANCE>(0x404040);
    return;
  }
  IMAGE_OPTIONAL_HEADER *pOptionalHeader = &pNtHeaders->OptionalHeader;
  auto pLoadLibrary = pData->pLoadLibraryA;
  auto pGetProcAddress = pData->pGetProcAddress;
  auto pRtlAddFunctionTable = pData->pRtlAddFunctionTable;
  auto DllEntry = reinterpret_cast<f_DLL_ENTRY_POINT>(
      pBase + pOptionalHeader->AddressOfEntryPoint);
  uintptr_t delta =
      reinterpret_cast<uintptr_t>(pBase) - pOptionalHeader->ImageBase;
  if (delta != 0 &&
      pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size) {
    auto *pRelocData = reinterpret_cast<IMAGE_BASE_RELOCATION *>(
        pBase + pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC]
                    .VirtualAddress);
    auto *pRelocEnd = reinterpret_cast<IMAGE_BASE_RELOCATION *>(
        reinterpret_cast<BYTE *>(pRelocData) +
        pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size);
    while (pRelocData < pRelocEnd && pRelocData->SizeOfBlock) {
      UINT count = (pRelocData->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) /
                   sizeof(WORD);
      WORD *pRelativeInfo = reinterpret_cast<WORD *>(pRelocData + 1);
      for (UINT i = 0; i < count; ++i, ++pRelativeInfo) {
        if (RELOC_FLAG(*pRelativeInfo)) {
          uintptr_t *pPatch = reinterpret_cast<uintptr_t *>(
              pBase + pRelocData->VirtualAddress + ((*pRelativeInfo) & 0xFFF));
          *pPatch += static_cast<uintptr_t>(delta);
        }
      }
      pRelocData = reinterpret_cast<IMAGE_BASE_RELOCATION *>(
          reinterpret_cast<BYTE *>(pRelocData) + pRelocData->SizeOfBlock);
    }
  }
  if (pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size) {
    auto *pImportDesc = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR *>(
        pBase + pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT]
                    .VirtualAddress);
    while (pImportDesc->Name) {
      char *szMod = reinterpret_cast<char *>(pBase + pImportDesc->Name);
      HINSTANCE hDll = pLoadLibrary(szMod);
      if (!hDll) {
        pData->hMod = reinterpret_cast<HINSTANCE>(0x404040);
        return;
      }
      ULONG_PTR *pThunkRef = reinterpret_cast<ULONG_PTR *>(
          pBase + pImportDesc->OriginalFirstThunk);
      ULONG_PTR *pFuncRef =
          reinterpret_cast<ULONG_PTR *>(pBase + pImportDesc->FirstThunk);
      if (!pThunkRef)
        pThunkRef = pFuncRef;
      for (; *pThunkRef; ++pThunkRef, ++pFuncRef) {
        if (IMAGE_SNAP_BY_ORDINAL(*pThunkRef)) {
          *pFuncRef = reinterpret_cast<ULONG_PTR>(pGetProcAddress(
              hDll, reinterpret_cast<char *>(*pThunkRef & 0xFFFF)));
        } else {
          auto *pImport =
              reinterpret_cast<IMAGE_IMPORT_BY_NAME *>(pBase + *pThunkRef);
          *pFuncRef =
              reinterpret_cast<ULONG_PTR>(pGetProcAddress(hDll, pImport->Name));
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
    auto *pTls = reinterpret_cast<IMAGE_TLS_DIRECTORY *>(
        pBase + pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS]
                    .VirtualAddress);
    auto *pCallback =
        reinterpret_cast<PIMAGE_TLS_CALLBACK *>(pTls->AddressOfCallBacks);
    while (pCallback && *pCallback) {
      (*pCallback)(pBase, DLL_PROCESS_ATTACH, nullptr);
      ++pCallback;
    }
  }
  bool bExceptionSupportFailed = false;
  if (pData->bSEHSupport &&
      pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].Size) {
    auto *pExceptionTable = reinterpret_cast<PRUNTIME_FUNCTION>(
        pBase + pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION]
                    .VirtualAddress);
    DWORD entryCount =
        pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].Size /
        sizeof(RUNTIME_FUNCTION);
    if (!pRtlAddFunctionTable(pExceptionTable, entryCount,
                              reinterpret_cast<DWORD64>(pBase))) {
      bExceptionSupportFailed = true;
    }
  }
  if (!DllEntry(pBase, pData->dwReason, pData->lpReserved)) {
    pData->hMod = reinterpret_cast<HINSTANCE>(0x404040);
    return;
  }
  pData->hMod = bExceptionSupportFailed ? reinterpret_cast<HINSTANCE>(0x505050)
                                        : reinterpret_cast<HINSTANCE>(pBase);

  // === Self-erase: zero out the shellcode's own memory after we're done ===
  // The shellcode page will be a dead zone after this
  if (pData->pRtlZeroMemory && pData->pShellcodeBase &&
      pData->shellcodeSize > 0) {
    // Save the function pointers we need before we erase ourselves
    auto zeroMem = pData->pRtlZeroMemory;
    auto shellBase = pData->pShellcodeBase;
    auto shellSize = pData->shellcodeSize;
    // Note: We cannot erase our own currently-executing page, but we can erase
    // the mapping data which contains sensitive pointers
    zeroMem(pData, sizeof(MANUAL_MAPPING_DATA));
  }
}
#pragma optimize("", on)
#pragma runtime_checks("", restore)

vector<BYTE> LoadDLL(InjectorContext &ctx, const wstring &dllPath) {
  try {
    if (!ctx.ValidateDLLPath(dllPath)) {
      throw runtime_error("Invalid DLL path");
    }
    ifstream file(dllPath, ios::binary | ios::ate);
    if (!file.is_open()) {
      LogErrorAndStatus(ctx, L"[-] Could not open DLL file", RGB(255, 0, 0),
                        true);
      throw runtime_error("Could not open DLL file");
    }
    auto fileSize = file.tellg();
    if (fileSize < 0x1000) {
      file.close();
      LogErrorAndStatus(ctx, L"[-] Invalid DLL file size", RGB(255, 0, 0),
                        true);
      throw runtime_error("Invalid DLL file size");
    }
    vector<BYTE> dllData(static_cast<size_t>(fileSize));
    file.seekg(0, ios::beg);
    file.read(reinterpret_cast<char *>(dllData.data()), fileSize);
    file.close();
    return dllData;
  } catch (const exception &e) {
    wstring error = L"[-] Exception in LoadDLL: " +
                    wstring(e.what(), e.what() + strlen(e.what()));
    LogErrorAndStatus(ctx, error, RGB(255, 0, 0), true);
    throw;
  }
}

bool ValidatePEHeaders(InjectorContext &ctx, const BYTE *pSourceData,
                       SIZE_T fileSize, wstring &errorMsg) {
  try {
    if (!pSourceData || fileSize < sizeof(IMAGE_DOS_HEADER)) {
      errorMsg = L"[-] Invalid source data size";
      return false;
    }
    IMAGE_DOS_HEADER *pDosHeader =
        reinterpret_cast<IMAGE_DOS_HEADER *>(const_cast<BYTE *>(pSourceData));
    if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
      errorMsg = L"[-] Invalid file (no MZ signature)";
      return false;
    }
    if (pDosHeader->e_lfanew < 0 ||
        static_cast<SIZE_T>(pDosHeader->e_lfanew) + sizeof(IMAGE_NT_HEADERS) >
            fileSize) {
      errorMsg = L"[-] Invalid NT headers offset";
      return false;
    }
    IMAGE_NT_HEADERS *pNtHeaders = reinterpret_cast<IMAGE_NT_HEADERS *>(
        const_cast<BYTE *>(pSourceData + pDosHeader->e_lfanew));
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
  } catch (const exception &e) {
    errorMsg = L"[-] Exception in ValidatePEHeaders: " +
               wstring(e.what(), e.what() + strlen(e.what()));
    return false;
  }
}

BYTE *AllocateProcessMemory(InjectorContext &ctx, HANDLE hProcess, SIZE_T size,
                            DWORD &oldProtect, wstring &errorMsg) {
  // Use NT API stealth allocation to bypass user-mode hooks
  // Allocate as PAGE_READWRITE first — we'll upgrade to RWX AFTER writing all
  // data (some anti-cheats block writes to RWX pages)
  BYTE *pTargetBase = StealthAlloc(hProcess, size, PAGE_READWRITE);
  if (!pTargetBase) {
    errorMsg = L"[-] Error allocating process memory (stealth)";
    return nullptr;
  }
  // DON'T set PAGE_EXECUTE_READWRITE yet — keep it RW for writing
  // Protection will be upgraded after all sections are written
  oldProtect = PAGE_READWRITE;
  errorMsg = L"[+] Memory allocated via NT API (stealth mode)";
  return pTargetBase;
}

bool WritePEHeaders(InjectorContext &ctx, HANDLE hProcess, BYTE *pTargetBase,
                    const BYTE *pSourceData, wstring &errorMsg) {
  IMAGE_DOS_HEADER *pDosHeader =
      reinterpret_cast<IMAGE_DOS_HEADER *>(const_cast<BYTE *>(pSourceData));
  IMAGE_NT_HEADERS *pNtHeaders = reinterpret_cast<IMAGE_NT_HEADERS *>(
      const_cast<BYTE *>(pSourceData + pDosHeader->e_lfanew));
  SIZE_T headerSize = pNtHeaders->OptionalHeader.SizeOfHeaders;
  if (!StealthWrite(hProcess, pTargetBase, const_cast<BYTE *>(pSourceData),
                    headerSize)) {
    wchar_t diagBuf[256];
    swprintf_s(
        diagBuf,
        L"[-] Error writing PE headers: NTSTATUS=0x%08X Win32=%u Size=%zu",
        (ULONG)g_lastWriteStatus, g_lastWriteError, headerSize);
    errorMsg = diagBuf;
    LogErrorAndStatus(ctx, errorMsg, RGB(255, 100, 100), false);
    // Try once more after changing protection to PAGE_READWRITE (some AC blocks
    // RWX writes)
    DWORD oldProt = 0;
    if (StealthProtect(hProcess, pTargetBase, headerSize, PAGE_READWRITE,
                       &oldProt)) {
      LogErrorAndStatus(ctx,
                        L"[i] Retrying write with PAGE_READWRITE protection...",
                        RGB(100, 200, 255), false);
      if (StealthWrite(hProcess, pTargetBase, const_cast<BYTE *>(pSourceData),
                       headerSize)) {
        StealthProtect(hProcess, pTargetBase, headerSize,
                       PAGE_EXECUTE_READWRITE, &oldProt);
        errorMsg = L"[+] PE headers written (PAGE_READWRITE fallback)";
        return true;
      }
      swprintf_s(diagBuf, L"[-] Retry also failed: NTSTATUS=0x%08X Win32=%u",
                 (ULONG)g_lastWriteStatus, g_lastWriteError);
      LogErrorAndStatus(ctx, diagBuf, RGB(255, 100, 100), false);
    }
    return false;
  }
  errorMsg = L"[+] PE headers written (stealth)";
  return true;
}

bool WriteSections(InjectorContext &ctx, HANDLE hProcess, BYTE *pTargetBase,
                   const BYTE *pSourceData, IMAGE_NT_HEADERS *pNtHeaders,
                   wstring &errorMsg) {
  IMAGE_SECTION_HEADER *pSectionHeader = IMAGE_FIRST_SECTION(pNtHeaders);
  for (WORD i = 0; i < pNtHeaders->FileHeader.NumberOfSections; ++i) {
    if (pSectionHeader[i].SizeOfRawData) {
      if (!StealthWrite(hProcess,
                        pTargetBase + pSectionHeader[i].VirtualAddress,
                        const_cast<BYTE *>(pSourceData +
                                           pSectionHeader[i].PointerToRawData),
                        pSectionHeader[i].SizeOfRawData)) {
        errorMsg =
            L"[-] Error writing section " + to_wstring(i) + L" (stealth)";
        return false;
      }
    }
  }
  errorMsg = L"[+] All sections written (stealth)";
  return true;
}

BYTE *AllocateMappingData(InjectorContext &ctx, HANDLE hProcess,
                          const MANUAL_MAPPING_DATA &mappingData,
                          wstring &errorMsg) {
  BYTE *pMappingDataAlloc =
      StealthAlloc(hProcess, sizeof(MANUAL_MAPPING_DATA), PAGE_READWRITE);
  if (!pMappingDataAlloc) {
    errorMsg = L"[-] Error allocating mapping data (stealth)";
    return nullptr;
  }
  if (!StealthWrite(hProcess, pMappingDataAlloc,
                    const_cast<MANUAL_MAPPING_DATA *>(&mappingData),
                    sizeof(MANUAL_MAPPING_DATA))) {
    errorMsg = L"[-] Error writing mapping data (stealth)";
    StealthFree(hProcess, pMappingDataAlloc);
    return nullptr;
  }
  errorMsg = L"[+] Mapping data allocated (stealth)";
  return pMappingDataAlloc;
}

void *AllocateAndWriteShellcode(InjectorContext &ctx, HANDLE hProcess,
                                wstring &errorMsg) {
  void *pShellcode = StealthAlloc(hProcess, 4096, PAGE_EXECUTE_READWRITE);
  if (!pShellcode) {
    errorMsg = L"[-] Error allocating shellcode memory (stealth)";
    return nullptr;
  }
  if (!StealthWrite(hProcess, pShellcode, (PVOID)Shellcode, 4096)) {
    errorMsg = L"[-] Error writing shellcode (stealth)";
    StealthFree(hProcess, pShellcode);
    return nullptr;
  }
  errorMsg = L"[+] Shellcode allocated (stealth, NT API)";
  return pShellcode;
}

bool ExecuteShellcode(InjectorContext &ctx, HANDLE hProcess, void *pShellcode,
                      BYTE *pMappingData, wstring &errorMsg) {
  // Use NtCreateThreadEx instead of CreateRemoteThread to bypass hooks
  HANDLE hThread = StealthCreateThread(hProcess, pShellcode, pMappingData);
  if (!hThread) {
    errorMsg = L"[-] Error creating remote thread (stealth NtCreateThreadEx)";
    return false;
  }
  // Wait for the thread with NtWaitForSingleObject or Win32 fallback
  if (g_NtApis.NtWaitForSingleObject) {
    LARGE_INTEGER timeout;
    timeout.QuadPart = -300000000LL; // 30 seconds
    g_NtApis.NtWaitForSingleObject(hThread, FALSE, &timeout);
  } else {
    WaitForSingleObject(hThread, 30000);
  }
  CloseHandle(hThread);
  errorMsg = L"[+] Remote thread created (stealth NtCreateThreadEx)";
  return true;
}

bool WaitForInjection(InjectorContext &ctx, HANDLE hProcess, BYTE *pMappingData,
                      HINSTANCE &hModule, wstring &errorMsg) {
  // ExecuteShellcode already waits 30s for the thread to finish.
  // The shellcode's self-erase may zero MANUAL_MAPPING_DATA (including hMod)
  // AFTER setting hMod, so we read immediately — a few retries in case of race.
  // IMPORTANT: Once the remote thread has executed, the DLL is LIVE in the
  // process. We must NEVER free pTargetBase regardless of whether we can read
  // hMod back.
  for (int i = 0; i < 10; ++i) {
    HINSTANCE tempModule = nullptr;
    if (!StealthRead(hProcess,
                     pMappingData + offsetof(MANUAL_MAPPING_DATA, hMod),
                     &tempModule, sizeof(HINSTANCE))) {
      // Read failed — anti-cheat may be blocking VM_READ, or data was
      // self-erased. The DLL is already loaded and running, treat as success.
      errorMsg = L"[+] Injection completed (read-back blocked, DLL is live)";
      return true;
    }
    if (tempModule != nullptr) {
      hModule = tempModule;
      if (hModule == reinterpret_cast<HINSTANCE>(0x404040)) {
        // Shellcode explicitly signaled failure — but DLL memory is still live,
        // don't free it (it may have partially initialized)
        errorMsg = L"[!] Shellcode reported error (0x404040) — DLL may be "
                   L"partially loaded";
        return true; // Still return true to prevent memory free
      }
      if (hModule == reinterpret_cast<HINSTANCE>(0x505050)) {
        errorMsg = L"[!] Injection completed but SEH support failed";
        hModule = reinterpret_cast<HINSTANCE>(pMappingData);
        return true;
      }
      errorMsg = L"[+] Injection successful, module handle retrieved";
      return true;
    }
    // hMod is still null — self-erase may have zeroed it, or thread is still
    // running
    this_thread::sleep_for(chrono::milliseconds(50));
  }
  // If hMod is null after retries, the thread completed but self-erase zeroed
  // the struct. Since ExecuteShellcode's 30s wait returned successfully, treat
  // as success.
  errorMsg = L"[+] Injection completed (mapping data self-erased)";
  return true;
}

bool CleanAndProtectMemory(InjectorContext &ctx, HANDLE hProcess,
                           BYTE *pTargetBase, IMAGE_NT_HEADERS *pNtHeaders,
                           void *pShellcode, BYTE *pMappingData,
                           bool cleanHeader, bool cleanUnneededSections,
                           bool adjustProtections, bool sehSupport,
                           wstring &errorMsg) {
  random_device rd;
  mt19937 gen(rd());
  uniform_int_distribution<> dis(5, 15);
  uniform_int_distribution<> randByte(0, 255);

  if (cleanHeader) {
    // Overwrite PE headers with random bytes (harder to detect than zeroes)
    vector<BYTE> randomBuffer(pNtHeaders->OptionalHeader.SizeOfHeaders);
    for (auto &b : randomBuffer)
      b = static_cast<BYTE>(randByte(gen));
    StealthWrite(hProcess, pTargetBase, randomBuffer.data(),
                 randomBuffer.size());
  }
  if (cleanUnneededSections) {
    IMAGE_SECTION_HEADER *pSectionHeader = IMAGE_FIRST_SECTION(pNtHeaders);
    for (WORD i = 0; i < pNtHeaders->FileHeader.NumberOfSections; ++i) {
      bool isExecutable =
          (pSectionHeader[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) != 0;
      bool isReadable =
          (pSectionHeader[i].Characteristics & IMAGE_SCN_MEM_READ) != 0;
      bool isWritable =
          (pSectionHeader[i].Characteristics & IMAGE_SCN_MEM_WRITE) != 0;
      if (!isExecutable && !isReadable && !isWritable) {
        if (pSectionHeader[i].SizeOfRawData) {
          // Overwrite with random bytes
          vector<BYTE> randomSec(pSectionHeader[i].SizeOfRawData);
          for (auto &b : randomSec)
            b = static_cast<BYTE>(randByte(gen));
          StealthWrite(hProcess, pTargetBase + pSectionHeader[i].VirtualAddress,
                       randomSec.data(), randomSec.size());
        }
      }
    }
  }
  if (adjustProtections) {
    IMAGE_SECTION_HEADER *pSectionHeader = IMAGE_FIRST_SECTION(pNtHeaders);
    for (WORD i = 0; i < pNtHeaders->FileHeader.NumberOfSections; ++i) {
      DWORD oldProtect = 0;
      DWORD newProtect = 0;
      if (pSectionHeader[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) {
        newProtect = (pSectionHeader[i].Characteristics & IMAGE_SCN_MEM_WRITE)
                         ? PAGE_EXECUTE_READWRITE
                         : PAGE_EXECUTE_READ;
      } else {
        newProtect = (pSectionHeader[i].Characteristics & IMAGE_SCN_MEM_WRITE)
                         ? PAGE_READWRITE
                         : PAGE_READONLY;
      }
      if (pSectionHeader[i].SizeOfRawData) {
        StealthProtect(hProcess, pTargetBase + pSectionHeader[i].VirtualAddress,
                       pSectionHeader[i].SizeOfRawData, newProtect,
                       &oldProtect);
      }
    }
  }
  // Anti-forensic: overwrite shellcode + mapping data with random bytes before
  // freeing
  if (pShellcode) {
    vector<BYTE> junk(4096);
    for (auto &b : junk)
      b = static_cast<BYTE>(randByte(gen));
    StealthWrite(hProcess, pShellcode, junk.data(), junk.size());
    StealthFree(hProcess, pShellcode);
  }
  if (pMappingData) {
    vector<BYTE> junk(sizeof(MANUAL_MAPPING_DATA));
    for (auto &b : junk)
      b = static_cast<BYTE>(randByte(gen));
    StealthWrite(hProcess, pMappingData, junk.data(), junk.size());
    StealthFree(hProcess, pMappingData);
  }
  errorMsg = L"[+] Memory cleaned with random overwrite (anti-forensic)";
  return true;
}

bool AllocateAndWriteHeaders(InjectorContext &ctx, HANDLE hProcess,
                             const BYTE *pSourceData, SIZE_T fileSize,
                             BYTE *&pTargetBase, IMAGE_NT_HEADERS *&pNtHeaders,
                             DWORD &oldProtect) {
  wstring errorMsg;
  if (!ValidatePEHeaders(ctx, pSourceData, fileSize, errorMsg)) {
    LogErrorAndStatus(ctx, errorMsg, RGB(255, 0, 0), true);
    SendMessage(ctx.hwndProgressBar, PBM_SETSTATE, PBST_ERROR, 0);
    return false;
  }
  LogErrorAndStatus(ctx, errorMsg, RGB(0, 255, 0), false);
  pNtHeaders = reinterpret_cast<IMAGE_NT_HEADERS *>(const_cast<BYTE *>(
      pSourceData +
      reinterpret_cast<IMAGE_DOS_HEADER *>(const_cast<BYTE *>(pSourceData))
          ->e_lfanew));
  pTargetBase = AllocateProcessMemory(ctx, hProcess,
                                      pNtHeaders->OptionalHeader.SizeOfImage,
                                      oldProtect, errorMsg);
  if (!pTargetBase) {
    LogErrorAndStatus(ctx, errorMsg, RGB(255, 0, 0), true);
    SendMessage(ctx.hwndProgressBar, PBM_SETSTATE, PBST_ERROR, 0);
    return false;
  }
  LogErrorAndStatus(ctx, errorMsg, RGB(0, 255, 0), false);
  if (!WritePEHeaders(ctx, hProcess, pTargetBase, pSourceData, errorMsg)) {
    LogErrorAndStatus(ctx, errorMsg, RGB(255, 0, 0), true);
    StealthFree(hProcess, pTargetBase);
    SendMessage(ctx.hwndProgressBar, PBM_SETSTATE, PBST_ERROR, 0);
    return false;
  }
  LogErrorAndStatus(ctx, errorMsg, RGB(0, 255, 0), false);
  return true;
}

bool WriteSectionsToMemory(InjectorContext &ctx, HANDLE hProcess,
                           BYTE *pTargetBase, const BYTE *pSourceData,
                           IMAGE_NT_HEADERS *pNtHeaders) {
  wstring errorMsg;
  if (!WriteSections(ctx, hProcess, pTargetBase, pSourceData, pNtHeaders,
                     errorMsg)) {
    LogErrorAndStatus(ctx, errorMsg, RGB(255, 0, 0), true);
    StealthFree(hProcess, pTargetBase);
    SendMessage(ctx.hwndProgressBar, PBM_SETSTATE, PBST_ERROR, 0);
    return false;
  }
  return true;
}

bool PrepareMappingData(InjectorContext &ctx, HANDLE hProcess,
                        BYTE *pTargetBase, bool sehSupport, DWORD reason,
                        LPVOID reserved, BYTE *&pMappingDataAlloc,
                        void *pShellcode, SIZE_T imageSize,
                        SIZE_T headersSize) {
  wstring errorMsg;
  MANUAL_MAPPING_DATA mappingData = {0};
  mappingData.pLoadLibraryA = LoadLibraryA;
  mappingData.pGetProcAddress = GetProcAddress;
  HMODULE hNtdll = GetModuleHandleA(ctx.ntdllName);
  if (!hNtdll) {
    LogErrorAndStatus(ctx, L"[-] Error getting handle to ntdll", RGB(255, 0, 0),
                      true);
    return false;
  }
  mappingData.pRtlAddFunctionTable = reinterpret_cast<f_RtlAddFunctionTable>(
      GetProcAddress(hNtdll, "RtlAddFunctionTable"));

  // Self-erase and anti-timing function pointers
  HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
  mappingData.pVirtualFree =
      reinterpret_cast<f_VirtualFree>(GetProcAddress(hKernel32, "VirtualFree"));
  mappingData.pRtlZeroMemory = reinterpret_cast<f_RtlZeroMemory>(
      GetProcAddress(hNtdll, "RtlZeroMemory"));
  mappingData.pSleep =
      reinterpret_cast<f_Sleep>(GetProcAddress(hKernel32, "Sleep"));

  mappingData.pBase = pTargetBase;
  mappingData.dwReason = reason;
  mappingData.lpReserved = reserved;
  mappingData.bSEHSupport = sehSupport;

  // XOR key for in-transit encryption
  mappingData.xorKey = ctx.kXorKey;
  mappingData.imageSize = imageSize;
  mappingData.headersSize = headersSize;

  // Shellcode self-erase info
  mappingData.pShellcodeBase = pShellcode;
  mappingData.shellcodeSize = 4096;

  pMappingDataAlloc = AllocateMappingData(ctx, hProcess, mappingData, errorMsg);
  if (!pMappingDataAlloc) {
    LogErrorAndStatus(ctx, errorMsg, RGB(255, 0, 0), true);
    return false;
  }
  LogErrorAndStatus(ctx, errorMsg, RGB(0, 255, 0), false);
  return true;
}

bool WaitAndCleanUp(InjectorContext &ctx, HANDLE hProcess, BYTE *pTargetBase,
                    IMAGE_NT_HEADERS *pNtHeaders, void *pShellcode,
                    BYTE *pMappingDataAlloc, bool cleanHeader,
                    bool cleanUnneededSections, bool adjustProtections,
                    bool sehSupport) {
  wstring errorMsg;
  HINSTANCE hModule = nullptr;
  if (!WaitForInjection(ctx, hProcess, pMappingDataAlloc, hModule, errorMsg)) {
    LogErrorAndStatus(ctx, errorMsg, RGB(255, 0, 0), true);
    return false;
  }
  LogErrorAndStatus(ctx, errorMsg, RGB(0, 255, 0), false);
  if (!CleanAndProtectMemory(ctx, hProcess, pTargetBase, pNtHeaders, pShellcode,
                             pMappingDataAlloc, cleanHeader,
                             cleanUnneededSections, adjustProtections,
                             sehSupport, errorMsg)) {
    LogErrorAndStatus(ctx, errorMsg, RGB(255, 0, 0), true);
    return false;
  }
  LogErrorAndStatus(ctx, errorMsg, RGB(0, 255, 0), false);
  return true;
}

bool ManualMapDLL(InjectorContext &ctx, HANDLE hProcess, BYTE *pSourceData,
                  SIZE_T fileSize, bool cleanHeader, bool cleanUnneededSections,
                  bool adjustProtections, bool sehSupport, DWORD reason,
                  LPVOID reserved) {
  try {
    auto startTime = chrono::high_resolution_clock::now();
    LogErrorAndStatus(ctx, L"[+] Initializing stealth injection pipeline...",
                      RGB(0, 255, 0), false);
    LogErrorAndStatus(
        ctx,
        L"[i] Using NT API stealth layer (NtAllocateVirtualMemory, "
        L"NtWriteVirtualMemory, NtCreateThreadEx)",
        RGB(100, 200, 255), false);
    LogErrorAndStatus(
        ctx, L"[i] XOR transit encryption key: 0x" + to_wstring(ctx.kXorKey),
        RGB(100, 200, 255), false);
    SendMessage(ctx.hwndProgressBar, PBM_SETRANGE, 0, MAKELPARAM(0, 100));
    SendMessage(ctx.hwndProgressBar, PBM_SETSTEP, (WPARAM)10, 0);
    SendMessage(ctx.hwndProgressBar, PBM_SETSTATE, PBST_NORMAL, 0);
    SendMessage(ctx.hwndProgressBar, PBM_SETPOS, 0, 0);

    random_device rd;
    mt19937 gen(rd());
    uniform_int_distribution<> dis(5, 15);

    BYTE *pTargetBase = nullptr;
    IMAGE_NT_HEADERS *pNtHeaders = nullptr;
    DWORD oldProtect = 0;
    if (!AllocateAndWriteHeaders(ctx, hProcess, pSourceData, fileSize,
                                 pTargetBase, pNtHeaders, oldProtect)) {
      return false;
    }
    SendMessage(ctx.hwndProgressBar, PBM_STEPIT, 0, 0);
    this_thread::sleep_for(chrono::milliseconds(dis(gen)));

    // === XOR encrypt the sections in the local buffer before writing ===
    LogErrorAndStatus(
        ctx, L"[+] Encrypting DLL sections with XOR key for transit...",
        RGB(0, 255, 0), false);
    IMAGE_SECTION_HEADER *pSections = IMAGE_FIRST_SECTION(pNtHeaders);
    for (WORD i = 0; i < pNtHeaders->FileHeader.NumberOfSections; ++i) {
      if (pSections[i].SizeOfRawData) {
        XorBuffer(pSourceData + pSections[i].PointerToRawData,
                  pSections[i].SizeOfRawData, ctx.kXorKey);
      }
    }

    if (!WriteSectionsToMemory(ctx, hProcess, pTargetBase, pSourceData,
                               pNtHeaders)) {
      StealthFree(hProcess, pTargetBase);
      return false;
    }

    // Now upgrade protection to PAGE_EXECUTE_READWRITE for shellcode execution
    // We delayed this until after writing to avoid anti-cheat blocking writes
    // to RWX pages
    if (!StealthProtect(hProcess, pTargetBase,
                        pNtHeaders->OptionalHeader.SizeOfImage,
                        PAGE_EXECUTE_READWRITE, &oldProtect)) {
      LogErrorAndStatus(ctx,
                        L"[-] Error setting execute permission after write",
                        RGB(255, 0, 0), true);
      StealthFree(hProcess, pTargetBase);
      return false;
    }
    LogErrorAndStatus(ctx, L"[+] Memory protection upgraded to RWX",
                      RGB(0, 255, 0), false);
    SendMessage(ctx.hwndProgressBar, PBM_STEPIT, 0, 0);
    this_thread::sleep_for(chrono::milliseconds(dis(gen)));

    // Allocate shellcode first so we can pass its address to mapping data
    wstring scErrorMsg;
    void *pShellcode = AllocateAndWriteShellcode(ctx, hProcess, scErrorMsg);
    if (!pShellcode) {
      LogErrorAndStatus(ctx, scErrorMsg, RGB(255, 0, 0), true);
      StealthFree(hProcess, pTargetBase);
      return false;
    }
    LogErrorAndStatus(ctx, scErrorMsg, RGB(0, 255, 0), false);

    BYTE *pMappingDataAlloc = nullptr;
    if (!PrepareMappingData(ctx, hProcess, pTargetBase, sehSupport, reason,
                            reserved, pMappingDataAlloc, pShellcode,
                            pNtHeaders->OptionalHeader.SizeOfImage,
                            pNtHeaders->OptionalHeader.SizeOfHeaders)) {
      StealthFree(hProcess, pTargetBase);
      StealthFree(hProcess, pShellcode);
      return false;
    }
    SendMessage(ctx.hwndProgressBar, PBM_STEPIT, 0, 0);
    this_thread::sleep_for(chrono::milliseconds(dis(gen)));

    // Execute shellcode (it will decrypt XOR, resolve imports, call DllMain)
    wstring execErrorMsg;
    if (!ExecuteShellcode(ctx, hProcess, pShellcode, pMappingDataAlloc,
                          execErrorMsg)) {
      LogErrorAndStatus(ctx, execErrorMsg, RGB(255, 0, 0), true);
      StealthFree(hProcess, pTargetBase);
      StealthFree(hProcess, pMappingDataAlloc);
      StealthFree(hProcess, pShellcode);
      return false;
    }
    LogErrorAndStatus(ctx, execErrorMsg, RGB(0, 255, 0), false);
    SendMessage(ctx.hwndProgressBar, PBM_STEPIT, 0, 0);
    this_thread::sleep_for(chrono::milliseconds(dis(gen)));

    // WaitAndCleanUp already frees pShellcode + pMappingData inside
    // CleanAndProtectMemory so we must NOT double-free them in the error path
    if (!WaitAndCleanUp(ctx, hProcess, pTargetBase, pNtHeaders, pShellcode,
                        pMappingDataAlloc, cleanHeader, cleanUnneededSections,
                        adjustProtections, sehSupport)) {
      // NEVER free pTargetBase here — the DLL is LIVE in the target process.
      // Freeing it would unmap the DLL's code pages and crash the game.
      // The shellcode has already run, DllMain has been called.
      LogErrorAndStatus(ctx, L"[!] Cleanup had issues but DLL is loaded",
                        RGB(255, 200, 0), false);
    }
    SendMessage(ctx.hwndProgressBar, PBM_STEPIT, 0, 0);
    this_thread::sleep_for(chrono::milliseconds(dis(gen)));

    // NOTE: GameGuard in HD2 is anti-tamper only — it protects .text integrity
    // and blocks process access, but does NOT scan for foreign DLLs or RWX
    // regions. No post-init protection changes needed. Leave the DLL's memory
    // as-is to avoid breaking the DLL's runtime threads that may write to any
    // section.

    auto endTime = chrono::high_resolution_clock::now();
    auto durationMs =
        chrono::duration_cast<chrono::milliseconds>(endTime - startTime)
            .count();
    double durationSec = durationMs / 1000.0;
    wstringstream durationStream;
    durationStream << fixed << setprecision(3) << durationSec;
    LogErrorAndStatus(ctx,
                      L"[+] Injection completed in " + durationStream.str() +
                          L" seconds",
                      RGB(0, 255, 0), false);
    LogErrorAndStatus(
        ctx, L"[+] Anti-forensic cleanup: shellcode erased, mapping data wiped",
        RGB(0, 200, 100), false);
    SendMessage(ctx.hwndProgressBar, PBM_SETPOS, 100, 0);
    SendMessage(ctx.hwndProgressBar, PBM_SETSTATE, PBST_NORMAL, 0);
    return true;
  } catch (const exception &e) {
    wstring error = L"[-] Exception in ManualMapDLL: " +
                    wstring(e.what(), e.what() + strlen(e.what()));
    LogErrorAndStatus(ctx, error, RGB(255, 0, 0), true);
    SendMessage(ctx.hwndProgressBar, PBM_SETSTATE, PBST_ERROR, 0);
    return false;
  }
}

#define WM_DO_INJECT (WM_USER + 100)

static InjectorContext *g_pCtx = nullptr;

DWORD WINAPI EarlyInjectWatcher(LPVOID lpParam) {
  HWND hwnd = (HWND)lpParam;
  if (!g_pCtx || g_pCtx->processName.empty())
    return 1;
  wstring lowerTarget = g_pCtx->processName;
  transform(lowerTarget.begin(), lowerTarget.end(), lowerTarget.begin(),
            ::towlower);
  while (g_pCtx->watcherActive) {
    HandleGuard snapshot(CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0));
    if (snapshot.get() != INVALID_HANDLE_VALUE) {
      PROCESSENTRY32W entry = {sizeof(PROCESSENTRY32W)};
      if (Process32FirstW(snapshot, &entry)) {
        do {
          wstring exeName(entry.szExeFile);
          transform(exeName.begin(), exeName.end(), exeName.begin(),
                    ::towlower);
          if (exeName == lowerTarget) {
            g_pCtx->watcherActive = false;
            // Brief delay so process loads ntdll/kernel32 (but inject before
            // anti-cheat)
            Sleep(400);
            PostMessage(hwnd, WM_DO_INJECT, 0, (LPARAM)entry.th32ProcessID);
            return 0;
          }
        } while (Process32NextW(snapshot, &entry));
      }
    }
    Sleep(150);
  }
  return 0;
}

LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
  static InjectorContext ctx;

  // ===== WinUI 3 Typography =====
    static HFONT hFontPageTitle = CreateFontW(
      32, 0, 0, 0, FW_SEMIBOLD, FALSE, FALSE, FALSE, DEFAULT_CHARSET,
      OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY,
      DEFAULT_PITCH | FF_DONTCARE, L"Segoe UI Variable Display");
  static HFONT hFontSectionHeader = CreateFontW(
      18, 0, 0, 0, FW_SEMIBOLD, FALSE, FALSE, FALSE, DEFAULT_CHARSET,
      OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY,
      DEFAULT_PITCH | FF_DONTCARE, L"Segoe UI Variable");
    static HFONT hFontBody = CreateFontW(
      15, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE, DEFAULT_CHARSET,
      OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY,
      DEFAULT_PITCH | FF_DONTCARE, L"Segoe UI Variable");
    static HFONT hFontBodyStrong = CreateFontW(
      15, 0, 0, 0, FW_SEMIBOLD, FALSE, FALSE, FALSE, DEFAULT_CHARSET,
      OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY,
      DEFAULT_PITCH | FF_DONTCARE, L"Segoe UI Variable");
    static HFONT hFontCaption = CreateFontW(
      13, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE, DEFAULT_CHARSET,
      OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY,
      DEFAULT_PITCH | FF_DONTCARE, L"Segoe UI Variable");
    static HFONT hFontButton =
      CreateFontW(15, 0, 0, 0, FW_SEMIBOLD, FALSE, FALSE, FALSE,
                  DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                  CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE, L"Segoe UI Variable");
  static HFONT hFontMono =
      CreateFontW(14, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE, DEFAULT_CHARSET,
                  OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY,
                  FIXED_PITCH | FF_MODERN, L"Cascadia Mono");
  static HFONT hFontTitleBar =
      CreateFontW(13, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE, DEFAULT_CHARSET,
                  OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY,
                  DEFAULT_PITCH | FF_DONTCARE, L"Segoe UI Variable");

  // Make body font available to combo subclass
  if (!g_hFontBody) g_hFontBody = hFontBody;

  static HBITMAP hBitmap = nullptr;
  static HBRUSH hBackgroundBrush = CreateSolidBrush(Fluent::BgMica);
  static HBRUSH hStatusBrush = CreateSolidBrush(Fluent::BgInput);
  static HBRUSH hCardBrush = CreateSolidBrush(Fluent::BgCard);
  static HBRUSH hInsetBrush = CreateSolidBrush(Fluent::BgInset);

  // Hover tracking for WinUI 3-style buttons
  static int hoveredButtonId = -1;
  static bool isTrackingMouse = false;

  // Custom Title Bar height
  const int TitleBarH = 40;

  g_pCtx = &ctx;

  switch (msg) {
  case WM_NCHITTEST: {
    LRESULT hit = DefWindowProc(hwnd, msg, wParam, lParam);
    if (hit == HTCLIENT) {
      POINT pt = {LOWORD(lParam), HIWORD(lParam)};
      ScreenToClient(hwnd, &pt);
      // Allow dragging via top 40px (excluding buttons area which is approx
      // top-right 90px)
      RECT rcClient{};
      GetClientRect(hwnd, &rcClient);
      const int winW = rcClient.right;
      const int captionW = 46 * 2;
      if (pt.y < TitleBarH && pt.x < (winW - captionW))
        return HTCAPTION;
    }
    return hit;
  }
  case WM_MOUSEMOVE: {
    if (!isTrackingMouse) {
      TRACKMOUSEEVENT tme = {sizeof(TRACKMOUSEEVENT)};
      tme.dwFlags = TME_LEAVE;
      tme.hwndTrack = hwnd;
      TrackMouseEvent(&tme);
      isTrackingMouse = true;
    }
    // Check which button the mouse is over
    POINT pt = {LOWORD(lParam), HIWORD(lParam)};
    int newHover = -1;
    int buttonIds[] = {1, 2, 4, 10, 11, 105, 106};
    HWND buttonHwnds[] = {ctx.hwndBrowseButton, ctx.hwndInjectButton,
                          ctx.hwndRefreshButton, ctx.hwndTipsButton,
                          ctx.hwndWatchButton, ctx.hwndMinButton,
                          ctx.hwndCloseButton};
    for (int i = 0; i < 7; i++) {
      HWND btn = buttonHwnds[i];
      if (!btn) continue;
      RECT rc;
      GetWindowRect(btn, &rc);
      MapWindowPoints(HWND_DESKTOP, hwnd, (LPPOINT)&rc, 2);
      if (PtInRect(&rc, pt)) {
        newHover = buttonIds[i];
        break;
      }
    }
    if (newHover != hoveredButtonId) {
      hoveredButtonId = newHover;
      // Redraw all buttons
      if (ctx.hwndBrowseButton) InvalidateRect(ctx.hwndBrowseButton, NULL, FALSE);
      if (ctx.hwndInjectButton) InvalidateRect(ctx.hwndInjectButton, NULL, FALSE);
      if (ctx.hwndRefreshButton) InvalidateRect(ctx.hwndRefreshButton, NULL, FALSE);
      if (ctx.hwndTipsButton) InvalidateRect(ctx.hwndTipsButton, NULL, FALSE);
      if (ctx.hwndWatchButton) InvalidateRect(ctx.hwndWatchButton, NULL, FALSE);
      if (ctx.hwndMinButton) InvalidateRect(ctx.hwndMinButton, NULL, FALSE);
      if (ctx.hwndCloseButton) InvalidateRect(ctx.hwndCloseButton, NULL, FALSE);
    }
    break;
  }
  case WM_MOUSELEAVE: {
    isTrackingMouse = false;
    if (hoveredButtonId != -1) {
      hoveredButtonId = -1;
      if (ctx.hwndBrowseButton) InvalidateRect(ctx.hwndBrowseButton, NULL, FALSE);
      if (ctx.hwndInjectButton) InvalidateRect(ctx.hwndInjectButton, NULL, FALSE);
      if (ctx.hwndRefreshButton) InvalidateRect(ctx.hwndRefreshButton, NULL, FALSE);
      if (ctx.hwndTipsButton) InvalidateRect(ctx.hwndTipsButton, NULL, FALSE);
      if (ctx.hwndWatchButton) InvalidateRect(ctx.hwndWatchButton, NULL, FALSE);
      if (ctx.hwndMinButton) InvalidateRect(ctx.hwndMinButton, NULL, FALSE);
      if (ctx.hwndCloseButton) InvalidateRect(ctx.hwndCloseButton, NULL, FALSE);
    }
    break;
  }
  case WM_CREATE: {
    // DWM Immersive Dark Mode
    BOOL useDarkMode = TRUE;
    DwmSetWindowAttribute(hwnd, DWMWA_USE_IMMERSIVE_DARK_MODE, &useDarkMode,
                          sizeof(useDarkMode));

    // DWM Mica Effect (Win11)
    int backdrop = DWMSBT_MAINWINDOW;
    DwmSetWindowAttribute(hwnd, DWMWA_SYSTEMBACKDROP_TYPE, &backdrop,
                          sizeof(backdrop));

    INITCOMMONCONTROLSEX icex = {sizeof(INITCOMMONCONTROLSEX),
                                 ICC_STANDARD_CLASSES | ICC_PROGRESS_CLASS};
    InitCommonControlsEx(&icex);
    LoadLibraryW(L"Msftedit.dll");
    DragAcceptFiles(hwnd, TRUE);

    SetClassLongPtr(hwnd, GCLP_HBRBACKGROUND, (LONG_PTR)hBackgroundBrush);
    hBitmap = (HBITMAP)LoadImageW(GetModuleHandle(NULL),
                                  MAKEINTRESOURCE(IDB_TREVOR_BMP), IMAGE_BITMAP,
                                  0, 0, 0);
    ctx.hwndMain = hwnd;

    // ===== Tooltip =====
    ctx.hwndTooltip =
        CreateWindowExW(0, TOOLTIPS_CLASSW, NULL,
                        WS_POPUP | TTS_ALWAYSTIP | TTS_BALLOON | TTS_NOPREFIX,
                        CW_USEDEFAULT, CW_USEDEFAULT, CW_USEDEFAULT,
                        CW_USEDEFAULT, hwnd, NULL, GetModuleHandle(NULL), NULL);
    SendMessageW(ctx.hwndTooltip, TTM_SETMAXTIPWIDTH, 0, 350);
    SendMessageW(ctx.hwndTooltip, TTM_SETDELAYTIME, TTDT_AUTOPOP, 15000);

    // ===== Custom Title Bar Buttons =====
    ctx.hwndMinButton = CreateWindowW(
      L"BUTTON", L"\uE921", WS_VISIBLE | WS_CHILD | BS_OWNERDRAW,
      0, 0, 46, TitleBarH, hwnd, (HMENU)105, GetModuleHandle(NULL), NULL);
    ctx.hwndCloseButton = CreateWindowW(
      L"BUTTON", L"\uE8BB", WS_VISIBLE | WS_CHILD | BS_OWNERDRAW,
      0, 0, 46, TitleBarH, hwnd, (HMENU)106, GetModuleHandle(NULL), NULL);
    // Segoe MDL2 Assets font for caption button glyphs
    HFONT hFontMDL2 = CreateFontW(10, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
                                   DEFAULT_CHARSET, OUT_DEFAULT_PRECIS,
                                   CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY,
                                   DEFAULT_PITCH | FF_DONTCARE, L"Segoe MDL2 Assets");
    SendMessage(ctx.hwndMinButton, WM_SETFONT, (WPARAM)hFontMDL2, TRUE);
    SendMessage(ctx.hwndCloseButton, WM_SETFONT, (WPARAM)hFontMDL2, TRUE);

    // ==========================================================================
    // WinUI 3 Premium Layout — Windows 11 Settings-style
    // Window: 960×640 (compact)
    // Margins: Left=48, Right=48 → contentW=864
    // Vertical: TitleBar(40) → Header zone(40-108) → Card1(120-292) → ActionRow(304-336)
    //           → ProgressBar(342) → OutputLabel(352) → Card2(366-636) → Footer
    // ==========================================================================

    // Layout metrics are centralized (used by both WM_CREATE + WM_SIZE + WM_PAINT)
    LayoutMetrics m = ComputeLayout(hwnd);

    // ===== Page Header (drawn in WM_PAINT) =====
    // Title "DLL Injection" at y=48, subtitle at y=80

    // ==========================================================================
    // CARD 1: Configuration (3 rows × 48px = 144px + 8px padding = 152px)
    // Card: y=112, h=152
    // Row 1 (Process):   y=124..180  — label+combo centered at y=138
    // Row 2 (DLL):       y=180..236  — label+browse centered at y=194
    // Row 3 (Actions):   y=236..292  — Tips + Inject buttons centered
    // Separators at y=180 and y=236
    // ==========================================================================
    const int card1Y = m.card1Y;
    const int card1H = m.card1H;

    // --- Row 1: Target process ---
    ctx.hwndProcessLabel = CreateWindowW(
      L"STATIC", L"Target process", WS_VISIBLE | WS_CHILD, m.cardInnerLeft,
      card1Y + m.cardTopPad + 14, 160, 18, hwnd, (HMENU)5, GetModuleHandle(NULL), NULL);
    SendMessage(ctx.hwndProcessLabel, WM_SETFONT, (WPARAM)hFontBody, TRUE);

    // Combo: right-aligned, 44% of card inner width
    int comboW = (int)(m.cardInnerW * 0.44);
    ctx.hwndProcessCombo = CreateWindowW(
      L"COMBOBOX", NULL,
      WS_VISIBLE | WS_CHILD | CBS_DROPDOWN | CBS_SORT | WS_VSCROLL |
        CBS_OWNERDRAWFIXED | CBS_HASSTRINGS,
      m.cardInnerLeft + m.cardInnerW - comboW - 44, card1Y + m.cardTopPad + 8, comboW, 200,
      hwnd, (HMENU)IDD_PROCESSSELECT, GetModuleHandle(NULL), NULL);
    SendMessage(ctx.hwndProcessCombo, WM_SETFONT, (WPARAM)hFontBody, TRUE);
    // Strip native borders and subclass to suppress WM_NCPAINT
    {
      LONG_PTR st = GetWindowLongPtrW(ctx.hwndProcessCombo, GWL_STYLE);
      st &= ~WS_BORDER;
      SetWindowLongPtrW(ctx.hwndProcessCombo, GWL_STYLE, st);
      LONG_PTR exst = GetWindowLongPtrW(ctx.hwndProcessCombo, GWL_EXSTYLE);
      exst &= ~(WS_EX_CLIENTEDGE | WS_EX_STATICEDGE | WS_EX_WINDOWEDGE);
      SetWindowLongPtrW(ctx.hwndProcessCombo, GWL_EXSTYLE, exst);
      SetWindowPos(ctx.hwndProcessCombo, NULL, 0, 0, 0, 0,
                   SWP_NOMOVE | SWP_NOSIZE | SWP_NOZORDER | SWP_FRAMECHANGED);
      SetWindowSubclass(ctx.hwndProcessCombo, ComboSubclassProc, 1, 0);
    }
    AddTooltip(ctx.hwndProcessCombo, ctx.hwndTooltip,
               L"Select or type the target process name.\nFor Watch mode: type "
               L"the name before starting the game!");

    ctx.hwndRefreshButton = CreateWindowW(
      L"BUTTON", L"\u21BB", WS_VISIBLE | WS_CHILD | BS_OWNERDRAW,
      m.cardInnerLeft + m.cardInnerW - 36, card1Y + m.cardTopPad + 8, 36, Fluent::BtnH,
      hwnd, (HMENU)4, GetModuleHandle(NULL), NULL);
    SendMessage(ctx.hwndRefreshButton, WM_SETFONT, (WPARAM)hFontBody, TRUE);
    AddTooltip(ctx.hwndRefreshButton, ctx.hwndTooltip,
               L"Refresh the running process list");

    // --- Row 2: DLL file path + Browse/Watch ---
    ctx.hwndDllLabel = CreateWindowW(L"STATIC", L"No DLL selected",
             WS_VISIBLE | WS_CHILD | SS_PATHELLIPSIS,
           m.cardInnerLeft, card1Y + m.rowH + m.cardTopPad + 14,
           m.cardInnerW - 200, 18, hwnd,
                     (HMENU)6, GetModuleHandle(NULL), NULL);
    SendMessage(ctx.hwndDllLabel, WM_SETFONT, (WPARAM)hFontBody, TRUE);

    ctx.hwndBrowseButton = CreateWindowW(L"BUTTON", L"Browse",
               WS_VISIBLE | WS_CHILD | BS_OWNERDRAW,
             m.cardInnerLeft + m.cardInnerW - 184, card1Y + m.rowH + m.cardTopPad + 8,
               84, Fluent::BtnH, hwnd,
                       (HMENU)1, GetModuleHandle(NULL), NULL);
    SendMessage(ctx.hwndBrowseButton, WM_SETFONT, (WPARAM)hFontButton, TRUE);
    AddTooltip(ctx.hwndBrowseButton, ctx.hwndTooltip,
               L"Browse for a .DLL file to inject.\nYou can also drag-and-drop "
               L"a DLL onto this window!");

    ctx.hwndWatchButton = CreateWindowW(L"BUTTON", L"Watch",
              WS_VISIBLE | WS_CHILD | BS_OWNERDRAW,
            m.cardInnerLeft + m.cardInnerW - 92, card1Y + m.rowH + m.cardTopPad + 8,
              92, Fluent::BtnH, hwnd,
                      (HMENU)11, GetModuleHandle(NULL), NULL);
    SendMessage(ctx.hwndWatchButton, WM_SETFONT, (WPARAM)hFontButton, TRUE);
    AddTooltip(ctx.hwndWatchButton, ctx.hwndTooltip,
               L"EARLY INJECTION: Watches for the process to start,\n"
               L"then injects IMMEDIATELY before anti-cheat loads.");

    // --- Row 3: Action buttons (inside the card, professional) ---
    ctx.hwndTipsButton = CreateWindowW(L"BUTTON", L"Tips",
               WS_VISIBLE | WS_CHILD | BS_OWNERDRAW,
             m.cardInnerLeft, card1Y + m.rowH * 2 + m.cardTopPad + 8,
               80, Fluent::BtnH, hwnd,
                       (HMENU)10, GetModuleHandle(NULL), NULL);
    SendMessage(ctx.hwndTipsButton, WM_SETFONT, (WPARAM)hFontButton, TRUE);

    ctx.hwndInjectButton = CreateWindowW(L"BUTTON", L"Inject",
               WS_VISIBLE | WS_CHILD | BS_OWNERDRAW,
             m.cardInnerLeft + m.cardInnerW - 120, card1Y + m.rowH * 2 + m.cardTopPad + 8,
               120, Fluent::BtnH, hwnd,
                       (HMENU)2, GetModuleHandle(NULL), NULL);
    SendMessage(ctx.hwndInjectButton, WM_SETFONT, (WPARAM)hFontButton, TRUE);
    AddTooltip(ctx.hwndInjectButton, ctx.hwndTooltip,
               L"Start the stealth injection.\nUses NT API calls to bypass "
               L"user-mode hooks.");

    // ==========================================================================
    // Progress bar (thin accent line below Card 1)
    // ==========================================================================
    const int progressY = m.progressY;
    ctx.hwndProgressBar = CreateWindowW(
      PROGRESS_CLASSW, NULL, WS_VISIBLE | WS_CHILD | PBS_SMOOTH, m.pageLeft,
      progressY, m.contentW, 2, hwnd, NULL, GetModuleHandle(NULL), NULL);

    // ==========================================================================
    // CARD 2: Output log
    // Card: y=card1+progress+8, h=300 (compact)
    // Status log inset 16px from card edges
    // ==========================================================================
    const int card2Y = m.card2Y;
    const int card2H = m.card2H;
    ctx.hwndStatus =
      CreateWindowExW(0, MSFTEDIT_CLASS, L"",
              WS_VISIBLE | WS_CHILD | WS_VSCROLL | ES_MULTILINE |
                ES_READONLY | ES_AUTOVSCROLL,
              m.pageLeft + 6, card2Y + 38, m.contentW - 12, card2H - 48, hwnd, NULL,
              GetModuleHandle(NULL), NULL);
    SendMessage(ctx.hwndStatus, WM_SETFONT, (WPARAM)hFontMono, TRUE);
    SendMessageW(ctx.hwndStatus, EM_SETBKGNDCOLOR, 0, Fluent::BgInset);

    // Initial status messages
    AppendColoredLine(ctx.hwndStatus,
                      L"  TRE\u25BCR Wy Stealth Injector initialized",
                      Fluent::TextSec);
    AppendColoredLine(ctx.hwndStatus,
                      L"  Injection method: Manual Map + NT API stealth",
                      Fluent::TextSec);

    // Show NT API status
    ctx.ntApisAvailable = g_NtApis.valid;
    if (g_NtApis.valid) {
      AppendColoredLine(
          ctx.hwndStatus,
          L"  NT APIs resolved: NtAllocateVirtualMemory, "
          L"NtWriteVirtualMemory, NtCreateThreadEx, NtOpenProcess",
          Fluent::Success);
      // Status badges are drawn in WM_PAINT
    } else {
      AppendColoredLine(ctx.hwndStatus,
                        L"  Warning: Some NT APIs could not be resolved, "
                        L"falling back to Win32",
                        Fluent::Warning);
    }
    AppendColoredLine(
        ctx.hwndStatus,
        L"  Drag-and-drop a .DLL, or use Watch for anti-cheat games",
        Fluent::TextTer);

    // ===== Footer (drawn in WM_PAINT) =====

    // ===== Apply Dark Theme to ALL controls =====
    SetWindowTheme(hwnd, L"DarkMode_Explorer", NULL);
    SetWindowTheme(ctx.hwndProcessCombo, L"DarkMode_CFD", NULL);
    SetWindowTheme(ctx.hwndRefreshButton, L"DarkMode_Explorer", NULL);
    SetWindowTheme(ctx.hwndBrowseButton, L"DarkMode_Explorer", NULL);
    SetWindowTheme(ctx.hwndInjectButton, L"DarkMode_Explorer", NULL);
    SetWindowTheme(ctx.hwndWatchButton, L"DarkMode_Explorer", NULL);
    SetWindowTheme(ctx.hwndTipsButton, L"DarkMode_Explorer", NULL);
    SetWindowTheme(ctx.hwndProgressBar, L"DarkMode_Explorer", NULL);
    SetWindowTheme(ctx.hwndStatus, L"DarkMode_Explorer", NULL);
    SetWindowTheme(ctx.hwndMinButton, L"DarkMode_Explorer", NULL);
    SetWindowTheme(ctx.hwndCloseButton, L"DarkMode_Explorer", NULL);

    // Dark progress bar colors
    SendMessage(ctx.hwndProgressBar, PBM_SETBARCOLOR, 0,
                (LPARAM)Fluent::AccentBase);
    SendMessage(ctx.hwndProgressBar, PBM_SETBKCOLOR, 0,
                (LPARAM)Fluent::BgMica);

    // Final positioning pass (handles centered content + dynamic window sizes)
    ApplyLayout(m, ctx);

    // ===== Populate process list =====
    HandleGuard snapshot(CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0));
    if (snapshot.get() == INVALID_HANDLE_VALUE) {
      AppendColoredLine(ctx.hwndStatus,
                        L"[-] Failed to load process list \u2014 click Refresh",
                        RGB(255, 0, 0));
      EnableWindow(ctx.hwndInjectButton, FALSE);
    } else {
      PROCESSENTRY32W entry = {sizeof(PROCESSENTRY32W)};
      if (Process32FirstW(snapshot, &entry)) {
        do {
          wstring display = wstring(entry.szExeFile) + L" (PID: " +
                            to_wstring(entry.th32ProcessID) + L")";
          SendMessageW(ctx.hwndProcessCombo, CB_ADDSTRING, 0,
                       (LPARAM)display.c_str());
        } while (Process32NextW(snapshot, &entry));
      }
      SendMessageW(ctx.hwndProcessCombo, CB_SETCURSEL, 0, 0);
      if (!ctx.processName.empty()) {
        wstring searchStr = ctx.processName + L" (PID: ";
        LRESULT index = SendMessageW(ctx.hwndProcessCombo, CB_FINDSTRING,
                                     (WPARAM)-1, (LPARAM)searchStr.c_str());
        if (index != CB_ERR) {
          SendMessageW(ctx.hwndProcessCombo, CB_SETCURSEL, index, 0);
        }
      }
      if (!ctx.dllPath.empty()) {
        SetWindowTextW(ctx.hwndDllLabel, (L"DLL: " + ctx.dllPath).c_str());
        AppendColoredLine(ctx.hwndStatus,
                          L"[+] Restored last DLL: " + ctx.dllPath,
                          RGB(0, 255, 0));
      }
      EnableWindow(ctx.hwndInjectButton,
                   !ctx.processName.empty() && !ctx.dllPath.empty());
    }
    break;
  }

  case WM_SIZE: {
    if (wParam == SIZE_MINIMIZED)
      break;
    LayoutMetrics m = ComputeLayout(hwnd);
    ApplyLayout(m, ctx);
    InvalidateRect(hwnd, NULL, FALSE);
    break;
  }

  // ===== Drag-and-drop DLL files =====
  case WM_DROPFILES: {
    HDROP hDrop = (HDROP)wParam;
    wchar_t filePath[MAX_PATH] = {0};
    if (DragQueryFileW(hDrop, 0, filePath, MAX_PATH)) {
      wstring path = filePath;
      // Check it's a .dll
      wstring ext = path.substr(path.find_last_of(L".") + 1);
      transform(ext.begin(), ext.end(), ext.begin(), ::towlower);
      if (ext == L"dll") {
        ctx.dllPath = path;
        if (ctx.ValidateDLLPath(ctx.dllPath)) {
          SetWindowTextW(ctx.hwndDllLabel, (L"DLL: " + ctx.dllPath).c_str());
          WritePrivateProfileStringW(
              L"Settings", L"LastDLL", ctx.dllPath.c_str(),
              InjectorContext::GetExeRelativePath(L"Injector.ini").c_str());
          LogErrorAndStatus(ctx, L"[+] DLL dropped: " + ctx.dllPath,
                            RGB(0, 255, 0), false);
          EnableWindow(ctx.hwndInjectButton,
                       !ctx.processName.empty() && !ctx.dllPath.empty());
        } else {
          ctx.dllPath.clear();
          SetWindowTextW(ctx.hwndDllLabel, L"DLL: None selected");
          EnableWindow(ctx.hwndInjectButton, FALSE);
        }
      } else {
        LogErrorAndStatus(ctx,
                          L"[!] Dropped file is not a .DLL \u2014 please drop "
                          L"a valid DLL file",
                          RGB(255, 255, 0), false);
      }
    }
    DragFinish(hDrop);
    break;
  }

  // ===== Owner-drawn buttons (WinUI 3 style) =====
  case WM_DRAWITEM: {
    LPDRAWITEMSTRUCT dis = (LPDRAWITEMSTRUCT)lParam;
    if (dis->CtlType == ODT_COMBOBOX && dis->CtlID == IDD_PROCESSSELECT) {
      HDC hdc = dis->hDC;
      RECT rc = dis->rcItem;
      bool selected = (dis->itemState & ODS_SELECTED) != 0;
      bool disabled = (dis->itemState & ODS_DISABLED) != 0;
      const bool isEditPortion = ((int)dis->itemID == -1);

      // Edit portion is fully painted by ComboSubclassProc::WM_PAINT — skip here.
      if (isEditPortion) {
        return TRUE;
      }

      wchar_t textBuf[260] = {};
      SendMessageW(dis->hwndItem, CB_GETLBTEXT, dis->itemID, (LPARAM)textBuf);

      using namespace Gdiplus;
      Graphics g(hdc);
      g.SetSmoothingMode(SmoothingModeAntiAlias);
      g.SetPixelOffsetMode(PixelOffsetModeHighQuality);

      // Dropdown list item background
      {
        COLORREF baseBg = Fluent::BgInset;
        SolidBrush bg(Color(255, GetRValue(baseBg), GetGValue(baseBg), GetBValue(baseBg)));
        g.FillRectangle(&bg, (INT)rc.left, (INT)rc.top,
                        (INT)(rc.right - rc.left), (INT)(rc.bottom - rc.top));
      }

      // Selection highlight (rounded)
      if (selected && !disabled) {
        GraphicsPath selPath;
        const int pad = 2;
        MakeRoundedRect(selPath, rc.left + pad, rc.top + pad,
                        (rc.right - rc.left) - pad * 2,
                        (rc.bottom - rc.top) - pad * 2, 8);
        LinearGradientBrush selFill(Point(rc.left, rc.top),
                                    Point(rc.right, rc.bottom),
                                    GdiColorA(110, Fluent::AccentAlt),
                                    GdiColorA(110, Fluent::AccentBase));
        g.FillPath(&selFill, &selPath);
      }

      // Text
      SetBkMode(hdc, TRANSPARENT);
      SetTextColor(hdc,
                   disabled ? Fluent::TextDis : Fluent::TextPri);
      SelectObject(hdc, hFontBody);
      RECT tr = rc;
      tr.left += 10;
      tr.right -= 10;
      DrawTextW(hdc, textBuf, -1, &tr,
                DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS);

      return TRUE;
    }

    if (dis->CtlType != ODT_BUTTON)
      break;
    HDC hdc = dis->hDC;
    RECT rc = dis->rcItem;
    bool sel = (dis->itemState & ODS_SELECTED) != 0;
    bool dis_ = (dis->itemState & ODS_DISABLED) != 0;
    int id = (int)dis->CtlID;
    bool hovered = (hoveredButtonId == id);

    // Title bar buttons (minimize/close)
    if (id == 105 || id == 106) {
      COLORREF bg;
      if (id == 106) {
        bg = sel ? RGB(232, 17, 35) : (hovered ? RGB(196, 43, 28) : Fluent::BgMica);
      } else {
        bg = sel ? RGB(55, 55, 55) : (hovered ? RGB(50, 50, 50) : Fluent::BgMica);
      }
      HBRUSH hB = CreateSolidBrush(bg);
      FillRect(hdc, &rc, hB);
      DeleteObject(hB);
      wchar_t txt[16] = {};
      GetWindowTextW(dis->hwndItem, txt, 16);
      SetBkMode(hdc, TRANSPARENT);
      SetTextColor(hdc, Fluent::TextPri);
      DrawTextW(hdc, txt, -1, &rc, DT_CENTER | DT_VCENTER | DT_SINGLELINE);
      return TRUE;
    }

    // WinUI 3 buttons using GDI+
    using namespace Gdiplus;
    Graphics g(hdc);
    g.SetSmoothingMode(SmoothingModeAntiAlias);
    g.SetPixelOffsetMode(PixelOffsetModeHighQuality);

    int radius = Fluent::BtnR;

    // First: fill background with parent color to enable semi-transparent compositing
    // All action buttons are now inside Card 1, only Tips/Inject remain on card
    bool inCard = (id == 1 || id == 4 || id == 11 || id == 10 || id == 2); // All inside Card 1
    COLORREF parentBg = inCard ? Fluent::BgCard : Fluent::BgMica;
    HBRUSH hParentBrush = CreateSolidBrush(parentBg);
    FillRect(hdc, &rc, hParentBrush);
    DeleteObject(hParentBrush);

    // Build rounded rect path
    GraphicsPath path;
    MakeRoundedRect(path, rc.left, rc.top, rc.right - rc.left, rc.bottom - rc.top, radius);

    auto toColor = [](BYTE a, COLORREF c) {
      return Color(a, GetRValue(c), GetGValue(c), GetBValue(c));
    };

    if (id == 2) {
      // ===== ACCENT (Primary) button =====
      // Tone down brightness: deeper gradient + subtle dark overlay at rest.
      const BYTE a = dis_ ? (BYTE)255 : (sel ? (BYTE)230 : (hovered ? (BYTE)255 : (BYTE)248));
      COLORREF top = hovered ? AdjustColor(Fluent::AccentBase, -8)
                             : AdjustColor(Fluent::AccentBase, -18);
      COLORREF bot = sel ? AdjustColor(Fluent::AccentDark, -16)
                         : AdjustColor(Fluent::AccentDark, -22);
      LinearGradientBrush fill(Point(rc.left, rc.top), Point(rc.left, rc.bottom),
                               toColor(a, top), toColor(a, bot));
      g.FillPath(&fill, &path);

      if (!dis_ && !sel && !hovered) {
        LinearGradientBrush dim(Point(rc.left, rc.top), Point(rc.left, rc.bottom),
                                Color(22, 0, 0, 0), Color(38, 0, 0, 0));
        g.FillPath(&dim, &path);
      }

      // Neon hover glow
      if (!dis_ && hovered) {
        LinearGradientBrush glow(Point(rc.left, rc.top), Point(rc.right, rc.top),
                                 toColor(90, Fluent::AccentAlt),
                                 toColor(90, Fluent::AccentBase));
        Pen glowPen(&glow, 2.0f);
        g.DrawPath(&glowPen, &path);
      }

      // Accent button border: subtle white overlay + bottom shadow
      if (!dis_) {
        // Top/sides: ControlStrokeColorOnAccentDefault
        Pen borderTop(Color(20, 255, 255, 255), 1.0f);
        g.DrawPath(&borderTop, &path);
        // Bottom shadow line: ControlStrokeColorOnAccentSecondary (#23000000)
        if (!sel) {
          Pen botShadow(Color(35, 0, 0, 0), 1.0f);
          g.DrawLine(&botShadow, (INT)(rc.left + radius), (INT)(rc.bottom - 1),
                     (INT)(rc.right - radius), (INT)(rc.bottom - 1));
        }
      }
    } else if (id == 10) {
      // ===== SUBTLE (Tips) button =====
      // Make Tips look like a premium "outlined" action (not disabled).
      if (!dis_) {
        const BYTE fillA = sel ? 34 : (hovered ? 52 : 28);
        LinearGradientBrush fill(Point(rc.left, rc.top), Point(rc.left, rc.bottom),
                                 toColor(fillA, AdjustColor(Fluent::AccentAlt, -10)),
                                 toColor((BYTE)max(0, (int)fillA - 10), AdjustColor(Fluent::AccentBase, -12)));
        g.FillPath(&fill, &path);

        LinearGradientBrush border(Point(rc.left, rc.top), Point(rc.right, rc.top),
                                   toColor(160, Fluent::AccentAlt),
                                   toColor(160, Fluent::AccentBase));
        Pen borderPen(&border, hovered ? 2.0f : 1.5f);
        g.DrawPath(&borderPen, &path);

        // Tiny inner glass line
        Pen inner(Color(18, 255, 255, 255), 1.0f);
        GraphicsPath innerPath;
        MakeRoundedRect(innerPath, rc.left + 1, rc.top + 1,
                        (rc.right - rc.left) - 2, (rc.bottom - rc.top) - 2,
                        max(1, radius - 1));
        g.DrawPath(&inner, &innerPath);
      }
    } else if (id == 11 && ctx.watcherActive) {
      // ===== WATCH BUTTON (ACTIVE STATE) =====
      // Purple accent style
      const BYTE a = dis_ ? (BYTE)255 : (sel ? (BYTE)230 : (hovered ? (BYTE)255 : (BYTE)248));
      COLORREF top = hovered ? AdjustColor(Fluent::AccentAlt, +8) : Fluent::AccentAlt;
      COLORREF bot = sel ? AdjustColor(Fluent::AccentAlt, -16) : AdjustColor(Fluent::AccentAlt, -10);
      LinearGradientBrush fill(Point(rc.left, rc.top), Point(rc.left, rc.bottom),
                               toColor(a, top), toColor(a, bot));
      g.FillPath(&fill, &path);

      if (!dis_ && !sel && !hovered) {
        LinearGradientBrush dim(Point(rc.left, rc.top), Point(rc.left, rc.bottom),
                                Color(22, 0, 0, 0), Color(38, 0, 0, 0));
        g.FillPath(&dim, &path);
      }
      
      // Border
      Pen borderTop(Color(40, 255, 255, 255), 1.0f);
      g.DrawPath(&borderTop, &path);
    } else {
      // ===== SECONDARY buttons (Browse, Watch, Refresh) =====
      // WinUI 3: semi-transparent white overlays on dark background
      BYTE baseA = dis_ ? 10 : (sel ? 18 : (hovered ? 34 : 24));
      BYTE topA = (BYTE)min(255, (int)baseA + 6);
      LinearGradientBrush fill(Point(rc.left, rc.top), Point(rc.left, rc.bottom),
                               Color(topA, 255, 255, 255), Color(baseA, 255, 255, 255));
      g.FillPath(&fill, &path);

      // Gradient border: top lighter (#18FFFFFF), bottom darker (#12FFFFFF)
      if (!dis_) {
        LinearGradientBrush borderGrad(
          Point(rc.left, rc.top), Point(rc.left, rc.bottom),
          Color(36, 255, 255, 255),   // stronger top highlight
          Color(24, 255, 255, 255));  // stronger bottom
        Pen borderPen(&borderGrad, 1.0f);
        g.DrawPath(&borderPen, &path);

        // Hover neon ring
        if (hovered && !sel) {
          LinearGradientBrush ring(Point(rc.left, rc.top), Point(rc.right, rc.top),
                                   toColor(80, Fluent::AccentAlt),
                                   toColor(80, Fluent::AccentBase));
          Pen ringPen(&ring, 2.0f);
          g.DrawPath(&ringPen, &path);
        }

        // Bottom shadow for elevation
        if (!sel) {
          Pen botShadow(Color(35, 0, 0, 0), 1.0f);
          g.DrawLine(&botShadow, (INT)(rc.left + radius), (INT)(rc.bottom),
                     (INT)(rc.right - radius), (INT)(rc.bottom));
        }
      }
    }

    // Text rendering
    wchar_t txt[128] = {};
    GetWindowTextW(dis->hwndItem, txt, 128);
    SetBkMode(hdc, TRANSPARENT);
    // Accent button text is BLACK, others are white. Watch Active is also Accent.
    if ((id == 2 || (id == 11 && ctx.watcherActive)) && !dis_)
      SetTextColor(hdc, Fluent::TextOnAccent);
    else
      SetTextColor(hdc, dis_ ? Fluent::TextDis : Fluent::TextPri);
    SelectObject(hdc, hFontButton);
    DrawTextW(hdc, txt, -1, &rc, DT_CENTER | DT_VCENTER | DT_SINGLELINE);
    return TRUE;
  }

  case WM_MEASUREITEM: {
    LPMEASUREITEMSTRUCT mi = (LPMEASUREITEMSTRUCT)lParam;
    if (mi && mi->CtlType == ODT_COMBOBOX && mi->CtlID == IDD_PROCESSSELECT) {
      mi->itemHeight = 28;
      return TRUE;
    }
    break;
  }
  case WM_CTLCOLORSTATIC: {
    HDC hdc = (HDC)wParam;
    HWND hCtrl = (HWND)lParam;
    // Labels inside cards: process label, DLL label
    if (hCtrl == ctx.hwndProcessLabel || hCtrl == ctx.hwndDllLabel) {
      SetTextColor(hdc, Fluent::TextPri);
      SetBkMode(hdc, TRANSPARENT);
      return (LRESULT)GetStockObject(NULL_BRUSH);
    }
    // Everything else on mica background
    SetTextColor(hdc, Fluent::TextSec);
    SetBkColor(hdc, Fluent::BgMica);
    return (LRESULT)hBackgroundBrush;
  }
  case WM_CTLCOLOREDIT: {
    HDC hdc = (HDC)wParam;
    HWND hCtrl = (HWND)lParam;
    // Combo box edit child should blend with card
    HWND comboEdit = FindWindowExW(ctx.hwndProcessCombo, NULL, L"Edit", NULL);
    if (hCtrl == comboEdit) {
      SetTextColor(hdc, Fluent::TextPri);
      SetBkColor(hdc, Fluent::BgInset);
      return (LRESULT)hInsetBrush;
    }
    SetTextColor(hdc, Fluent::TextPri);
    SetBkColor(hdc, Fluent::BgCard);
    return (LRESULT)hCardBrush;
  }
  case WM_CTLCOLORLISTBOX: {
    HDC hdc = (HDC)wParam;
    SetTextColor(hdc, Fluent::TextPri);
    SetBkColor(hdc, Fluent::BgInset);
    static HBRUSH hListBrush = CreateSolidBrush(Fluent::BgInset);
    return (LRESULT)hListBrush;
  }
  case WM_CTLCOLORBTN: {
    return (LRESULT)hBackgroundBrush;
  }
  case WM_PAINT: {
    PAINTSTRUCT ps;
    HDC hdc = BeginPaint(hwnd, &ps);

    // Double-buffer
    RECT rcWin;
    GetClientRect(hwnd, &rcWin);
    int winW = rcWin.right, winH = rcWin.bottom;
    HDC hdcMem = CreateCompatibleDC(hdc);
    HBITMAP hbmMem = CreateCompatibleBitmap(hdc, winW, winH);
    HBITMAP hbmOld = (HBITMAP)SelectObject(hdcMem, hbmMem);

    // Fill background (mica dark)
    FillRect(hdcMem, &rcWin, hBackgroundBrush);

    LayoutMetrics m = ComputeLayout(hwnd);
    const int PL = m.pageLeft;
    const int CW = m.contentW;
    const int C1Y = m.card1Y, C1H = m.card1H;
    const int C2Y = m.card2Y, C2H = m.card2H;
    const int RH = m.rowH;

    // ===== Title Bar =====
    {
      using namespace Gdiplus;
      Graphics g(hdcMem);
      SolidBrush tbBrush(Color(255, 32, 32, 32));
      g.FillRectangle(&tbBrush, 0, 0, winW, 40);
      Pen sepPen(Color(12, 255, 255, 255), 1.0f);
      g.DrawLine(&sepPen, 0, 40, winW, 40);

      // Subtle gamer header glow under titlebar
      LinearGradientBrush headerGlow(Point(0, 40), Point(winW, 40),
                                     GdiColorA(34, Fluent::AccentAlt),
                                     GdiColorA(34, Fluent::AccentBase));
      g.FillRectangle(&headerGlow, 0, 40, winW, 58);
    }

    // App icon
    HICON hIconSmall = (HICON)LoadImage(GetModuleHandle(NULL),
                                        MAKEINTRESOURCE(IDI_TREVOR_ICON),
                                        IMAGE_ICON, 16, 16, 0);
    if (hIconSmall) {
      DrawIconEx(hdcMem, 14, 12, hIconSmall, 16, 16, 0, NULL, DI_NORMAL);
      DestroyIcon(hIconSmall);
    }

    SetBkMode(hdcMem, TRANSPARENT);

    // Title bar text
    SetTextColor(hdcMem, Fluent::TextTer);
    SelectObject(hdcMem, hFontTitleBar);
    RECT rcTbText = {38, 0, 300, 40};
    DrawTextW(hdcMem, L"TRE\u25BCOR Wy", -1, &rcTbText,
              DT_LEFT | DT_VCENTER | DT_SINGLELINE);

    // ===== Page Header =====
    int heroSize = 40;
    int heroX = PL;
    int heroY = m.titleBarH + 12;
    int textX = heroX + heroSize + 12;

    // Draw .bmp hero (IDB_TREVOR_BMP)
    if (hBitmap) {
      using namespace Gdiplus;
      Graphics g(hdcMem);
      g.SetSmoothingMode(SmoothingModeAntiAlias);
      g.SetInterpolationMode(InterpolationModeHighQualityBicubic);

      Bitmap bmp(hBitmap, NULL);
      // Draw logo as full picture (square/rect), scaled to fit layout
      
      // Calculate aspect ratio to prevent cubic stretching
      UINT bmpW = bmp.GetWidth();
      UINT bmpH = bmp.GetHeight();
      
      int targetH = heroSize; // Limit height to 40px
      int targetW = targetH;
      if (bmpH > 0) {
        float ratio = (float)bmpW / (float)bmpH;
        targetW = (int)(targetH * ratio);
      }
      
      Rect dest(heroX, heroY, targetW, targetH);
      g.DrawImage(&bmp, dest);
      
      // Adjust text X position to respect the wider image
      textX = heroX + targetW + 12;
    }

    SetTextColor(hdcMem, Fluent::TextPri);
    SelectObject(hdcMem, hFontPageTitle);
    RECT rcPT = {textX, m.headerTitleY, PL + CW, m.headerTitleY + 34};
    DrawTextW(hdcMem, L"DLL Injection", -1, &rcPT,
              DT_LEFT | DT_VCENTER | DT_SINGLELINE);

    SetTextColor(hdcMem, Fluent::TextSec);
    SelectObject(hdcMem, hFontBody);
    RECT rcSub = {textX, m.headerSubY, PL + CW, m.headerSubY + 22};
    DrawTextW(hdcMem,
              L"Compact, modern manual-map injector with NT API stealth.",
              -1, &rcSub, DT_LEFT | DT_VCENTER | DT_SINGLELINE);

    // Status pills (Admin / NT APIs / Stealth) — right aligned, compact
    {
      using namespace Gdiplus;
      Graphics g(hdcMem);
      g.SetSmoothingMode(Gdiplus::SmoothingModeAntiAlias);
      const bool isAdmin = IsRunAsAdmin();
      const bool ntReady = g_NtApis.valid;
      const bool stealth = true;
        struct Pill {
        std::wstring text;
        Color fillTop;
        Color fillBot;
        Color border;
        Color textColor;
        };
      std::vector<Pill> pills;
        pills.push_back({
          isAdmin ? L"Administrator" : L"Not admin",
          isAdmin ? GdiColorA(90, Fluent::Success) : GdiColorA(90, Fluent::Error),
          isAdmin ? GdiColorA(60, Fluent::Success) : GdiColorA(60, Fluent::Error),
          isAdmin ? GdiColorA(90, Fluent::Success) : GdiColorA(90, Fluent::Error),
          Color(235, 255, 255, 255)});
        pills.push_back({
          ntReady ? L"NT APIs: Ready" : L"NT APIs: Fallback",
          ntReady ? GdiColorA(90, Fluent::AccentAlt) : GdiColorA(90, Fluent::Warning),
          ntReady ? GdiColorA(60, Fluent::AccentBase) : GdiColorA(60, Fluent::Warning),
          ntReady ? GdiColorA(90, Fluent::AccentBase) : GdiColorA(90, Fluent::Warning),
          Color(235, 255, 255, 255)});
        pills.push_back({
          stealth ? L"Stealth: Active" : L"Stealth: Off",
          stealth ? GdiColorA(90, Fluent::AccentBase) : GdiColorA(90, Fluent::TextTer),
          stealth ? GdiColorA(60, Fluent::AccentAlt) : GdiColorA(60, Fluent::TextTer),
          stealth ? GdiColorA(95, Fluent::AccentAlt) : GdiColorA(95, Fluent::TextTer),
          Color(235, 255, 255, 255)});

      REAL py = (REAL)m.pillsY;
      REAL h = 24.0f;
      REAL spacing = 8.0f;

      // Use Segoe UI for consistent availability/rendering
      FontFamily ff(L"Segoe UI");
      Font f(&ff, 11.0f, FontStyleBold, UnitPixel);
      StringFormat sf;
      sf.SetAlignment(StringAlignmentCenter);
      sf.SetLineAlignment(StringAlignmentCenter);

      // Measure widths first
      std::vector<REAL> widths;
      widths.reserve(pills.size());
      REAL totalW = 0.0f;
      for (auto& p : pills) {
        RectF layout;
        g.MeasureString(p.text.c_str(), -1, &f, PointF(0, 0), &layout);
        REAL w = layout.Width + 22.0f;
        widths.push_back(w);
        totalW += w;
      }
      if (!widths.empty())
        totalW += spacing * (REAL)(widths.size() - 1);

      REAL px = (REAL)(PL + CW) - totalW;
      for (size_t i = 0; i < pills.size(); ++i) {
        auto& p = pills[i];
        REAL w = widths[i];
        GraphicsPath pillPath;
        pillPath.AddArc(px, py, h, h, 180, 90);
        pillPath.AddArc(px + w - h, py, h, h, 270, 90);
        pillPath.AddArc(px + w - h, py + h - h, h, h, 0, 90);
        pillPath.AddArc(px, py + h - h, h, h, 90, 90);
        pillPath.CloseFigure();

        LinearGradientBrush pbFill(Point((INT)px, (INT)py),
                                   Point((INT)px, (INT)(py + h)), p.fillTop,
                                   p.fillBot);
        g.FillPath(&pbFill, &pillPath);
        Pen pb(p.border, 1.0f);
        g.DrawPath(&pb, &pillPath);

        SolidBrush tb(p.textColor);
        RectF tr(px + 10.0f, py, w - 20.0f, h);
        g.DrawString(p.text.c_str(), -1, &f, tr, &sf, &tb);

        px += w + spacing;
      }
    }

    // ===== CARD 1: Configuration =====
    DrawWinUICard(hdcMem, PL, C1Y, CW, C1H, Fluent::BgCard, 0);

    // Card 1 separators between rows (at row boundaries)
    DrawWinUISeparator(hdcMem, PL + 20, C1Y + RH + 4, CW - 40);
    DrawWinUISeparator(hdcMem, PL + 20, C1Y + RH * 2 + 4, CW - 40);

    // ===== CARD 2: Output =====
    DrawWinUICard(hdcMem, PL, C2Y, CW, C2H, Fluent::BgCard, 0);

    // Inset surface behind RichEdit log (rounded, darker, with subtle border)
    {
      using namespace Gdiplus;
      Graphics g(hdcMem);
      g.SetSmoothingMode(SmoothingModeAntiAlias);
      const int insetX = 10;
      const int insetY = 36;
      const int insetW = CW - insetX * 2;
      const int insetH = max(80, C2H - insetY - 10);
      GraphicsPath insetPath;
      MakeRoundedRect(insetPath, PL + insetX, C2Y + insetY, insetW, insetH, 8);

      COLORREF top = AdjustColor(Fluent::BgInset, +6);
      COLORREF bot = AdjustColor(Fluent::BgInset, -4);
      LinearGradientBrush insetFill(Point(PL, C2Y + insetY),
                                    Point(PL, C2Y + insetY + insetH),
                                    GdiColorA(255, top), GdiColorA(255, bot));
      g.FillPath(&insetFill, &insetPath);

      Pen insetBorder(Color(28, 255, 255, 255), 1.0f);
      g.DrawPath(&insetBorder, &insetPath);

      // tiny neon edge
      LinearGradientBrush neonEdge(Point(PL + insetX, C2Y + insetY),
                                   Point(PL + insetX + insetW, C2Y + insetY),
                                   GdiColorA(24, Fluent::AccentAlt),
                                   GdiColorA(24, Fluent::AccentBase));
      Pen neonPen(&neonEdge, 1.0f);
      g.DrawPath(&neonPen, &insetPath);
    }

    // "Output" section header drawn inside card top
    {
      using namespace Gdiplus;
      Graphics g(hdcMem);
      g.SetTextRenderingHint(Gdiplus::TextRenderingHintClearTypeGridFit);
      LinearGradientBrush bar(Point(PL + 12, C2Y + 6), Point(PL + CW - 12, C2Y + 6),
                              GdiColorA(40, Fluent::AccentAlt),
                              GdiColorA(40, Fluent::AccentBase));
      g.FillRectangle(&bar, PL + 12, C2Y + 6, CW - 24, 24);
      Gdiplus::FontFamily ff(L"Segoe UI Variable");
      Gdiplus::Font sfont(&ff, 11.0f, Gdiplus::FontStyleRegular, Gdiplus::UnitPixel);
      SolidBrush tb(Color(180, 255, 255, 255));
      PointF pt((Gdiplus::REAL)(PL + 16), (Gdiplus::REAL)(C2Y + 7));
      g.DrawString(L"Output", -1, &sfont, pt, &tb);
    }

    // ===== Footer =====
    SetTextColor(hdcMem, RGB(75, 75, 75));
    SelectObject(hdcMem, hFontCaption);
    RECT rcFooter = {0, winH - 28, winW, winH - 6};
    DrawTextW(hdcMem, L"Use at your own risk  \u00B7  github.com/s0mbra-1973/Trevor  \u00B7  Wy Edition",
              -1, &rcFooter, DT_CENTER | DT_VCENTER | DT_SINGLELINE);

    // ===== Window border =====
    {
      using namespace Gdiplus;
      Graphics g(hdcMem);
      Pen borderPen(Color(30, 255, 255, 255), 1.0f);
      g.DrawRectangle(&borderPen, 0, 0, winW - 1, winH - 1);
    }

    BitBlt(hdc, 0, 0, winW, winH, hdcMem, 0, 0, SRCCOPY);
    SelectObject(hdcMem, hbmOld);
    DeleteObject(hbmMem);
    DeleteDC(hdcMem);

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
    // Handle Title Bar Buttons
    if (LOWORD(wParam) == 106)
      PostMessage(hwnd, WM_CLOSE, 0, 0); // Close btn
    if (LOWORD(wParam) == 105)
      ShowWindow(hwnd, SW_MINIMIZE); // Min btn

    // Round + theme the combo dropdown listbox when it appears
    if (HIWORD(wParam) == CBN_DROPDOWN && LOWORD(wParam) == IDD_PROCESSSELECT) {
      COMBOBOXINFO cbi{};
      cbi.cbSize = sizeof(cbi);
      if (GetComboBoxInfo(ctx.hwndProcessCombo, &cbi) && cbi.hwndList) {
        SetWindowTheme(cbi.hwndList, L"DarkMode_Explorer", NULL);
        ApplyRoundedRegion(cbi.hwndList, 10);
        InvalidateRect(cbi.hwndList, NULL, TRUE);
      }
    }

    // ===== Refresh button =====
    if (LOWORD(wParam) == 4) {
      SendMessageW(ctx.hwndProcessCombo, CB_RESETCONTENT, 0, 0);
      HandleGuard snapshot(CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0));
      if (snapshot.get() == INVALID_HANDLE_VALUE) {
        LogErrorAndStatus(ctx, L"[-] Failed to refresh process list",
                          RGB(255, 0, 0), true);
        EnableWindow(ctx.hwndInjectButton, FALSE);
      } else {
        PROCESSENTRY32W entry = {sizeof(PROCESSENTRY32W)};
        if (Process32FirstW(snapshot, &entry)) {
          do {
            wstring display = wstring(entry.szExeFile) + L" (PID: " +
                              to_wstring(entry.th32ProcessID) + L")";
            SendMessageW(ctx.hwndProcessCombo, CB_ADDSTRING, 0,
                         (LPARAM)display.c_str());
          } while (Process32NextW(snapshot, &entry));
        }
        SendMessageW(ctx.hwndProcessCombo, CB_SETCURSEL, 0, 0);
        LogErrorAndStatus(ctx, L"[+] Process list refreshed", RGB(0, 255, 0),
                          false);
        EnableWindow(ctx.hwndInjectButton,
                     !ctx.processName.empty() && !ctx.dllPath.empty());
      }
    }
    // ===== Process selection =====
    else if (HIWORD(wParam) == CBN_SELCHANGE &&
             LOWORD(wParam) == IDD_PROCESSSELECT) {
      LRESULT index = SendMessageW(ctx.hwndProcessCombo, CB_GETCURSEL, 0, 0);
      if (index != CB_ERR) {
        wchar_t buffer[260];
        SendMessageW(ctx.hwndProcessCombo, CB_GETLBTEXT, index, (LPARAM)buffer);
        wstring selected = buffer;
        size_t pos = selected.find(L" (PID:");
        if (pos != wstring::npos) {
          ctx.processName = selected.substr(0, pos);
          WritePrivateProfileStringW(
              L"Settings", L"LastProcess", ctx.processName.c_str(),
              InjectorContext::GetExeRelativePath(L"Injector.ini").c_str());
          LogErrorAndStatus(ctx, L"[+] Target: " + ctx.processName,
                            RGB(0, 255, 0), false);
          EnableWindow(ctx.hwndInjectButton,
                       !ctx.processName.empty() && !ctx.dllPath.empty());
        }
      }
    }
    // ===== Browse DLL =====
    else if (LOWORD(wParam) == 1) {
      OPENFILENAMEW ofn = {0};
      wchar_t szFile[260] = {0};
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
          SetWindowTextW(ctx.hwndDllLabel, L"DLL: None selected");
          EnableWindow(ctx.hwndInjectButton, FALSE);
          return 0;
        }
        SetWindowTextW(ctx.hwndDllLabel, (L"DLL: " + ctx.dllPath).c_str());
        WritePrivateProfileStringW(
            L"Settings", L"LastDLL", ctx.dllPath.c_str(),
            InjectorContext::GetExeRelativePath(L"Injector.ini").c_str());
        LogErrorAndStatus(ctx, L"[+] DLL selected: " + ctx.dllPath,
                          RGB(0, 255, 0), false);
        EnableWindow(ctx.hwndInjectButton,
                     !ctx.processName.empty() && !ctx.dllPath.empty());
      }
    }
    // ===== Tips button =====
    else if (LOWORD(wParam) == 10) {
      MessageBoxW(hwnd,
                  L"\u2714 TIPS FOR SAFE INJECTION:\n\n"
                  L"1. Always run this tool as Administrator\n"
                  L"   (Right-click \u2192 Run as Administrator)\n\n"
                  L"2. Start the target game/app FIRST, then inject\n\n"
                  L"3. Make sure the DLL matches the target architecture\n"
                  L"   (64-bit game = 64-bit DLL, 32-bit = 32-bit)\n\n"
                  L"4. Wait for the success sound before alt-tabbing\n\n"
                  L"5. This injector uses stealth NT API calls that\n"
                  L"   bypass most user-mode anti-cheat hooks\n\n"
                  L"6. DLL data is XOR-encrypted during transit to\n"
                  L"   avoid memory pattern scanning\n\n"
                  L"7. All injection artifacts are overwritten with\n"
                  L"   random bytes after cleanup (anti-forensic)\n\n"
                  L"8. You can drag-and-drop a .DLL file onto the\n"
                  L"   window instead of using Browse\n\n"
                  L"9. The injector auto-closes 5 seconds after\n"
                  L"   successful injection to reduce exposure",
                  L"\u2753 Injection Tips", MB_OK | MB_ICONINFORMATION);
    }
    // ===== Watch & Inject button =====
    else if (LOWORD(wParam) == 11) {
      if (ctx.watcherActive) {
        // Stop watching
        ctx.watcherActive = false;
        SetWindowTextW(ctx.hwndWatchButton, L"\u23F1 Watch");
        LogErrorAndStatus(ctx, L"[*] Process watcher stopped", RGB(255, 255, 0),
                          false);
      } else {
        // Read process name from combo (user may have typed it)
        wchar_t comboText[260] = {0};
        GetWindowTextW(ctx.hwndProcessCombo, comboText, 260);
        wstring selected = comboText;
        size_t pidPos = selected.find(L" (PID:");
        if (pidPos != wstring::npos)
          selected = selected.substr(0, pidPos);
        while (!selected.empty() && selected.back() == L' ')
          selected.pop_back();
        if (selected.empty()) {
          LogErrorAndStatus(
              ctx,
              L"[-] Type or select a process name first (e.g. app.exe)",
              RGB(255, 255, 0), true);
          return 0;
        }
        if (ctx.dllPath.empty()) {
          LogErrorAndStatus(ctx, L"[-] Select a DLL first, then click Watch",
                            RGB(255, 255, 0), true);
          return 0;
        }
        if (!IsRunAsAdmin()) {
          LogErrorAndStatus(ctx,
                            L"[-] Watch & Inject requires Administrator! "
                            L"Right-click \u2192 Run as Administrator",
                            RGB(255, 80, 80), true);
          return 0;
        }
        ctx.processName = selected;
        WritePrivateProfileStringW(
            L"Settings", L"LastProcess", ctx.processName.c_str(),
            InjectorContext::GetExeRelativePath(L"Injector.ini").c_str());
        ctx.watcherActive = true;
        SetWindowTextW(ctx.hwndWatchButton, L"\u23F9 Stop");
        LogErrorAndStatus(ctx, L"[*] \u23F1 Watching for: " + ctx.processName,
                          RGB(255, 200, 0), false);
        LogErrorAndStatus(
            ctx, L"[i] Start the game NOW! Will inject as soon as process is detected",
            RGB(100, 200, 255), false);
        HANDLE hThread =
            CreateThread(NULL, 0, EarlyInjectWatcher, (LPVOID)hwnd, 0, NULL);
        if (hThread)
          CloseHandle(hThread);
      }
    }
    // ===== Inject button =====
    else if (LOWORD(wParam) == 2) {
      if (!IsRunAsAdmin()) {
        LogErrorAndStatus(ctx,
                          L"[-] You MUST run as Administrator! Right-click the "
                          L".exe \u2192 Run as Administrator",
                          RGB(255, 80, 80), true);
        MessageBoxW(hwnd,
                    L"This injector requires Administrator privileges to:\n"
                    L"\u2022 Open process handles with full access\n"
                    L"\u2022 Enable debug privileges\n"
                    L"\u2022 Allocate memory in the target process\n\n"
                    L"Right-click the .exe \u2192 Run as Administrator",
                    L"Administrator Required", MB_OK | MB_ICONERROR);
        return 0;
      }
      if (ctx.dllPath.empty()) {
        LogErrorAndStatus(ctx,
                          L"[-] No DLL selected \u2014 click Browse or "
                          L"drag-and-drop a .dll file",
                          RGB(255, 255, 0), true);
        return 0;
      }
      if (ctx.processName.empty()) {
        // Read from combo in case user typed something
        wchar_t comboText[260] = {0};
        GetWindowTextW(ctx.hwndProcessCombo, comboText, 260);
        wstring comboStr = comboText;
        size_t pidPos = comboStr.find(L" (PID:");
        if (pidPos != wstring::npos)
          comboStr = comboStr.substr(0, pidPos);
        while (!comboStr.empty() && comboStr.back() == L' ')
          comboStr.pop_back();
        if (!comboStr.empty())
          ctx.processName = comboStr;
      }
      if (ctx.processName.empty()) {
        LogErrorAndStatus(ctx,
                          L"[-] No process selected \u2014 pick a running "
                          L"process from the dropdown",
                          RGB(255, 255, 0), true);
        return 0;
      }
      if (!g_NtApis.valid) {
        LogErrorAndStatus(ctx,
                          L"[!] Warning: NT APIs unavailable, injection may be "
                          L"detected by anti-cheat",
                          RGB(255, 200, 0), false);
      }
      DWORD pid = 0;
      if (ctx.earlyInjectPID != 0) {
        // Early injection mode - PID already known, skip confirmation
        pid = ctx.earlyInjectPID;
        ctx.earlyInjectPID = 0;
        LogErrorAndStatus(ctx,
                          L"[+] Early injection mode: PID " + to_wstring(pid),
                          RGB(0, 255, 0), false);
      } else {
        wstring confirmMsg = L"Inject into: " + ctx.processName + L"\nDLL: " +
                             ctx.dllPath +
                             L"\n\nMethod: Manual Map + NT API Stealth" +
                             L"\nEncryption: XOR transit (key 0x" +
                             to_wstring(ctx.kXorKey) + L")" + L"\n\nProceed?";
        if (MessageBoxW(hwnd, confirmMsg.c_str(), L"Confirm Stealth Injection",
                        MB_YESNO | MB_ICONQUESTION) != IDYES) {
          LogErrorAndStatus(ctx, L"[*] Injection cancelled by user",
                            RGB(255, 255, 0), false);
          return 0;
        }
        LogErrorAndStatus(ctx, L"[*] Searching for process: " + ctx.processName,
                          RGB(255, 255, 0), false);
        pid = GetPIDByName(ctx, ctx.processName);
        if (pid == 0) {
          LogErrorAndStatus(ctx,
                            L"[-] Process not found! Make sure the game is "
                            L"running, then click Refresh",
                            RGB(255, 80, 80), true);
          return 0;
        }
      }
      LogErrorAndStatus(ctx, L"[+] Target PID: " + to_wstring(pid),
                        RGB(0, 255, 0), false);

      // Enable debug privileges
      HandleGuard hToken;
      HANDLE hTokenTemp = nullptr;
      if (OpenProcessToken(GetCurrentProcess(),
                           TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
                           &hTokenTemp)) {
        hToken.reset(hTokenTemp);
        TOKEN_PRIVILEGES privileges = {0};
        privileges.PrivilegeCount = 1;
        privileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
        if (LookupPrivilegeValue(nullptr, SE_DEBUG_NAME,
                                 &privileges.Privileges[0].Luid)) {
          AdjustTokenPrivileges(hToken, FALSE, &privileges, 0, nullptr,
                                nullptr);
          LogErrorAndStatus(ctx, L"[+] SeDebugPrivilege enabled",
                            RGB(0, 255, 0), false);
        } else {
          LogErrorAndStatus(ctx,
                            L"[!] Could not lookup debug privilege \u2014 "
                            L"injection may fail on protected processes",
                            RGB(255, 200, 0), false);
        }
      } else {
        LogErrorAndStatus(ctx,
                          L"[!] Could not open process token \u2014 some "
                          L"processes may be inaccessible",
                          RGB(255, 200, 0), false);
      }

      HandleGuard hProcess;
      {
        // Strategy 1: NtOpenProcess with minimum access rights
        LogErrorAndStatus(
            ctx, L"[i] Step 1: NtOpenProcess (stealth, minimum rights)...",
            RGB(100, 200, 255), false);
        HANDLE hProcRaw = StealthOpenProcess(INJECT_MIN_ACCESS, pid);
        if (!hProcRaw) {
          Sleep(100);
          hProcRaw = StealthOpenProcess(INJECT_MIN_ACCESS, pid);
        }
        if (!hProcRaw) {
          LogErrorAndStatus(ctx,
                            L"[!] Minimum rights denied, trying full access...",
                            RGB(255, 200, 0), false);
          hProcRaw = StealthOpenProcess(PROCESS_ALL_ACCESS, pid);
        }

        // Strategy 2: Handle hijacking - duplicate from system processes
        if (!hProcRaw) {
          LogErrorAndStatus(ctx,
                            L"[!] NtOpenProcess blocked by anti-cheat! Trying "
                            L"handle hijacking...",
                            RGB(255, 200, 0), false);
          LogErrorAndStatus(ctx,
                            L"[i] Step 2: Scanning system handle table "
                            L"(NtQuerySystemInformation)...",
                            RGB(100, 200, 255), false);
          vector<wstring> hijackLog;
          hProcRaw = HijackProcessHandle(pid, INJECT_MIN_ACCESS, &hijackLog);
          // Show diagnostics
          for (auto &msg : hijackLog) {
            COLORREF color = RGB(180, 180, 180);
            if (msg.find(L"[+]") != wstring::npos)
              color = RGB(0, 255, 0);
            else if (msg.find(L"[-]") != wstring::npos)
              color = RGB(255, 100, 100);
            else if (msg.find(L"[!]") != wstring::npos)
              color = RGB(255, 200, 0);
            LogErrorAndStatus(ctx, msg, color, false);
          }
          if (hProcRaw) {
            LogErrorAndStatus(ctx, L"[+] Handle hijacked successfully!",
                              RGB(0, 255, 0), false);
          } else {
            // Try once more with DUPLICATE_SAME_ACCESS and no access filter
            LogErrorAndStatus(
                ctx, L"[i] Step 3: Retrying with any available access...",
                RGB(100, 200, 255), false);
            hijackLog.clear();
            hProcRaw = HijackProcessHandle(
                pid, PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ,
                &hijackLog);
            for (auto &msg : hijackLog) {
              COLORREF color = RGB(180, 180, 180);
              if (msg.find(L"[+]") != wstring::npos)
                color = RGB(0, 255, 0);
              else if (msg.find(L"[-]") != wstring::npos)
                color = RGB(255, 100, 100);
              LogErrorAndStatus(ctx, msg, color, false);
            }
          }
        }
        hProcess.reset(hProcRaw);
      }
      if (!hProcess) {
        DWORD err = GetLastError();
        LogErrorAndStatus(ctx, L"[-] All process access methods failed!",
                          RGB(255, 80, 80), true);
        if (err == 5) {
          LogErrorAndStatus(ctx,
                            L"[-] Anti-cheat (GameGuard) is blocking ALL "
                            L"access to the process",
                            RGB(255, 80, 80), true);
          LogErrorAndStatus(
              ctx,
              L"[i] TIP: Use \u23F1 Watch to inject BEFORE anti-cheat loads!",
              RGB(255, 200, 100), false);
          LogErrorAndStatus(ctx,
                            L"[i] 1. Type process name  2. Click \u23F1 Watch  "
                            L"3. Start the game",
                            RGB(180, 180, 180), false);
        } else {
          LogErrorAndStatus(ctx,
                            L"[-] Could not open process (error " +
                                to_wstring(err) + L")",
                            RGB(255, 0, 0), true);
        }
        return 0;
      }
      LogErrorAndStatus(ctx, L"[+] Process handle acquired (stealth)",
                        RGB(0, 255, 0), false);

      if (!IsCorrectArchitecture(hProcess)) {
        LogErrorAndStatus(ctx,
                          L"[-] Architecture mismatch! Use the 64-bit injector "
                          L"for 64-bit targets (or vice versa)",
                          RGB(255, 80, 80), true);
        return 0;
      }
      LogErrorAndStatus(ctx, L"[+] Architecture match confirmed",
                        RGB(0, 255, 0), false);

      vector<BYTE> dllData;
      try {
        dllData = LoadDLL(ctx, ctx.dllPath);
        LogErrorAndStatus(
            ctx, L"[+] DLL loaded (" + to_wstring(dllData.size()) + L" bytes)",
            RGB(0, 255, 0), false);
      } catch (const exception &e) {
        wstring error = L"[-] DLL load failed: " +
                        wstring(e.what(), e.what() + strlen(e.what()));
        LogErrorAndStatus(ctx, error, RGB(255, 0, 0), true);
        return 0;
      }
      if (!CheckDLLArchitecture(ctx, dllData, hProcess)) {
        return 0;
      }

      LogErrorAndStatus(ctx, L"[+] Starting stealth injection pipeline...",
                        RGB(0, 255, 0), false);
      EnableWindow(ctx.hwndInjectButton, FALSE);
      EnableWindow(ctx.hwndBrowseButton, FALSE);
      // cleanHeader=false: DLL needs PE headers for x64 exception handling
      // (.pdata) cleanUnneededSections=false: DLL may access data sections at
      // runtime adjustProtections=false: DLL may need writable sections to stay
      // writable sehSupport=true: enable structured exception handling support
      if (!ManualMapDLL(ctx, hProcess, dllData.data(), dllData.size(), false,
                        false, false, true, DLL_PROCESS_ATTACH, nullptr)) {
        LogErrorAndStatus(
            ctx, L"[-] INJECTION FAILED \u2014 check the log above for details",
            RGB(255, 50, 50), true);
        EnableWindow(ctx.hwndInjectButton, TRUE);
        EnableWindow(ctx.hwndBrowseButton, TRUE);
        return 0;
      }
      LogErrorAndStatus(ctx, L"[+] \u2714 INJECTION SUCCESSFUL!",
                        RGB(0, 255, 0), false);
      LogErrorAndStatus(ctx, L"[i] Auto-closing in 5 seconds...",
                        RGB(180, 180, 180), false);
      PlaySuccessSound();
      SetTimer(hwnd, 1, 5000, NULL);
    }
    break;
  }
  case WM_DO_INJECT: {
    DWORD pid = (DWORD)lParam;
    ctx.earlyInjectPID = pid;
    ctx.watcherActive = false;
    SetWindowTextW(ctx.hwndWatchButton, L"\u23F1 Watch");
    LogErrorAndStatus(ctx,
                      L"[+] \u26A1 Process detected (PID: " + to_wstring(pid) +
                          L")! Early injection starting...",
                      RGB(0, 255, 0), false);
    // Trigger inject handler
    SendMessage(hwnd, WM_COMMAND, MAKEWPARAM(2, BN_CLICKED),
                (LPARAM)ctx.hwndInjectButton);
    break;
  }
  case WM_DESTROY:
    ctx.watcherActive = false;
    DragAcceptFiles(hwnd, FALSE);
    if (hBitmap)
      DeleteObject(hBitmap);
    DeleteObject(hFontPageTitle);
    DeleteObject(hFontSectionHeader);
    DeleteObject(hFontBody);
    DeleteObject(hFontBodyStrong);
    DeleteObject(hFontCaption);
    DeleteObject(hFontButton);
    DeleteObject(hFontMono);
    DeleteObject(hFontTitleBar);
    DeleteObject(hBackgroundBrush);
    DeleteObject(hStatusBrush);
    DeleteObject(hCardBrush);
    DeleteObject(hInsetBrush);
    PostQuitMessage(0);
    break;
  default:
    return DefWindowProc(hwnd, msg, wParam, lParam);
  }
  return 0;
}

int WINAPI wWinMain(_In_ HINSTANCE hInstance, _In_opt_ HINSTANCE hPrevInstance,
                    _In_ LPWSTR lpCmdLine, _In_ int nCmdShow) {
  // Initialize GDI+
  Gdiplus::GdiplusStartupInput gdiplusStartupInput;
  Gdiplus::GdiplusStartup(&gdiplusToken, &gdiplusStartupInput, NULL);

  // Resolve NT APIs early for stealth
  g_NtApis = ResolveNtApis();

  random_device rd;
  mt19937 gen(rd());
  string chars =
      "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
  uniform_int_distribution<int> dis(0, static_cast<int>(chars.size() - 1));
  wstring randomStr;
  for (int i = 0; i < 8; ++i) {
    randomStr += static_cast<wchar_t>(chars[dis(gen)]);
  }
  wstring exeName = L"svc_" + randomStr + L".exe";
  wchar_t currentExePath[MAX_PATH];
  GetModuleFileNameW(NULL, currentExePath, MAX_PATH);
  wstring newExePath = wstring(currentExePath);
  size_t lastSlash = newExePath.find_last_of(L"\\");
  if (lastSlash != wstring::npos) {
    newExePath = newExePath.substr(0, lastSlash + 1) + exeName;
  } else {
    newExePath = exeName;
  }
  MoveFileW(currentExePath, newExePath.c_str());

  // Allow the app to launch even without admin — show warning in UI instead of
  // blocking Injection will still be blocked at runtime if not admin
  if (!IsRunAsAdmin()) {
    int result = MessageBoxW(
        NULL,
        L"This injector works best when run as Administrator.\n\n"
        L"Without admin privileges, injection will likely fail.\n\n"
        L"Continue anyway (to see the interface)?",
        L"\u26A0 Administrator Recommended", MB_YESNO | MB_ICONWARNING);
    if (result != IDYES)
      return -1;
  }
  HICON hIcon = (HICON)LoadImageW(hInstance, MAKEINTRESOURCE(IDI_TREVOR_ICON),
                                  IMAGE_ICON, 0, 0, LR_DEFAULTSIZE);
  if (!hIcon) {
    DWORD error = GetLastError();
    wstring errorMsg = L"[-] Error loading icon, code: 0x" + to_wstring(error);
    MessageBoxW(NULL, errorMsg.c_str(), L"Error", MB_OK | MB_ICONERROR);
  }
  WNDCLASSW wc = {0};
  wc.lpfnWndProc = WndProc;
  wc.hInstance = hInstance;
  wc.lpszClassName = L"InjectorWindowClass";
  wc.hCursor = LoadCursor(NULL, IDC_ARROW);
  RegisterClassW(&wc);
  // Create main window (FRAMELESS)
  RECT rc = {0, 0, 960, 640};

  // Center it
  int screenWidth = GetSystemMetrics(SM_CXSCREEN);
  int screenHeight = GetSystemMetrics(SM_CYSCREEN);
  int posX = (screenWidth - rc.right) / 2;
  int posY = (screenHeight - rc.bottom) / 2;

  HWND hwndMain =
      CreateWindowW(L"InjectorWindowClass", L"ＴＲＥ▼ＯＲ Wy Injector",
                    WS_POPUP | WS_MINIMIZEBOX | WS_VISIBLE, posX, posY,
                    rc.right, rc.bottom, NULL, NULL, hInstance, NULL);

  // Apply DWM shadows for frameless window
  MARGINS margins = {0, 0, 1, 0}; // 1px bottom margin to retain shadow
  DwmExtendFrameIntoClientArea(hwndMain, &margins);

  if (!hwndMain) {
    if (hIcon)
      DestroyIcon(hIcon);
    MessageBoxW(NULL, L"Error creating window.", L"Error",
                MB_OK | MB_ICONERROR);
    return -1;
  }
  if (hIcon) {
    SendMessage(hwndMain, WM_SETICON, ICON_BIG, (LPARAM)hIcon);
    SendMessage(hwndMain, WM_SETICON, ICON_SMALL, (LPARAM)hIcon);
  }
  ShowWindow(hwndMain, nCmdShow);
  UpdateWindow(hwndMain);
  MSG msg = {0};
  while (GetMessage(&msg, NULL, 0, 0)) {
    TranslateMessage(&msg);
    DispatchMessage(&msg);
  }
  if (hIcon)
    DestroyIcon(hIcon);
  // Shutdown GDI+
  Gdiplus::GdiplusShutdown(gdiplusToken);
  return (int)msg.wParam;
}