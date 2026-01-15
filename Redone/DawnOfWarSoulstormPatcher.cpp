#ifndef DAWN_OF_WAR_SOULSTORM_PATCHER_H
#define DAWN_OF_WAR_SOULSTORM_PATCHER_H
#define _WIN32_WINNT 0x0600
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <DbgHelp.h>
#include <shlwapi.h>
#include <commdlg.h>
#include <shellapi.h>
#include <tchar.h>
#include <psapi.h>
#include <iostream>
#include <vector>
#include <string>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <cstdio>
#include <cstdlib>
#include <cstdarg>
#include <unordered_map>
#include "ZeroPEChecksum.h"
#include <cstddef>

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "comdlg32.lib")
#pragma comment(lib, "Dbghelp.lib")
#pragma comment(lib, "psapi.lib")
#pragma comment(linker, "/SECTION:.injsec,RWE")
#endif

#include "../MasterLoggerDLL/include/Logger.h"
#include "DllUtils.h"

// Constants for Dawn of War memory patching
#define DAWN_OF_WAR_PATCH_SIZE 2

#pragma section(".injsec", read, execute, shared)
__declspec(allocate(".injsec")) char dummyInjSec = 1;  // Instead of 0

// Dawn of War memory patch signatures
static const BYTE DAWN_OF_WAR_PATCH_SIGNATURE[2] = { 0x75, 0x40 }; // JNZ instruction to bypass
static const BYTE DAWN_OF_WAR_PATCH_BYTES[2] = { 0x90, 0x90 };     // NOP NOP instructions

// Dawn of War patching function declarations
DWORD_PTR FindDawnOfWarPatchAddress(const BYTE* signature, size_t size);
BYTE* FindMemoryPattern(BYTE* base, DWORD size, const BYTE* pattern, const char* mask);

void ApplyDawnOfWarMultiplayerLobbyPatch(HANDLE gameProcess, LPVOID patchAddress) {
    DWORD originalMemoryProtection;
    MEMORY_BASIC_INFORMATION memoryInfo;
    if (VirtualQueryEx(gameProcess, patchAddress, &memoryInfo, sizeof(memoryInfo))) {
        Log_Write(LOG_INFO, "ApplyDawnOfWarMultiplayerLobbyPatch", "Current Memory Protection: %lu", memoryInfo.Protect);
    }
    else {
        Log_Write(LOG_ERROR, "ApplyDawnOfWarMultiplayerLobbyPatch", "Failed to query memory protection.");
        return;
    }
    if (VirtualProtectEx(gameProcess, patchAddress, DAWN_OF_WAR_PATCH_SIZE, PAGE_EXECUTE_READWRITE, &originalMemoryProtection)) {
        SIZE_T bytesWrittenCount;
        if (WriteProcessMemory(gameProcess, patchAddress, DAWN_OF_WAR_PATCH_BYTES, DAWN_OF_WAR_PATCH_SIZE, &bytesWrittenCount)) {
            if (!VirtualProtectEx(gameProcess, patchAddress, DAWN_OF_WAR_PATCH_SIZE, originalMemoryProtection, &originalMemoryProtection)) {
                Log_Write(LOG_WARN, "ApplyDawnOfWarMultiplayerLobbyPatch", "Failed to restore original memory protection.");
            }
            else {
                MessageBoxA(nullptr, "[+] Successfully applied Dawn of War multiplayer lobby patch!", "Dawn of War Patcher", MB_OK);
                return;
            }
        }
        else {
            DWORD errorCode = GetLastError();
            Log_Write(LOG_ERROR, "ApplyDawnOfWarMultiplayerLobbyPatch", "Failed to write memory: %lu", errorCode);
        }
    }
    else {
        DWORD errorCode = GetLastError();
        Log_Write(LOG_ERROR, "ApplyDawnOfWarMultiplayerLobbyPatch", "Failed to change memory protection: %lu", errorCode);
    }
}

DWORD_PTR FindDawnOfWarPatchAddress(const BYTE* signature, size_t signatureSize) {
    SYSTEM_INFO systemInfo;
    GetSystemInfo(&systemInfo);
    DWORD_PTR baseAddress = (DWORD_PTR)systemInfo.lpMinimumApplicationAddress;
    DWORD_PTR maxAddress = (DWORD_PTR)systemInfo.lpMaximumApplicationAddress;
    MEMORY_BASIC_INFORMATION memoryBasicInfo;
    BYTE* searchBuffer = new BYTE[signatureSize];
    while (baseAddress < maxAddress) {
        if (VirtualQuery((LPCVOID)baseAddress, &memoryBasicInfo, sizeof(memoryBasicInfo)) == 0) {
            baseAddress += 0x1000;
            continue;
        }
        if (memoryBasicInfo.State == MEM_COMMIT && (memoryBasicInfo.Protect & (PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_READ))) {
            DWORD_PTR regionEnd = (DWORD_PTR)memoryBasicInfo.BaseAddress + memoryBasicInfo.RegionSize - signatureSize;
            for (DWORD_PTR addr = (DWORD_PTR)memoryBasicInfo.BaseAddress; addr < regionEnd; addr++) {
                SIZE_T bytesRead = 0;
                BOOL result = FALSE;
                __try {
                    result = ReadProcessMemory(GetCurrentProcess(), (LPCVOID)addr, searchBuffer, signatureSize, &bytesRead);
                }
                __except (EXCEPTION_EXECUTE_HANDLER) {
                    result = FALSE;
                }
                if (result && bytesRead == signatureSize && memcmp(searchBuffer, signature, signatureSize) == 0) {
                    delete[] searchBuffer;
                    return addr;
                }
            }
        }
        baseAddress += memoryBasicInfo.RegionSize;
    }
    delete[] searchBuffer;
    return 0;
}

BYTE* FindPattern(BYTE* base, DWORD size, const BYTE* pattern, const char* mask) {
    DWORD patternLength = static_cast<DWORD>(strlen(mask));
    for (DWORD i = 0; i <= size - patternLength; i++) {
        bool found = true;
        for (DWORD j = 0; j < patternLength; j++) {
            if (mask[j] == 'x' && pattern[j] != *(base + i + j)) {
                found = false;
                break;
            }
        }
        if (found) return base + i;
    }
    return nullptr;
}

bool IsRunningAsAdmin() {
    BOOL isAdmin = FALSE;
    PSID adminGroup = nullptr;
    SID_IDENTIFIER_AUTHORITY ntAuthority = SECURITY_NT_AUTHORITY;
    if (AllocateAndInitializeSid(&ntAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &adminGroup)) {
        CheckTokenMembership(nullptr, adminGroup, &isAdmin);
        FreeSid(adminGroup);
    }
    return (isAdmin != FALSE);
}

void RelaunchAsAdmin() {
    TCHAR szPath[MAX_PATH];
    if (GetModuleFileName(nullptr, szPath, MAX_PATH)) {
        SHELLEXECUTEINFO sei = { sizeof(sei) };
        sei.lpVerb = _T("runas");
        sei.lpFile = szPath;
        sei.hwnd = nullptr;
        sei.nShow = SW_NORMAL;
        if (!ShellExecuteEx(&sei)) {
            MessageBox(nullptr, _T("Must be run as administrator."), _T("Error"), MB_ICONERROR);
        }
        ExitProcess(0);
    }
}

static std::string SelectSoulstormExecutable() {
    OPENFILENAMEA ofn = {};
    char fileName[MAX_PATH] = "";
    ofn.lStructSize = sizeof(ofn);
    ofn.lpstrFile = fileName;
    ofn.nMaxFile = MAX_PATH;
    ofn.lpstrFilter = "Exe Files\0*.exe\0All Files\0*.*\0";
    ofn.lpstrTitle = "Select Dawn of War Soulstorm.exe";
    ofn.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST;
    if (GetOpenFileNameA(&ofn)) return std::string(fileName);
    return {};
}

bool EnableLargeAddressAware(const std::string& executablePath) {
    Log_Write(LOG_INFO, "EnableLargeAddressAware", "Opening file %s", executablePath.c_str());
    std::fstream executableFile(executablePath.c_str(), std::ios::in | std::ios::out | std::ios::binary);
    if (!executableFile.is_open()) {
        Log_Write(LOG_ERROR, "EnableLargeAddressAware", "Failed to open file.");
        return false;
    }
    IMAGE_DOS_HEADER dosHeader = {};
    executableFile.read(reinterpret_cast<char*>(&dosHeader), sizeof(dosHeader));
    if (dosHeader.e_magic != IMAGE_DOS_SIGNATURE) {
        Log_Write(LOG_ERROR, "EnableLargeAddressAware", "Invalid DOS signature.");
        executableFile.close();
        return false;
    }
    executableFile.seekg(dosHeader.e_lfanew, std::ios::beg);
    IMAGE_NT_HEADERS32 ntHeaders = {};
    executableFile.read(reinterpret_cast<char*>(&ntHeaders), sizeof(ntHeaders));
    if (ntHeaders.Signature != IMAGE_NT_SIGNATURE || ntHeaders.OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
        Log_Write(LOG_ERROR, "EnableLargeAddressAware", "Invalid NT header.");
        executableFile.close();
        return false;
    }
    ntHeaders.FileHeader.Characteristics |= IMAGE_FILE_LARGE_ADDRESS_AWARE;
    executableFile.clear();
    executableFile.seekp(dosHeader.e_lfanew, std::ios::beg);
    executableFile.write(reinterpret_cast<const char*>(&ntHeaders), sizeof(ntHeaders));
    executableFile.close();
    Log_Write(LOG_INFO, "EnableLargeAddressAware", "Large Address Aware enabled successfully.");
    return true;
}

DWORD AlignValue(DWORD value, DWORD alignment) {
    return (value + alignment - 1) & ~(alignment - 1);
}

bool InjectDawnOfWarInjectionSection(const std::string& executablePath) {
    Log_Write(LOG_INFO, "InjectDawnOfWarInjectionSection", "Opening file %s", executablePath.c_str());
    std::fstream executableFile(executablePath, std::ios::in | std::ios::out | std::ios::binary);
    if (!executableFile.is_open()) {
        Log_Write(LOG_ERROR, "InjectDawnOfWarInjectionSection", "Failed to open file.");
        return false;
    }
    IMAGE_DOS_HEADER dosHeader = {};
    executableFile.read(reinterpret_cast<char*>(&dosHeader), sizeof(dosHeader));
    if (dosHeader.e_magic != IMAGE_DOS_SIGNATURE) {
        Log_Write(LOG_ERROR, "InjectDawnOfWarInjectionSection", "Invalid DOS signature.");
        executableFile.close();
        return false;
    }
    executableFile.seekg(dosHeader.e_lfanew, std::ios::beg);
    IMAGE_NT_HEADERS32 ntHeaders = {};
    executableFile.read(reinterpret_cast<char*>(&ntHeaders), sizeof(ntHeaders));
    if (ntHeaders.Signature != IMAGE_NT_SIGNATURE || ntHeaders.OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
        Log_Write(LOG_ERROR, "InjectDawnOfWarInjectionSection", "Invalid NT header.");
        executableFile.close();
        return false;
    }
    WORD sectionCount = ntHeaders.FileHeader.NumberOfSections;
    Log_Write(LOG_INFO, "InjectDawnOfWarInjectionSection", "Section count: %d", sectionCount);
    std::vector<IMAGE_SECTION_HEADER> sections(sectionCount);
    executableFile.read(reinterpret_cast<char*>(sections.data()), sectionCount * sizeof(IMAGE_SECTION_HEADER));
    DWORD fileAlignment = ntHeaders.OptionalHeader.FileAlignment;
    DWORD sectionAlignment = ntHeaders.OptionalHeader.SectionAlignment;
    IMAGE_SECTION_HEADER& lastSection = sections.back();
    DWORD newSectionRawOffset = AlignValue(lastSection.PointerToRawData + lastSection.SizeOfRawData, fileAlignment);
    DWORD newSectionVirtualAddress = AlignValue(lastSection.VirtualAddress + lastSection.Misc.VirtualSize, sectionAlignment);
    IMAGE_SECTION_HEADER injectionSection = {};
    memcpy(injectionSection.Name, ".injsec", 7);
    injectionSection.VirtualAddress = newSectionVirtualAddress;
    injectionSection.PointerToRawData = newSectionRawOffset;
    injectionSection.Misc.VirtualSize = 0x3000;
    injectionSection.SizeOfRawData = AlignValue(injectionSection.Misc.VirtualSize, fileAlignment);
    injectionSection.Characteristics = IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_CNT_CODE;
    ntHeaders.FileHeader.NumberOfSections++;
    ntHeaders.OptionalHeader.SizeOfImage = newSectionVirtualAddress + AlignValue(injectionSection.Misc.VirtualSize, sectionAlignment);
    executableFile.clear();
    executableFile.seekp(dosHeader.e_lfanew, std::ios::beg);
    executableFile.write(reinterpret_cast<const char*>(&ntHeaders), sizeof(ntHeaders));
    executableFile.write(reinterpret_cast<const char*>(sections.data()), sectionCount * sizeof(IMAGE_SECTION_HEADER));
    executableFile.write(reinterpret_cast<const char*>(&injectionSection), sizeof(injectionSection));
    executableFile.seekp(injectionSection.PointerToRawData, std::ios::beg);
    std::vector<char> blankSectionData(injectionSection.SizeOfRawData, 0);
    executableFile.write(blankSectionData.data(), blankSectionData.size());
    executableFile.close();
    Log_Write(LOG_INFO, "InjectDawnOfWarInjectionSection", "Injection section added successfully.");
    return true;
}

// Dawn of War runtime patch execution
void ExecuteDawnOfWarRuntimePatch() {
    Log_Write(LOG_INFO, "ExecuteDawnOfWarRuntimePatch", "Executing in-game modifications...");
    HANDLE currentProcess = GetCurrentProcess();
    DWORD_PTR patchAddress = FindDawnOfWarPatchAddress(DAWN_OF_WAR_PATCH_SIGNATURE, DAWN_OF_WAR_PATCH_SIZE);
    if (!patchAddress) {
        Log_Write(LOG_ERROR, "ExecuteDawnOfWarRuntimePatch", "Could not find patch address!");
        MessageBoxA(nullptr, "[-] Could not find Dawn of War patch address!", "Dawn of War Patcher Error", MB_ICONERROR);
        return;
    }
    ApplyDawnOfWarMultiplayerLobbyPatch(currentProcess, (LPVOID)patchAddress);
}

bool ApplyDawnOfWarSoulstormPatches(const std::string& soulstormExecutablePath) {
    Log_Write(LOG_INFO, "ApplyDawnOfWarSoulstormPatches", "Starting patch for %s", soulstormExecutablePath.c_str());
    if (!EnableLargeAddressAware(soulstormExecutablePath)) {
        Log_Write(LOG_ERROR, "ApplyDawnOfWarSoulstormPatches", "EnableLargeAddressAware failed.");
        return false;
    }
    Log_Write(LOG_INFO, "ApplyDawnOfWarSoulstormPatches", "[OK] Large Address Aware enabled successfully.");
    if (!InjectDawnOfWarInjectionSection(soulstormExecutablePath)) {
        Log_Write(LOG_ERROR, "ApplyDawnOfWarSoulstormPatches", "InjectDawnOfWarInjectionSection failed.");
        return false;
    }
    Log_Write(LOG_INFO, "ApplyDawnOfWarSoulstormPatches", "[OK] Injection section added successfully.");
    Log_Write(LOG_INFO, "ApplyDawnOfWarSoulstormPatches", "[->] Executing runtime patch modifications...");
    ExecuteDawnOfWarRuntimePatch();
    Log_Write(LOG_INFO, "ApplyDawnOfWarSoulstormPatches", "[OK] Runtime patch executed successfully.");
    Log_Write(LOG_INFO, "ApplyDawnOfWarSoulstormPatches", "All Dawn of War patch steps completed successfully.");
    return true;
}

#pragma warning(push)
#pragma warning(disable: 4244) // Suppress conversion from 'const wchar_t' to 'char' warning
std::wstring GetDawnOfWarSoulstormInstallationPath() {
    HKEY hKey;
    const wchar_t* regPath = L"SOFTWARE\\WOW6432Node\\THQ\\Dawn of War - Soulstorm";
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, regPath, 0, KEY_READ, &hKey) != ERROR_SUCCESS) {
        throw std::runtime_error("Failed to open registry key for Dawn of War Soulstorm");
    }
    wchar_t buffer[MAX_PATH];
    DWORD bufferSize = sizeof(buffer);
    DWORD type = REG_SZ;
    if (RegQueryValueExW(hKey, L"InstallLocation", 0, &type, (LPBYTE)buffer, &bufferSize) != ERROR_SUCCESS) {
        RegCloseKey(hKey);
        throw std::runtime_error("Failed to read Dawn of War Soulstorm InstallLocation from registry");
    }
    RegCloseKey(hKey);
    std::wstring path = buffer;
    if (!path.empty() && path.back() != L'\\') {
        path += L'\\';
    }
    if (GetFileAttributesW(path.c_str()) == INVALID_FILE_ATTRIBUTES) {
        throw std::runtime_error("Dawn of War Soulstorm installation directory not found");
    }
    return path;
#pragma warning(pop)
}

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
    Log_Initialize(nullptr);
    Log_Write(LOG_INFO, "WinMain", "WinMain started.");
    if (!IsRunningAsAdmin()) {
        Log_Write(LOG_ERROR, "WinMain", "Not running as admin. Relaunching...");
        RelaunchAsAdmin();
        return 0;
    }
    std::string soulstormExecutable = SelectSoulstormExecutable();
    if (soulstormExecutable.empty()) {
        Log_Write(LOG_ERROR, "WinMain", "No Dawn of War Soulstorm EXE selected by user.");
        MessageBoxA(nullptr, "No Dawn of War Soulstorm EXE selected.", "Error", MB_ICONERROR);
        return 1;
    }
    Log_Write(LOG_INFO, "WinMain", "User selected Dawn of War Soulstorm EXE: %s", soulstormExecutable.c_str());
    try {
        Log_Write(LOG_INFO, "WinMain", "Getting Dawn of War Soulstorm installation path from registry...");
        std::wstring soulstormInstallationPath;
        try {
            soulstormInstallationPath = GetDawnOfWarSoulstormInstallationPath();
            Log_Write(LOG_INFO, "WinMain", "Found Dawn of War Soulstorm installation path in registry");
        }
        catch (const std::exception& e) {
            Log_Write(LOG_ERROR, "WinMain", "Failed to get Dawn of War Soulstorm path: %s", e.what());
            MessageBoxA(nullptr, "Failed to locate Dawn of War Soulstorm installation in registry.", "Error", MB_ICONERROR);
            return 1;
        }
        const std::wstring memoryPoolDllPath = soulstormInstallationPath + L"DawnOfWarMemoryPoolDLL.dll";
        if (GetFileAttributesW(memoryPoolDllPath.c_str()) == INVALID_FILE_ATTRIBUTES) {
            Log_Write(LOG_ERROR, "WinMain", "DawnOfWarMemoryPoolDLL.dll not found in Soulstorm directory");
            MessageBoxA(nullptr, "DawnOfWarMemoryPoolDLL.dll not found in Dawn of War Soulstorm directory.", "Error", MB_ICONERROR);
            return 1;
        }
        Log_Write(LOG_INFO, "WinMain", "Loading Dawn of War Memory Pool DLL...");
        DllHandle memoryPoolDll = loadDll(memoryPoolDllPath);
        if (!memoryPoolDll.get()) {
            Log_Write(LOG_ERROR, "WinMain", "Failed to load Dawn of War Memory Pool DLL");
            MessageBoxA(nullptr, "Failed to load Dawn of War Memory Pool DLL.", "Error", MB_ICONERROR);
            return 1;
        }
        if (!ApplyDawnOfWarSoulstormPatches(soulstormExecutable)) {
            Log_Write(LOG_ERROR, "WinMain", "ApplyDawnOfWarSoulstormPatches failed.");
            MessageBoxA(nullptr, "Dawn of War Soulstorm patch failed – multiplayer net-lobby might remain hidden.", "Dawn of War Patch Error", MB_ICONERROR);
            return 1;
        }
        MessageBoxA(nullptr,
            "Dawn of War Soulstorm Performance Patch Applied:\n\n"
            " - Large Address Aware enabled\n"
            " - Injection section (.injsec) added\n"
            " - Multiplayer lobby JNZ instruction patched\n"
            " - Dawn of War Memory Pool DLL injected\n\n"
            "Performance optimization complete!",
            "Dawn of War Soulstorm Patcher", MB_OK);
        Log_Write(LOG_INFO, "WinMain", "All done.");
    }
    catch (const std::exception& e) {
        Log_Write(LOG_ERROR, "WinMain", "Exception caught: %s", e.what());
        MessageBoxA(nullptr, e.what(), "Error", MB_ICONERROR);
        return 1;
    }
    catch (...) {
        Log_Write(LOG_ERROR, "WinMain", "Unknown exception caught.");
        MessageBoxA(nullptr, "Unknown error occurred.", "Error", MB_ICONERROR);
        return 1;
    }
    Log_Shutdown();
    return 0;
}