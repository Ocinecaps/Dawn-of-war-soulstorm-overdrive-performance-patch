#include "../MasterLoggerDLL/include/Logger.h"
#include "DllUtils.h"

DllHandle loadDll(const std::wstring& path) {
    HMODULE handle = GetModuleHandleW(path.c_str());
    if (handle) return DllHandle(handle);
    DWORD dwAttrib = GetFileAttributesW(path.c_str());
    if (dwAttrib == INVALID_FILE_ATTRIBUTES || (dwAttrib & FILE_ATTRIBUTE_DIRECTORY)) {
        std::string pathStr(path.begin(), path.end());
        Log_Write(LOG_WARN, "DllUtils", "DLL not found: %s", pathStr.c_str());
        return DllHandle();
    }
    handle = LoadLibraryW(path.c_str());
    if (!handle) {
        const DWORD errorCode = GetLastError();
        std::string pathStr(path.begin(), path.end());
        Log_Write(LOG_ERROR, "DllUtils", "Failed to load DLL: %s with error code: %d", pathStr.c_str(), errorCode);
        return DllHandle();
    }
    std::string pathStr(path.begin(), path.end());
    Log_Write(LOG_INFO, "DllUtils", "Successfully loaded DLL: %s", pathStr.c_str());
    return DllHandle(handle);
}