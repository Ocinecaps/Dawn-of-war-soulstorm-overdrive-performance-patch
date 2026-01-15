#include "include/Logger.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <process.h>
#include <io.h>
#include <share.h>
#include <dbghelp.h>
#include <shlobj.h>
#include <psapi.h>
#include <signal.h>

#pragma comment(lib, "dbghelp.lib")
#pragma comment(lib, "psapi.lib")

// Global variable definitions
DawnOfWarLoggerState g_dawnOfWarLogger = {0};
DawnOfWarModuleLevel* g_dawnOfWarModuleLevels = NULL;
CRITICAL_SECTION g_dawnOfWarModuleLevelsCs;

// Forward declarations
static DWORD WINAPI WorkerThread(LPVOID param);
static void ProcessLogEntry(const DawnOfWarLogEntry* entry);
static void WriteToFile(const DawnOfWarLogEntry* entry);
static void WriteToConsole(const DawnOfWarLogEntry* entry);
static void WriteToMemory(const DawnOfWarLogEntry* entry);
static void WriteToNetwork(const DawnOfWarLogEntry* entry);
static void LoadConfig(const char* configPath);
static void SaveConfig(const char* configPath);
static BOOL ShouldLog(DawnOfWarLogLevel level, const char* module);
static DawnOfWarLogLevel GetModuleLevel(const char* module);
static void RotateLogFile(void);
static void FormatLogMessage(const DawnOfWarLogEntry* entry, char* buffer, size_t bufferSize);
static const char* GetLevelString(DawnOfWarLogLevel level);
static WORD GetConsoleColor(DawnOfWarLogLevel level);
static void CaptureStackTrace(char* buffer, size_t bufferSize);
static void ExceptionHandler(EXCEPTION_POINTERS* exceptionInfo);
static void SignalHandler(int signal);
static void InitializeConsole(void);
static void CleanupConsole(void);

// DLL entry point
BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH:
        DisableThreadLibraryCalls(hModule);
        break;
    case DLL_PROCESS_DETACH:
        DawnOfWarLog_Shutdown();
        break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
        break;
    }
    return TRUE;
}

// Initialize Dawn of War logger system
void DawnOfWarLog_Initialize(const char* configPath) {
    if (g_dawnOfWarLogger.initialized) {
        return;
    }

    // Initialize critical sections
    InitializeCriticalSection(&g_dawnOfWarLogger.statsCs);
    InitializeCriticalSection(&g_dawnOfWarModuleLevelsCs);
    InitializeCriticalSection(&g_dawnOfWarLogger.ringBuffer.cs);

    // Set default configuration
    g_dawnOfWarLogger.config.globalLevel = DAWN_OF_WAR_LOG_INFO;
    g_dawnOfWarLogger.config.outputs = DAWN_OF_WAR_OUTPUT_CONSOLE | DAWN_OF_WAR_OUTPUT_FILE;
    strcpy_s(g_dawnOfWarLogger.config.logPath, sizeof(g_dawnOfWarLogger.config.logPath), "logs");
    g_dawnOfWarLogger.config.maxFileSizeMB = 100;
    g_dawnOfWarLogger.config.rotationCount = 5;
    g_dawnOfWarLogger.config.enableNetwork = FALSE;
    g_dawnOfWarLogger.config.bufferSize = 1024;
    g_dawnOfWarLogger.config.enableColors = TRUE;
    g_dawnOfWarLogger.config.enableStackTrace = TRUE;

    // Load configuration
    if (configPath) {
        LoadConfig(configPath);
    } else {
        LoadConfig("logger.ini");
    }

    // Initialize ring buffer
    g_dawnOfWarLogger.ringBuffer.capacity = g_dawnOfWarLogger.config.bufferSize;
    g_dawnOfWarLogger.ringBuffer.entries = (DawnOfWarLogEntry*)malloc(g_dawnOfWarLogger.ringBuffer.capacity * sizeof(DawnOfWarLogEntry));
    g_dawnOfWarLogger.ringBuffer.head = 0;
    g_dawnOfWarLogger.ringBuffer.tail = 0;
    g_dawnOfWarLogger.ringBuffer.count = 0;

    // Create log directory if it doesn't exist
    CreateDirectoryA(g_dawnOfWarLogger.config.logPath, NULL);

    // Open log file
    char logFileName[MAX_PATH];
    SYSTEMTIME st;
    GetLocalTime(&st);
    sprintf_s(logFileName, sizeof(logFileName), "%s\\DawnOfWar_%04d%02d%02d_%02d%02d%02d.log",
        g_dawnOfWarLogger.config.logPath, st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
    
    g_dawnOfWarLogger.logFile = CreateFileA(logFileName, GENERIC_WRITE, FILE_SHARE_READ,
        NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

    // Initialize console if enabled
    if (g_dawnOfWarLogger.config.outputs & DAWN_OF_WAR_OUTPUT_CONSOLE) {
        InitializeConsole();
    }

    // Create synchronization objects
    g_dawnOfWarLogger.shutdownEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
    g_dawnOfWarLogger.configChangeEvent = CreateEvent(NULL, FALSE, FALSE, NULL);

    // Start worker thread
    g_dawnOfWarLogger.workerThread = (HANDLE)_beginthreadex(NULL, 0, (unsigned int (__stdcall *)(void *))WorkerThread, NULL, 0, NULL);

    // Set up exception handlers
    if (g_dawnOfWarLogger.config.enableStackTrace) {
        DawnOfWarLog_SetCrashHandler();
    }

    // Initialize performance counters
    QueryPerformanceFrequency(&g_dawnOfWarLogger.performanceFrequency);
    QueryPerformanceCounter(&g_dawnOfWarLogger.lastStatsTime);

    g_dawnOfWarLogger.initialized = TRUE;

    // Log initialization
    DawnOfWarLog_Write(DAWN_OF_WAR_LOG_INFO, "DawnOfWarLogger", "Dawn of War Logger initialized successfully");
}

// Shutdown Dawn of War logger system
void DawnOfWarLog_Shutdown(void) {
    if (!g_dawnOfWarLogger.initialized) {
        return;
    }

    DawnOfWarLog_Write(DAWN_OF_WAR_LOG_INFO, "DawnOfWarLogger", "Shutting down Dawn of War Logger");

    // Signal shutdown
    SetEvent(g_dawnOfWarLogger.shutdownEvent);

    // Wait for worker thread to finish
    if (g_dawnOfWarLogger.workerThread) {
        WaitForSingleObject(g_dawnOfWarLogger.workerThread, 5000);
        CloseHandle(g_dawnOfWarLogger.workerThread);
        g_dawnOfWarLogger.workerThread = NULL;
    }

    // Flush remaining entries
    DawnOfWarLog_Flush();

    // Close log file
    if (g_dawnOfWarLogger.logFile != INVALID_HANDLE_VALUE) {
        CloseHandle(g_dawnOfWarLogger.logFile);
        g_dawnOfWarLogger.logFile = INVALID_HANDLE_VALUE;
    }

    // Cleanup console
    CleanupConsole();

    // Free ring buffer
    if (g_dawnOfWarLogger.ringBuffer.entries) {
        free(g_dawnOfWarLogger.ringBuffer.entries);
        g_dawnOfWarLogger.ringBuffer.entries = NULL;
    }

    // Cleanup module levels
    EnterCriticalSection(&g_dawnOfWarModuleLevelsCs);
    DawnOfWarModuleLevel* current = g_dawnOfWarModuleLevels;
    while (current) {
        DawnOfWarModuleLevel* next = current->next;
        free(current);
        current = next;
    }
    g_dawnOfWarModuleLevels = NULL;
    LeaveCriticalSection(&g_dawnOfWarModuleLevelsCs);

    // Close handles
    if (g_dawnOfWarLogger.shutdownEvent) {
        CloseHandle(g_dawnOfWarLogger.shutdownEvent);
        g_dawnOfWarLogger.shutdownEvent = NULL;
    }
    if (g_dawnOfWarLogger.configChangeEvent) {
        CloseHandle(g_dawnOfWarLogger.configChangeEvent);
        g_dawnOfWarLogger.configChangeEvent = NULL;
    }

    // Delete critical sections
    DeleteCriticalSection(&g_dawnOfWarLogger.statsCs);
    DeleteCriticalSection(&g_dawnOfWarModuleLevelsCs);
    DeleteCriticalSection(&g_dawnOfWarLogger.ringBuffer.cs);

    g_dawnOfWarLogger.initialized = FALSE;
}

// Set global Dawn of War log level
void DawnOfWarLog_SetLevel(DawnOfWarLogLevel level) {
    if (!g_dawnOfWarLogger.initialized) return;
    
    g_dawnOfWarLogger.config.globalLevel = level;
    DawnOfWarLog_Write(DAWN_OF_WAR_LOG_INFO, "DawnOfWarLogger", "Global Dawn of War log level set to %s", GetLevelString(level));
}

// Set module-specific Dawn of War log level
void DawnOfWarLog_SetModuleLevel(const char* module, DawnOfWarLogLevel level) {
    if (!g_dawnOfWarLogger.initialized || !module) return;

    EnterCriticalSection(&g_dawnOfWarModuleLevelsCs);
    
    // Check if module already exists
    DawnOfWarModuleLevel* current = g_dawnOfWarModuleLevels;
    while (current) {
        if (strcmp(current->module, module) == 0) {
            current->level = level;
            LeaveCriticalSection(&g_dawnOfWarModuleLevelsCs);
            DawnOfWarLog_Write(DAWN_OF_WAR_LOG_DEBUG, "DawnOfWarLogger", "Dawn of War module '%s' level updated to %s", module, GetLevelString(level));
            return;
        }
        current = current->next;
    }

    // Add new module level
    DawnOfWarModuleLevel* newLevel = (DawnOfWarModuleLevel*)malloc(sizeof(DawnOfWarModuleLevel));
    strcpy_s(newLevel->module, sizeof(newLevel->module), module);
    newLevel->level = level;
    newLevel->next = g_dawnOfWarModuleLevels;
    g_dawnOfWarModuleLevels = newLevel;
    
    LeaveCriticalSection(&g_dawnOfWarModuleLevelsCs);
    
    DawnOfWarLog_Write(DAWN_OF_WAR_LOG_DEBUG, "DawnOfWarLogger", "Dawn of War module '%s' level set to %s", module, GetLevelString(level));
}

// Main Dawn of War logging function
void DawnOfWarLog_Write(DawnOfWarLogLevel level, const char* module, const char* format, ...) {
    if (!g_dawnOfWarLogger.initialized || !module || !format) return;
    
    if (!ShouldLog(level, module)) return;

    va_list args;
    va_start(args, format);
    DawnOfWarLog_WriteVA(level, module, format, args);
    va_end(args);
}

// Write Dawn of War log entry with va_list
void DawnOfWarLog_WriteVA(DawnOfWarLogLevel level, const char* module, const char* format, va_list args) {
    if (!g_dawnOfWarLogger.initialized || !module || !format) return;
    
    if (!ShouldLog(level, module)) return;

    DawnOfWarLogEntry entry = {0};
    entry.timestamp = GetTickCount();
    entry.threadId = GetCurrentThreadId();
    entry.level = level;
    strncpy_s(entry.module, sizeof(entry.module), module, _TRUNCATE);

    // Format message
    vsnprintf_s(entry.message, sizeof(entry.message), _TRUNCATE, format, args);
    entry.messageLength = strlen(entry.message);

    // Add to ring buffer
    EnterCriticalSection(&g_dawnOfWarLogger.ringBuffer.cs);
    
    DWORD nextHead = (g_dawnOfWarLogger.ringBuffer.head + 1) % g_dawnOfWarLogger.ringBuffer.capacity;
    
    if (nextHead == g_dawnOfWarLogger.ringBuffer.tail) {
        // Buffer full, overwrite oldest
        g_dawnOfWarLogger.ringBuffer.tail = (g_dawnOfWarLogger.ringBuffer.tail + 1) % g_dawnOfWarLogger.ringBuffer.capacity;
    } else {
        g_dawnOfWarLogger.ringBuffer.count++;
    }
    
    g_dawnOfWarLogger.ringBuffer.entries[g_dawnOfWarLogger.ringBuffer.head] = entry;
    g_dawnOfWarLogger.ringBuffer.head = nextHead;
    
    LeaveCriticalSection(&g_dawnOfWarLogger.ringBuffer.cs);
}

// Write Dawn of War hex dump
void DawnOfWarLog_HexDump(DawnOfWarLogLevel level, const char* module, const void* data, size_t size) {
    if (!g_dawnOfWarLogger.initialized || !module || !data || size == 0) return;
    
    if (!ShouldLog(level, module)) return;

    const BYTE* bytes = (const BYTE*)data;
    char hexLine[128];
    
    for (size_t i = 0; i < size; i += 16) {
        char* ptr = hexLine;
        ptr += sprintf_s(ptr, sizeof(hexLine) - (ptr - hexLine), "%04X: ", (DWORD)i);
        
        for (size_t j = 0; j < 16; j++) {
            if (i + j < size) {
                ptr += sprintf_s(ptr, sizeof(hexLine) - (ptr - hexLine), "%02X ", bytes[i + j]);
            } else {
                ptr += sprintf_s(ptr, sizeof(hexLine) - (ptr - hexLine), "   ");
            }
        }
        
        ptr += sprintf_s(ptr, sizeof(hexLine) - (ptr - hexLine), " ");
        
        for (size_t j = 0; j < 16 && i + j < size; j++) {
            ptr += sprintf_s(ptr, sizeof(hexLine) - (ptr - hexLine), "%c", 
                (bytes[i + j] >= 32 && bytes[i + j] <= 126) ? bytes[i + j] : '.');
        }
        
        DawnOfWarLog_Write(level, module, "%s", hexLine);
    }
}

// Flush all pending Dawn of War log entries
void DawnOfWarLog_Flush(void) {
    if (!g_dawnOfWarLogger.initialized) return;

    // Process all entries in ring buffer
    EnterCriticalSection(&g_dawnOfWarLogger.ringBuffer.cs);
    
    while (g_dawnOfWarLogger.ringBuffer.tail != g_dawnOfWarLogger.ringBuffer.head) {
        DawnOfWarLogEntry* entry = &g_dawnOfWarLogger.ringBuffer.entries[g_dawnOfWarLogger.ringBuffer.tail];
        ProcessLogEntry(entry);
        g_dawnOfWarLogger.ringBuffer.tail = (g_dawnOfWarLogger.ringBuffer.tail + 1) % g_dawnOfWarLogger.ringBuffer.capacity;
    }
    
    g_dawnOfWarLogger.ringBuffer.count = 0;
    LeaveCriticalSection(&g_dawnOfWarLogger.ringBuffer.cs);

    // Flush file
    if (g_dawnOfWarLogger.logFile != INVALID_HANDLE_VALUE) {
        FlushFileBuffers(g_dawnOfWarLogger.logFile);
    }
}

// Reload Dawn of War configuration
void DawnOfWarLog_ReloadConfig(void) {
    if (!g_dawnOfWarLogger.initialized) return;
    
    SetEvent(g_dawnOfWarLogger.configChangeEvent);
}

// Check if Dawn of War level is enabled for module
BOOL DawnOfWarLog_IsLevelEnabled(DawnOfWarLogLevel level, const char* module) {
    return ShouldLog(level, module) ? TRUE : FALSE;
}

// Get Dawn of War performance statistics
void DawnOfWarLog_GetStats(DWORD* messagesPerSec, DWORD* queueDepth, DWORD* memoryUsage) {
    if (!g_dawnOfWarLogger.initialized) return;

    if (messagesPerSec) {
        EnterCriticalSection(&g_dawnOfWarLogger.statsCs);
        *messagesPerSec = g_dawnOfWarLogger.messagesPerSecond;
        LeaveCriticalSection(&g_dawnOfWarLogger.statsCs);
    }

    if (queueDepth) {
        EnterCriticalSection(&g_dawnOfWarLogger.ringBuffer.cs);
        *queueDepth = g_dawnOfWarLogger.ringBuffer.count;
        LeaveCriticalSection(&g_dawnOfWarLogger.ringBuffer.cs);
    }

    if (memoryUsage) {
        *memoryUsage = (DWORD)(g_dawnOfWarLogger.ringBuffer.capacity * sizeof(DawnOfWarLogEntry));
    }
}

// Set up Dawn of War crash handlers
void DawnOfWarLog_SetCrashHandler(void) {
    SetUnhandledExceptionFilter((LPTOP_LEVEL_EXCEPTION_FILTER)ExceptionHandler);
    signal(SIGABRT, SignalHandler);
    signal(SIGFPE, SignalHandler);
    signal(SIGILL, SignalHandler);
    signal(SIGSEGV, SignalHandler);
    signal(SIGTERM, SignalHandler);
}

// Write Dawn of War stack trace
void DawnOfWarLog_WriteStackTrace(DawnOfWarLogLevel level, const char* module) {
    if (!g_dawnOfWarLogger.initialized || !module) return;

    char stackTrace[4096];
    CaptureStackTrace(stackTrace, sizeof(stackTrace));
    DawnOfWarLog_Write(level, module, "Dawn of War Stack Trace:\n%s", stackTrace);
}

// Worker thread for async Dawn of War logging
static DWORD WINAPI WorkerThread(LPVOID param) {
    HANDLE waitHandles[2] = { g_dawnOfWarLogger.shutdownEvent, g_dawnOfWarLogger.configChangeEvent };
    
    while (TRUE) {
        DWORD waitResult = WaitForMultipleObjects(2, waitHandles, FALSE, 100);
        
        if (waitResult == WAIT_OBJECT_0) {
            // Shutdown signal
            break;
        }
        else if (waitResult == WAIT_OBJECT_0 + 1) {
            // Config change signal
            LoadConfig("logger.ini");
        }
        else if (waitResult == WAIT_TIMEOUT) {
            // Process log entries
            EnterCriticalSection(&g_dawnOfWarLogger.ringBuffer.cs);
            
            while (g_dawnOfWarLogger.ringBuffer.tail != g_dawnOfWarLogger.ringBuffer.head) {
                DawnOfWarLogEntry* entry = &g_dawnOfWarLogger.ringBuffer.entries[g_dawnOfWarLogger.ringBuffer.tail];
                ProcessLogEntry(entry);
                g_dawnOfWarLogger.ringBuffer.tail = (g_dawnOfWarLogger.ringBuffer.tail + 1) % g_dawnOfWarLogger.ringBuffer.capacity;
            }
            
            g_dawnOfWarLogger.ringBuffer.count = 0;
            LeaveCriticalSection(&g_dawnOfWarLogger.ringBuffer.cs);

            // Update statistics
            LARGE_INTEGER currentTime;
            QueryPerformanceCounter(&currentTime);
            
            EnterCriticalSection(&g_dawnOfWarLogger.statsCs);
            LONGLONG elapsedTicks = currentTime.QuadPart - g_dawnOfWarLogger.lastStatsTime.QuadPart;
            if (elapsedTicks > 0) {
                g_dawnOfWarLogger.messagesPerSecond = (DWORD)((g_dawnOfWarLogger.totalMessages * g_dawnOfWarLogger.performanceFrequency.QuadPart) / elapsedTicks);
            }
            LeaveCriticalSection(&g_dawnOfWarLogger.statsCs);
        }
    }
    
    return 0;
}

// Write Dawn of War entry to file
static void WriteToFile(const DawnOfWarLogEntry* entry) {
    if (g_dawnOfWarLogger.logFile == INVALID_HANDLE_VALUE) return;

    char formatted[4096];
    FormatLogMessage(entry, formatted, sizeof(formatted));
    
    DWORD bytesWritten;
    WriteFile(g_dawnOfWarLogger.logFile, formatted, (DWORD)strlen(formatted), &bytesWritten, NULL);
    WriteFile(g_dawnOfWarLogger.logFile, "\r\n", 2, &bytesWritten, NULL);

    // Check file size and rotate if necessary
    LARGE_INTEGER fileSize;
    GetFileSizeEx(g_dawnOfWarLogger.logFile, &fileSize);
    
    if (fileSize.QuadPart > (LONGLONG)(g_dawnOfWarLogger.config.maxFileSizeMB * 1024 * 1024)) {
        RotateLogFile();
    }
}

// Write Dawn of War entry to console
static void WriteToConsole(const DawnOfWarLogEntry* entry) {
    if (!g_dawnOfWarLogger.consoleHandle) return;

    char formatted[4096];
    FormatLogMessage(entry, formatted, sizeof(formatted));
    
    if (g_dawnOfWarLogger.config.enableColors) {
        SetConsoleTextAttribute(g_dawnOfWarLogger.consoleHandle, GetConsoleColor(entry->level));
    }
    
    printf("%s\n", formatted);
    
    if (g_dawnOfWarLogger.config.enableColors) {
        SetConsoleTextAttribute(g_dawnOfWarLogger.consoleHandle, g_dawnOfWarLogger.defaultConsoleAttributes);
    }
}

// Write Dawn of War entry to memory (already in ring buffer)
static void WriteToMemory(const DawnOfWarLogEntry* entry) {
    // Entries are already stored in the ring buffer
    // This function can be extended for additional memory storage if needed
}

// Write Dawn of War entry to network (placeholder)
static void WriteToNetwork(const DawnOfWarLogEntry* entry) {
    if (!g_dawnOfWarLogger.config.enableNetwork) return;
    
    // TODO: Implement Dawn of War network logging
    // This would send log entry to a remote server via UDP/TCP
}

// Process Dawn of War log entry (route to appropriate outputs)
static void ProcessLogEntry(const DawnOfWarLogEntry* entry) {
    if (!entry) return;
    
    if (g_dawnOfWarLogger.config.outputs & DAWN_OF_WAR_OUTPUT_CONSOLE) {
        WriteToConsole(entry);
    }
    
    if (g_dawnOfWarLogger.config.outputs & DAWN_OF_WAR_OUTPUT_FILE) {
        WriteToFile(entry);
    }
    
    if (g_dawnOfWarLogger.config.outputs & DAWN_OF_WAR_OUTPUT_MEMORY) {
        WriteToMemory(entry);
    }
    
    if (g_dawnOfWarLogger.config.outputs & DAWN_OF_WAR_OUTPUT_NETWORK) {
        WriteToNetwork(entry);
    }
}

// Load Dawn of War configuration from INI file
static void LoadConfig(const char* configPath) {
    char buffer[256];
    
    // General section
    GetPrivateProfileStringA("General", "LogLevel", "INFO", buffer, sizeof(buffer), configPath);
    if (strcmp(buffer, "TRACE") == 0) g_dawnOfWarLogger.config.globalLevel = DAWN_OF_WAR_LOG_TRACE;
    else if (strcmp(buffer, "DEBUG") == 0) g_dawnOfWarLogger.config.globalLevel = DAWN_OF_WAR_LOG_DEBUG;
    else if (strcmp(buffer, "INFO") == 0) g_dawnOfWarLogger.config.globalLevel = DAWN_OF_WAR_LOG_INFO;
    else if (strcmp(buffer, "WARN") == 0) g_dawnOfWarLogger.config.globalLevel = DAWN_OF_WAR_LOG_WARN;
    else if (strcmp(buffer, "ERROR") == 0) g_dawnOfWarLogger.config.globalLevel = DAWN_OF_WAR_LOG_ERROR;
    else if (strcmp(buffer, "FATAL") == 0) g_dawnOfWarLogger.config.globalLevel = DAWN_OF_WAR_LOG_FATAL;
    
    GetPrivateProfileStringA("General", "Outputs", "Console,File", buffer, sizeof(buffer), configPath);
    g_dawnOfWarLogger.config.outputs = (DawnOfWarLogOutput)0;
    if (strstr(buffer, "Console")) g_dawnOfWarLogger.config.outputs |= DAWN_OF_WAR_OUTPUT_CONSOLE;
    if (strstr(buffer, "File")) g_dawnOfWarLogger.config.outputs |= DAWN_OF_WAR_OUTPUT_FILE;
    if (strstr(buffer, "Memory")) g_dawnOfWarLogger.config.outputs |= DAWN_OF_WAR_OUTPUT_MEMORY;
    if (strstr(buffer, "Network")) g_dawnOfWarLogger.config.outputs |= DAWN_OF_WAR_OUTPUT_NETWORK;
    
    // File section
    GetPrivateProfileStringA("File", "Path", "logs", g_dawnOfWarLogger.config.logPath, sizeof(g_dawnOfWarLogger.config.logPath), configPath);
    g_dawnOfWarLogger.config.maxFileSizeMB = GetPrivateProfileIntA("File", "MaxSizeMB", 100, configPath);
    g_dawnOfWarLogger.config.rotationCount = GetPrivateProfileIntA("File", "RotationCount", 5, configPath);
    
    // Network section
    g_dawnOfWarLogger.config.enableNetwork = GetPrivateProfileIntA("Network", "Enable", 0, configPath) != 0;
    GetPrivateProfileStringA("Network", "Host", "localhost", g_dawnOfWarLogger.config.networkHost, sizeof(g_dawnOfWarLogger.config.networkHost), configPath);
    g_dawnOfWarLogger.config.networkPort = (USHORT)GetPrivateProfileIntA("Network", "Port", 514, configPath);
    
    // Performance section
    g_dawnOfWarLogger.config.bufferSize = GetPrivateProfileIntA("Performance", "BufferSize", 1024, configPath);
    g_dawnOfWarLogger.config.enableColors = GetPrivateProfileIntA("Performance", "EnableColors", 1, configPath) != 0;
    g_dawnOfWarLogger.config.enableStackTrace = GetPrivateProfileIntA("Performance", "EnableStackTrace", 1, configPath) != 0;
}

// Check if we should log this Dawn of War entry
static BOOL ShouldLog(DawnOfWarLogLevel level, const char* module) {
    DawnOfWarLogLevel moduleLevel = GetModuleLevel(module);
    return level >= moduleLevel;
}

// Get module-specific Dawn of War log level
static DawnOfWarLogLevel GetModuleLevel(const char* module) {
    EnterCriticalSection(&g_dawnOfWarModuleLevelsCs);
    
    DawnOfWarModuleLevel* current = g_dawnOfWarModuleLevels;
    while (current) {
        if (strcmp(current->module, module) == 0) {
            DawnOfWarLogLevel level = current->level;
            LeaveCriticalSection(&g_dawnOfWarModuleLevelsCs);
            return level;
        }
        current = current->next;
    }
    
    LeaveCriticalSection(&g_dawnOfWarModuleLevelsCs);
    return g_dawnOfWarLogger.config.globalLevel;
}

// Rotate Dawn of War log file
static void RotateLogFile(void) {
    if (g_dawnOfWarLogger.logFile == INVALID_HANDLE_VALUE) return;

    CloseHandle(g_dawnOfWarLogger.logFile);

    // Rename current file
    char oldName[MAX_PATH];
    char newName[MAX_PATH];
    SYSTEMTIME st;
    GetLocalTime(&st);
    
    sprintf_s(oldName, sizeof(oldName), "%s\\DawnOfWar_%04d%02d%02d_%02d%02d%02d.log",
        g_dawnOfWarLogger.config.logPath, st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
    
    sprintf_s(newName, sizeof(newName), "%s\\DawnOfWar_%04d%02d%02d_%02d%02d%02d_old.log",
        g_dawnOfWarLogger.config.logPath, st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
    
    MoveFileA(oldName, newName);

    // Create new log file
    sprintf_s(oldName, sizeof(oldName), "%s\\DawnOfWar_%04d%02d%02d_%02d%02d%02d.log",
        g_dawnOfWarLogger.config.logPath, st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
    
    g_dawnOfWarLogger.logFile = CreateFileA(oldName, GENERIC_WRITE, FILE_SHARE_READ,
        NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
}

// Format Dawn of War log message
static void FormatLogMessage(const DawnOfWarLogEntry* entry, char* buffer, size_t bufferSize) {
    DWORD seconds = entry->timestamp / 1000;
    DWORD milliseconds = entry->timestamp % 1000;
    
    DWORD hours = seconds / 3600;
    DWORD minutes = (seconds % 3600) / 60;
    DWORD secs = seconds % 60;
    
    sprintf_s(buffer, bufferSize, "[%02d:%02d:%02d.%03d] [%08X] [%s] [%s] %s",
        hours, minutes, secs, milliseconds,
        entry->threadId,
        GetLevelString(entry->level),
        entry->module,
        entry->message);
}

// Get string representation of Dawn of War log level
static const char* GetLevelString(DawnOfWarLogLevel level) {
    switch (level) {
    case DAWN_OF_WAR_LOG_TRACE: return "TRACE";
    case DAWN_OF_WAR_LOG_DEBUG: return "DEBUG";
    case DAWN_OF_WAR_LOG_INFO:  return "INFO ";
    case DAWN_OF_WAR_LOG_WARN:  return "WARN ";
    case DAWN_OF_WAR_LOG_ERROR: return "ERROR";
    case DAWN_OF_WAR_LOG_FATAL: return "FATAL";
    default: return "UNKN ";
    }
}

// Get console color for Dawn of War log level
static WORD GetConsoleColor(DawnOfWarLogLevel level) {
    switch (level) {
    case DAWN_OF_WAR_LOG_TRACE: return FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE;  // Gray
    case DAWN_OF_WAR_LOG_DEBUG: return FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE;  // Gray
    case DAWN_OF_WAR_LOG_INFO:  return FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_INTENSITY;  // Cyan
    case DAWN_OF_WAR_LOG_WARN:  return FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_INTENSITY;  // Yellow
    case DAWN_OF_WAR_LOG_ERROR: return FOREGROUND_RED | FOREGROUND_INTENSITY;  // Red
    case DAWN_OF_WAR_LOG_FATAL: return FOREGROUND_RED | FOREGROUND_BLUE | FOREGROUND_INTENSITY;  // Magenta
    default: return FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE;  // White
    }
}

// Capture stack trace
static void CaptureStackTrace(char* buffer, size_t bufferSize) {
    HANDLE process = GetCurrentProcess();
    HANDLE thread = GetCurrentThread();
    
    CONTEXT context = {0};
    context.ContextFlags = CONTEXT_FULL;
    RtlCaptureContext(&context);
    
    SymInitialize(process, NULL, TRUE);
    
    STACKFRAME64 frame = {0};
#ifdef _M_X64
    frame.AddrPC.Offset = context.Rip;
    frame.AddrPC.Mode = AddrModeFlat;
    frame.AddrFrame.Offset = context.Rbp;
    frame.AddrFrame.Mode = AddrModeFlat;
    frame.AddrStack.Offset = context.Rsp;
    frame.AddrStack.Mode = AddrModeFlat;
#else
    frame.AddrPC.Offset = context.Eip;
    frame.AddrPC.Mode = AddrModeFlat;
    frame.AddrFrame.Offset = context.Ebp;
    frame.AddrFrame.Mode = AddrModeFlat;
    frame.AddrStack.Offset = context.Esp;
    frame.AddrStack.Mode = AddrModeFlat;
#endif
    
    char* ptr = buffer;
    size_t remaining = bufferSize;
    
    for (int i = 0; i < 20 && remaining > 0; i++) {
#ifdef _M_X64
        if (!StackWalk64(IMAGE_FILE_MACHINE_AMD64, process, thread, &frame, &context,
            NULL, SymFunctionTableAccess64, SymGetModuleBase64, NULL)) {
            break;
        }
#else
        if (!StackWalk64(IMAGE_FILE_MACHINE_I386, process, thread, &frame, &context,
            NULL, SymFunctionTableAccess64, SymGetModuleBase64, NULL)) {
            break;
        }
#endif
        
        DWORD64 address = frame.AddrPC.Offset;
        char symbolBuffer[sizeof(SYMBOL_INFO) + MAX_PATH];
        PSYMBOL_INFO symbol = (PSYMBOL_INFO)symbolBuffer;
        symbol->SizeOfStruct = sizeof(SYMBOL_INFO);
        symbol->MaxNameLen = MAX_PATH;
        
        if (SymFromAddr(process, address, NULL, symbol)) {
            int written = _snprintf_s(ptr, remaining, _TRUNCATE, "0x%016llX %s+0x%llX\n",
                address, symbol->Name, address - symbol->Address);
            if (written > 0) {
                ptr += written;
                remaining -= written;
            }
        } else {
            int written = _snprintf_s(ptr, remaining, _TRUNCATE, "0x%016llX\n", address);
            if (written > 0) {
                ptr += written;
                remaining -= written;
            }
        }
    }
    
    SymCleanup(process);
}

// Exception handler for Dawn of War Logger
static void ExceptionHandler(EXCEPTION_POINTERS* exceptionInfo) {
    DawnOfWarLog_Write(DAWN_OF_WAR_LOG_FATAL, "DawnOfWarLogger", "Dawn of War unhandled exception occurred");
    DawnOfWarLog_WriteStackTrace(DAWN_OF_WAR_LOG_FATAL, "DawnOfWarLogger");
    
    // Write mini-dump
    char dumpPath[MAX_PATH];
    SYSTEMTIME st;
    GetLocalTime(&st);
    sprintf_s(dumpPath, sizeof(dumpPath), "%s\\DawnOfWar_Crash_%04d%02d%02d_%02d%02d%02d.dmp",
        g_dawnOfWarLogger.config.logPath, st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
    
    HANDLE dumpFile = CreateFileA(dumpPath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (dumpFile != INVALID_HANDLE_VALUE) {
        MINIDUMP_EXCEPTION_INFORMATION dumpInfo;
        dumpInfo.ThreadId = GetCurrentThreadId();
        dumpInfo.ExceptionPointers = exceptionInfo;
        dumpInfo.ClientPointers = FALSE;
        
        MiniDumpWriteDump(GetCurrentProcess(), GetCurrentProcessId(), dumpFile,
            MiniDumpNormal, &dumpInfo, NULL, NULL);
        
        CloseHandle(dumpFile);
    }
    
    DawnOfWarLog_Flush();
    
    // Call original exception handler
    EXCEPTION_POINTERS* exception = exceptionInfo;
    EXCEPTION_RECORD* record = exception->ExceptionRecord;
    CONTEXT* context = exception->ContextRecord;
    
    // Terminate process
    TerminateProcess(GetCurrentProcess(), 1);
}

// Signal handler for Dawn of War Logger
static void SignalHandler(int signal) {
    DawnOfWarLog_Write(DAWN_OF_WAR_LOG_FATAL, "DawnOfWarLogger", "Dawn of War fatal signal received: %d", signal);
    DawnOfWarLog_WriteStackTrace(DAWN_OF_WAR_LOG_FATAL, "DawnOfWarLogger");
    DawnOfWarLog_Flush();
    
    exit(1);
}

// Initialize Dawn of War console
static void InitializeConsole(void) {
    if (AllocConsole()) {
        freopen_s((FILE**)stdout, "CONOUT$", "w", stdout);
        freopen_s((FILE**)stderr, "CONOUT$", "w", stderr);
        freopen_s((FILE**)stdin, "CONIN$", "r", stdin);
        
        g_dawnOfWarLogger.consoleHandle = GetStdHandle(STD_OUTPUT_HANDLE);
        CONSOLE_SCREEN_BUFFER_INFO csbi;
        GetConsoleScreenBufferInfo(g_dawnOfWarLogger.consoleHandle, &csbi);
        g_dawnOfWarLogger.defaultConsoleAttributes = csbi.wAttributes;
        
        SetConsoleTitleA("Dawn of War - Master Logger");
    }
}

// Cleanup Dawn of War console
static void CleanupConsole(void) {
    if (g_dawnOfWarLogger.consoleHandle) {
        FreeConsole();
        g_dawnOfWarLogger.consoleHandle = NULL;
    }
}
