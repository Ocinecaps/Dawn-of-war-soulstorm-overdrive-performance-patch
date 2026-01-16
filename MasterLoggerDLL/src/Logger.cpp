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

// LAA State Tracking Structure
struct LAAStateLog {
    bool isLAAEnabled;
    bool is64BitOS;
    size_t totalPhysicalMemory;
    size_t availablePhysicalMemory;
    size_t usableAddressSpace;
    DWORD_PTR processImageBase;
    time_t timestamp;
    char executablePath[MAX_PATH];
};

static LAAStateLog g_lastLAAState = {};
static bool g_laaStateInitialized = false;
static CRITICAL_SECTION g_logCriticalSection = {};

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
    InitializeCriticalSection(&g_dawnOfWarLogger.memoryStats.memoryCs);
    InitializeCriticalSection(&g_logCriticalSection);

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

    // Initialize enhanced console settings
    g_dawnOfWarLogger.enhancedConsoleEnabled = TRUE;
    g_dawnOfWarLogger.consoleUpdateInterval = 1000; // Update every 1 second
    QueryPerformanceCounter(&g_dawnOfWarLogger.lastConsoleUpdate);

    // Initialize performance statistics
    ZeroMemory(&g_dawnOfWarLogger.stats, sizeof(DawnOfWarLoggerStats));
    QueryPerformanceCounter(&g_dawnOfWarLogger.stats.startupTime);
    g_dawnOfWarLogger.stats.totalSessions = 1;

    // Initialize memory statistics
    ZeroMemory(&g_dawnOfWarLogger.memoryStats, sizeof(DawnOfWarMemoryStats));
    g_dawnOfWarLogger.memoryStats.smallestAllocation = SIZE_MAX;

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

    // Initialize console FIRST - so we can show errors
    if (g_dawnOfWarLogger.config.outputs & DAWN_OF_WAR_OUTPUT_CONSOLE) {
        InitializeConsole();
    }

    // Single log file for technical details - consistent naming
    char logFileName[MAX_PATH];
    char logPath[MAX_PATH];
    
    // Try multiple paths for log directory creation
    bool logFileCreated = false;
    DWORD logPathAttempts = 0;
    
    // Attempt 1: Use configured path (typically "logs")
    strcpy_s(logPath, sizeof(logPath), g_dawnOfWarLogger.config.logPath);
    
    while (!logFileCreated && logPathAttempts < 4) {
        // Use consistent single log file name for technical details
        sprintf_s(logFileName, sizeof(logFileName), "%s\\DawnOfWar_Technical.log", logPath);
        
        // Create directory with enhanced error handling
        if (logPathAttempts > 0) {
            // For fallback attempts, create directory more aggressively
            char fullPath[MAX_PATH];
            strcpy_s(fullPath, sizeof(fullPath), logPath);
            
            // Create directory recursively
            char* p = fullPath;
            while (*p) {
                if (*p == '\\' || *p == '/') {
                    char temp = *p;
                    *p = '\0';
                    CreateDirectoryA(fullPath, NULL);
                    *p = temp;
                }
                p++;
            }
            CreateDirectoryA(fullPath, NULL);
        }
        
        g_dawnOfWarLogger.logFile = CreateFileA(logFileName, GENERIC_WRITE, FILE_SHARE_READ,
            NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        
        if (g_dawnOfWarLogger.logFile != INVALID_HANDLE_VALUE) {
            logFileCreated = true;
            strcpy_s(g_dawnOfWarLogger.config.logPath, sizeof(g_dawnOfWarLogger.config.logPath), logPath);
            
            // Move to end of file for appending
            SetFilePointer(g_dawnOfWarLogger.logFile, 0, NULL, FILE_END);
            
            // Report success to console immediately
            if (g_dawnOfWarLogger.consoleHandle) {
                char successMsg[512];
                sprintf_s(successMsg, sizeof(successMsg), "SUCCESS: Technical log file opened for appending: %s\n", logFileName);
                DWORD bytesWritten;
                WriteConsoleA(g_dawnOfWarLogger.consoleHandle, successMsg, (DWORD)strlen(successMsg), &bytesWritten, NULL);
            }
            break;
        } else {
            // Report specific error for this attempt
            DWORD error = GetLastError();
            if (g_dawnOfWarLogger.consoleHandle) {
                char errorMsg[512];
                sprintf_s(errorMsg, sizeof(errorMsg), "FAILED to open technical log file '%s' (attempt %d). Error: %lu\n", 
                    logFileName, logPathAttempts + 1, error);
                DWORD bytesWritten;
                WriteConsoleA(g_dawnOfWarLogger.consoleHandle, errorMsg, (DWORD)strlen(errorMsg), &bytesWritten, NULL);
            }
        }
        
        // Fallback attempts with different paths
        logPathAttempts++;
        switch (logPathAttempts) {
        case 1:
            // Try current directory
            strcpy_s(logPath, sizeof(logPath), ".");
            break;
        case 2:
            // Try temp directory
            GetTempPathA(sizeof(logPath), logPath);
            strcat_s(logPath, sizeof(logPath), "DawnOfWarLogs");
            break;
        case 3:
            // Try desktop
            if (SHGetFolderPathA(NULL, CSIDL_DESKTOP, NULL, SHGFP_TYPE_CURRENT, logPath) != S_OK) {
                strcpy_s(logPath, sizeof(logPath), "C:\\");
            }
            strcat_s(logPath, sizeof(logPath), "DawnOfWarLogs");
            break;
        }
    }
    
    // Final status report
    if (!logFileCreated) {
        if (g_dawnOfWarLogger.consoleHandle) {
            char finalError[512];
            sprintf_s(finalError, sizeof(finalError), 
                "CRITICAL: All log file creation attempts failed! Logging will be console-only.\n"
                "Attempted paths:\n"
                "1. %s\\DawnOfWar_Technical.log\n"
                "2. .\\DawnOfWar_Technical.log\n"
                "3. <temp>\\DawnOfWarLogs\\DawnOfWar_Technical.log\n"
                "4. <desktop>\\DawnOfWarLogs\\DawnOfWar_Technical.log\n",
                g_dawnOfWarLogger.config.logPath);
            DWORD bytesWritten;
            WriteConsoleA(g_dawnOfWarLogger.consoleHandle, finalError, (DWORD)strlen(finalError), &bytesWritten, NULL);
        }
        
        // Force file output to be disabled since we couldn't create a file
        g_dawnOfWarLogger.config.outputs &= ~DAWN_OF_WAR_OUTPUT_FILE;
    }
    
    // Write log header if file is valid
    if (g_dawnOfWarLogger.logFile != INVALID_HANDLE_VALUE) {
        char header[1024];
        SYSTEMTIME st;
        GetLocalTime(&st);
        
        // Check if file is empty to decide whether to write header
        DWORD fileSize = GetFileSize(g_dawnOfWarLogger.logFile, NULL);
        
        if (fileSize == 0) {
            // New file - write header
            sprintf_s(header, sizeof(header), 
                "=== Dawn of War Soulstorm - Technical Log File ===\n"
                "This file contains detailed technical information about patching and memory management\n"
                "Session Start: %04d-%02d-%02d %02d:%02d:%02d\n"
                "Process ID: %lu\n"
                "Logger Version: 2.0 Enhanced\n"
                "================================================\n",
                st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond,
                GetCurrentProcessId());
        } else {
            // Existing file - append session separator
            sprintf_s(header, sizeof(header), 
                "\n=== NEW SESSION ===\n"
                "Session Start: %04d-%02d-%02d %02d:%02d:%02d\n"
                "Process ID: %lu\n"
                "-------------------\n",
                st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond,
                GetCurrentProcessId());
        }
        
        DWORD bytesWritten;
        WriteFile(g_dawnOfWarLogger.logFile, header, (DWORD)strlen(header), &bytesWritten, NULL);
        g_dawnOfWarLogger.stats.bytesWritten += bytesWritten;
        FlushFileBuffers(g_dawnOfWarLogger.logFile);
        
        // Also write success to console
        if (g_dawnOfWarLogger.consoleHandle) {
            char successMsg[256];
            sprintf_s(successMsg, sizeof(successMsg), "Log file created: %s\n", logFileName);
            WriteConsoleA(g_dawnOfWarLogger.consoleHandle, successMsg, (DWORD)strlen(successMsg), &bytesWritten, NULL);
        }
        
        // IMMEDIATE TEST: Write a test message directly to file to verify it works
        const char* testMsg = "=== IMMEDIATE FILE WRITE TEST ===\nIf you see this, file writing is working!\n";
        WriteFile(g_dawnOfWarLogger.logFile, testMsg, (DWORD)strlen(testMsg), &bytesWritten, NULL);
        FlushFileBuffers(g_dawnOfWarLogger.logFile);
    } else {
        // File creation failed, but we have console - report it
        if (g_dawnOfWarLogger.consoleHandle) {
            char errorMsg[256];
            sprintf_s(errorMsg, sizeof(errorMsg), "WARNING: Log file creation failed, using console only\n");
            DWORD bytesWritten;
            WriteConsoleA(g_dawnOfWarLogger.consoleHandle, errorMsg, (DWORD)strlen(errorMsg), &bytesWritten, NULL);
        }
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

    // Mark as initialized
    g_dawnOfWarLogger.initialized = TRUE;
    
    // Write test message to verify logger is working
    DawnOfWarLog_Write(DAWN_OF_WAR_LOG_INFO, "DawnOfWarLogger", 
        "Logger successfully initialized! Console: %s, File: %s, Outputs: %lu",
        g_dawnOfWarLogger.consoleHandle ? "YES" : "NO",
        g_dawnOfWarLogger.logFile != INVALID_HANDLE_VALUE ? "YES" : "NO",
        g_dawnOfWarLogger.config.outputs);
    
    // Flush immediately to show the test message
    DawnOfWarLog_Flush();

    // Log initialization
    DawnOfWarLog_Write(DAWN_OF_WAR_LOG_INFO, "DawnOfWarLogger", "Dawn of War Logger initialized successfully");
    
    // Test logging functionality across all levels
    DawnOfWarLog_Write(DAWN_OF_WAR_LOG_DEBUG, "DawnOfWarLogger", "Testing DEBUG level logging");
    DawnOfWarLog_Write(DAWN_OF_WAR_LOG_INFO, "DawnOfWarLogger", "Testing INFO level logging");
    DawnOfWarLog_Write(DAWN_OF_WAR_LOG_WARN, "DawnOfWarLogger", "Testing WARN level logging");
    DawnOfWarLog_Write(DAWN_OF_WAR_LOG_ERROR, "DawnOfWarLogger", "Testing ERROR level logging");
    
    // Test module-specific logging
    DawnOfWarLog_Write(DAWN_OF_WAR_LOG_INFO, "MemoryPoolDLL", "Memory pool logger integration test");
    DawnOfWarLog_Write(DAWN_OF_WAR_LOG_INFO, "Patcher", "Patcher logger integration test");
    
    // DIRECT FILE WRITE TEST: Bypass worker thread
    if (g_dawnOfWarLogger.logFile != INVALID_HANDLE_VALUE) {
        const char* directTest = "=== DIRECT FILE WRITE TEST (bypassing worker thread) ===\nThis proves the file handle is valid and writable!\n";
        DWORD bytesWritten;
        WriteFile(g_dawnOfWarLogger.logFile, directTest, (DWORD)strlen(directTest), &bytesWritten, NULL);
        FlushFileBuffers(g_dawnOfWarLogger.logFile);
        
        if (g_dawnOfWarLogger.consoleHandle) {
            char consoleMsg[256];
            sprintf_s(consoleMsg, sizeof(consoleMsg), "DIRECT TEST: Wrote %lu bytes directly to log file\n", bytesWritten);
            WriteConsoleA(g_dawnOfWarLogger.consoleHandle, consoleMsg, (DWORD)strlen(consoleMsg), &bytesWritten, NULL);
        }
    }
    
    // Flush to ensure everything is written
    DawnOfWarLog_Flush();
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
    DeleteCriticalSection(&g_dawnOfWarLogger.memoryStats.memoryCs);

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
void DawnOfWarLog_HexDump(DawnOfWarLogLevel level, const char* module, const unsigned char* data, size_t size) {
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

// Enhanced console writing with performance tracking
static void WriteToConsole(const DawnOfWarLogEntry* entry) {
    if (!g_dawnOfWarLogger.consoleHandle) {
        return;
    }

    char formattedMessage[2048];
    FormatLogMessage(entry, formattedMessage, sizeof(formattedMessage));
    
    // Add newline for proper console formatting
    strcat_s(formattedMessage, sizeof(formattedMessage), "\n");
    
    if (g_dawnOfWarLogger.config.enableColors) {
        WORD color = GetConsoleColor(entry->level);
        SetConsoleTextAttribute(g_dawnOfWarLogger.consoleHandle, color);
    }
    
    DWORD bytesWritten;
    WriteConsoleA(g_dawnOfWarLogger.consoleHandle, formattedMessage, 
                  (DWORD)strlen(formattedMessage), &bytesWritten, NULL);
    
    if (g_dawnOfWarLogger.config.enableColors) {
        SetConsoleTextAttribute(g_dawnOfWarLogger.consoleHandle, 
                               g_dawnOfWarLogger.defaultConsoleAttributes);
    }
    
    // Update enhanced console display if enabled
    if (g_dawnOfWarLogger.enhancedConsoleEnabled) {
        LARGE_INTEGER currentTime;
        QueryPerformanceCounter(&currentTime);
        
        LONGLONG elapsedMs = (currentTime.QuadPart - g_dawnOfWarLogger.lastConsoleUpdate.QuadPart) * 1000 / 
                            g_dawnOfWarLogger.performanceFrequency.QuadPart;
        
        if (elapsedMs >= g_dawnOfWarLogger.consoleUpdateInterval) {
            DawnOfWarLog_UpdateConsoleDisplay();
            g_dawnOfWarLogger.lastConsoleUpdate = currentTime;
        }
    }
}

// Enhanced file writing with consistent error handling and statistics
static void WriteToFile(const DawnOfWarLogEntry* entry) {
    if (g_dawnOfWarLogger.logFile == INVALID_HANDLE_VALUE) {
        return;
    }

    char formattedMessage[2048];
    FormatLogMessage(entry, formattedMessage, sizeof(formattedMessage));
    
    // Add newline for proper file formatting
    strcat_s(formattedMessage, sizeof(formattedMessage), "\n");
    
    DWORD bytesWritten;
    BOOL success = WriteFile(g_dawnOfWarLogger.logFile, formattedMessage, 
                            (DWORD)strlen(formattedMessage), &bytesWritten, NULL);
    
    if (success && bytesWritten > 0) {
        EnterCriticalSection(&g_dawnOfWarLogger.statsCs);
        g_dawnOfWarLogger.stats.bytesWritten += bytesWritten;
        LeaveCriticalSection(&g_dawnOfWarLogger.statsCs);
        
        // Check for log rotation
        LARGE_INTEGER fileSize;
        if (GetFileSizeEx(g_dawnOfWarLogger.logFile, &fileSize)) {
            size_t sizeMB = (size_t)(fileSize.QuadPart / (1024 * 1024));
            if (sizeMB >= g_dawnOfWarLogger.config.maxFileSizeMB) {
                RotateLogFile();
                EnterCriticalSection(&g_dawnOfWarLogger.statsCs);
                g_dawnOfWarLogger.stats.logRotations++;
                LeaveCriticalSection(&g_dawnOfWarLogger.statsCs);
            }
        }
    } else {
        // Handle write failure - avoid recursion by not calling DawnOfWarLog_Write
        DWORD error = GetLastError();
        // Write directly to console for critical file errors
        if (g_dawnOfWarLogger.consoleHandle) {
            char errorMsg[256];
            sprintf_s(errorMsg, sizeof(errorMsg), 
                "[LOGGER ERROR] Failed to write to log file. Error: %lu\n", error);
            DWORD bytesWritten;
            WriteConsoleA(g_dawnOfWarLogger.consoleHandle, errorMsg, 
                          (DWORD)strlen(errorMsg), &bytesWritten, NULL);
        }
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
    // For now, just write to console that network logging is not implemented
    if (g_dawnOfWarLogger.consoleHandle) {
        char networkMsg[512];
        sprintf_s(networkMsg, sizeof(networkMsg), 
            "[NETWORK] Network logging not implemented for: [%s] %s\n", 
            entry->module, entry->message);
        DWORD bytesWritten;
        WriteConsoleA(g_dawnOfWarLogger.consoleHandle, networkMsg, 
                      (DWORD)strlen(networkMsg), &bytesWritten, NULL);
    }
}


// Process Dawn of War log entry (route to appropriate outputs)
static void ProcessLogEntry(const DawnOfWarLogEntry* entry) {
    if (!entry) return;
    
    // Update performance statistics
    EnterCriticalSection(&g_dawnOfWarLogger.statsCs);
    g_dawnOfWarLogger.stats.messagesLogged++;
    g_dawnOfWarLogger.totalMessages++;
    
    // Track error and warning counts
    if (entry->level >= DAWN_OF_WAR_LOG_ERROR) {
        g_dawnOfWarLogger.stats.totalErrors++;
    } else if (entry->level == DAWN_OF_WAR_LOG_WARN) {
        g_dawnOfWarLogger.stats.totalWarnings++;
    }
    
    // Update highest queue depth
    if (g_dawnOfWarLogger.ringBuffer.count > g_dawnOfWarLogger.stats.highestQueueDepth) {
        g_dawnOfWarLogger.stats.highestQueueDepth = g_dawnOfWarLogger.ringBuffer.count;
    }
    LeaveCriticalSection(&g_dawnOfWarLogger.statsCs);
    
    // Route to outputs
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

// Save Dawn of War configuration to INI file
static void SaveConfig(const char* configPath) {
    // Create default configuration
    WritePrivateProfileStringA("General", "LogLevel", "INFO", configPath);
    WritePrivateProfileStringA("General", "Outputs", "Console,File", configPath);
    
    WritePrivateProfileStringA("File", "Path", "logs", configPath);
    WritePrivateProfileStringA("File", "MaxSizeMB", "100", configPath);
    WritePrivateProfileStringA("File", "RotationCount", "5", configPath);
    
    WritePrivateProfileStringA("Network", "Enable", "0", configPath);
    WritePrivateProfileStringA("Network", "Host", "localhost", configPath);
    WritePrivateProfileStringA("Network", "Port", "514", configPath);
    
    WritePrivateProfileStringA("Performance", "BufferSize", "1024", configPath);
    WritePrivateProfileStringA("Performance", "EnableColors", "1", configPath);
    WritePrivateProfileStringA("Performance", "EnableStackTrace", "1", configPath);
    
    // Add comments section
    WritePrivateProfileStringA("Comments", "LogFileFormat", "DawnOfWar_YYYYMMDD_HHMMSS.log", configPath);
    WritePrivateProfileStringA("Comments", "LogLevels", "TRACE,DEBUG,INFO,WARN,ERROR,FATAL", configPath);
    WritePrivateProfileStringA("Comments", "Outputs", "Console,File,Memory,Network", configPath);
}

// Load Dawn of War configuration from INI file
static void LoadConfig(const char* configPath) {
    char buffer[256];
    
    // Create default config file if it doesn't exist
    if (GetFileAttributesA(configPath) == INVALID_FILE_ATTRIBUTES) {
        SaveConfig(configPath);
    }
    
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

// Rotate Dawn of War log file with enhanced naming
static void RotateLogFile(void) {
    if (g_dawnOfWarLogger.logFile == INVALID_HANDLE_VALUE) return;

    CloseHandle(g_dawnOfWarLogger.logFile);

    // Get current log file name
    char currentName[MAX_PATH];
    SYSTEMTIME st;
    GetLocalTime(&st);
    sprintf_s(currentName, sizeof(currentName), "%s\\DawnOfWar_%04d%02d%02d_%02d%02d%02d.log",
        g_dawnOfWarLogger.config.logPath, st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
    
    // Create archive directory
    char archiveDir[MAX_PATH];
    sprintf_s(archiveDir, sizeof(archiveDir), "%s\\archive", g_dawnOfWarLogger.config.logPath);
    CreateDirectoryA(archiveDir, NULL);
    
    // Move current file to archive with timestamp
    char archiveName[MAX_PATH];
    sprintf_s(archiveName, sizeof(archiveName), "%s\\DawnOfWar_%04d%02d%02d_%02d%02d%02d_completed.log",
        archiveDir, st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
    
    MoveFileA(currentName, archiveName);

    // Create new log file
    sprintf_s(currentName, sizeof(currentName), "%s\\DawnOfWar_%04d%02d%02d_%02d%02d%02d.log",
        g_dawnOfWarLogger.config.logPath, st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
    
    g_dawnOfWarLogger.logFile = CreateFileA(currentName, GENERIC_WRITE, FILE_SHARE_READ,
        NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    
    if (g_dawnOfWarLogger.logFile != INVALID_HANDLE_VALUE) {
        const char* rotationMsg = "=== Log Rotated ===\n";
        DWORD bytesWritten;
        WriteFile(g_dawnOfWarLogger.logFile, rotationMsg, (DWORD)strlen(rotationMsg), &bytesWritten, NULL);
        DawnOfWarLog_Write(DAWN_OF_WAR_LOG_INFO, "DawnOfWarLogger", "Log file rotated to: %s", archiveName);
    }
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
    // Try to allocate console, but don't fail if we can't
    if (!AllocConsole()) {
        DWORD error = GetLastError();
        if (error != ERROR_ACCESS_DENIED) { // Console already exists is OK
            // Try to attach to existing console
            if (!AttachConsole(ATTACH_PARENT_PROCESS)) {
                // No console available, continue without it
                g_dawnOfWarLogger.consoleHandle = NULL;
                return;
            }
        }
    }
    
    // Redirect stdout/stderr to console
    FILE* dummyFile;
    freopen_s(&dummyFile, "CONOUT$", "w", stdout);
    freopen_s(&dummyFile, "CONOUT$", "w", stderr);
    freopen_s(&dummyFile, "CONIN$", "r", stdin);
    
    // Get console handle and set title
    g_dawnOfWarLogger.consoleHandle = GetStdHandle(STD_OUTPUT_HANDLE);
    if (g_dawnOfWarLogger.consoleHandle && g_dawnOfWarLogger.consoleHandle != INVALID_HANDLE_VALUE) {
        CONSOLE_SCREEN_BUFFER_INFO csbi;
        if (GetConsoleScreenBufferInfo(g_dawnOfWarLogger.consoleHandle, &csbi)) {
            g_dawnOfWarLogger.defaultConsoleAttributes = csbi.wAttributes;
        }
        SetConsoleTitleA("Dawn of War - Master Logger");
        
        // Write initialization message to console
        DWORD bytesWritten;
        const char* initMsg = "=== Dawn of War Logger Console Initialized ===\n";
        WriteConsoleA(g_dawnOfWarLogger.consoleHandle, initMsg, (DWORD)strlen(initMsg), &bytesWritten, NULL);
    }
}

// Cleanup Dawn of War console
static void CleanupConsole(void) {
    if (g_dawnOfWarLogger.consoleHandle) {
        FreeConsole();
        g_dawnOfWarLogger.consoleHandle = NULL;
    }
}

// Enhanced statistics functions
void DawnOfWarLog_GetDetailedStats(DawnOfWarLoggerStats* stats) {
    if (!stats || !g_dawnOfWarLogger.initialized) return;
    
    EnterCriticalSection(&g_dawnOfWarLogger.statsCs);
    *stats = g_dawnOfWarLogger.stats;
    LeaveCriticalSection(&g_dawnOfWarLogger.statsCs);
}

void DawnOfWarLog_GetMemoryStats(DawnOfWarMemoryStats* stats) {
    if (!stats || !g_dawnOfWarLogger.initialized) return;
    
    EnterCriticalSection(&g_dawnOfWarLogger.memoryStats.memoryCs);
    *stats = g_dawnOfWarLogger.memoryStats;
    LeaveCriticalSection(&g_dawnOfWarLogger.memoryStats.memoryCs);
}

void DawnOfWarLog_ResetStats(void) {
    if (!g_dawnOfWarLogger.initialized) return;
    
    EnterCriticalSection(&g_dawnOfWarLogger.statsCs);
    ZeroMemory(&g_dawnOfWarLogger.stats, sizeof(DawnOfWarLoggerStats));
    QueryPerformanceCounter(&g_dawnOfWarLogger.stats.startupTime);
    g_dawnOfWarLogger.stats.totalSessions = 1;
    LeaveCriticalSection(&g_dawnOfWarLogger.statsCs);
    
    EnterCriticalSection(&g_dawnOfWarLogger.memoryStats.memoryCs);
    ZeroMemory(&g_dawnOfWarLogger.memoryStats, sizeof(DawnOfWarMemoryStats));
    g_dawnOfWarLogger.memoryStats.smallestAllocation = SIZE_MAX;
    LeaveCriticalSection(&g_dawnOfWarLogger.memoryStats.memoryCs);
}

void DawnOfWarLog_EnableEnhancedConsole(BOOL enable) {
    if (!g_dawnOfWarLogger.initialized) return;
    g_dawnOfWarLogger.enhancedConsoleEnabled = enable;
}

void DawnOfWarLog_UpdateConsoleDisplay(void) {
    if (!g_dawnOfWarLogger.consoleHandle || !g_dawnOfWarLogger.enhancedConsoleEnabled) return;
    
    // Save current cursor position
    CONSOLE_SCREEN_BUFFER_INFO csbi;
    GetConsoleScreenBufferInfo(g_dawnOfWarLogger.consoleHandle, &csbi);
    COORD originalPos = csbi.dwCursorPosition;
    
    // Move to top for status display
    COORD statusPos = {0, 0};
    SetConsoleCursorPosition(g_dawnOfWarLogger.consoleHandle, statusPos);
    
    // Display status information
    char statusLine[256];
    DawnOfWarLoggerStats stats;
    DawnOfWarLog_GetDetailedStats(&stats);
    
    sprintf_s(statusLine, sizeof(statusLine), 
        "=== DAWN OF WAR LOGGER STATUS ===\n"
        "Messages: %lu | Bytes: %lu | Rotations: %lu | Peak Queue: %lu\n"
        "Errors: %lu | Warnings: %lu | Sessions: %lu\n"
        "================================\n",
        stats.messagesLogged, stats.bytesWritten, stats.logRotations, stats.highestQueueDepth,
        stats.totalErrors, stats.totalWarnings, stats.totalSessions);
    
    SetConsoleTextAttribute(g_dawnOfWarLogger.consoleHandle, 
                           FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_INTENSITY);
    WriteConsoleA(g_dawnOfWarLogger.consoleHandle, statusLine, (DWORD)strlen(statusLine), NULL, NULL);
    SetConsoleTextAttribute(g_dawnOfWarLogger.consoleHandle, g_dawnOfWarLogger.defaultConsoleAttributes);
    
    // Restore cursor position
    SetConsoleCursorPosition(g_dawnOfWarLogger.consoleHandle, originalPos);
}

// Memory tracking hooks for integration with memory pool
void DawnOfWarLog_TrackAllocation(size_t size, void* ptr) {
    if (!g_dawnOfWarLogger.initialized || !ptr) return;
    
    EnterCriticalSection(&g_dawnOfWarLogger.memoryStats.memoryCs);
    g_dawnOfWarLogger.memoryStats.currentAllocations++;
    g_dawnOfWarLogger.memoryStats.totalAllocated += size;
    
    if (g_dawnOfWarLogger.memoryStats.currentAllocations > g_dawnOfWarLogger.memoryStats.peakAllocations) {
        g_dawnOfWarLogger.memoryStats.peakAllocations = g_dawnOfWarLogger.memoryStats.currentAllocations;
    }
    
    if (size > g_dawnOfWarLogger.memoryStats.largestAllocation) {
        g_dawnOfWarLogger.memoryStats.largestAllocation = size;
    }
    
    if (size < g_dawnOfWarLogger.memoryStats.smallestAllocation) {
        g_dawnOfWarLogger.memoryStats.smallestAllocation = size;
    }
    
    g_dawnOfWarLogger.memoryStats.memoryChecksPerformed++;
    LeaveCriticalSection(&g_dawnOfWarLogger.memoryStats.memoryCs);
}

void DawnOfWarLog_TrackDeallocation(size_t size, void* ptr) {
    if (!g_dawnOfWarLogger.initialized || !ptr) return;
    
    EnterCriticalSection(&g_dawnOfWarLogger.memoryStats.memoryCs);
    if (g_dawnOfWarLogger.memoryStats.currentAllocations > 0) {
        g_dawnOfWarLogger.memoryStats.currentAllocations--;
    }
    g_dawnOfWarLogger.memoryStats.totalFreed += size;
    g_dawnOfWarLogger.memoryStats.memoryChecksPerformed++;
    LeaveCriticalSection(&g_dawnOfWarLogger.memoryStats.memoryCs);
}

void DawnOfWarLog_TrackAllocationFailure(size_t size) {
    if (!g_dawnOfWarLogger.initialized) return;
    
    EnterCriticalSection(&g_dawnOfWarLogger.memoryStats.memoryCs);
    g_dawnOfWarLogger.memoryStats.allocationFailures++;
    g_dawnOfWarLogger.memoryStats.memoryChecksPerformed++;
    LeaveCriticalSection(&g_dawnOfWarLogger.memoryStats.memoryCs);
    
    DawnOfWarLog_Write(DAWN_OF_WAR_LOG_ERROR, "MemoryTracker", 
        "Memory allocation failed for size: %zu bytes", size);
}

void DawnOfWarLog_TrackFragmentation(size_t wastedBytes) {
    if (!g_dawnOfWarLogger.initialized) return;
    
    EnterCriticalSection(&g_dawnOfWarLogger.memoryStats.memoryCs);
    g_dawnOfWarLogger.memoryStats.fragmentationEvents++;
    g_dawnOfWarLogger.memoryStats.memoryChecksPerformed++;
    LeaveCriticalSection(&g_dawnOfWarLogger.memoryStats.memoryCs);
    
    DawnOfWarLog_Write(DAWN_OF_WAR_LOG_WARN, "MemoryTracker", 
        "Memory fragmentation detected: %zu bytes wasted", wastedBytes);
}

// LAA State Tracking Functions Implementation

// Function to log LAA state from patcher
void LogLAAStateFromPatcher(const char* executablePath, bool laaEnabled, 
                           bool is64BitOS, size_t totalMemory, size_t availableMemory,
                           size_t addressSpace, DWORD_PTR imageBase) {
    if (!g_dawnOfWarLogger.initialized) return;
    
    EnterCriticalSection(&g_logCriticalSection);
    
    // Store LAA state
    g_lastLAAState.isLAAEnabled = laaEnabled;
    g_lastLAAState.is64BitOS = is64BitOS;
    g_lastLAAState.totalPhysicalMemory = totalMemory;
    g_lastLAAState.availablePhysicalMemory = availableMemory;
    g_lastLAAState.usableAddressSpace = addressSpace;
    g_lastLAAState.processImageBase = imageBase;
    g_lastLAAState.timestamp = time(nullptr);
    strncpy_s(g_lastLAAState.executablePath, sizeof(g_lastLAAState.executablePath), 
              executablePath, _TRUNCATE);
    g_laaStateInitialized = true;
    
    // Log comprehensive LAA state information
    DAWN_OF_WAR_LOG_INFO("LAA_TRACKER", "=== LAA State from Patcher ===");
    DAWN_OF_WAR_LOG_INFO("LAA_TRACKER", "Executable: %s", executablePath);
    DAWN_OF_WAR_LOG_INFO("LAA_TRACKER", "LAA Enabled: %s", laaEnabled ? "YES" : "NO");
    DAWN_OF_WAR_LOG_INFO("LAA_TRACKER", "64-bit OS: %s", is64BitOS ? "YES" : "NO");
    DAWN_OF_WAR_LOG_INFO("LAA_TRACKER", "Total Physical Memory: %zu MB", totalMemory / (1024 * 1024));
    DAWN_OF_WAR_LOG_INFO("LAA_TRACKER", "Available Physical Memory: %zu MB", availableMemory / (1024 * 1024));
    DAWN_OF_WAR_LOG_INFO("LAA_TRACKER", "Usable Address Space: %zu MB", addressSpace / (1024 * 1024));
    DAWN_OF_WAR_LOG_INFO("LAA_TRACKER", "Process Image Base: 0x%p", (void*)imageBase);
    DAWN_OF_WAR_LOG_INFO("LAA_TRACKER", "Timestamp: %lld", (long long)g_lastLAAState.timestamp);
    
    LeaveCriticalSection(&g_logCriticalSection);
}

// Function to log LAA state from memory DLL
void LogLAAStateFromMemoryDLL(const char* executablePath, bool laaEnabled,
                             bool is64BitOS, bool highMemoryAvailable, 
                             size_t totalMemory, size_t availableMemory,
                             size_t currentProcessMemory, size_t addressSpace,
                             DWORD_PTR imageBase, bool canUseLargeAddresses) {
    if (!g_dawnOfWarLogger.initialized) return;
    
    EnterCriticalSection(&g_logCriticalSection);
    
    // Log memory DLL LAA state
    DAWN_OF_WAR_LOG_INFO("LAA_TRACKER", "=== LAA State from Memory DLL ===");
    DAWN_OF_WAR_LOG_INFO("LAA_TRACKER", "Executable: %s", executablePath);
    DAWN_OF_WAR_LOG_INFO("LAA_TRACKER", "LAA Enabled: %s", laaEnabled ? "YES" : "NO");
    DAWN_OF_WAR_LOG_INFO("LAA_TRACKER", "64-bit OS: %s", is64BitOS ? "YES" : "NO");
    DAWN_OF_WAR_LOG_INFO("LAA_TRACKER", "High Memory Available: %s", highMemoryAvailable ? "YES" : "NO");
    DAWN_OF_WAR_LOG_INFO("LAA_TRACKER", "Can Use Large Addresses: %s", canUseLargeAddresses ? "YES" : "NO");
    DAWN_OF_WAR_LOG_INFO("LAA_TRACKER", "Total Physical Memory: %zu MB", totalMemory / (1024 * 1024));
    DAWN_OF_WAR_LOG_INFO("LAA_TRACKER", "Available Physical Memory: %zu MB", availableMemory / (1024 * 1024));
    DAWN_OF_WAR_LOG_INFO("LAA_TRACKER", "Current Process Memory: %zu MB", currentProcessMemory / (1024 * 1024));
    DAWN_OF_WAR_LOG_INFO("LAA_TRACKER", "Usable Address Space: %zu MB", addressSpace / (1024 * 1024));
    DAWN_OF_WAR_LOG_INFO("LAA_TRACKER", "Process Image Base: 0x%p", (void*)imageBase);
    
    // Compare with patcher state if available
    if (g_laaStateInitialized) {
        DAWN_OF_WAR_LOG_INFO("LAA_TRACKER", "=== LAA State Comparison ===");
        DAWN_OF_WAR_LOG_INFO("LAA_TRACKER", "Patcher LAA: %s", g_lastLAAState.isLAAEnabled ? "YES" : "NO");
        DAWN_OF_WAR_LOG_INFO("LAA_TRACKER", "Memory DLL LAA: %s", laaEnabled ? "YES" : "NO");
        
        bool laaConsistent = (g_lastLAAState.isLAAEnabled == laaEnabled);
        DAWN_OF_WAR_LOG_INFO("LAA_TRACKER", "LAA State Consistent: %s", laaConsistent ? "YES" : "NO");
        
        if (!laaConsistent) {
            DAWN_OF_WAR_LOG_WARN("LAA_TRACKER", "LAA STATE MISMATCH DETECTED!");
            DAWN_OF_WAR_LOG_WARN("LAA_TRACKER", "Patcher reports: %s", g_lastLAAState.isLAAEnabled ? "ENABLED" : "DISABLED");
            DAWN_OF_WAR_LOG_WARN("LAA_TRACKER", "Memory DLL reports: %s", laaEnabled ? "ENABLED" : "DISABLED");
        }
        
        // Log memory utilization differences
        size_t memoryDiff = (totalMemory > g_lastLAAState.totalPhysicalMemory) ? 
                           (totalMemory - g_lastLAAState.totalPhysicalMemory) :
                           (g_lastLAAState.totalPhysicalMemory - totalMemory);
        
        if (memoryDiff > 0) {
            DAWN_OF_WAR_LOG_INFO("LAA_TRACKER", "Memory difference: %zu MB", memoryDiff / (1024 * 1024));
        }
    } else {
        DAWN_OF_WAR_LOG_INFO("LAA_TRACKER", "No patcher LAA state available for comparison");
    }
    
    LeaveCriticalSection(&g_logCriticalSection);
}

// Function to log LAA transition events
void LogLAATransition(const char* source, const char* executablePath, 
                     bool fromState, bool toState, const char* reason) {
    if (!g_dawnOfWarLogger.initialized) return;
    
    EnterCriticalSection(&g_logCriticalSection);
    
    DAWN_OF_WAR_LOG_INFO("LAA_TRACKER", "=== LAA Transition Event ===");
    DAWN_OF_WAR_LOG_INFO("LAA_TRACKER", "Source: %s", source);
    DAWN_OF_WAR_LOG_INFO("LAA_TRACKER", "Executable: %s", executablePath);
    DAWN_OF_WAR_LOG_INFO("LAA_TRACKER", "Transition: %s -> %s", 
                         fromState ? "ENABLED" : "DISABLED", 
                         toState ? "ENABLED" : "DISABLED");
    DAWN_OF_WAR_LOG_INFO("LAA_TRACKER", "Reason: %s", reason);
    DAWN_OF_WAR_LOG_INFO("LAA_TRACKER", "Timestamp: %lld", (long long)time(nullptr));
    
    // Update stored state
    if (g_laaStateInitialized) {
        g_lastLAAState.isLAAEnabled = toState;
        g_lastLAAState.timestamp = time(nullptr);
    }
    
    LeaveCriticalSection(&g_logCriticalSection);
}

// Function to get current LAA state summary
void GetLAAStateSummary(char* buffer, size_t bufferSize) {
    if (!g_dawnOfWarLogger.initialized || !g_laaStateInitialized) {
        strncpy_s(buffer, bufferSize, "LAA state not initialized", _TRUNCATE);
        return;
    }
    
    EnterCriticalSection(&g_logCriticalSection);
    
    sprintf_s(buffer, bufferSize,
        "LAA State Summary:\n"
        "  Executable: %s\n"
        "  LAA Enabled: %s\n"
        "  64-bit OS: %s\n"
        "  Total Memory: %zu MB\n"
        "  Available Memory: %zu MB\n"
        "  Address Space: %zu MB\n"
        "  Image Base: 0x%p\n"
        "  Last Updated: %lld",
        g_lastLAAState.executablePath,
        g_lastLAAState.isLAAEnabled ? "YES" : "NO",
        g_lastLAAState.is64BitOS ? "YES" : "NO",
        g_lastLAAState.totalPhysicalMemory / (1024 * 1024),
        g_lastLAAState.availablePhysicalMemory / (1024 * 1024),
        g_lastLAAState.usableAddressSpace / (1024 * 1024),
        (void*)g_lastLAAState.processImageBase,
        (long long)g_lastLAAState.timestamp);
    
    LeaveCriticalSection(&g_logCriticalSection);
}
