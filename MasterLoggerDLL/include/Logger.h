// Dawn of War Soulstorm Performance Logger - Enhanced logging system for game optimization

#pragma once

#include <windows.h>
#include <stdarg.h>

// Dawn of War Logger Log Levels
typedef enum {
    DAWN_OF_WAR_LOG_TRACE = 0,
    DAWN_OF_WAR_LOG_DEBUG = 1,
    DAWN_OF_WAR_LOG_INFO = 2,
    DAWN_OF_WAR_LOG_WARN = 3,
    DAWN_OF_WAR_LOG_ERROR = 4,
    DAWN_OF_WAR_LOG_FATAL = 5
} DawnOfWarLogLevel;

// Dawn of War Logger Output Destinations
typedef enum {
    DAWN_OF_WAR_OUTPUT_CONSOLE = 1,
    DAWN_OF_WAR_OUTPUT_FILE = 2,
    DAWN_OF_WAR_OUTPUT_MEMORY = 4,
    DAWN_OF_WAR_OUTPUT_NETWORK = 8
} DawnOfWarLogOutput;

// Dawn of War Logger Internal Data Structures
typedef struct {
    DWORD timestamp;
    DWORD threadId;
    DawnOfWarLogLevel level;
    char module[64];
    char message[1024];
    char stackTrace[2048];
    DWORD messageLength;
} DawnOfWarLogEntry;

typedef struct {
    DawnOfWarLogEntry* entries;
    DWORD capacity;
    DWORD head;
    DWORD tail;
    DWORD count;
    CRITICAL_SECTION cs;
} DawnOfWarRingBuffer;

typedef struct {
    char logPath[MAX_PATH];
    DawnOfWarLogLevel globalLevel;
    DWORD outputs;
    DWORD maxFileSizeMB;
    DWORD rotationCount;
    BOOL enableNetwork;
    DWORD bufferSize;
    BOOL enableColors;
    BOOL enableStackTrace;
    char networkAddress[256];
    char networkHost[256];
    int networkPort;
} DawnOfWarLogConfig;

typedef struct {
    DawnOfWarLogConfig config;
    HANDLE logFile;
    HANDLE workerThread;
    HANDLE shutdownEvent;
    HANDLE configChangeEvent;
    HANDLE consoleHandle;
    WORD defaultConsoleAttributes;
    DawnOfWarRingBuffer ringBuffer;
    BOOL initialized;
    LARGE_INTEGER performanceFrequency;
    LARGE_INTEGER lastStatsTime;
    DWORD messagesLogged;
    DWORD messagesDropped;
    DWORD totalMessages;
    DWORD messagesPerSecond;
    CRITICAL_SECTION statsCs;
} DawnOfWarLoggerState;

typedef struct DawnOfWarModuleLevel {
    char module[64];
    DawnOfWarLogLevel level;
    struct DawnOfWarModuleLevel* next;
} DawnOfWarModuleLevel;

// Dawn of War Logger Global Variables
extern DawnOfWarLoggerState g_dawnOfWarLogger;
extern DawnOfWarModuleLevel* g_dawnOfWarModuleLevels;
extern CRITICAL_SECTION g_dawnOfWarModuleLevelsCs;

#ifdef __cplusplus
extern "C" {
#endif

// Dawn of War Logger Core Functions
__declspec(dllexport) void DawnOfWarLog_Initialize(const char* configPath);
__declspec(dllexport) void DawnOfWarLog_Shutdown(void);
__declspec(dllexport) void DawnOfWarLog_SetLevel(DawnOfWarLogLevel level);
__declspec(dllexport) void DawnOfWarLog_SetModuleLevel(const char* module, DawnOfWarLogLevel level);

// Dawn of War Logger Main Logging Function
__declspec(dllexport) void DawnOfWarLog_Write(DawnOfWarLogLevel level, const char* module, const char* format, ...);

// Dawn of War Logger Specialized Functions
__declspec(dllexport) void DawnOfWarLog_HexDump(DawnOfWarLogLevel level, const char* module, const void* data, size_t size);
__declspec(dllexport) void DawnOfWarLog_WriteVA(DawnOfWarLogLevel level, const char* module, const char* format, va_list args);

// Dawn of War Logger Configuration and Control
__declspec(dllexport) void DawnOfWarLog_Flush(void);
__declspec(dllexport) void DawnOfWarLog_ReloadConfig(void);
__declspec(dllexport) BOOL DawnOfWarLog_IsLevelEnabled(DawnOfWarLogLevel level, const char* module);

// Dawn of War Logger Performance and Statistics
__declspec(dllexport) void DawnOfWarLog_GetStats(DWORD* messagesPerSec, DWORD* queueDepth, DWORD* memoryUsage);

// Dawn of War Logger Crash Handling
__declspec(dllexport) void DawnOfWarLog_SetCrashHandler(void);
__declspec(dllexport) void DawnOfWarLog_WriteStackTrace(DawnOfWarLogLevel level, const char* module);

#ifdef __cplusplus
}

// Dawn of War Logger C++ Wrapper Class
class DawnOfWarLogger {
public:
    static void Initialize(const char* configPath = nullptr) {
        DawnOfWarLog_Initialize(configPath);
    }
    
    static void Shutdown() {
        DawnOfWarLog_Shutdown();
    }
    
    static void SetLevel(DawnOfWarLogLevel level) {
        DawnOfWarLog_SetLevel(level);
    }
    
    static void SetModuleLevel(const char* module, DawnOfWarLogLevel level) {
        DawnOfWarLog_SetModuleLevel(module, level);
    }
    
    static void Write(DawnOfWarLogLevel level, const char* module, const char* format, ...) {
        va_list args;
        va_start(args, format);
        DawnOfWarLog_WriteVA(level, module, format, args);
        va_end(args);
    }
    
    static void Trace(const char* module, const char* format, ...) {
        va_list args;
        va_start(args, format);
        DawnOfWarLog_WriteVA(DAWN_OF_WAR_LOG_TRACE, module, format, args);
        va_end(args);
    }
    
    static void Debug(const char* module, const char* format, ...) {
        va_list args;
        va_start(args, format);
        DawnOfWarLog_WriteVA(DAWN_OF_WAR_LOG_DEBUG, module, format, args);
        va_end(args);
    }
    
    static void Info(const char* module, const char* format, ...) {
        va_list args;
        va_start(args, format);
        DawnOfWarLog_WriteVA(DAWN_OF_WAR_LOG_INFO, module, format, args);
        va_end(args);
    }
    
    static void Warn(const char* module, const char* format, ...) {
        va_list args;
        va_start(args, format);
        DawnOfWarLog_WriteVA(DAWN_OF_WAR_LOG_WARN, module, format, args);
        va_end(args);
    }
    
    static void Error(const char* module, const char* format, ...) {
        va_list args;
        va_start(args, format);
        DawnOfWarLog_WriteVA(DAWN_OF_WAR_LOG_ERROR, module, format, args);
        va_end(args);
    }
    
    static void Fatal(const char* module, const char* format, ...) {
        va_list args;
        va_start(args, format);
        DawnOfWarLog_WriteVA(DAWN_OF_WAR_LOG_FATAL, module, format, args);
        va_end(args);
    }
    
    static void HexDump(DawnOfWarLogLevel level, const char* module, const void* data, size_t size) {
        DawnOfWarLog_HexDump(level, module, data, size);
    }
    
    static void Flush() {
        DawnOfWarLog_Flush();
    }
    
    static void ReloadConfig() {
        DawnOfWarLog_ReloadConfig();
    }
    
    static bool IsLevelEnabled(DawnOfWarLogLevel level, const char* module) {
        return DawnOfWarLog_IsLevelEnabled(level, module) != FALSE;
    }
};

// Legacy compatibility macros for Dawn of War Logger (function name mapping only)
#define Log_Initialize DawnOfWarLog_Initialize
#define Log_Shutdown DawnOfWarLog_Shutdown
#define Log_Write DawnOfWarLog_Write
#define Log_WriteVA DawnOfWarLog_WriteVA
#define Log_HexDump DawnOfWarLog_HexDump
#define Log_Flush DawnOfWarLog_Flush
#define Log_ReloadConfig DawnOfWarLog_ReloadConfig
#define Log_IsLevelEnabled DawnOfWarLog_IsLevelEnabled
#define Log_SetCrashHandler DawnOfWarLog_SetCrashHandler
#define Log_WriteStackTrace DawnOfWarLog_WriteStackTrace
#define Log_GetStats DawnOfWarLog_GetStats
#define Log_SetLevel DawnOfWarLog_SetLevel
#define Log_SetModuleLevel DawnOfWarLog_SetModuleLevel

#endif // DAWN_OF_WAR_LOGGER_H

// Dawn of War Logger Convenience Macros (use new naming)
#define DAWN_OF_WAR_LOG_TRACE(module, ...) DawnOfWarLogger::Trace(module, __VA_ARGS__)
#define DAWN_OF_WAR_LOG_DEBUG(module, ...) DawnOfWarLogger::Debug(module, __VA_ARGS__)
#define DAWN_OF_WAR_LOG_INFO(module, ...) DawnOfWarLogger::Info(module, __VA_ARGS__)
#define DAWN_OF_WAR_LOG_WARN(module, ...) DawnOfWarLogger::Warn(module, __VA_ARGS__)
#define DAWN_OF_WAR_LOG_ERROR(module, ...) DawnOfWarLogger::Error(module, __VA_ARGS__)
#define DAWN_OF_WAR_LOG_FATAL(module, ...) DawnOfWarLogger::Fatal(module, __VA_ARGS__)

// Legacy compatibility macros (map to new constants)
#ifndef LOG_TRACE
#define LOG_TRACE DAWN_OF_WAR_LOG_TRACE
#endif
#ifndef LOG_DEBUG
#define LOG_DEBUG DAWN_OF_WAR_LOG_DEBUG
#endif
#ifndef LOG_INFO
#define LOG_INFO DAWN_OF_WAR_LOG_INFO
#endif
#ifndef LOG_WARN
#define LOG_WARN DAWN_OF_WAR_LOG_WARN
#endif
#ifndef LOG_ERROR
#define LOG_ERROR DAWN_OF_WAR_LOG_ERROR
#endif
#ifndef LOG_FATAL
#define LOG_FATAL DAWN_OF_WAR_LOG_FATAL
#endif

// Compile-time filtering macros
#ifndef LOG_LEVEL_MIN
#define LOG_LEVEL_MIN DAWN_OF_WAR_LOG_TRACE
#endif

#if LOG_LEVEL_MIN <= DAWN_OF_WAR_LOG_TRACE
#define LOG_TRACE_IF_ENABLED(module, ...) LOG_TRACE(module, __VA_ARGS__)
#else
#define LOG_TRACE_IF_ENABLED(module, ...)
#endif

#if LOG_LEVEL_MIN <= DAWN_OF_WAR_LOG_DEBUG
#define LOG_DEBUG_IF_ENABLED(module, ...) LOG_DEBUG(module, __VA_ARGS__)
#else
#define LOG_DEBUG_IF_ENABLED(module, ...)
#endif

#if LOG_LEVEL_MIN <= DAWN_OF_WAR_LOG_INFO
#define LOG_INFO_IF_ENABLED(module, ...) LOG_INFO(module, __VA_ARGS__)
#else
#define LOG_INFO_IF_ENABLED(module, ...)
#endif

#if LOG_LEVEL_MIN <= DAWN_OF_WAR_LOG_WARN
#define LOG_WARN_IF_ENABLED(module, ...) LOG_WARN(module, __VA_ARGS__)
#else
#define LOG_WARN_IF_ENABLED(module, ...)
#endif

#if LOG_LEVEL_MIN <= DAWN_OF_WAR_LOG_ERROR
#define LOG_ERROR_IF_ENABLED(module, ...) LOG_ERROR(module, __VA_ARGS__)
#else
#define LOG_ERROR_IF_ENABLED(module, ...)
#endif

#if LOG_LEVEL_MIN <= DAWN_OF_WAR_LOG_FATAL
#define LOG_FATAL_IF_ENABLED(module, ...) LOG_FATAL(module, __VA_ARGS__)
#else
#define LOG_FATAL_IF_ENABLED(module, ...)
#endif
