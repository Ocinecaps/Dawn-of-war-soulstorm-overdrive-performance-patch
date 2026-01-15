# Master Logger DLL for Dawn of War: Soulstorm

A comprehensive, centralized logging system designed for Dawn of War: Soulstorm modding and debugging.

## Features

- **Multiple Log Levels**: TRACE, DEBUG, INFO, WARN, ERROR, FATAL
- **Async Logging**: Dedicated worker thread for minimal performance impact
- **Multiple Outputs**: Console, file with rotation, memory ring buffer, network streaming
- **Runtime Configuration**: Hot-reloadable INI file with module-specific settings
- **Crash Resilience**: Automatic stack trace capture and mini-dump generation
- **Thread-Safe**: Lock-free data structures for high-frequency logging
- **Performance Optimized**: <5ms overhead per log call, <50MB memory usage

## Quick Start

### Basic Usage

```cpp
#include "Logger.h"

// Initialize logger
Log_Initialize("logger.ini");

// Log messages
LOG_INFO("MyModule", "Application started");
LOG_ERROR("MyModule", "Error occurred: %s", errorMessage);

// Cleanup
Log_Shutdown();
```

### C++ Interface

```cpp
#include "Logger.h"

// Initialize
Logger::Initialize("logger.ini");

// Use convenience methods
Logger::Info("MyModule", "Processing %d items", count);
Logger::Error("MyModule", "Failed to process item %d", itemId);

// Set module-specific levels
Logger::SetModuleLevel("MyModule", LOG_DEBUG);
```

## Configuration

Create a `logger.ini` file:

```ini
[General]
LogLevel=INFO
Outputs=Console,File,Memory

[File]
Path=logs
MaxSizeMB=100
RotationCount=5

[Network]
Enable=0
Host=localhost
Port=514

[Performance]
BufferSize=1024
EnableColors=1
EnableStackTrace=1

[Modules]
MemoryDLL=DEBUG
GameLogic=INFO
Rendering=WARN
```

## Integration Methods

### 1. Static Linking (Recommended)

1. Add `Logger.h` to your project
2. Link against `Logger.lib`
3. Include `Logger.h` in source files

### 2. Dynamic Loading

```cpp
// Load at runtime
HMODULE loggerDll = LoadLibraryA("MasterLogger.dll");
auto pLog_Initialize = (Log_InitializeFunc)GetProcAddress(loggerDll, "Log_Initialize");
auto pLog_Write = (Log_WriteFunc)GetProcAddress(loggerDll, "Log_Write");

pLog_Initialize("logger.ini");
pLog_Write(LOG_INFO, "MyModule", "Dynamic loading works!");
```

### 3. EXE Injector Integration

Use the provided `LoggerInjector` class to inject `MasterLogger.dll` into the game process:

```cpp
LoggerInjector::InjectIntoProcess(processId);
```

## API Reference

### Core Functions

```c
void Log_Initialize(const char* configPath);
void Log_Shutdown(void);
void Log_SetLevel(LogLevel level);
void Log_SetModuleLevel(const char* module, LogLevel level);
void Log_Write(LogLevel level, const char* module, const char* format, ...);
void Log_HexDump(LogLevel level, const char* module, const void* data, size_t size);
void Log_Flush(void);
BOOL Log_IsLevelEnabled(LogLevel level, const char* module);
```

### C++ Wrapper

```cpp
class Logger {
    static void Initialize(const char* configPath = nullptr);
    static void Write(LogLevel level, const char* module, const char* format, ...);
    static void Trace/Debug/Info/Warn/Error/Fatal(const char* module, const char* format, ...);
    static void HexDump(LogLevel level, const char* module, const void* data, size_t size);
    static void SetLevel(LogLevel level);
    static void SetModuleLevel(const char* module, LogLevel level);
    static void Flush();
};
```

## Performance Considerations

- **Async Processing**: All log entries are processed in a dedicated worker thread
- **Lock-Free Ring Buffer**: High-frequency logging with minimal contention
- **Compile-Time Filtering**: Use `LOG_LEVEL_MIN` to filter messages at compile time
- **Module-Specific Levels**: Fine-grained control over logging verbosity

### Performance Tuning

```ini
[Performance]
BufferSize=2048          ; Increase for high-volume logging
EnableColors=0           ; Disable for console performance
EnableStackTrace=0       ; Disable for crash performance
```

## Crash Handling

The logger automatically captures:

- Stack traces on ERROR/FATAL levels
- Mini-dumps on unhandled exceptions
- Signal handlers for common crash signals

```cpp
// Manual stack trace capture
Log_WriteStackTrace(LOG_ERROR, "MyModule");

// Set up crash handlers
Log_SetCrashHandler();
```

## Log Format

```
[HH:MM:SS.mmm] [ThreadID] [LEVEL] [Module] Message
```

Example:
```
[14:23:45.678] [00001234] [INFO ] [GameLogic] Player 1 connected
[14:23:45.679] [00001234] [DEBUG] [Network] Socket 123 established
[14:23:45.680] [00001235] [WARN ] [Rendering] Frame time exceeded 16.67ms
```

## Module Integration Examples

### Memory DLL Integration

```cpp
class MemoryDLLLogger {
public:
    static void LogAllocation(void* ptr, size_t size, const char* function) {
        LOG_DEBUG("MemoryDLL", "Allocated %zu bytes at 0x%p in %s", size, ptr, function);
    }
    
    static void LogPoolStats(const char* poolName, size_t used, size_t capacity) {
        LOG_INFO("MemoryDLL", "Pool '%s': %zu/%zu bytes used (%.1f%%)",
            poolName, used, capacity, (double)used / capacity * 100.0);
    }
};
```

### Performance Monitoring

```cpp
class PerformanceLogger {
public:
    static void LogFrameTime(float frameTimeMs) {
        if (frameTimeMs > 16.67f) {
            LOG_WARN("Performance", "Slow frame: %.2f ms", frameTimeMs);
        }
    }
};
```

## Troubleshooting

### Common Issues

1. **DLL Not Found**: Ensure `MasterLogger.dll` is in the same directory as your EXE
2. **Config Not Found**: Place `logger.ini` in the same directory as the DLL
3. **Permission Denied**: Ensure write permissions for log directory
4. **High Memory Usage**: Reduce `BufferSize` in configuration

### Debug Mode

Enable debug logging:

```cpp
Logger::SetModuleLevel("Logger", LOG_TRACE);
```

### Performance Issues

1. Disable console colors: `EnableColors=0`
2. Reduce buffer size: `BufferSize=512`
3. Use compile-time filtering: `#define LOG_LEVEL_MIN LOG_INFO`

## Building

### Requirements

- Visual Studio 2019 or later
- Windows SDK 8.1 or later
- C++17 support

### Build Steps

1. Open `MasterLogger.sln`
2. Build Release configuration
3. Output: `MasterLogger.dll` and `Logger.lib`

## Testing

Run the performance test:

```cpp
PerformanceTest();  // Logs 10,000 messages and reports timing
```

Expected performance: >10,000 messages/second on modern hardware.

## License

This logger is designed specifically for Dawn of War: Soulstorm modding and debugging purposes.
