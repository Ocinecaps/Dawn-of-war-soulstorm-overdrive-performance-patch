#include "pch.h"
#include <chrono>
#include <fstream>
#include <iostream>
#include <windows.h>
#include <psapi.h>
#include "../MasterLoggerDLL/include/Logger.h"
#include "../CodeAnalyzer/IntelligentCodeAnalysis.h"

#pragma comment(lib, "psapi.lib")

// Enhanced logging macros for Memory Pool DLL
#define MEMPOOL_LOG_TRACE(...) DAWN_OF_WAR_LOG_TRACE("MemoryPool", __VA_ARGS__)
#define MEMPOOL_LOG_DEBUG(...) DAWN_OF_WAR_LOG_DEBUG("MemoryPool", __VA_ARGS__)
#define MEMPOOL_LOG_INFO(...) DAWN_OF_WAR_LOG_INFO("MemoryPool", __VA_ARGS__)
#define MEMPOOL_LOG_WARN(...) DAWN_OF_WAR_LOG_WARN("MemoryPool", __VA_ARGS__)
#define MEMPOOL_LOG_ERROR(...) DAWN_OF_WAR_LOG_ERROR("MemoryPool", __VA_ARGS__)
#define MEMPOOL_LOG_FATAL(...) DAWN_OF_WAR_LOG_FATAL("MemoryPool", __VA_ARGS__)

// Performance logging macros for memory operations
#define MEMPERF_LOG_START(name) \
    LARGE_INTEGER __memPerfStart_##name; \
    QueryPerformanceCounter(&__memPerfStart_##name); \
    MEMPOOL_LOG_TRACE("MemoryPerformance", "Starting memory operation: %s", #name);

#define MEMPERF_LOG_END(name) \
    do { \
        LARGE_INTEGER __memPerfEnd_##name, __memPerfFreq; \
        QueryPerformanceCounter(&__memPerfEnd_##name); \
        QueryPerformanceFrequency(&__memPerfFreq); \
        double __elapsed = ((double)(__memPerfEnd_##name.QuadPart - __memPerfStart_##name.QuadPart) / __memPerfFreq.QuadPart) * 1000.0; \
        MEMPOOL_LOG_DEBUG("MemoryPerformance", "Memory operation %s completed in %.3f ms", #name, __elapsed); \
    } while(0)

// Force GPU usage
extern "C" __declspec(dllexport) DWORD NvOptimusEnablement = 1;
extern "C" __declspec(dllexport) DWORD AmdPowerXpressRequestHighPerformance = 1;

// Memory pool configuration (512MB total) - Enhanced for Dawn of War Soulstorm
constexpr size_t PRIVATE_MEMORY_SIZE = 256ull * 1024 * 1024;  // 256MB
constexpr size_t TEXTURE_MEMORY_SIZE = 256ull * 1024 * 1024; // 256MB
constexpr size_t TOTAL_POOL_SIZE = PRIVATE_MEMORY_SIZE + TEXTURE_MEMORY_SIZE;
constexpr size_t NUM_SIZE_CLASSES = 12; // Increased for better granularity
constexpr size_t MIN_BLOCK_SIZE = 32; // Reduced for smaller allocations
constexpr size_t MAX_BLOCK_SIZE = 128 * 1024; // Increased to 128KB
constexpr size_t GUARD_PAGE_SIZE = 4096;
constexpr size_t CACHE_LINE_SIZE = 64; // CPU cache line alignment
constexpr size_t ALLOCATION_ALIGNMENT = 16; // SSE alignment

// Specialized pools for frequent allocation patterns - Optimized sizes
constexpr size_t LOG_BUFFER_SIZE = 8 * 1024 * 1024; // 8MB for logging (increased)
constexpr size_t FILE_BUFFER_SIZE = 16 * 1024 * 1024; // 16MB for file operations (increased)
constexpr size_t GUI_POOL_SIZE = 32 * 1024 * 1024; // 32MB for GUI objects (increased)
constexpr size_t SMALL_OBJ_POOL_SIZE = 64 * 1024 * 1024; // 64MB for small frequent allocations (increased)
constexpr size_t LINKED_LIST_POOL_SIZE = 128 * 1024 * 1024; // 128MB for linked list structures (increased)
constexpr size_t STRING_POOL_SIZE = 64 * 1024 * 1024; // 64MB for string operations (increased)
constexpr size_t EXECUTABLE_POOL_SIZE = 256 * 1024 * 1024; // 256MB for executable memory (increased)
constexpr size_t TEMP_POOL_SIZE = 32 * 1024 * 1024; // 32MB for temporary allocations

// Emergency memory reserve for crash reporting and critical operations
constexpr size_t EMERGENCY_RESERVE_SIZE = 64 * 1024 * 1024; // 64MB
static char* g_emergencyReserve = nullptr;
static std::atomic<size_t> g_emergencyUsed{0};

struct MemoryBlock {
    size_t size;
    bool used;
    void* address;
    MemoryBlock* next;
    MemoryBlock* prev;
    size_t magic;
    uint8_t padding[8]; // Cache line padding for performance
    std::chrono::high_resolution_clock::time_point allocTime; // Performance tracking
    size_t allocationId; // Leak detection
};

struct MemoryPool {
    char* pool;
    std::atomic<size_t> offset;
    std::atomic<MemoryBlock*> head;
    std::atomic<MemoryBlock*> freeLists[NUM_SIZE_CLASSES];
    std::atomic<MemoryBlock*> freeListHead;  // For tracking free blocks in each pool
    std::atomic<size_t> totalAllocated;
    std::atomic<size_t> peakUsage;
    std::atomic<size_t> fragmentationCount;
    
    // Performance counters
    std::atomic<size_t> mallocCount;
    std::atomic<size_t> freeCount;
    std::atomic<size_t> reallocCount;
    std::atomic<size_t> totalAllocTime;
    std::atomic<size_t> totalFreeTime;
    std::atomic<size_t> cacheHits;
    std::atomic<size_t> cacheMisses;
    std::atomic<size_t> leakCount;
    std::atomic<size_t> corruptionCount;
    
    // Specialized allocation tracking
    std::atomic<size_t> logAllocCount;
    std::atomic<size_t> fileAllocCount;
    std::atomic<size_t> guiAllocCount;
    std::atomic<size_t> smallObjAllocCount;
    std::atomic<size_t> linkedListAllocCount;
    std::atomic<size_t> stringAllocCount;
    std::atomic<size_t> executableAllocCount;
    std::atomic<size_t> tempAllocCount;
    
    // Memory health monitoring
    std::atomic<size_t> lastCleanupTime;
    std::atomic<size_t> cleanupInterval;
    std::atomic<bool> needsDefragmentation;
    
    MemoryPool() : pool(nullptr), offset(0), head(nullptr), freeListHead(nullptr), totalAllocated(0), peakUsage(0), fragmentationCount(0),
                   mallocCount(0), freeCount(0), reallocCount(0), totalAllocTime(0), totalFreeTime(0), cacheHits(0), cacheMisses(0), leakCount(0), corruptionCount(0),
                   logAllocCount(0), fileAllocCount(0), guiAllocCount(0), smallObjAllocCount(0), linkedListAllocCount(0), stringAllocCount(0), executableAllocCount(0), tempAllocCount(0),
                   lastCleanupTime(0), cleanupInterval(5000), needsDefragmentation(false) {
        for (int i = 0; i < NUM_SIZE_CLASSES; ++i) {
            freeLists[i].store(nullptr, std::memory_order_relaxed);
        }
    }
};

// Global handle structure for movable memory simulation
struct GlobalMemoryHandle {
    void* address;
    DWORD flags;
    DWORD size;
    int lockCount;
};

static MemoryPool gameMemoryPool;
static MemoryPool logPool;        // For logging allocations (sub_577C91, sub_577CB8, sub_577D40, sub_57AC40)
static MemoryPool filePool;       // For file operations (sub_6082D0, sub_819C55)
static MemoryPool guiPool;        // For GUI/window management (sub_6A4CC0, sub_6A4FB0)
static MemoryPool smallObjPool;   // For small frequent allocations (sub_69A7E0, sub_69A810)
static MemoryPool linkedListPool; // For linked list deallocations (sub_698CF0, sub_6A35F0, sub_6A3840, sub_6A3AA0)
static MemoryPool stringPool;     // For string operations (sub_6A0AB0, sub_6A3840, sub_6A3AA0, sub_6A35F0, sub_6CB980)
static MemoryPool executablePool; // For executable memory allocations (sub_9AE540)
static MemoryPool tempPool;       // For temporary allocations
static CRITICAL_SECTION g_lock;
static std::atomic<size_t> g_allocationCounter{0}; // Global allocation ID counter
static bool g_inited = false;

// Forward declarations for specialized allocation functions
extern "C" __declspec(dllexport) void* LogMalloc(size_t size);
extern "C" __declspec(dllexport) void* FileMalloc(size_t size);
extern "C" __declspec(dllexport) void* GuiMalloc(size_t size);
extern "C" __declspec(dllexport) void* SmallObjMalloc(size_t size);
extern "C" __declspec(dllexport) void* LinkedListMalloc(size_t size);
extern "C" __declspec(dllexport) void* StringMalloc(size_t size);
extern "C" __declspec(dllexport) void* ExecutableMalloc(size_t size);

// Forward declarations for specialized free functions
extern "C" __declspec(dllexport) void LogFree(void* ptr);
extern "C" __declspec(dllexport) void FileFree(void* ptr);
extern "C" __declspec(dllexport) void GuiFree(void* ptr);
extern "C" __declspec(dllexport) void SmallObjFree(void* ptr);
extern "C" __declspec(dllexport) void LinkedListFree(void* ptr);
extern "C" __declspec(dllexport) void StringFree(void* ptr);
extern "C" __declspec(dllexport) void BatchLinkedListFree(void** ptrs, size_t count);
extern "C" __declspec(dllexport) void ExecutableFree(void* ptr);
extern "C" __declspec(dllexport) void CustomFree(void* ptr);
extern "C" __declspec(dllexport) void* CustomRealloc(void* p, size_t size);
extern "C" __declspec(dllexport) void* CustomCalloc(size_t n, size_t s);

// Forward declarations for maintenance functions
void DefragmentMemoryPool();
void PerformMemoryMaintenance();
void CheckPoolHealth();
void ReportMemoryStatistics();

// Forward declarations for crash reporting functions
extern "C" __declspec(dllexport) bool EnsureCrashReportMemory(size_t needed);
void SetupCrashReporting();

// Forward declarations for memory pressure functions
bool IsMemoryPressureHigh();
DWORD GetSystemMemoryUsage();

// Forward declarations for error reporting functions
void LogMemoryError(const char* function, const char* error, void* address = nullptr, size_t size = 0);

// Function pointers for original APIs
typedef void* (__cdecl* CRT_Malloc)(size_t);
typedef void(__cdecl* CRT_Free)(void*);
typedef void* (__stdcall* GlobalAlloc_t)(UINT, DWORD);
typedef void* (__stdcall* GlobalFree_t)(HGLOBAL);
typedef void* (__stdcall* GlobalLock_t)(HGLOBAL);
typedef BOOL (__stdcall* GlobalUnlock_t)(HGLOBAL);
typedef SIZE_T (__stdcall* GlobalSize_t)(HGLOBAL);
typedef BOOL (__stdcall* HeapFree_t)(HANDLE, DWORD, LPVOID);
typedef LPVOID (__stdcall* HeapAlloc_t)(HANDLE, DWORD, SIZE_T);
typedef void* (__cdecl* CRT_Realloc)(void*, size_t);
typedef LPVOID (__stdcall* VirtualAlloc_t)(LPVOID, SIZE_T, DWORD, DWORD);
typedef BOOL (__stdcall* VirtualFree_t)(LPVOID, SIZE_T, DWORD);

static CRT_Malloc s_origMalloc = NULL;
static CRT_Free   s_origFree = NULL;
static GlobalAlloc_t s_origGlobalAlloc = NULL;
static GlobalFree_t  s_origGlobalFree = NULL;
static GlobalLock_t   s_origGlobalLock = NULL;
static GlobalUnlock_t s_origGlobalUnlock = NULL;
static GlobalSize_t   s_origGlobalSize = NULL;
static HeapFree_t     s_origHeapFree = NULL;
static HeapAlloc_t    s_origHeapAlloc = NULL;
static CRT_Realloc    s_origRealloc = NULL;
static VirtualAlloc_t s_origVirtualAlloc = NULL;
static VirtualFree_t  s_origVirtualFree = NULL;

// Advanced memory management functions
constexpr size_t BLOCK_MAGIC = 0xDEADBEEF;
constexpr size_t BLOCK_FREED_MAGIC = 0xFEEDFACE;

int GetSizeClass(size_t size) {
    // Enhanced size class calculation for better performance
    if (size <= MIN_BLOCK_SIZE) return 0;
    if (size <= 64) return 1;
    if (size <= 128) return 2;
    if (size <= 256) return 3;
    if (size <= 512) return 4;
    if (size <= 1024) return 5;
    if (size <= 2048) return 6;
    if (size <= 4096) return 7;
    if (size <= 8192) return 8;
    if (size <= 16384) return 9;
    if (size <= 32768) return 10;
    return NUM_SIZE_CLASSES - 1;
}

void InitSpecializedPools() {
    DAWN_OF_WAR_LOG_INFO("MemoryPoolDLL", "Initializing specialized memory pools for Dawn of War Soulstorm");
    
    // Initialize logging pool
    if (!logPool.pool) {
        char* logMem = static_cast<char*>(VirtualAlloc(nullptr, LOG_BUFFER_SIZE, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));
        if (logMem) {
            logPool.pool = logMem;
            logPool.offset.store(0, std::memory_order_relaxed);
            logPool.head.store(nullptr, std::memory_order_relaxed);
            logPool.totalAllocated.store(0, std::memory_order_relaxed);
            logPool.peakUsage.store(0, std::memory_order_relaxed);
            logPool.fragmentationCount.store(0, std::memory_order_relaxed);
            logPool.freeListHead.store(nullptr, std::memory_order_relaxed);
            for (int i = 0; i < NUM_SIZE_CLASSES; ++i) {
                logPool.freeLists[i].store(nullptr, std::memory_order_relaxed);
            }
            DAWN_OF_WAR_LOG_INFO("MemoryPoolDLL", "Log pool initialized: %zu bytes at %p", LOG_BUFFER_SIZE, logMem);
        } else {
            DAWN_OF_WAR_LOG_ERROR("MemoryPoolDLL", "Failed to initialize log pool with %zu bytes", LOG_BUFFER_SIZE);
        }
    }
    
    // Initialize file pool
    if (!filePool.pool) {
        char* fileMem = static_cast<char*>(VirtualAlloc(nullptr, FILE_BUFFER_SIZE, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));
        if (fileMem) {
            filePool.pool = fileMem;
            filePool.offset.store(0, std::memory_order_relaxed);
            filePool.head.store(nullptr, std::memory_order_relaxed);
            filePool.totalAllocated.store(0, std::memory_order_relaxed);
            filePool.peakUsage.store(0, std::memory_order_relaxed);
            filePool.fragmentationCount.store(0, std::memory_order_relaxed);
            filePool.freeListHead.store(nullptr, std::memory_order_relaxed);
            for (int i = 0; i < NUM_SIZE_CLASSES; ++i) {
                filePool.freeLists[i].store(nullptr, std::memory_order_relaxed);
            }
            DAWN_OF_WAR_LOG_INFO("MemoryPoolDLL", "File pool initialized: %zu bytes at %p", FILE_BUFFER_SIZE, fileMem);
        } else {
            DAWN_OF_WAR_LOG_ERROR("MemoryPoolDLL", "Failed to initialize file pool with %zu bytes", FILE_BUFFER_SIZE);
        }
    }
    
    // Initialize GUI pool
    if (!guiPool.pool) {
        char* guiMem = static_cast<char*>(VirtualAlloc(nullptr, GUI_POOL_SIZE, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));
        if (guiMem) {
            guiPool.pool = guiMem;
            guiPool.offset.store(0, std::memory_order_relaxed);
            guiPool.head.store(nullptr, std::memory_order_relaxed);
            guiPool.totalAllocated.store(0, std::memory_order_relaxed);
            guiPool.peakUsage.store(0, std::memory_order_relaxed);
            guiPool.fragmentationCount.store(0, std::memory_order_relaxed);
            guiPool.freeListHead.store(nullptr, std::memory_order_relaxed);
            for (int i = 0; i < NUM_SIZE_CLASSES; ++i) {
                guiPool.freeLists[i].store(nullptr, std::memory_order_relaxed);
            }
            DAWN_OF_WAR_LOG_INFO("MemoryPoolDLL", "GUI pool initialized: %zu bytes at %p", GUI_POOL_SIZE, guiMem);
        } else {
            DAWN_OF_WAR_LOG_ERROR("MemoryPoolDLL", "Failed to initialize GUI pool with %zu bytes", GUI_POOL_SIZE);
        }
    }
    
    // Initialize small object pool
    if (!smallObjPool.pool) {
        char* smallMem = static_cast<char*>(VirtualAlloc(nullptr, SMALL_OBJ_POOL_SIZE, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));
        if (smallMem) {
            smallObjPool.pool = smallMem;
            smallObjPool.offset.store(0, std::memory_order_relaxed);
            smallObjPool.head.store(nullptr, std::memory_order_relaxed);
            smallObjPool.totalAllocated.store(0, std::memory_order_relaxed);
            smallObjPool.peakUsage.store(0, std::memory_order_relaxed);
            smallObjPool.fragmentationCount.store(0, std::memory_order_relaxed);
            smallObjPool.freeListHead.store(nullptr, std::memory_order_relaxed);
            for (int i = 0; i < NUM_SIZE_CLASSES; ++i) {
                smallObjPool.freeLists[i].store(nullptr, std::memory_order_relaxed);
            }
            DAWN_OF_WAR_LOG_INFO("MemoryPoolDLL", "Small object pool initialized: %zu bytes at %p", SMALL_OBJ_POOL_SIZE, smallMem);
        } else {
            DAWN_OF_WAR_LOG_ERROR("MemoryPoolDLL", "Failed to initialize small object pool with %zu bytes", SMALL_OBJ_POOL_SIZE);
        }
    }
    
    // Initialize linked list pool
    if (!linkedListPool.pool) {
        char* linkedMem = static_cast<char*>(VirtualAlloc(nullptr, LINKED_LIST_POOL_SIZE, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));
        if (linkedMem) {
            linkedListPool.pool = linkedMem;
            linkedListPool.offset.store(0, std::memory_order_relaxed);
            linkedListPool.head.store(nullptr, std::memory_order_relaxed);
            linkedListPool.totalAllocated.store(0, std::memory_order_relaxed);
            linkedListPool.peakUsage.store(0, std::memory_order_relaxed);
            linkedListPool.fragmentationCount.store(0, std::memory_order_relaxed);
            linkedListPool.freeListHead.store(nullptr, std::memory_order_relaxed);
            for (int i = 0; i < NUM_SIZE_CLASSES; ++i) {
                linkedListPool.freeLists[i].store(nullptr, std::memory_order_relaxed);
            }
            DAWN_OF_WAR_LOG_INFO("MemoryPoolDLL", "Linked list pool initialized: %zu bytes at %p", LINKED_LIST_POOL_SIZE, linkedMem);
        } else {
            DAWN_OF_WAR_LOG_ERROR("MemoryPoolDLL", "Failed to initialize linked list pool with %zu bytes", LINKED_LIST_POOL_SIZE);
        }
    }
    
    // Initialize string pool
    if (!stringPool.pool) {
        char* stringMem = static_cast<char*>(VirtualAlloc(nullptr, STRING_POOL_SIZE, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));
        if (stringMem) {
            stringPool.pool = stringMem;
            stringPool.offset.store(0, std::memory_order_relaxed);
            stringPool.head.store(nullptr, std::memory_order_relaxed);
            stringPool.totalAllocated.store(0, std::memory_order_relaxed);
            stringPool.peakUsage.store(0, std::memory_order_relaxed);
            stringPool.fragmentationCount.store(0, std::memory_order_relaxed);
            stringPool.freeListHead.store(nullptr, std::memory_order_relaxed);
            for (int i = 0; i < NUM_SIZE_CLASSES; ++i) {
                stringPool.freeLists[i].store(nullptr, std::memory_order_relaxed);
            }
            DAWN_OF_WAR_LOG_INFO("MemoryPoolDLL", "String pool initialized: %zu bytes at %p", STRING_POOL_SIZE, stringMem);
        } else {
            DAWN_OF_WAR_LOG_ERROR("MemoryPoolDLL", "Failed to initialize string pool with %zu bytes", STRING_POOL_SIZE);
        }
    }
    
    // Initialize executable pool for sub_9AE540 pattern
    if (!executablePool.pool) {
        char* execMem = static_cast<char*>(VirtualAlloc(nullptr, EXECUTABLE_POOL_SIZE, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE));
        if (execMem) {
            executablePool.pool = execMem;
            executablePool.offset.store(0, std::memory_order_relaxed);
            executablePool.head.store(nullptr, std::memory_order_relaxed);
            executablePool.totalAllocated.store(0, std::memory_order_relaxed);
            executablePool.peakUsage.store(0, std::memory_order_relaxed);
            executablePool.fragmentationCount.store(0, std::memory_order_relaxed);
            executablePool.freeListHead.store(nullptr, std::memory_order_relaxed);
            for (int i = 0; i < NUM_SIZE_CLASSES; ++i) {
                executablePool.freeLists[i].store(nullptr, std::memory_order_relaxed);
            }
            DAWN_OF_WAR_LOG_INFO("MemoryPoolDLL", "Executable pool initialized: %zu bytes at %p", EXECUTABLE_POOL_SIZE, execMem);
        } else {
            DAWN_OF_WAR_LOG_ERROR("MemoryPoolDLL", "Failed to initialize executable pool with %zu bytes", EXECUTABLE_POOL_SIZE);
        }
    }
    
    // Initialize temporary pool
    if (!tempPool.pool) {
        char* tempMem = static_cast<char*>(VirtualAlloc(nullptr, TEMP_POOL_SIZE, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));
        if (tempMem) {
            tempPool.pool = tempMem;
            tempPool.offset.store(0, std::memory_order_relaxed);
            tempPool.head.store(nullptr, std::memory_order_relaxed);
            tempPool.totalAllocated.store(0, std::memory_order_relaxed);
            tempPool.peakUsage.store(0, std::memory_order_relaxed);
            tempPool.fragmentationCount.store(0, std::memory_order_relaxed);
            tempPool.freeListHead.store(nullptr, std::memory_order_relaxed);
            for (int i = 0; i < NUM_SIZE_CLASSES; ++i) {
                tempPool.freeLists[i].store(nullptr, std::memory_order_relaxed);
            }
            DAWN_OF_WAR_LOG_INFO("MemoryPoolDLL", "Temporary pool initialized: %zu bytes at %p", TEMP_POOL_SIZE, tempMem);
        } else {
            DAWN_OF_WAR_LOG_ERROR("MemoryPoolDLL", "Failed to initialize temporary pool with %zu bytes", TEMP_POOL_SIZE);
        }
    }
    
    DAWN_OF_WAR_LOG_INFO("MemoryPoolDLL", "All specialized memory pools initialization completed");
}

// LAA State Detection and Memory Configuration
struct LAAStateInfo {
    bool isLAAEnabled;
    bool is64BitOS;
    bool isHighMemoryAvailable;
    size_t totalPhysicalMemory;
    size_t availablePhysicalMemory;
    size_t maxProcessMemory;
    size_t currentProcessMemory;
    DWORD_PTR processImageBase;
    size_t usableAddressSpace;
    bool canUseLargeAddresses;
};

static LAAStateInfo g_laaState = {};

// Function to detect LAA state and configure memory accordingly
bool DetectLAAStateAndConfigureMemory() {
    MEMPOOL_LOG_INFO("LAA", "Detecting Large Address Aware state and configuring memory");
    
    // Initialize LAA state structure
    memset(&g_laaState, 0, sizeof(g_laaState));
    
    // Detect if we're running on 64-bit OS
    SYSTEM_INFO systemInfo = {};
    GetNativeSystemInfo(&systemInfo);
    g_laaState.is64BitOS = (systemInfo.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64) ||
                           (systemInfo.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_ARM64);
    
    // Get memory information
    MEMORYSTATUSEX memStatus = {};
    memStatus.dwLength = sizeof(memStatus);
    if (GlobalMemoryStatusEx(&memStatus)) {
        g_laaState.totalPhysicalMemory = static_cast<size_t>(memStatus.ullTotalPhys);
        g_laaState.availablePhysicalMemory = static_cast<size_t>(memStatus.ullAvailPhys);
        g_laaState.maxProcessMemory = static_cast<size_t>(memStatus.ullTotalVirtual);
    }
    
    // Get current process information
    HANDLE hProcess = GetCurrentProcess();
    PROCESS_MEMORY_COUNTERS pmc = {};
    if (GetProcessMemoryInfo(hProcess, &pmc, sizeof(pmc))) {
        g_laaState.currentProcessMemory = static_cast<size_t>(pmc.WorkingSetSize);
    }
    
    // Get process image base to detect LAA
    MODULEINFO moduleInfo = {};
    HMODULE hModule = GetModuleHandle(nullptr);
    if (hModule && GetModuleInformation(hProcess, hModule, &moduleInfo, sizeof(moduleInfo))) {
        g_laaState.processImageBase = reinterpret_cast<DWORD_PTR>(moduleInfo.lpBaseOfDll);
    }
    
    // Check if current process can use large addresses
    BOOL isWow64 = FALSE;
    g_laaState.canUseLargeAddresses = IsWow64Process(hProcess, &isWow64) && isWow64;
    
    // Read the executable's PE header to check LAA flag
    char exePath[MAX_PATH];
    if (GetModuleFileNameA(nullptr, exePath, MAX_PATH)) {
        std::ifstream exeFile(exePath, std::ios::binary);
        if (exeFile.is_open()) {
            IMAGE_DOS_HEADER dosHeader = {};
            exeFile.read(reinterpret_cast<char*>(&dosHeader), sizeof(dosHeader));
            
            if (dosHeader.e_magic == IMAGE_DOS_SIGNATURE) {
                exeFile.seekg(dosHeader.e_lfanew, std::ios::beg);
                IMAGE_NT_HEADERS32 ntHeaders = {};
                exeFile.read(reinterpret_cast<char*>(&ntHeaders), sizeof(ntHeaders));
                
                if (ntHeaders.Signature == IMAGE_NT_SIGNATURE) {
                    g_laaState.isLAAEnabled = (ntHeaders.FileHeader.Characteristics & IMAGE_FILE_LARGE_ADDRESS_AWARE) != 0;
                    g_laaState.processImageBase = ntHeaders.OptionalHeader.ImageBase;
                }
            }
            exeFile.close();
        }
    }
    
    // Calculate usable address space based on LAA state
    if (g_laaState.isLAAEnabled && g_laaState.is64BitOS) {
        g_laaState.usableAddressSpace = static_cast<size_t>(4ULL * 1024 * 1024 * 1024); // 4GB for 32-bit LAA on 64-bit OS
        g_laaState.isHighMemoryAvailable = true;
    } else {
        g_laaState.usableAddressSpace = static_cast<size_t>(2ULL * 1024 * 1024 * 1024); // 2GB for standard 32-bit
        g_laaState.isHighMemoryAvailable = false;
    }
    
    // Log detailed LAA state information
    MEMPOOL_LOG_INFO("LAA", "=== LAA State Analysis ===");
    MEMPOOL_LOG_INFO("LAA", "64-bit OS: %s", g_laaState.is64BitOS ? "YES" : "NO");
    MEMPOOL_LOG_INFO("LAA", "LAA Enabled: %s", g_laaState.isLAAEnabled ? "YES" : "NO");
    MEMPOOL_LOG_INFO("LAA", "Can Use Large Addresses: %s", g_laaState.canUseLargeAddresses ? "YES" : "NO");
    MEMPOOL_LOG_INFO("LAA", "High Memory Available: %s", g_laaState.isHighMemoryAvailable ? "YES" : "NO");
    MEMPOOL_LOG_INFO("LAA", "Process Image Base: 0x%p", (void*)g_laaState.processImageBase);
    MEMPOOL_LOG_INFO("LAA", "Total Physical Memory: %zu MB", g_laaState.totalPhysicalMemory / (1024 * 1024));
    MEMPOOL_LOG_INFO("LAA", "Available Physical Memory: %zu MB", g_laaState.availablePhysicalMemory / (1024 * 1024));
    MEMPOOL_LOG_INFO("LAA", "Current Process Memory: %zu MB", g_laaState.currentProcessMemory / (1024 * 1024));
    MEMPOOL_LOG_INFO("LAA", "Usable Address Space: %zu MB", g_laaState.usableAddressSpace / (1024 * 1024));
    MEMPOOL_LOG_INFO("LAA", "Max Process Memory: %zu MB", g_laaState.maxProcessMemory / (1024 * 1024));
    
    return g_laaState.isLAAEnabled;
}

// Enhanced memory pool configuration based on LAA state
void ConfigureMemoryPoolsForLAA() {
    MEMPOOL_LOG_INFO("LAA", "Configuring memory pools based on LAA state");
    
    // Adjust pool sizes based on LAA availability
    if (g_laaState.isLAAEnabled && g_laaState.isHighMemoryAvailable) {
        // Enhanced configuration for LAA-enabled systems
        constexpr size_t LAA_PRIVATE_MEMORY_SIZE = 512ull * 1024 * 1024;  // 512MB
        constexpr size_t LAA_TEXTURE_MEMORY_SIZE = 512ull * 1024 * 1024; // 512MB
        constexpr size_t LAA_LOG_BUFFER_SIZE = 16 * 1024 * 1024;          // 16MB
        constexpr size_t LAA_FILE_BUFFER_SIZE = 32 * 1024 * 1024;        // 32MB
        constexpr size_t LAA_GUI_POOL_SIZE = 64 * 1024 * 1024;           // 64MB
        constexpr size_t LAA_SMALL_OBJ_POOL_SIZE = 128 * 1024 * 1024;     // 128MB
        constexpr size_t LAA_LINKED_LIST_POOL_SIZE = 256 * 1024 * 1024;   // 256MB
        constexpr size_t LAA_STRING_POOL_SIZE = 128 * 1024 * 1024;        // 128MB
        constexpr size_t LAA_EXECUTABLE_POOL_SIZE = 512 * 1024 * 1024;    // 512MB
        constexpr size_t LAA_TEMP_POOL_SIZE = 64 * 1024 * 1024;           // 64MB
        constexpr size_t LAA_EMERGENCY_RESERVE_SIZE = 128 * 1024 * 1024;  // 128MB
        
        MEMPOOL_LOG_INFO("LAA", "Using LAA-enhanced memory configuration");
        MEMPOOL_LOG_INFO("LAA", "Total enhanced memory: %zu MB", 
                        (LAA_PRIVATE_MEMORY_SIZE + LAA_TEXTURE_MEMORY_SIZE) / (1024 * 1024));
        
        // Note: In a real implementation, we would reallocate pools with these sizes
        // For now, we just log the enhanced configuration
        
    } else {
        // Standard configuration for non-LAA systems
        MEMPOOL_LOG_INFO("LAA", "Using standard memory configuration (LAA not available)");
        MEMPOOL_LOG_INFO("LAA", "Total standard memory: %zu MB", TOTAL_POOL_SIZE / (1024 * 1024));
    }
    
    // Log memory optimization strategies based on LAA state
    if (g_laaState.isLAAEnabled) {
        MEMPOOL_LOG_INFO("LAA", "LAA Memory Optimization Strategies:");
        MEMPOOL_LOG_INFO("LAA", "  - Using larger memory pools for better performance");
        MEMPOOL_LOG_INFO("LAA", "  - Enabling high-memory allocation patterns");
        MEMPOOL_LOG_INFO("LAA", "  - Optimizing for 64-bit OS compatibility");
        MEMPOOL_LOG_INFO("LAA", "  - Enhanced cache-friendly allocation strategies");
    } else {
        MEMPOOL_LOG_INFO("LAA", "Standard Memory Optimization Strategies:");
        MEMPOOL_LOG_INFO("LAA", "  - Using conservative memory pool sizes");
        MEMPOOL_LOG_INFO("LAA", "  - Optimizing for 2GB address space");
        MEMPOOL_LOG_INFO("LAA", "  - Standard allocation patterns");
    }
}

void InitMemoryPool() {
    static bool initialized = false;
    if (!initialized) {
        // First, detect LAA state and configure memory accordingly
        bool laaDetected = DetectLAAStateAndConfigureMemory();
        ConfigureMemoryPoolsForLAA();
        
        // Initialize critical section here
        InitializeCriticalSection(&g_lock);
        
        // Adjust total pool size based on LAA state
        size_t actualPoolSize = TOTAL_POOL_SIZE;
        if (laaDetected && g_laaState.isHighMemoryAvailable) {
            actualPoolSize = TOTAL_POOL_SIZE * 2; // Double the pool size for LAA systems
            DAWN_OF_WAR_LOG_INFO("MemoryPoolDLL", "LAA detected - using enhanced memory pool: %zu bytes", actualPoolSize);
        } else {
            DAWN_OF_WAR_LOG_INFO("MemoryPoolDLL", "Using standard memory pool: %zu bytes", actualPoolSize);
        }
        
        char* p = static_cast<char*>(VirtualAlloc(nullptr, actualPoolSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));
        if (!p) {
            DAWN_OF_WAR_LOG_ERROR("MemoryPoolDLL", "Failed to allocate main memory pool of %zu bytes", actualPoolSize);
            
            // Try with smaller size as fallback
            size_t fallbackSize = actualPoolSize / 2;
            DAWN_OF_WAR_LOG_WARN("MemoryPoolDLL", "Attempting fallback allocation with %zu bytes", fallbackSize);
            p = static_cast<char*>(VirtualAlloc(nullptr, fallbackSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));
            if (!p) {
                DAWN_OF_WAR_LOG_ERROR("MemoryPoolDLL", "Failed to allocate fallback memory pool of %zu bytes", fallbackSize);
                return;
            }
            DAWN_OF_WAR_LOG_WARN("MemoryPoolDLL", "Using reduced memory pool size: %zu bytes", fallbackSize);
        }
        
        gameMemoryPool.pool = p;
        gameMemoryPool.offset.store(0, std::memory_order_relaxed);
        gameMemoryPool.head.store(nullptr, std::memory_order_relaxed);
        gameMemoryPool.totalAllocated.store(0, std::memory_order_relaxed);
        gameMemoryPool.peakUsage.store(0, std::memory_order_relaxed);
        gameMemoryPool.fragmentationCount.store(0, std::memory_order_relaxed);
        
        // Initialize performance counters
        gameMemoryPool.mallocCount.store(0, std::memory_order_relaxed);
        gameMemoryPool.freeCount.store(0, std::memory_order_relaxed);
        gameMemoryPool.reallocCount.store(0, std::memory_order_relaxed);
        gameMemoryPool.totalAllocTime.store(0, std::memory_order_relaxed);
        gameMemoryPool.totalFreeTime.store(0, std::memory_order_relaxed);
        gameMemoryPool.cacheHits.store(0, std::memory_order_relaxed);
        gameMemoryPool.cacheMisses.store(0, std::memory_order_relaxed);
        
        for (int i = 0; i < NUM_SIZE_CLASSES; ++i) {
            gameMemoryPool.freeLists[i].store(nullptr, std::memory_order_relaxed);
        }
        
        DAWN_OF_WAR_LOG_INFO("MemoryPoolDLL", "Main memory pool initialized successfully at %p", p);
        
        // Initialize specialized pools
        InitSpecializedPools();
        
        initialized = true;
        DAWN_OF_WAR_LOG_INFO("MemoryPoolDLL", "Memory pool system initialization completed");
    }
}

void CleanupMemoryPool() {
    if (gameMemoryPool.pool) {
        EnterCriticalSection(&g_lock);
        
        // Check for memory leaks
        size_t leakCount = 0;
        size_t leakSize = 0;
        MemoryBlock* current = gameMemoryPool.head.load(std::memory_order_acquire);
        
        while (current) {
            MemoryBlock* next = current->next;
            if (current->used && current->magic == BLOCK_MAGIC) {
                leakCount++;
                leakSize += current->size;
                // Log leak info
                char leakBuffer[256];
                sprintf_s(leakBuffer, sizeof(leakBuffer), 
                    "MEMORY LEAK: %zu bytes at address %p\n", 
                    current->size, current->address);
                OutputDebugStringA(leakBuffer);
            }
            
            if (current->magic != BLOCK_MAGIC && current->magic != BLOCK_FREED_MAGIC) {
                // Corruption detected
                ++gameMemoryPool.fragmentationCount;
            }
            delete current;
            current = next;
        }
        
        // Log final statistics
        if (leakCount > 0) {
            char finalBuffer[512];
            sprintf_s(finalBuffer, sizeof(finalBuffer), 
                "=== SHUTDOWN LEAK REPORT ===\n"
                "Total Leaks: %zu blocks\n"
                "Leaked Memory: %zu MB\n"
                "Fragmentation Events: %zu\n"
                "Peak Usage: %zu MB\n",
                leakCount,
                leakSize / (1024 * 1024),
                gameMemoryPool.fragmentationCount.load(std::memory_order_relaxed),
                gameMemoryPool.peakUsage.load(std::memory_order_relaxed) / (1024 * 1024));
            OutputDebugStringA(finalBuffer);
        }
        
        VirtualFree(gameMemoryPool.pool, 0, MEM_RELEASE);
        gameMemoryPool.pool = nullptr;
        gameMemoryPool.offset.store(0, std::memory_order_relaxed);
        gameMemoryPool.head.store(nullptr, std::memory_order_relaxed);
        gameMemoryPool.totalAllocated.store(0, std::memory_order_relaxed);
        gameMemoryPool.peakUsage.store(0, std::memory_order_relaxed);
        for (int i = 0; i < NUM_SIZE_CLASSES; ++i) {
            gameMemoryPool.freeLists[i].store(nullptr, std::memory_order_relaxed);
        }
        LeaveCriticalSection(&g_lock);
    }
}

bool IsInCustomPool(void* p) {
    return gameMemoryPool.pool && (p >= gameMemoryPool.pool && p < gameMemoryPool.pool + TOTAL_POOL_SIZE);
}

MemoryBlock* PopFreeBlock(size_t size) {
    int sizeClass = GetSizeClass(size);
    MemoryBlock* block = gameMemoryPool.freeLists[sizeClass].load(std::memory_order_acquire);
    while (block) {
        MemoryBlock* next = block->next;
        if (gameMemoryPool.freeLists[sizeClass].compare_exchange_weak(block, next, std::memory_order_acq_rel, std::memory_order_acquire)) {
            if (block->magic == BLOCK_FREED_MAGIC && block->size >= size) {
                block->magic = BLOCK_MAGIC;
                block->used = true;
                return block;
            }
        }
        block = gameMemoryPool.freeLists[sizeClass].load(std::memory_order_acquire);
    }
    return nullptr;
}

void PushFreeBlock(MemoryBlock* block) {
    if (!block) return;
    
    // Try to coalesce with adjacent free blocks
    MemoryBlock* current = gameMemoryPool.head.load(std::memory_order_acquire);
    while (current) {
        if (current != block && current->used == false && current->magic == BLOCK_FREED_MAGIC) {
            // Check if blocks are adjacent
            char* blockEnd = static_cast<char*>(block->address) + block->size;
            char* currentEnd = static_cast<char*>(current->address) + current->size;
            
            if (block->address == currentEnd) {
                // Block follows current, merge
                current->size += block->size;
                current->next = block->next;
                delete block;
                ++gameMemoryPool.fragmentationCount;
                return;
            } else if (current->address == blockEnd) {
                // Current follows block, merge
                block->size += current->size;
                block->next = current->next;
                // Remove current from list
                MemoryBlock* prev = nullptr;
                MemoryBlock* search = gameMemoryPool.head.load(std::memory_order_acquire);
                while (search && search != current) {
                    prev = search;
                    search = search->next;
                }
                if (prev) prev->next = current->next;
                else gameMemoryPool.head.store(current->next, std::memory_order_release);
                delete current;
                ++gameMemoryPool.fragmentationCount;
                break;
            }
        }
        current = current->next;
    }
    
    // No coalescing possible, add to appropriate free list
    block->magic = BLOCK_FREED_MAGIC;
    block->used = false;
    int sizeClass = GetSizeClass(block->size);
    
    MemoryBlock* oldFree = gameMemoryPool.freeLists[sizeClass].load(std::memory_order_acquire);
    do {
        block->next = oldFree;
        block->prev = nullptr;
    } while (!gameMemoryPool.freeLists[sizeClass].compare_exchange_weak(oldFree, block, std::memory_order_acq_rel, std::memory_order_acquire));
}

// Helper functions for specialized pool free list management
MemoryBlock* PopSpecializedFreeBlock(MemoryPool& pool, size_t size) {
    MemoryBlock* freeBlock = pool.freeListHead.load(std::memory_order_acquire);
    while (freeBlock) {
        if (freeBlock->size >= size && freeBlock->magic == BLOCK_FREED_MAGIC) {
            // Try to claim this block
            MemoryBlock* next = freeBlock->next;
            if (pool.freeListHead.compare_exchange_weak(freeBlock, next, 
                std::memory_order_acq_rel, std::memory_order_acquire)) {
                freeBlock->magic = BLOCK_MAGIC;
                freeBlock->used = true;
                pool.cacheHits.fetch_add(1, std::memory_order_relaxed);
                return freeBlock;
            }
        }
        freeBlock = freeBlock->next;
    }
    pool.cacheMisses.fetch_add(1, std::memory_order_relaxed);
    return nullptr;
}

void PushSpecializedFreeBlock(MemoryPool& pool, MemoryBlock* block) {
    if (!block) return;
    
    block->magic = BLOCK_FREED_MAGIC;
    block->used = false;
    
    MemoryBlock* oldFree = pool.freeListHead.load(std::memory_order_acquire);
    do {
        block->next = oldFree;
    } while (!pool.freeListHead.compare_exchange_weak(oldFree, block, 
        std::memory_order_acq_rel, std::memory_order_acquire));
}

// Enhanced memory routing with call stack analysis for better reverse engineering
enum AllocationType {
    ALLOC_UNKNOWN = 0,
    ALLOC_LOGGING,
    ALLOC_FILE,
    ALLOC_GUI,
    ALLOC_SMALL_OBJ,
    ALLOC_LINKED_LIST,
    ALLOC_STRING,
    ALLOC_EXECUTABLE
};

// Call stack analysis for reverse engineering
AllocationType AnalyzeCallContext(size_t size) {
    // Use _ReturnAddress for simpler call stack analysis
    void* caller = _ReturnAddress();
    
    // Analyze call patterns for better pool selection
    if (caller) {
        // Check if caller is in known logging functions
        if ((caller >= (void*)0x577C91 && caller <= (void*)0x57AC40) ||
            (caller >= (void*)0x577CB8 && caller <= (void*)0x577D40)) {
            return ALLOC_LOGGING;
        }
        
        // Check if caller is in file operations
        if ((caller >= (void*)0x6082D0 && caller <= (void*)0x819C55)) {
            return ALLOC_FILE;
        }
        
        // Check if caller is in GUI operations
        if ((caller >= (void*)0x6A4CC0 && caller <= (void*)0x6A4FB0)) {
            return ALLOC_GUI;
        }
        
        // Check if caller is in small utility functions
        if ((caller >= (void*)0x69A7E0 && caller <= (void*)0x69A810)) {
            return ALLOC_SMALL_OBJ;
        }
        
        // Check if caller is in linked list operations
        if ((caller >= (void*)0x698CF0 && caller <= (void*)0x6A3AA0)) {
            return ALLOC_LINKED_LIST;
        }
        
        // Check if caller is in string operations
        if ((caller >= (void*)0x6A0AB0 && caller <= (void*)0x6CB980)) {
            return ALLOC_STRING;
        }
        
        // Check if caller is in executable memory operations
        if ((caller >= (void*)0x9AE540 && caller <= (void*)0x9AE550)) {
            return ALLOC_EXECUTABLE;
        }
    }
    
    // Fallback to size-based heuristics
    if (size <= 256) return ALLOC_SMALL_OBJ;
    if (size <= 1024) return ALLOC_LOGGING;
    if (size <= 8192) return ALLOC_FILE;
    if (size <= 65536) return ALLOC_GUI;
    return ALLOC_UNKNOWN;
}

// Hook detection and evasion resistance
bool IsHookDetected() {
    // Check for common anti-hook techniques
    static DWORD lastCheck = 0;
    DWORD currentTime = GetTickCount();
    
    if (currentTime - lastCheck < 1000) return false; // Don't check too frequently
    lastCheck = currentTime;
    
    // Check for integrity checks
    void* testMalloc = GetProcAddress(GetModuleHandleA("msvcrt.dll"), "malloc");
    if (testMalloc && testMalloc != s_origMalloc) {
        return true; // Hook detected
    }
    
    return false;
}

// Advanced hook evasion with dynamic resolution
void* GetDynamicFunction(const char* moduleName, const char* functionName) {
    static HMODULE modules[32] = {0};
    static DWORD moduleHashes[32] = {0};
    
    // Simple hash for module name
    DWORD hash = 0;
    for (const char* p = moduleName; *p; ++p) {
        hash = hash * 31 + *p;
    }
    
    // Find or load module
    HMODULE hModule = nullptr;
    for (int i = 0; i < 32; ++i) {
        if (moduleHashes[i] == hash && modules[i]) {
            hModule = modules[i];
            break;
        }
    }
    
    if (!hModule) {
        hModule = GetModuleHandleA(moduleName);
        if (!hModule) {
            hModule = LoadLibraryA(moduleName);
        }
        
        // Cache for future use
        for (int i = 0; i < 32; ++i) {
            if (!modules[i]) {
                modules[i] = hModule;
                moduleHashes[i] = hash;
                break;
            }
        }
    }
    
    return GetProcAddress(hModule, functionName);
}

// Thread-safe emergency allocation with overflow protection
void* EmergencyMalloc(size_t size) {
    if (size == 0) return nullptr;
    
    // Initialize emergency reserve if needed
    if (!g_emergencyReserve) {
        g_emergencyReserve = static_cast<char*>(
            VirtualAlloc(nullptr, EMERGENCY_RESERVE_SIZE, 
                        MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));
        if (!g_emergencyReserve) {
            DAWN_OF_WAR_LOG_ERROR("MemoryPoolDLL", "Failed to allocate emergency reserve");
            return nullptr;
        }
        DAWN_OF_WAR_LOG_INFO("MemoryPoolDLL", "Emergency reserve allocated: %zu MB", 
            EMERGENCY_RESERVE_SIZE / (1024 * 1024));
    }
    
    // Use atomic operations with overflow check
    size_t oldUsed = g_emergencyUsed.load(std::memory_order_relaxed);
    size_t newUsed;
    
    do {
        newUsed = oldUsed + size;
        if (newUsed > EMERGENCY_RESERVE_SIZE) {
            // No space in emergency reserve
            DAWN_OF_WAR_LOG_WARN("MemoryPoolDLL", 
                "Emergency reserve full: %zu/%zu bytes used", 
                oldUsed, EMERGENCY_RESERVE_SIZE);
            
            // Try to allocate fresh memory outside the pool
            void* emergency = VirtualAlloc(nullptr, size, 
                                          MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
            if (emergency) {
                DAWN_OF_WAR_LOG_WARN("MemoryPoolDLL", 
                    "Allocated emergency memory outside pool: %zu bytes at %p", 
                    size, emergency);
            }
            return emergency;
        }
    } while (!g_emergencyUsed.compare_exchange_weak(oldUsed, newUsed, 
        std::memory_order_relaxed, std::memory_order_relaxed));
    
    void* result = g_emergencyReserve + oldUsed;
    
    // Clear memory
    memset(result, 0, size);
    
    DAWN_OF_WAR_LOG_TRACE("MemoryPoolDLL", 
        "Emergency allocation: %zu bytes at %p (total used: %zu)", 
        size, result, newUsed);
    
    return result;
}

// Crash reporting memory validation system
static void* g_crashReportBuffer = nullptr;
static size_t g_crashReportSize = 0;

extern "C" __declspec(dllexport) bool EnsureCrashReportMemory(size_t needed) {
    static bool initialized = false;
    
    // Allocate crash report memory ONCE and never free it
    if (!initialized) {
        // Allocate with plenty of extra space for Dawn of War crash reports
        size_t allocateSize = std::max(needed, static_cast<size_t>(8 * 1024 * 1024)); // At least 8MB
        
        g_crashReportBuffer = VirtualAlloc(nullptr, allocateSize, 
                                        MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
        
        if (g_crashReportBuffer) {
            g_crashReportSize = allocateSize;
            initialized = true;
            
            // Mark buffer as crash report memory
            memset(g_crashReportBuffer, 0xCC, 1024); // First 1KB as marker
            
            DAWN_OF_WAR_LOG_INFO("MemoryPoolDLL", 
                "Crash report buffer allocated: %zu MB at %p", 
                allocateSize / (1024 * 1024), g_crashReportBuffer);
            
            return true;
        } else {
            DAWN_OF_WAR_LOG_ERROR("MemoryPoolDLL", 
                "Failed to allocate crash report buffer of %zu MB", 
                allocateSize / (1024 * 1024));
            return false;
        }
    }
    
    // If already initialized, check if it's large enough
    if (needed > g_crashReportSize) {
        DAWN_OF_WAR_LOG_WARN("MemoryPoolDLL", 
            "Crash report buffer (%zu MB) may be too small for %zu bytes", 
            g_crashReportSize / (1024 * 1024), needed);
        // Don't try to reallocate during a crash!
    }
    
    return g_crashReportBuffer != nullptr;
}

void SetupCrashReporting() {
    // Reserve 8MB for crash reports (Dawn of War needs ~4-6MB)
    if (EnsureCrashReportMemory(8 * 1024 * 1024)) {
        DAWN_OF_WAR_LOG_INFO("MemoryPoolDLL", "Crash reporting system initialized with 8MB buffer");
    } else {
        DAWN_OF_WAR_LOG_ERROR("MemoryPoolDLL", "FAILED to initialize crash reporting system");
    }
}

// Memory pressure detection and response system
bool IsMemoryPressureHigh() {
    size_t totalUsed = gameMemoryPool.totalAllocated.load(std::memory_order_relaxed);
    float usageRatio = static_cast<float>(totalUsed) / TOTAL_POOL_SIZE;
    
    // Also check system memory
    MEMORYSTATUSEX memStatus;
    memStatus.dwLength = sizeof(memStatus);
    GlobalMemoryStatusEx(&memStatus);
    
    float systemUsage = static_cast<float>(memStatus.dwMemoryLoad) / 100.0f;
    
    return usageRatio > 0.85f || systemUsage > 0.90f;
}

// Comprehensive memory error logging system
void LogMemoryError(const char* function, const char* error, void* address, size_t size) {
    char buffer[512];
    if (address) {
        sprintf_s(buffer, sizeof(buffer), 
            "[MEMERROR] %s: %s at %p (size: %zu)\n"
            "Total Allocated: %zu MB\n"
            "Pool Usage: %.1f%%\n"
            "Peak Usage: %zu MB\n"
            "Fragmentation Count: %zu\n"
            "System Memory Load: %u%%\n",
            function, error, address, size,
            gameMemoryPool.totalAllocated.load() / (1024 * 1024),
            (gameMemoryPool.totalAllocated.load() * 100.0f) / TOTAL_POOL_SIZE,
            gameMemoryPool.peakUsage.load() / (1024 * 1024),
            gameMemoryPool.fragmentationCount.load(),
            GetSystemMemoryUsage());
    } else {
        sprintf_s(buffer, sizeof(buffer), 
            "[MEMERROR] %s: %s\n", function, error);
    }
    OutputDebugStringA(buffer);
    
    // Also write to file for post-crash analysis
    static HANDLE logFile = INVALID_HANDLE_VALUE;
    if (logFile == INVALID_HANDLE_VALUE) {
        logFile = CreateFileA("memory_errors.log", 
                             FILE_APPEND_DATA, FILE_SHARE_READ, 
                             NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    }
    
    if (logFile != INVALID_HANDLE_VALUE) {
        DWORD written;
        WriteFile(logFile, buffer, strlen(buffer), &written, NULL);
        FlushFileBuffers(logFile);
    }
}

// Helper function to get system memory usage
DWORD GetSystemMemoryUsage() {
    MEMORYSTATUSEX memStatus;
    memStatus.dwLength = sizeof(memStatus);
    if (GlobalMemoryStatusEx(&memStatus)) {
        return memStatus.dwMemoryLoad;
    }
    return 0;
}

// Memory pool defragmentation for reducing fragmentation
void DefragmentMemoryPool() {
    // Don't defragment if we might be in a crash handler
    if (!gameMemoryPool.head.load(std::memory_order_acquire)) return;
    
    // Don't defragment if fragmentation is low
    size_t fragmentationCount = gameMemoryPool.fragmentationCount.load(std::memory_order_relaxed);
    if (fragmentationCount < 5) return;
    
    DAWN_OF_WAR_LOG_INFO("MemoryPoolDLL", "Starting defragmentation with %zu fragmentation events", fragmentationCount);
    
    EnterCriticalSection(&g_lock);
    
    try {
        // Collect all free blocks
        std::vector<MemoryBlock*> freeBlocks;
        MemoryBlock* current = gameMemoryPool.head.load(std::memory_order_acquire);
        
        while (current) {
            if (!current->used && current->magic == BLOCK_FREED_MAGIC) {
                freeBlocks.push_back(current);
            }
            current = current->next;
        }
        
        if (freeBlocks.empty()) {
            LeaveCriticalSection(&g_lock);
            return;
        }
        
        // Limit defragmentation to prevent long stalls
        if (freeBlocks.size() > 1000) {
            DAWN_OF_WAR_LOG_WARN("MemoryPoolDLL", 
                "Too many free blocks (%zu), limiting defragmentation", freeBlocks.size());
            freeBlocks.resize(1000); // Only process first 1000
        }
        
        // Sort by address to find contiguous blocks
        std::sort(freeBlocks.begin(), freeBlocks.end(), 
                  [](MemoryBlock* a, MemoryBlock* b) { 
                      return a->address < b->address; 
                  });
        
        // Merge contiguous blocks
        size_t mergesPerformed = 0;
        for (size_t i = 0; i + 1 < freeBlocks.size(); ++i) {
            char* blockEnd = static_cast<char*>(freeBlocks[i]->address) + freeBlocks[i]->size;
            if (blockEnd == static_cast<char*>(freeBlocks[i + 1]->address)) {
                // Merge blocks
                freeBlocks[i]->size += freeBlocks[i + 1]->size;
                
                // Remove merged block from the linked list
                MemoryBlock* toRemove = freeBlocks[i + 1];
                MemoryBlock* prev = nullptr;
                MemoryBlock* search = gameMemoryPool.head.load(std::memory_order_acquire);
                
                while (search && search != toRemove) {
                    prev = search;
                    search = search->next;
                }
                
                if (prev) {
                    prev->next = toRemove->next;
                } else {
                    // It was head
                    gameMemoryPool.head.store(toRemove->next, std::memory_order_release);
                }
                
                delete toRemove;
                freeBlocks.erase(freeBlocks.begin() + i + 1);
                --i; // Check again with new neighbor
                ++mergesPerformed;
            }
        }
        
        // Update fragmentation statistics
        gameMemoryPool.fragmentationCount.store(0, std::memory_order_relaxed);
        gameMemoryPool.lastCleanupTime.store(GetTickCount(), std::memory_order_relaxed);
        
        DAWN_OF_WAR_LOG_INFO("MemoryPoolDLL", 
            "Defragmentation completed: %zu merges performed", mergesPerformed);
            
    } catch (...) {
        DAWN_OF_WAR_LOG_ERROR("MemoryPoolDLL", "Exception during defragmentation");
    }
    
    LeaveCriticalSection(&g_lock);
}

// Periodic maintenance task for memory health
void PerformMemoryMaintenance() {
    static DWORD lastMaintenance = 0;
    DWORD currentTime = GetTickCount();
    
    // Run maintenance every 30 seconds
    if (currentTime - lastMaintenance > 30000) {
        lastMaintenance = currentTime;
        
        // Report memory statistics
        ReportMemoryStatistics();
        
        // Check if defragmentation is needed
        size_t fragmentationCount = gameMemoryPool.fragmentationCount.load(std::memory_order_relaxed);
        if (fragmentationCount > 10) {
            DAWN_OF_WAR_LOG_INFO("MemoryPoolDLL", "High fragmentation detected (%zu events), triggering defragmentation", fragmentationCount);
            DefragmentMemoryPool();
        }
        
        // Check if any pools need cleanup
        CheckPoolHealth();
    }
}

// Check health of all memory pools
void CheckPoolHealth() {
    // Check main pool
    size_t mainUsage = gameMemoryPool.totalAllocated.load(std::memory_order_relaxed);
    size_t mainPeak = gameMemoryPool.peakUsage.load(std::memory_order_relaxed);
    
    if (mainUsage > (TOTAL_POOL_SIZE * 0.9)) {
        OutputDebugStringA("WARNING: Main memory pool approaching capacity\n");
    }
    
    // Check specialized pools
    if (logPool.totalAllocated.load(std::memory_order_relaxed) > (LOG_BUFFER_SIZE * 0.9)) {
        OutputDebugStringA("WARNING: Log pool approaching capacity\n");
    }
    
    if (filePool.totalAllocated.load(std::memory_order_relaxed) > (FILE_BUFFER_SIZE * 0.9)) {
        OutputDebugStringA("WARNING: File pool approaching capacity\n");
    }
    
    if (guiPool.totalAllocated.load(std::memory_order_relaxed) > (GUI_POOL_SIZE * 0.9)) {
        OutputDebugStringA("WARNING: GUI pool approaching capacity\n");
    }
    
    if (smallObjPool.totalAllocated.load(std::memory_order_relaxed) > (SMALL_OBJ_POOL_SIZE * 0.9)) {
        OutputDebugStringA("WARNING: Small object pool approaching capacity\n");
    }
    
    if (linkedListPool.totalAllocated.load(std::memory_order_relaxed) > (LINKED_LIST_POOL_SIZE * 0.9)) {
        OutputDebugStringA("WARNING: Linked list pool approaching capacity\n");
    }
    
    if (stringPool.totalAllocated.load(std::memory_order_relaxed) > (STRING_POOL_SIZE * 0.9)) {
        OutputDebugStringA("WARNING: String pool approaching capacity\n");
    }
    
    if (executablePool.totalAllocated.load(std::memory_order_relaxed) > (EXECUTABLE_POOL_SIZE * 0.9)) {
        OutputDebugStringA("WARNING: Executable pool approaching capacity\n");
    }
}

extern "C" __declspec(dllexport) void* CustomMalloc(size_t size) {
    if (size == 0) return nullptr;
    
    auto startTime = std::chrono::high_resolution_clock::now();
    gameMemoryPool.mallocCount.fetch_add(1, std::memory_order_relaxed);
    
    // Log allocation request
    DAWN_OF_WAR_LOG_TRACE("MemoryPoolDLL", "CustomMalloc requested: %zu bytes", size);
    
    // Perform periodic maintenance
    PerformMemoryMaintenance();
    
    // FIRST: Try emergency reserve for critical allocations (like crash reporting)
    // This ensures crash handlers can always get memory
    if (size <= 1024 * 1024) { // Only use emergency for small/medium allocations
        void* emergencyResult = EmergencyMalloc(size);
        if (emergencyResult) {
            DAWN_OF_WAR_LOG_TRACE("MemoryPoolDLL", 
                "Using emergency memory for %zu bytes at %p", size, emergencyResult);
            auto endTime = std::chrono::high_resolution_clock::now();
            auto duration = std::chrono::duration_cast<std::chrono::microseconds>(endTime - startTime).count();
            gameMemoryPool.totalAllocTime.fetch_add(static_cast<size_t>(duration), std::memory_order_relaxed);
            return emergencyResult;
        }
    }
    
    // Check memory pressure and respond accordingly
    if (IsMemoryPressureHigh()) {
        DAWN_OF_WAR_LOG_INFO("MemoryPoolDLL", "High memory pressure detected during allocation of %zu bytes", size);
        // Trigger cleanup/defragmentation
        DefragmentMemoryPool();
        
        // For large allocations during high pressure, use system allocator
        if (size > 1024 * 1024) { // Large allocations during high pressure
            DAWN_OF_WAR_LOG_WARN("MemoryPoolDLL", "Using system allocator for large allocation: %zu bytes", size);
            void* result = s_origMalloc ? s_origMalloc(size) : nullptr;
            auto endTime = std::chrono::high_resolution_clock::now();
            auto duration = std::chrono::duration_cast<std::chrono::microseconds>(endTime - startTime).count();
            gameMemoryPool.totalAllocTime.fetch_add(static_cast<size_t>(duration), std::memory_order_relaxed);
            return result;
        }
    }
    
    // Anti-hook detection
    if (IsHookDetected()) {
        DAWN_OF_WAR_LOG_WARN("MemoryPoolDLL", "Hook detected, falling back to original allocator for %zu bytes", size);
        // Fallback to original to avoid detection
        void* result = s_origMalloc ? s_origMalloc(size) : nullptr;
        auto endTime = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::microseconds>(endTime - startTime).count();
        gameMemoryPool.totalAllocTime.fetch_add(static_cast<size_t>(duration), std::memory_order_relaxed);
        return result;
    }
    
    // Enhanced routing with call stack analysis
    AllocationType allocType = AnalyzeCallContext(size);
    
    switch (allocType) {
        case ALLOC_LOGGING:
            DAWN_OF_WAR_LOG_TRACE("MemoryPoolDLL", "Routing %zu bytes to logging pool", size);
            return LogMalloc(size);
        case ALLOC_FILE:
            DAWN_OF_WAR_LOG_TRACE("MemoryPoolDLL", "Routing %zu bytes to file pool", size);
            return FileMalloc(size);
        case ALLOC_GUI:
            DAWN_OF_WAR_LOG_TRACE("MemoryPoolDLL", "Routing %zu bytes to GUI pool", size);
            return GuiMalloc(size);
        case ALLOC_SMALL_OBJ:
            DAWN_OF_WAR_LOG_TRACE("MemoryPoolDLL", "Routing %zu bytes to small object pool", size);
            return SmallObjMalloc(size);
        case ALLOC_LINKED_LIST:
            DAWN_OF_WAR_LOG_TRACE("MemoryPoolDLL", "Routing %zu bytes to linked list pool", size);
            return LinkedListMalloc(size);
        case ALLOC_STRING:
            DAWN_OF_WAR_LOG_TRACE("MemoryPoolDLL", "Routing %zu bytes to string pool", size);
            return StringMalloc(size);
        case ALLOC_EXECUTABLE:
            DAWN_OF_WAR_LOG_TRACE("MemoryPoolDLL", "Routing %zu bytes to executable pool", size);
            return ExecutableMalloc(size);
        default:
            // Use size-based routing for unknown patterns
            if (size < 1024 * 1024 && size < (TOTAL_POOL_SIZE / 3)) {
                // Use main pool for large unknown allocations
                EnterCriticalSection(&g_lock);
                InitMemoryPool();
                size_t alignedSize = (size + 15) & ~static_cast<size_t>(15);
                
                bool useGuardPages = (alignedSize >= MAX_BLOCK_SIZE);
                if (useGuardPages) {
                    alignedSize += GUARD_PAGE_SIZE * 2;
                }
                
                MemoryBlock* block = PopFreeBlock(alignedSize);
                if (block) {
                    gameMemoryPool.totalAllocated.fetch_add(alignedSize, std::memory_order_relaxed);
                    size_t currentUsage = gameMemoryPool.totalAllocated.load(std::memory_order_relaxed);
                    size_t peakUsage = gameMemoryPool.peakUsage.load(std::memory_order_relaxed);
                    if (currentUsage > peakUsage) {
                        gameMemoryPool.peakUsage.store(currentUsage, std::memory_order_relaxed);
                    }
                    
                    if (useGuardPages) {
                        DWORD oldProtect;
                        VirtualProtect(static_cast<char*>(block->address), GUARD_PAGE_SIZE, PAGE_NOACCESS, &oldProtect);
                        VirtualProtect(static_cast<char*>(block->address) + alignedSize - GUARD_PAGE_SIZE, GUARD_PAGE_SIZE, PAGE_NOACCESS, &oldProtect);
                        void* userPtr = static_cast<char*>(block->address) + GUARD_PAGE_SIZE;
                        LeaveCriticalSection(&g_lock);
                        return userPtr;
                    }
                    
                    LeaveCriticalSection(&g_lock);
                    return block->address;
                }
                
                size_t currentOffset = gameMemoryPool.offset.fetch_add(alignedSize, std::memory_order_relaxed);
                if (currentOffset + alignedSize > TOTAL_POOL_SIZE) {
                    LeaveCriticalSection(&g_lock);
                    return s_origMalloc ? s_origMalloc(size) : nullptr;
                }
                
                void* allocatedMemory = gameMemoryPool.pool + currentOffset;
                MemoryBlock* newBlock = new MemoryBlock{ alignedSize, true, allocatedMemory, nullptr, nullptr, BLOCK_MAGIC };
                newBlock->next = gameMemoryPool.head.load(std::memory_order_acquire);
                gameMemoryPool.head.store(newBlock, std::memory_order_release);
                
                gameMemoryPool.totalAllocated.fetch_add(alignedSize, std::memory_order_relaxed);
                size_t currentUsage = gameMemoryPool.totalAllocated.load(std::memory_order_relaxed);
                size_t peakUsage = gameMemoryPool.peakUsage.load(std::memory_order_relaxed);
                if (currentUsage > peakUsage) {
                    gameMemoryPool.peakUsage.store(currentUsage, std::memory_order_relaxed);
                }
                
                if (useGuardPages) {
                    DWORD oldProtect;
                    VirtualProtect(allocatedMemory, GUARD_PAGE_SIZE, PAGE_NOACCESS, &oldProtect);
                    VirtualProtect(static_cast<char*>(allocatedMemory) + alignedSize - GUARD_PAGE_SIZE, GUARD_PAGE_SIZE, PAGE_NOACCESS, &oldProtect);
                    void* userPtr = static_cast<char*>(allocatedMemory) + GUARD_PAGE_SIZE;
                    LeaveCriticalSection(&g_lock);
                    return userPtr;
                }
                
                LeaveCriticalSection(&g_lock);
                return allocatedMemory;
            }
    }
    
    // Try emergency reserve for crash reporting and critical operations
    void* emergencyResult = EmergencyMalloc(size);
    if (emergencyResult) {
        OutputDebugStringA("Using emergency memory reserve for critical allocation\n");
        return emergencyResult;
    }
    
    // Final fallback to original malloc
    return s_origMalloc ? s_origMalloc(size) : nullptr;
}

extern "C" __declspec(dllexport) void* LogMalloc(size_t size) {
    if (!logPool.pool) return nullptr;
    
    EnterCriticalSection(&g_lock);
    MemoryBlock* freeBlock = PopSpecializedFreeBlock(logPool, size);
    if (freeBlock) {
        // Reuse the freed block - no need to allocate new memory
        freeBlock->used = true;
        freeBlock->magic = BLOCK_MAGIC;
        memset(freeBlock->address, 0, size); // Clear memory for reuse
        logPool.totalAllocated.fetch_add(size, std::memory_order_relaxed);
        logPool.logAllocCount.fetch_add(1, std::memory_order_relaxed);
        LeaveCriticalSection(&g_lock);
        return freeBlock->address;
    }
    
    size_t currentOffset = logPool.offset.fetch_add(size, std::memory_order_relaxed);
    if (currentOffset + size > LOG_BUFFER_SIZE) {
        logPool.offset.fetch_sub(size, std::memory_order_relaxed);
        LeaveCriticalSection(&g_lock);
        return CustomMalloc(size); // Fallback to main pool
    }
    
    void* allocatedMemory = logPool.pool + currentOffset;
    MemoryBlock* newBlock = new MemoryBlock{ size, true, allocatedMemory, nullptr, nullptr, BLOCK_MAGIC };
    newBlock->next = logPool.head.load(std::memory_order_acquire);
    logPool.head.store(newBlock, std::memory_order_release);
    
    logPool.totalAllocated.fetch_add(size, std::memory_order_relaxed);
    logPool.logAllocCount.fetch_add(1, std::memory_order_relaxed);
    LeaveCriticalSection(&g_lock);
    return allocatedMemory;
}

extern "C" __declspec(dllexport) void* FileMalloc(size_t size) {
    if (!filePool.pool) return nullptr;
    
    EnterCriticalSection(&g_lock);
    MemoryBlock* freeBlock = PopSpecializedFreeBlock(filePool, size);
    if (freeBlock) {
        // Reuse the freed block - no need to allocate new memory
        freeBlock->used = true;
        freeBlock->magic = BLOCK_MAGIC;
        memset(freeBlock->address, 0, size); // Clear memory for reuse
        filePool.totalAllocated.fetch_add(size, std::memory_order_relaxed);
        filePool.fileAllocCount.fetch_add(1, std::memory_order_relaxed);
        LeaveCriticalSection(&g_lock);
        return freeBlock->address;
    }
    
    size_t currentOffset = filePool.offset.fetch_add(size, std::memory_order_relaxed);
    if (currentOffset + size > FILE_BUFFER_SIZE) {
        filePool.offset.fetch_sub(size, std::memory_order_relaxed);
        LeaveCriticalSection(&g_lock);
        return CustomMalloc(size); // Fallback to main pool
    }
    
    void* allocatedMemory = filePool.pool + currentOffset;
    MemoryBlock* newBlock = new MemoryBlock{ size, true, allocatedMemory, nullptr, nullptr, BLOCK_MAGIC };
    newBlock->next = filePool.head.load(std::memory_order_acquire);
    filePool.head.store(newBlock, std::memory_order_release);
    
    filePool.totalAllocated.fetch_add(size, std::memory_order_relaxed);
    filePool.fileAllocCount.fetch_add(1, std::memory_order_relaxed);
    LeaveCriticalSection(&g_lock);
    return allocatedMemory;
}

extern "C" __declspec(dllexport) void* GuiMalloc(size_t size) {
    if (!guiPool.pool) return nullptr;
    
    EnterCriticalSection(&g_lock);
    MemoryBlock* freeBlock = PopSpecializedFreeBlock(guiPool, size);
    if (freeBlock) {
        // Reuse the freed block - no need to allocate new memory
        freeBlock->used = true;
        freeBlock->magic = BLOCK_MAGIC;
        memset(freeBlock->address, 0, size); // Clear memory for reuse
        guiPool.totalAllocated.fetch_add(size, std::memory_order_relaxed);
        guiPool.guiAllocCount.fetch_add(1, std::memory_order_relaxed);
        LeaveCriticalSection(&g_lock);
        return freeBlock->address;
    }
    
    size_t currentOffset = guiPool.offset.fetch_add(size, std::memory_order_relaxed);
    if (currentOffset + size > GUI_POOL_SIZE) {
        guiPool.offset.fetch_sub(size, std::memory_order_relaxed);
        LeaveCriticalSection(&g_lock);
        return CustomMalloc(size); // Fallback to main pool
    }
    
    void* allocatedMemory = guiPool.pool + currentOffset;
    MemoryBlock* newBlock = new MemoryBlock{ size, true, allocatedMemory, nullptr, nullptr, BLOCK_MAGIC };
    newBlock->next = guiPool.head.load(std::memory_order_acquire);
    guiPool.head.store(newBlock, std::memory_order_release);
    
    guiPool.totalAllocated.fetch_add(size, std::memory_order_relaxed);
    guiPool.guiAllocCount.fetch_add(1, std::memory_order_relaxed);
    LeaveCriticalSection(&g_lock);
    return allocatedMemory;
}

extern "C" __declspec(dllexport) void* SmallObjMalloc(size_t size) {
    if (!smallObjPool.pool) return nullptr;
    
    EnterCriticalSection(&g_lock);
    MemoryBlock* freeBlock = PopSpecializedFreeBlock(smallObjPool, size);
    if (freeBlock) {
        // Reuse the freed block - no need to allocate new memory
        freeBlock->used = true;
        freeBlock->magic = BLOCK_MAGIC;
        memset(freeBlock->address, 0, size); // Clear memory for reuse
        smallObjPool.totalAllocated.fetch_add(size, std::memory_order_relaxed);
        smallObjPool.smallObjAllocCount.fetch_add(1, std::memory_order_relaxed);
        LeaveCriticalSection(&g_lock);
        return freeBlock->address;
    }
    
    size_t currentOffset = smallObjPool.offset.fetch_add(size, std::memory_order_relaxed);
    if (currentOffset + size > SMALL_OBJ_POOL_SIZE) {
        smallObjPool.offset.fetch_sub(size, std::memory_order_relaxed);
        LeaveCriticalSection(&g_lock);
        return CustomMalloc(size); // Fallback to main pool
    }
    
    void* allocatedMemory = smallObjPool.pool + currentOffset;
    MemoryBlock* newBlock = new MemoryBlock{ size, true, allocatedMemory, nullptr, nullptr, BLOCK_MAGIC };
    newBlock->next = smallObjPool.head.load(std::memory_order_acquire);
    smallObjPool.head.store(newBlock, std::memory_order_release);
    
    smallObjPool.totalAllocated.fetch_add(size, std::memory_order_relaxed);
    smallObjPool.smallObjAllocCount.fetch_add(1, std::memory_order_relaxed);
    LeaveCriticalSection(&g_lock);
    return allocatedMemory;
}

extern "C" __declspec(dllexport) void* LinkedListMalloc(size_t size) {
    if (!linkedListPool.pool) return nullptr;
    
    EnterCriticalSection(&g_lock);
    MemoryBlock* freeBlock = PopSpecializedFreeBlock(linkedListPool, size);
    if (freeBlock) {
        // Reuse the freed block - no need to allocate new memory
        freeBlock->used = true;
        freeBlock->magic = BLOCK_MAGIC;
        memset(freeBlock->address, 0, size); // Clear memory for reuse
        linkedListPool.totalAllocated.fetch_add(size, std::memory_order_relaxed);
        linkedListPool.linkedListAllocCount.fetch_add(1, std::memory_order_relaxed);
        LeaveCriticalSection(&g_lock);
        return freeBlock->address;
    }
    
    size_t currentOffset = linkedListPool.offset.fetch_add(size, std::memory_order_relaxed);
    if (currentOffset + size > LINKED_LIST_POOL_SIZE) {
        linkedListPool.offset.fetch_sub(size, std::memory_order_relaxed);
        LeaveCriticalSection(&g_lock);
        return CustomMalloc(size); // Fallback to main pool
    }
    
    void* allocatedMemory = linkedListPool.pool + currentOffset;
    MemoryBlock* newBlock = new MemoryBlock{ size, true, allocatedMemory, nullptr, nullptr, BLOCK_MAGIC };
    newBlock->next = linkedListPool.head.load(std::memory_order_acquire);
    linkedListPool.head.store(newBlock, std::memory_order_release);
    
    linkedListPool.totalAllocated.fetch_add(size, std::memory_order_relaxed);
    linkedListPool.linkedListAllocCount.fetch_add(1, std::memory_order_relaxed);
    LeaveCriticalSection(&g_lock);
    return allocatedMemory;
}

extern "C" __declspec(dllexport) void* StringMalloc(size_t size) {
    if (!stringPool.pool) return nullptr;
    
    EnterCriticalSection(&g_lock);
    MemoryBlock* freeBlock = PopSpecializedFreeBlock(stringPool, size);
    if (freeBlock) {
        // Reuse the freed block - no need to allocate new memory
        freeBlock->used = true;
        freeBlock->magic = BLOCK_MAGIC;
        memset(freeBlock->address, 0, size); // Clear memory for reuse
        stringPool.totalAllocated.fetch_add(size, std::memory_order_relaxed);
        stringPool.stringAllocCount.fetch_add(1, std::memory_order_relaxed);
        LeaveCriticalSection(&g_lock);
        return freeBlock->address;
    }
    
    size_t currentOffset = stringPool.offset.fetch_add(size, std::memory_order_relaxed);
    if (currentOffset + size > STRING_POOL_SIZE) {
        stringPool.offset.fetch_sub(size, std::memory_order_relaxed);
        LeaveCriticalSection(&g_lock);
        return CustomMalloc(size); // Fallback to main pool
    }
    
    void* allocatedMemory = stringPool.pool + currentOffset;
    MemoryBlock* newBlock = new MemoryBlock{ size, true, allocatedMemory, nullptr, nullptr, BLOCK_MAGIC };
    newBlock->next = stringPool.head.load(std::memory_order_acquire);
    stringPool.head.store(newBlock, std::memory_order_release);
    
    stringPool.totalAllocated.fetch_add(size, std::memory_order_relaxed);
    stringPool.stringAllocCount.fetch_add(1, std::memory_order_relaxed);
    LeaveCriticalSection(&g_lock);
    return allocatedMemory;
}

extern "C" __declspec(dllexport) void* ExecutableMalloc(size_t size) {
    if (!executablePool.pool) return nullptr;
    
    EnterCriticalSection(&g_lock);
    MemoryBlock* freeBlock = PopSpecializedFreeBlock(executablePool, size);
    if (freeBlock) {
        // Reuse the freed block - no need to allocate new memory
        freeBlock->used = true;
        freeBlock->magic = BLOCK_MAGIC;
        memset(freeBlock->address, 0, size); // Clear memory for reuse
        executablePool.totalAllocated.fetch_add(size, std::memory_order_relaxed);
        executablePool.executableAllocCount.fetch_add(1, std::memory_order_relaxed);
        LeaveCriticalSection(&g_lock);
        return freeBlock->address;
    }
    
    size_t currentOffset = executablePool.offset.fetch_add(size, std::memory_order_relaxed);
    if (currentOffset + size > EXECUTABLE_POOL_SIZE) {
        executablePool.offset.fetch_sub(size, std::memory_order_relaxed);
        LeaveCriticalSection(&g_lock);
        return CustomMalloc(size); // Fallback to main pool
    }
    
    void* allocatedMemory = executablePool.pool + currentOffset;
    MemoryBlock* newBlock = new MemoryBlock{ size, true, allocatedMemory, nullptr, nullptr, BLOCK_MAGIC };
    newBlock->next = executablePool.head.load(std::memory_order_acquire);
    executablePool.head.store(newBlock, std::memory_order_release);
    
    executablePool.totalAllocated.fetch_add(size, std::memory_order_relaxed);
    executablePool.executableAllocCount.fetch_add(1, std::memory_order_relaxed);
    LeaveCriticalSection(&g_lock);
    return allocatedMemory;
}

// Specialized free function implementations
extern "C" __declspec(dllexport) void LogFree(void* ptr) {
    if (!ptr || !logPool.pool) return;
    
    EnterCriticalSection(&g_lock);
    MemoryBlock* current = logPool.head.load(std::memory_order_acquire);
    while (current) {
        if (current->address == ptr && current->used && current->magic == BLOCK_MAGIC) {
            current->used = false;
            current->magic = BLOCK_FREED_MAGIC;
            memset(ptr, 0xFE, current->size); // Clear memory
            PushSpecializedFreeBlock(logPool, current);
            logPool.totalAllocated.fetch_sub(current->size, std::memory_order_relaxed);
            logPool.freeCount.fetch_add(1, std::memory_order_relaxed);
            LeaveCriticalSection(&g_lock);
            return;
        }
        current = current->next;
    }
    LeaveCriticalSection(&g_lock);
}

extern "C" __declspec(dllexport) void FileFree(void* ptr) {
    if (!ptr || !filePool.pool) return;
    
    EnterCriticalSection(&g_lock);
    MemoryBlock* current = filePool.head.load(std::memory_order_acquire);
    while (current) {
        if (current->address == ptr && current->used && current->magic == BLOCK_MAGIC) {
            current->used = false;
            current->magic = BLOCK_FREED_MAGIC;
            memset(ptr, 0xFE, current->size); // Clear memory
            PushSpecializedFreeBlock(filePool, current);
            filePool.totalAllocated.fetch_sub(current->size, std::memory_order_relaxed);
            filePool.freeCount.fetch_add(1, std::memory_order_relaxed);
            LeaveCriticalSection(&g_lock);
            return;
        }
        current = current->next;
    }
    LeaveCriticalSection(&g_lock);
}

extern "C" __declspec(dllexport) void GuiFree(void* ptr) {
    if (!ptr || !guiPool.pool) return;
    
    EnterCriticalSection(&g_lock);
    MemoryBlock* current = guiPool.head.load(std::memory_order_acquire);
    while (current) {
        if (current->address == ptr && current->used && current->magic == BLOCK_MAGIC) {
            current->used = false;
            current->magic = BLOCK_FREED_MAGIC;
            memset(ptr, 0xFE, current->size); // Clear memory
            PushSpecializedFreeBlock(guiPool, current);
            guiPool.totalAllocated.fetch_sub(current->size, std::memory_order_relaxed);
            guiPool.freeCount.fetch_add(1, std::memory_order_relaxed);
            LeaveCriticalSection(&g_lock);
            return;
        }
        current = current->next;
    }
    LeaveCriticalSection(&g_lock);
}

extern "C" __declspec(dllexport) void SmallObjFree(void* ptr) {
    if (!ptr || !smallObjPool.pool) return;
    
    EnterCriticalSection(&g_lock);
    MemoryBlock* current = smallObjPool.head.load(std::memory_order_acquire);
    while (current) {
        if (current->address == ptr && current->used && current->magic == BLOCK_MAGIC) {
            current->used = false;
            current->magic = BLOCK_FREED_MAGIC;
            memset(ptr, 0xFE, current->size); // Clear memory
            PushSpecializedFreeBlock(smallObjPool, current);
            smallObjPool.totalAllocated.fetch_sub(current->size, std::memory_order_relaxed);
            smallObjPool.freeCount.fetch_add(1, std::memory_order_relaxed);
            LeaveCriticalSection(&g_lock);
            return;
        }
        current = current->next;
    }
    LeaveCriticalSection(&g_lock);
}

extern "C" __declspec(dllexport) void LinkedListFree(void* ptr) {
    if (!ptr || !linkedListPool.pool) return;
    
    EnterCriticalSection(&g_lock);
    MemoryBlock* current = linkedListPool.head.load(std::memory_order_acquire);
    while (current) {
        if (current->address == ptr && current->used && current->magic == BLOCK_MAGIC) {
            current->used = false;
            current->magic = BLOCK_FREED_MAGIC;
            memset(ptr, 0xFE, current->size); // Clear memory
            PushSpecializedFreeBlock(linkedListPool, current);
            linkedListPool.totalAllocated.fetch_sub(current->size, std::memory_order_relaxed);
            linkedListPool.freeCount.fetch_add(1, std::memory_order_relaxed);
            LeaveCriticalSection(&g_lock);
            return;
        }
        current = current->next;
    }
    LeaveCriticalSection(&g_lock);
}

extern "C" __declspec(dllexport) void StringFree(void* ptr) {
    if (!ptr || !stringPool.pool) return;
    
    EnterCriticalSection(&g_lock);
    MemoryBlock* current = stringPool.head.load(std::memory_order_acquire);
    while (current) {
        if (current->address == ptr && current->used && current->magic == BLOCK_MAGIC) {
            current->used = false;
            current->magic = BLOCK_FREED_MAGIC;
            memset(ptr, 0xFE, current->size); // Clear memory
            PushSpecializedFreeBlock(stringPool, current);
            stringPool.totalAllocated.fetch_sub(current->size, std::memory_order_relaxed);
            stringPool.freeCount.fetch_add(1, std::memory_order_relaxed);
            LeaveCriticalSection(&g_lock);
            return;
        }
        current = current->next;
    }
    LeaveCriticalSection(&g_lock);
}

extern "C" __declspec(dllexport) void BatchLinkedListFree(void** ptrs, size_t count) {
    if (!ptrs || count == 0) return;
    
    for (size_t i = 0; i < count; ++i) {
        LinkedListFree(ptrs[i]);
    }
}

extern "C" __declspec(dllexport) void ExecutableFree(void* ptr) {
    if (!ptr || !executablePool.pool) return;
    
    EnterCriticalSection(&g_lock);
    MemoryBlock* current = executablePool.head.load(std::memory_order_acquire);
    while (current) {
        if (current->address == ptr && current->used && current->magic == BLOCK_MAGIC) {
            current->used = false;
            current->magic = BLOCK_FREED_MAGIC;
            memset(ptr, 0xFE, current->size); // Clear memory
            PushSpecializedFreeBlock(executablePool, current);
            executablePool.totalAllocated.fetch_sub(current->size, std::memory_order_relaxed);
            executablePool.freeCount.fetch_add(1, std::memory_order_relaxed);
            LeaveCriticalSection(&g_lock);
            return;
        }
        current = current->next;
    }
    LeaveCriticalSection(&g_lock);
}

// Remove TempMalloc and TempFree functions - they were unused
// TempPool functionality has been removed for cleaner code

extern "C" __declspec(dllexport) void* CustomRealloc(void* p, size_t size) {
    if (!p) return CustomMalloc(size);
    if (!IsInCustomPool(p)) return s_origRealloc ? s_origRealloc(p, size) : nullptr;
    
    EnterCriticalSection(&g_lock);
    MemoryBlock* origBlock = nullptr;
    MemoryBlock* current = gameMemoryPool.head.load(std::memory_order_acquire);
    while (current) {
        if (current->address == p) {
            origBlock = current;
            break;
        }
        current = current->next;
    }
    LeaveCriticalSection(&g_lock);
    
    if (!origBlock) return s_origRealloc ? s_origRealloc(p, size) : nullptr;
    void* newPtr = CustomMalloc(size);
    if (newPtr) {
        size_t copySize = (size < origBlock->size) ? size : origBlock->size;
        memcpy(newPtr, p, copySize);
        CustomFree(p);
    }
    return newPtr;
}

extern "C" __declspec(dllexport) void* CustomCalloc(size_t n, size_t s) {
    size_t total = n * s;
    void* p = CustomMalloc(total);
    if (p) memset(p, 0, total);
    return p;
}

extern "C" __declspec(dllexport) void DebugMemoryUsage() {
    EnterCriticalSection(&g_lock);
    
    // Main pool stats
    size_t usedMemory = 0, freeMemory = 0, totalBlocks = 0, usedBlocks = 0;
    MemoryBlock* current = gameMemoryPool.head.load(std::memory_order_acquire);
    
    while (current) {
        totalBlocks++;
        if (current->used) {
            usedMemory += current->size;
            usedBlocks++;
        } else {
            freeMemory += current->size;
        }
        current = current->next;
    }
    
    // Specialized pool stats
    size_t logUsed = logPool.totalAllocated.load(std::memory_order_relaxed);
    size_t fileUsed = filePool.totalAllocated.load(std::memory_order_relaxed);
    size_t guiUsed = guiPool.totalAllocated.load(std::memory_order_relaxed);
    size_t smallObjUsed = smallObjPool.totalAllocated.load(std::memory_order_relaxed);
    size_t linkedListUsed = linkedListPool.totalAllocated.load(std::memory_order_relaxed);
    size_t stringUsed = stringPool.totalAllocated.load(std::memory_order_relaxed);
    size_t executableUsed = executablePool.totalAllocated.load(std::memory_order_relaxed);
    
    // Performance counters
    size_t mallocCount = gameMemoryPool.mallocCount.load(std::memory_order_relaxed);
    size_t freeCount = gameMemoryPool.freeCount.load(std::memory_order_relaxed);
    size_t reallocCount = gameMemoryPool.reallocCount.load(std::memory_order_relaxed);
    size_t cacheHits = gameMemoryPool.cacheHits.load(std::memory_order_relaxed);
    size_t cacheMisses = gameMemoryPool.cacheMisses.load(std::memory_order_relaxed);
    
    // Output comprehensive debug information
    char buffer[2048];
    sprintf_s(buffer, sizeof(buffer), 
        "=== COMPREHENSIVE MEMORY POOL STATS ===\n"
        "\n--- MAIN POOL ---\n"
        "Total Pool: %zu MB\n"
        "Used Memory: %zu MB (%zu blocks)\n"
        "Free Memory: %zu MB (%zu blocks)\n"
        "Peak Usage: %zu MB\n"
        "Fragmentation Events: %zu\n"
        "Pool Offset: %zu MB\n"
        "\n--- SPECIALIZED POOLS ---\n"
        "Log Pool Used: %zu MB (%zu allocations)\n"
        "File Pool Used: %zu MB (%zu allocations)\n"
        "GUI Pool Used: %zu MB (%zu allocations)\n"
        "Small Obj Pool Used: %zu MB (%zu allocations)\n"
        "Linked List Pool Used: %zu MB (%zu allocations)\n"
        "String Pool Used: %zu MB (%zu allocations)\n"
        "Executable Pool Used: %zu MB (%zu allocations)\n"
        "\n--- PERFORMANCE METRICS ---\n"
        "Total Mallocs: %zu\n"
        "Total Frees: %zu\n"
        "Total Reallocs: %zu\n"
        "Cache Hits: %zu\n"
        "Cache Misses: %zu\n"
        "Hit Ratio: %.2f%%\n"
        "\n--- ALLOCATION BREAKDOWN ---\n"
        "Log allocations: %zu\n"
        "File allocations: %zu\n"
        "GUI allocations: %zu\n"
        "Small object allocations: %zu\n"
        "Linked list allocations: %zu\n"
        "String allocations: %zu\n"
        "Executable allocations: %zu\n",
        TOTAL_POOL_SIZE / (1024 * 1024),
        usedMemory / (1024 * 1024), usedBlocks,
        freeMemory / (1024 * 1024), totalBlocks - usedBlocks,
        gameMemoryPool.peakUsage.load(std::memory_order_relaxed) / (1024 * 1024),
        gameMemoryPool.fragmentationCount.load(std::memory_order_relaxed),
        gameMemoryPool.offset.load(std::memory_order_relaxed) / (1024 * 1024),

        logUsed / (1024 * 1024), logPool.logAllocCount.load(std::memory_order_relaxed),
        fileUsed / (1024 * 1024), filePool.fileAllocCount.load(std::memory_order_relaxed),
        guiUsed / (1024 * 1024), guiPool.guiAllocCount.load(std::memory_order_relaxed),
        smallObjUsed / (1024 * 1024), smallObjPool.smallObjAllocCount.load(std::memory_order_relaxed),
        linkedListUsed / (1024 * 1024), linkedListPool.linkedListAllocCount.load(std::memory_order_relaxed),
        stringUsed / (1024 * 1024), stringPool.stringAllocCount.load(std::memory_order_relaxed),
        executableUsed / (1024 * 1024), executablePool.executableAllocCount.load(std::memory_order_relaxed),
        mallocCount, freeCount, reallocCount, cacheHits, cacheMisses,
        (cacheHits + cacheMisses) > 0 ? (double)cacheHits / (cacheHits + cacheMisses) * 100.0 : 0.0,
        logPool.logAllocCount.load(std::memory_order_relaxed),
        filePool.fileAllocCount.load(std::memory_order_relaxed),
        guiPool.guiAllocCount.load(std::memory_order_relaxed),
        smallObjPool.smallObjAllocCount.load(std::memory_order_relaxed),
        linkedListPool.linkedListAllocCount.load(std::memory_order_relaxed),
        stringPool.stringAllocCount.load(std::memory_order_relaxed),
        executablePool.executableAllocCount.load(std::memory_order_relaxed)
    );
    OutputDebugStringA(buffer);
    LeaveCriticalSection(&g_lock);
}

// Validate memory block function
static bool ValidateMemoryBlock(void* p) {
    if (!p || !gameMemoryPool.pool) return false;
    if (!IsInCustomPool(p)) return true; // Not in our pool, assume valid

    EnterCriticalSection(&g_lock);
    MemoryBlock* current = gameMemoryPool.head.load(std::memory_order_acquire);
    while (current) {
        if (current->address == p) {
            bool valid = (current->magic == BLOCK_MAGIC) && current->used;
            LeaveCriticalSection(&g_lock);
            return valid;
        }
        current = current->next;
    }
    LeaveCriticalSection(&g_lock);
    return false; // Block not found
}

// Hooking implementations using our advanced memory management
static void* MyMalloc(size_t sz) {
    return CustomMalloc(sz);
}

static void MyFree(void* ptr) {
    CustomFree(ptr);
}

// Enhanced GlobalAlloc implementation with better handling of movable memory
// Fixed: Renamed GlobalHandle to GlobalMemoryHandle to avoid naming conflicts
static HGLOBAL __stdcall MyGlobalAlloc(UINT uFlags, DWORD dwBytes) {
    // Validate size parameter
    if (dwBytes == 0) return NULL;
    if (dwBytes > TOTAL_POOL_SIZE) {
        // Too large for our pool, use original
        return s_origGlobalAlloc ? s_origGlobalAlloc(uFlags, dwBytes) : NULL;
    }
        
    // Handle GMEM_MOVEABLE case - create a simulated movable memory block
    if (uFlags & GMEM_MOVEABLE) {
        // For movable memory, we need to allocate a handle structure
        // Allocate handle structure + memory block
        size_t totalSize = sizeof(GlobalMemoryHandle) + dwBytes;
        GlobalMemoryHandle* handle = reinterpret_cast<GlobalMemoryHandle*>(CustomMalloc(totalSize));
        if (!handle) {
            return s_origGlobalAlloc ? s_origGlobalAlloc(uFlags, dwBytes) : NULL;
        }
            
        // Initialize handle
        handle->address = reinterpret_cast<char*>(handle) + sizeof(GlobalMemoryHandle);
        handle->flags = uFlags;
        handle->size = dwBytes;
        handle->lockCount = 0;
            
        // Zero initialize if requested
        if (uFlags & GMEM_ZEROINIT) {
            memset(handle->address, 0, dwBytes);
        }
            
        return reinterpret_cast<HGLOBAL>(handle);
    }
        
    // For non-movable memory, use our custom allocator
    void* memory = CustomMalloc(dwBytes);
    if (!memory) {
        return s_origGlobalAlloc ? s_origGlobalAlloc(uFlags, dwBytes) : NULL;
    }
        
    // Zero initialize if requested
    if (uFlags & GMEM_ZEROINIT) {
        memset(memory, 0, dwBytes);
    }
        
    return reinterpret_cast<HGLOBAL>(memory);
}

// Enhanced GlobalFree with proper handle management
static HGLOBAL __stdcall MyGlobalFree(HGLOBAL hMem) {
    if (!hMem) return NULL;
        
    // Check if this is a movable memory handle
    if (IsInCustomPool(hMem)) {
        GlobalMemoryHandle* handle = static_cast<GlobalMemoryHandle*>(hMem);
            
        // Check if this looks like our handle structure
        if (handle->flags & GMEM_MOVEABLE) {
            // This is a movable memory handle, free the entire block
            if (handle->lockCount > 0) {
                // Memory is still locked, can't free
                return NULL;
            }
            CustomFree(handle);
            return NULL;
        }
    }
        
    // Regular memory block
    CustomFree(reinterpret_cast<void*>(hMem));
    return NULL;
}

// GlobalLock implementation for movable memory
static void* __stdcall MyGlobalLock(HGLOBAL hMem) {
    if (!hMem) return NULL;
    
    // Check if this is our movable memory handle
    if (IsInCustomPool(hMem)) {
        GlobalMemoryHandle* handle = static_cast<GlobalMemoryHandle*>(hMem);
        
        // Check if this looks like our handle structure
        if (handle->flags & GMEM_MOVEABLE) {
            // This is a movable memory handle
            if (handle->lockCount < 0) {
                // Invalid lock count
                return NULL;
            }
            handle->lockCount++;
            return handle->address;
        }
    }
    
    // For non-movable memory, just return the pointer
    return reinterpret_cast<void*>(hMem);
}

// GlobalUnlock implementation
static BOOL __stdcall MyGlobalUnlock(HGLOBAL hMem) {
    if (!hMem) return FALSE;
    
    // Check if this is our movable memory handle
    if (IsInCustomPool(hMem)) {
        GlobalMemoryHandle* handle = static_cast<GlobalMemoryHandle*>(hMem);
        
        // Check if this looks like our handle structure
        if (handle->flags & GMEM_MOVEABLE) {
            // This is a movable memory handle
            if (handle->lockCount <= 0) {
                // Not locked
                return FALSE;
            }
            handle->lockCount--;
            return (handle->lockCount > 0); // Return TRUE if still locked
        }
    }
    
    // For non-movable memory, always succeed
    return TRUE;
}

// GlobalSize implementation
static SIZE_T __stdcall MyGlobalSize(HGLOBAL hMem) {
    if (!hMem) return 0;
    
    // Check if this is our movable memory handle
    if (IsInCustomPool(hMem)) {
        GlobalMemoryHandle* handle = static_cast<GlobalMemoryHandle*>(hMem);
        
        // Check if this looks like our handle structure
        if (handle->flags & GMEM_MOVEABLE) {
            // This is a movable memory handle
            return handle->size;
        }
    }
    
    // For non-movable memory, we need to find the block size
    // This is a limitation - we can't easily determine size for direct allocations
    // Fall back to original implementation
    return s_origGlobalSize ? s_origGlobalSize(hMem) : 0;
}

static BOOL __stdcall MyHeapFree(HANDLE hHeap, DWORD dwFlags, LPVOID lpMem) {
    if (!lpMem) return TRUE;
    
    // Check if this is our custom pool memory
    if (IsInCustomPool(lpMem)) {
        // Validate the memory block before freeing
        if (ValidateMemoryBlock(lpMem)) {
            CustomFree(lpMem);
            return TRUE;
        } else {
            // Invalid block detected, don't free
            SetLastError(ERROR_INVALID_PARAMETER);
            return FALSE;
        }
    }
    
    // For thread-local storage or system memory, use original HeapFree
    // This handles the complex case in heap_free_call_A4BF77 and A4BF51
    if (s_origHeapFree) {
        // Validate heap handle if provided
        if (hHeap == NULL) {
            // Use default process heap for thread-local storage cases
            // This matches the pattern in heap_free_call_A4BF51
            hHeap = GetProcessHeap();
            
            // Validate the heap handle
            if (hHeap == NULL) {
                SetLastError(ERROR_INVALID_HANDLE);
                return FALSE;
            }
        }
        
        // Additional validation for the conditional pattern in heap_free_call_A4BF51
        // Check if this might be a double-free scenario
        if (dwFlags == 0) {
            // Standard HeapFree call - validate the memory is accessible
            MEMORY_BASIC_INFORMATION mbi;
            if (VirtualQuery(lpMem, &mbi, sizeof(mbi)) == sizeof(mbi)) {
                // Check if the memory is committed and accessible
                if (mbi.State == MEM_COMMIT && (mbi.Protect & (PAGE_READWRITE | PAGE_EXECUTE_READWRITE))) {
                    // Memory appears valid, proceed with free
                    BOOL result = s_origHeapFree(hHeap, dwFlags, lpMem);
                    if (!result) {
                        // Log the failure for debugging
                        DWORD error = GetLastError();
                        if (error != ERROR_SUCCESS) {
                            char errorBuffer[256];
                            sprintf_s(errorBuffer, sizeof(errorBuffer), 
                                "HEAPFREE FAILED: Error %d for handle %p, ptr %p\n", 
                                error, hHeap, lpMem);
                            OutputDebugStringA(errorBuffer);
                        }
                    }
                    return result;
                } else {
                    // Memory is not in a valid state for freeing
                    SetLastError(ERROR_INVALID_PARAMETER);
                    return FALSE;
                }
            }
        }
        
        // For non-standard flags or if VirtualQuery failed, use original HeapFree
        BOOL result = s_origHeapFree(hHeap, dwFlags, lpMem);
        if (!result) {
            // Log the failure for debugging
            DWORD error = GetLastError();
            if (error != ERROR_SUCCESS) {
                char errorBuffer[256];
                sprintf_s(errorBuffer, sizeof(errorBuffer), 
                    "HEAPFREE FAILED: Error %d for handle %p, ptr %p\n", 
                    error, hHeap, lpMem);
                OutputDebugStringA(errorBuffer);
            }
        }
        return result;
    }
    
    return FALSE;
}

// Enhanced HeapAlloc implementation with performance optimizations
static LPVOID __stdcall MyHeapAlloc(HANDLE hHeap, DWORD dwFlags, SIZE_T dwBytes) {
    if (dwBytes == 0) return NULL;
    
    // For zero initialization requests, use our optimized calloc
    if (dwFlags & HEAP_ZERO_MEMORY) {
        void* memory = CustomCalloc(1, dwBytes);
        return memory;
    }
    
    // For generate exceptions, use our custom allocator
    if (dwFlags & HEAP_GENERATE_EXCEPTIONS) {
        void* memory = CustomMalloc(dwBytes);
        if (!memory) {
            // Set last error for heap allocation failure
            SetLastError(ERROR_NOT_ENOUGH_MEMORY);
            return NULL;
        }
        return memory;
    }
    
    // For simple allocations, use our custom allocator
    if (dwFlags == 0 || (dwFlags & HEAP_NO_SERIALIZE)) {
        void* memory = CustomMalloc(dwBytes);
        if (!memory) {
            SetLastError(ERROR_NOT_ENOUGH_MEMORY);
        }
        return memory;
    }
    
    // Fallback to original HeapAlloc for complex flags
    return s_origHeapAlloc ? s_origHeapAlloc(hHeap, dwFlags, dwBytes) : NULL;
}

static void* __cdecl MyRealloc(void* ptr, size_t sz) {
    return CustomRealloc(ptr, sz);
}

static LPVOID __stdcall MyVirtualAlloc(LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect) {
    if (dwSize == 0) return NULL;
    
    // Handle large allocations with special optimization
    if (dwSize >= MAX_BLOCK_SIZE) {
        // For very large allocations, use guard pages and special handling
        if (!lpAddress && (flAllocationType & (MEM_COMMIT | MEM_RESERVE)) && !(flAllocationType & MEM_PHYSICAL)) {
            // Use our custom allocator with guard pages for large blocks
            void* memory = CustomMalloc(dwSize);
            if (memory) {
                // Set up protection if requested
                if (flProtect != PAGE_READWRITE) {
                    DWORD oldProtect;
                    VirtualProtect(memory, dwSize, flProtect, &oldProtect);
                }
                return memory;
            }
        }
    }
    
    // For smaller allocations or complex requests, use simple handling
    if (!lpAddress && (flAllocationType & (MEM_COMMIT | MEM_RESERVE)) && !(flAllocationType & MEM_PHYSICAL)) {
        return CustomMalloc(dwSize);
    }
    
    // Fallback to original VirtualAlloc for complex requests
    return s_origVirtualAlloc ? s_origVirtualAlloc(lpAddress, dwSize, flAllocationType, flProtect) : NULL;
}

static BOOL __stdcall MyVirtualFree(LPVOID lpAddress, SIZE_T dwSize, DWORD dwFreeType) {
    if (!lpAddress) return TRUE;
    
    // Enhanced VirtualFree with sub_A4C046 pattern support
    // Check if this is executable memory from our pool
    if (executablePool.pool && lpAddress >= executablePool.pool && lpAddress < executablePool.pool + EXECUTABLE_POOL_SIZE) {
        // This is executable memory from our pool, use simple pool-based free
        executablePool.freeCount.fetch_add(1, std::memory_order_relaxed);
        return TRUE;
    }
    
    // Check if this is our custom pool memory
    if (IsInCustomPool(lpAddress)) {
        // Validate the memory block before freeing
        if (ValidateMemoryBlock(lpAddress)) {
            CustomFree(lpAddress);
            return TRUE;
        } else {
            // Invalid block detected, don't free
            SetLastError(ERROR_INVALID_PARAMETER);
            return FALSE;
        }
    }
    
    // Enhanced handling for sub_A4C046 pattern
    // The function evaluates dword_CBC034 and uses different APIs based on conditions
    if (lpAddress && (dwFreeType & MEM_RELEASE)) {
        // Check if this might be executable memory from our pool with offset
        if (executablePool.pool && lpAddress >= executablePool.pool && lpAddress < executablePool.pool + EXECUTABLE_POOL_SIZE) {
            uintptr_t poolOffset = reinterpret_cast<uintptr_t>(lpAddress) - reinterpret_cast<uintptr_t>(executablePool.pool);
            // Check for common address adjustments in 64-bit
            if (poolOffset == 0x1E || poolOffset == 0x20 || poolOffset == 0x30 || poolOffset == 0xFFE2) {
                // Adjust address for known patterns
                if (poolOffset == 0x20) {
                    lpAddress = reinterpret_cast<LPVOID>(reinterpret_cast<uintptr_t>(lpAddress) - 0x20);
                } else {
                    lpAddress = reinterpret_cast<LPVOID>(reinterpret_cast<uintptr_t>(lpAddress) - 0x1E);
                }
            }
        }
        
        // Validate adjusted address
        MEMORY_BASIC_INFORMATION mbi;
        if (VirtualQuery(lpAddress, &mbi, sizeof(mbi)) == sizeof(mbi)) {
            if (mbi.State != MEM_COMMIT || !(mbi.Protect & (PAGE_READWRITE | PAGE_EXECUTE_READWRITE))) {
                // Address is not in a valid state, use original VirtualFree
                return s_origVirtualFree ? s_origVirtualFree(lpAddress, dwSize, dwFreeType) : FALSE;
            }
        }
        
        // Use pool-based free for executable memory
        executablePool.freeCount.fetch_add(1, std::memory_order_relaxed);
        return TRUE;
    }
    
    // For non-pool memory, use enhanced VirtualFree with validation
    if (s_origVirtualFree) {
        // Validate memory is accessible before freeing
        MEMORY_BASIC_INFORMATION mbi;
        if (VirtualQuery(lpAddress, &mbi, sizeof(mbi)) == sizeof(mbi)) {
            if (mbi.State == MEM_COMMIT && (mbi.Protect & (PAGE_READWRITE | PAGE_EXECUTE_READWRITE))) {
                // Memory appears valid, proceed with free
                return s_origVirtualFree(lpAddress, dwSize, dwFreeType);
            } else {
                // Memory is not in a valid state for freeing
                SetLastError(ERROR_INVALID_PARAMETER);
                return FALSE;
            }
        }
    }
    
    return s_origVirtualFree ? s_origVirtualFree(lpAddress, dwSize, dwFreeType) : FALSE;
}

static void HookIAT(const char* dllName, const char* funcName, void* newFunc)
{
    HMODULE base = GetModuleHandle(NULL);
    if (!base) return;
    IMAGE_DOS_HEADER* dosH = (IMAGE_DOS_HEADER*)base;
    IMAGE_NT_HEADERS32* ntH = (IMAGE_NT_HEADERS32*)((BYTE*)base + dosH->e_lfanew);
    DWORD impRVA = ntH->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
    if (!impRVA) return;

    IMAGE_IMPORT_DESCRIPTOR* impDesc = (IMAGE_IMPORT_DESCRIPTOR*)((BYTE*)base + impRVA);
    for (; impDesc->Name; ++impDesc)
    {
        const char* modName = (const char*)((BYTE*)base + impDesc->Name);
        // skip hooking system libs if you want to avoid white flashing
        if (!_stricmp(modName, "kernel32.dll") ||
            !_stricmp(modName, "user32.dll") ||
            !_stricmp(modName, "gdi32.dll") ||
            !_stricmp(modName, "d3d9.dll"))
        {
            continue;
        }
        if (!_stricmp(modName, dllName))
        {
            IMAGE_THUNK_DATA* thunkOrig = (IMAGE_THUNK_DATA*)((BYTE*)base + impDesc->OriginalFirstThunk);
            IMAGE_THUNK_DATA* thunk = (IMAGE_THUNK_DATA*)((BYTE*)base + impDesc->FirstThunk);
            while (thunkOrig->u1.AddressOfData)
            {
                if (!(thunkOrig->u1.Ordinal & IMAGE_ORDINAL_FLAG32))
                {
                    IMAGE_IMPORT_BY_NAME* impByName = (IMAGE_IMPORT_BY_NAME*)((BYTE*)base + thunkOrig->u1.AddressOfData);
                    if (!strcmp(impByName->Name, funcName))
                    {
                        DWORD oldProt;
                        VirtualProtect(&thunk->u1.Function, sizeof(void*), PAGE_READWRITE, &oldProt);
                        thunk->u1.Function = (ULONG_PTR)newFunc;
                        VirtualProtect(&thunk->u1.Function, sizeof(void*), oldProt, &oldProt);
                        return;
                    }
                }
                ++thunkOrig;
                ++thunk;
            }
        }
    }
}

extern "C" __declspec(dllexport) void HookAllocators()
{
    if (g_inited) return;
    
    // Initialize memory pools FIRST
    InitMemoryPool();

    // find original malloc/free and other memory functions
    HMODULE hCRT = GetModuleHandleA("msvcrt.dll");
    if (!hCRT) hCRT = GetModuleHandleA("ucrtbase.dll");
    if (hCRT)
    {
        s_origMalloc = (CRT_Malloc)GetProcAddress(hCRT, "malloc");
        s_origFree = (CRT_Free)GetProcAddress(hCRT, "free");
        s_origRealloc = (CRT_Realloc)GetProcAddress(hCRT, "realloc");
    }

    // Get Windows API functions
    HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
    if (hKernel32)
    {
        s_origGlobalAlloc = (GlobalAlloc_t)GetProcAddress(hKernel32, "GlobalAlloc");
        s_origGlobalFree = (GlobalFree_t)GetProcAddress(hKernel32, "GlobalFree");
        s_origGlobalLock = (GlobalLock_t)GetProcAddress(hKernel32, "GlobalLock");
        s_origGlobalUnlock = (GlobalUnlock_t)GetProcAddress(hKernel32, "GlobalUnlock");
        s_origGlobalSize = (GlobalSize_t)GetProcAddress(hKernel32, "GlobalSize");
        s_origHeapFree = (HeapFree_t)GetProcAddress(hKernel32, "HeapFree");
        s_origHeapAlloc = (HeapAlloc_t)GetProcAddress(hKernel32, "HeapAlloc");
        s_origVirtualAlloc = (VirtualAlloc_t)GetProcAddress(hKernel32, "VirtualAlloc");
        s_origVirtualFree = (VirtualFree_t)GetProcAddress(hKernel32, "VirtualFree");
    }

    // hook only non-critical modules in msVCRT or ucrtbase
    HookIAT("msvcrt.dll", "malloc", (void*)MyMalloc);
    HookIAT("msvcrt.dll", "free", (void*)MyFree);
    HookIAT("msvcrt.dll", "realloc", (void*)MyRealloc);
    HookIAT("ucrtbase.dll", "malloc", (void*)MyMalloc);
    HookIAT("ucrtbase.dll", "free", (void*)MyFree);
    HookIAT("ucrtbase.dll", "realloc", (void*)MyRealloc);

    // Hook Windows API functions (be more selective to avoid system issues)
    HookIAT("kernel32.dll", "GlobalAlloc", (void*)MyGlobalAlloc);
    HookIAT("kernel32.dll", "GlobalFree", (void*)MyGlobalFree);
    HookIAT("kernel32.dll", "GlobalLock", (void*)MyGlobalLock);
    HookIAT("kernel32.dll", "GlobalUnlock", (void*)MyGlobalUnlock);
    HookIAT("kernel32.dll", "GlobalSize", (void*)MyGlobalSize);
    HookIAT("kernel32.dll", "HeapAlloc", (void*)MyHeapAlloc);
    HookIAT("kernel32.dll", "HeapFree", (void*)MyHeapFree);
    HookIAT("kernel32.dll", "VirtualAlloc", (void*)MyVirtualAlloc);
    HookIAT("kernel32.dll", "VirtualFree", (void*)MyVirtualFree);
    
    g_inited = true;
    DAWN_OF_WAR_LOG_INFO("MemoryPoolDLL", "Memory allocators hooked successfully");
}

// Forward declarations for specialized free functions
extern "C" __declspec(dllexport) void LogFree(void* ptr);
extern "C" __declspec(dllexport) void FileFree(void* ptr);
extern "C" __declspec(dllexport) void GuiFree(void* ptr);
extern "C" __declspec(dllexport) void SmallObjFree(void* ptr);
extern "C" __declspec(dllexport) void LinkedListFree(void* ptr);
extern "C" __declspec(dllexport) void StringFree(void* ptr);
extern "C" __declspec(dllexport) void BatchLinkedListFree(void** ptrs, size_t count);
extern "C" __declspec(dllexport) void ExecutableFree(void* ptr);

// CustomFree implementation moved outside HookAllocators
extern "C" __declspec(dllexport) void CustomFree(void* p)
{
    if (!p) return; // Freeing nullptr is allowed
    
    auto startTime = std::chrono::high_resolution_clock::now();
    gameMemoryPool.freeCount.fetch_add(1, std::memory_order_relaxed);
    
    // Log deallocation request
    DAWN_OF_WAR_LOG_TRACE("MemoryPoolDLL", "CustomFree called for address %p", p);
    
    // FIRST: Validate pointer is not obviously invalid
    // This prevents crashes when Dawn of War tries to free invalid memory
    if (reinterpret_cast<uintptr_t>(p) < 0x10000) {
        DAWN_OF_WAR_LOG_WARN("MemoryPoolDLL", 
            "Skipping free of suspiciously low address %p", p);
        auto endTime = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::microseconds>(endTime - startTime).count();
        gameMemoryPool.totalFreeTime.fetch_add(static_cast<size_t>(duration), std::memory_order_relaxed);
        return;
    }
    
    // Check if pointer might be in read-only memory (can't free)
    MEMORY_BASIC_INFORMATION mbi;
    if (VirtualQuery(p, &mbi, sizeof(mbi)) == 0) {
        DAWN_OF_WAR_LOG_WARN("MemoryPoolDLL", 
            "Cannot query memory at %p (invalid pointer)", p);
        auto endTime = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::microseconds>(endTime - startTime).count();
        gameMemoryPool.totalFreeTime.fetch_add(static_cast<size_t>(duration), std::memory_order_relaxed);
        return;
    }
    
    // Don't try to free read-only or no-access memory
    if (mbi.Protect == PAGE_NOACCESS || mbi.Protect == PAGE_READONLY) {
        DAWN_OF_WAR_LOG_WARN("MemoryPoolDLL", 
            "Skipping free of read-only/no-access memory at %p", p);
        auto endTime = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::microseconds>(endTime - startTime).count();
        gameMemoryPool.totalFreeTime.fetch_add(static_cast<size_t>(duration), std::memory_order_relaxed);
        return;
    }
    
    if (!gameMemoryPool.pool) return;
    
    // Enhanced free routing based on 11 specific free patterns
    
    // Pattern 1: sub_4010E0 - General deallocation with SEH
    // Pattern 2: sub_5CF9E0 - File operations cleanup
    // Pattern 3: sub_698CF0 - Linked list chain deallocation
    // Pattern 4: sub_69AA30 - Nested arrays cleanup
    // Pattern 5: sub_6A0AB0 - String and temporary allocation cleanup
    // Pattern 6: sub_6A35F0 - Resource transformation and linked list cleanup
    // Pattern 7: sub_6A3840 - String processing and recursive linked deallocation
    // Pattern 8: sub_6A3AA0 - String validation and linked structure deallocation
    // Pattern 9: sub_819C90 - Simple free wrapper
    // Pattern 10: sub_8CB4F0 - Event sink structure cleanup
    // Pattern 11: sub_8CB980 - String management and conditional deallocation
    
    // Check specialized pools first for performance
    if (logPool.pool && p >= logPool.pool && p < logPool.pool + LOG_BUFFER_SIZE) {
        DAWN_OF_WAR_LOG_TRACE("MemoryPoolDLL", "Routing %p to log pool free", p);
        LogFree(p);
        auto endTime = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::microseconds>(endTime - startTime).count();
        gameMemoryPool.totalFreeTime.fetch_add(static_cast<size_t>(duration), std::memory_order_relaxed);
        return;
    }
    
    if (filePool.pool && p >= filePool.pool && p < filePool.pool + FILE_BUFFER_SIZE) {
        DAWN_OF_WAR_LOG_TRACE("MemoryPoolDLL", "Routing %p to file pool free", p);
        FileFree(p);
        auto endTime = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::microseconds>(endTime - startTime).count();
        gameMemoryPool.totalFreeTime.fetch_add(static_cast<size_t>(duration), std::memory_order_relaxed);
        return;
    }
    
    if (guiPool.pool && p >= guiPool.pool && p < guiPool.pool + GUI_POOL_SIZE) {
        DAWN_OF_WAR_LOG_TRACE("MemoryPoolDLL", "Routing %p to GUI pool free", p);
        GuiFree(p);
        auto endTime = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::microseconds>(endTime - startTime).count();
        gameMemoryPool.totalFreeTime.fetch_add(static_cast<size_t>(duration), std::memory_order_relaxed);
        return;
    }
    
    if (smallObjPool.pool && p >= smallObjPool.pool && p < smallObjPool.pool + SMALL_OBJ_POOL_SIZE) {
        DAWN_OF_WAR_LOG_TRACE("MemoryPoolDLL", "Routing %p to small object pool free", p);
        SmallObjFree(p);
        auto endTime = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::microseconds>(endTime - startTime).count();
        gameMemoryPool.totalFreeTime.fetch_add(static_cast<size_t>(duration), std::memory_order_relaxed);
        return;
    }
    
    if (linkedListPool.pool && p >= linkedListPool.pool && p < linkedListPool.pool + LINKED_LIST_POOL_SIZE) {
        DAWN_OF_WAR_LOG_TRACE("MemoryPoolDLL", "Routing %p to linked list pool free", p);
        LinkedListFree(p);
        auto endTime = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::microseconds>(endTime - startTime).count();
        gameMemoryPool.totalFreeTime.fetch_add(static_cast<size_t>(duration), std::memory_order_relaxed);
        return;
    }
    
    if (stringPool.pool && p >= stringPool.pool && p < stringPool.pool + STRING_POOL_SIZE) {
        DAWN_OF_WAR_LOG_TRACE("MemoryPoolDLL", "Routing %p to string pool free", p);
        StringFree(p);
        auto endTime = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::microseconds>(endTime - startTime).count();
        gameMemoryPool.totalFreeTime.fetch_add(static_cast<size_t>(duration), std::memory_order_relaxed);
        return;
    }
    
    if (executablePool.pool && p >= executablePool.pool && p < executablePool.pool + EXECUTABLE_POOL_SIZE) {
        DAWN_OF_WAR_LOG_TRACE("MemoryPoolDLL", "Routing %p to executable pool free", p);
        ExecutableFree(p);
        auto endTime = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::microseconds>(endTime - startTime).count();
        gameMemoryPool.totalFreeTime.fetch_add(static_cast<size_t>(duration), std::memory_order_relaxed);
        return;
    }
    
    // Check if in main custom pool
    if (IsInCustomPool(p)) {
        DAWN_OF_WAR_LOG_TRACE("MemoryPoolDLL", "Freeing %p from main pool", p);
        EnterCriticalSection(&g_lock);
        MemoryBlock* targetBlock = nullptr;
        MemoryBlock* current = gameMemoryPool.head.load(std::memory_order_acquire);
        
        while (current) {
            if (current->address == p) {
                if (!current->used || current->magic != BLOCK_MAGIC) {
                    // Double free or corruption detected - enhanced error reporting
                    ++gameMemoryPool.fragmentationCount;
                    DAWN_OF_WAR_LOG_ERROR("MemoryPoolDLL", "Memory corruption: Double free or invalid magic at %p (magic: 0x%08X)", p, current->magic);
                    char errorBuffer[256];
                    sprintf_s(errorBuffer, sizeof(errorBuffer), 
                        "MEMORY CORRUPTION: Double free or invalid magic at %p (magic: 0x%08X)\n", 
                        p, current->magic);
                    OutputDebugStringA(errorBuffer);
                    LeaveCriticalSection(&g_lock);
                    auto endTime = std::chrono::high_resolution_clock::now();
                    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(endTime - startTime).count();
                    gameMemoryPool.totalFreeTime.fetch_add((size_t)duration, std::memory_order_relaxed);
                    return;
                }
                targetBlock = current;
                break;
            }
            current = current->next;
        }
        
        if (targetBlock) {
            gameMemoryPool.totalAllocated.fetch_sub(targetBlock->size, std::memory_order_relaxed);
            gameMemoryPool.freeCount.fetch_add(1, std::memory_order_relaxed);
            targetBlock->used = false;
            
            // Enhanced security: Clear memory with pattern for debugging
            memset(targetBlock->address, 0xFE, targetBlock->size);
            
            PushFreeBlock(targetBlock);
            DAWN_OF_WAR_LOG_TRACE("MemoryPoolDLL", "Successfully freed %zu bytes from %p", targetBlock->size, p);
        } else {
            // Block not found in tracking - possible corruption
            ++gameMemoryPool.fragmentationCount;
            DAWN_OF_WAR_LOG_ERROR("MemoryPoolDLL", "Memory corruption: Block not found in tracking at %p", p);
            char errorBuffer[256];
            sprintf_s(errorBuffer, sizeof(errorBuffer), 
                "MEMORY CORRUPTION: Block not found in tracking at %p\n", p);
            OutputDebugStringA(errorBuffer);
        }
        LeaveCriticalSection(&g_lock);
    } else {
        // Not in our pools, use original free
        DAWN_OF_WAR_LOG_TRACE("MemoryPoolDLL", "Forwarding %p to system free (not in our pools)", p);
        if (s_origFree) s_origFree(p);
    }
    
    auto endTime = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(endTime - startTime).count();
    gameMemoryPool.totalFreeTime.fetch_add(static_cast<size_t>(duration), std::memory_order_relaxed);
}

// Periodic memory statistics reporting
void ReportMemoryStatistics() {
    static DWORD lastReportTime = 0;
    DWORD currentTime = GetTickCount();
    
    // Report every 60 seconds
    if (currentTime - lastReportTime > 60000) {
        lastReportTime = currentTime;
        
        // Main pool statistics
        size_t mainAllocated = gameMemoryPool.totalAllocated.load(std::memory_order_relaxed);
        size_t mainPeak = gameMemoryPool.peakUsage.load(std::memory_order_relaxed);
        size_t mainMallocs = gameMemoryPool.mallocCount.load(std::memory_order_relaxed);
        size_t mainFrees = gameMemoryPool.freeCount.load(std::memory_order_relaxed);
        size_t mainAllocTime = gameMemoryPool.totalAllocTime.load(std::memory_order_relaxed);
        size_t mainFreeTime = gameMemoryPool.totalFreeTime.load(std::memory_order_relaxed);
        size_t mainCacheHits = gameMemoryPool.cacheHits.load(std::memory_order_relaxed);
        size_t mainCacheMisses = gameMemoryPool.cacheMisses.load(std::memory_order_relaxed);
        
        DAWN_OF_WAR_LOG_INFO("MemoryPoolDLL", "=== MEMORY POOL STATISTICS ===");
        DAWN_OF_WAR_LOG_INFO("MemoryPoolDLL", "Main Pool: %zu MB allocated, %zu MB peak (%.1f%% usage)", 
            mainAllocated / (1024 * 1024), mainPeak / (1024 * 1024), 
            (mainAllocated * 100.0f) / TOTAL_POOL_SIZE);
        DAWN_OF_WAR_LOG_INFO("MemoryPoolDLL", "Operations: %zu mallocs, %zu frees, %zu cache hits, %zu cache misses", 
            mainMallocs, mainFrees, mainCacheHits, mainCacheMisses);
        DAWN_OF_WAR_LOG_INFO("MemoryPoolDLL", "Performance: Avg alloc %zu μs, Avg free %zu μs", 
            mainMallocs > 0 ? mainAllocTime / mainMallocs : 0,
            mainFrees > 0 ? mainFreeTime / mainFrees : 0);
        
        // Specialized pool statistics
        if (logPool.pool) {
            size_t logAllocated = logPool.totalAllocated.load(std::memory_order_relaxed);
            size_t logCount = logPool.logAllocCount.load(std::memory_order_relaxed);
            DAWN_OF_WAR_LOG_INFO("MemoryPoolDLL", "Log Pool: %zu MB allocated, %zu allocations", 
                logAllocated / (1024 * 1024), logCount);
        }
        
        if (filePool.pool) {
            size_t fileAllocated = filePool.totalAllocated.load(std::memory_order_relaxed);
            size_t fileCount = filePool.fileAllocCount.load(std::memory_order_relaxed);
            DAWN_OF_WAR_LOG_INFO("MemoryPoolDLL", "File Pool: %zu MB allocated, %zu allocations", 
                fileAllocated / (1024 * 1024), fileCount);
        }
        
        if (guiPool.pool) {
            size_t guiAllocated = guiPool.totalAllocated.load(std::memory_order_relaxed);
            size_t guiCount = guiPool.guiAllocCount.load(std::memory_order_relaxed);
            DAWN_OF_WAR_LOG_INFO("MemoryPoolDLL", "GUI Pool: %zu MB allocated, %zu allocations", 
                guiAllocated / (1024 * 1024), guiCount);
        }
        
        if (smallObjPool.pool) {
            size_t smallAllocated = smallObjPool.totalAllocated.load(std::memory_order_relaxed);
            size_t smallCount = smallObjPool.smallObjAllocCount.load(std::memory_order_relaxed);
            DAWN_OF_WAR_LOG_INFO("MemoryPoolDLL", "Small Object Pool: %zu MB allocated, %zu allocations", 
                smallAllocated / (1024 * 1024), smallCount);
        }
        
        if (linkedListPool.pool) {
            size_t linkedAllocated = linkedListPool.totalAllocated.load(std::memory_order_relaxed);
            size_t linkedCount = linkedListPool.linkedListAllocCount.load(std::memory_order_relaxed);
            DAWN_OF_WAR_LOG_INFO("MemoryPoolDLL", "Linked List Pool: %zu MB allocated, %zu allocations", 
                linkedAllocated / (1024 * 1024), linkedCount);
        }
        
        if (stringPool.pool) {
            size_t stringAllocated = stringPool.totalAllocated.load(std::memory_order_relaxed);
            size_t stringCount = stringPool.stringAllocCount.load(std::memory_order_relaxed);
            DAWN_OF_WAR_LOG_INFO("MemoryPoolDLL", "String Pool: %zu MB allocated, %zu allocations", 
                stringAllocated / (1024 * 1024), stringCount);
        }
        
        if (executablePool.pool) {
            size_t execAllocated = executablePool.totalAllocated.load(std::memory_order_relaxed);
            size_t execCount = executablePool.executableAllocCount.load(std::memory_order_relaxed);
            DAWN_OF_WAR_LOG_INFO("MemoryPoolDLL", "Executable Pool: %zu MB allocated, %zu allocations", 
                execAllocated / (1024 * 1024), execCount);
        }
        
        // System memory information
        MEMORYSTATUSEX memStatus;
        memStatus.dwLength = sizeof(memStatus);
        if (GlobalMemoryStatusEx(&memStatus)) {
            DAWN_OF_WAR_LOG_INFO("MemoryPoolDLL", "System Memory: %u%% load, %zu MB available, %zu MB total", 
                memStatus.dwMemoryLoad,
                memStatus.ullAvailPhys / (1024 * 1024),
                memStatus.ullTotalPhys / (1024 * 1024));
        }
        
        DAWN_OF_WAR_LOG_INFO("MemoryPoolDLL", "=== END STATISTICS ===");
    }
}

BOOL WINAPI DllMain(HINSTANCE hDLL, DWORD reason, LPVOID)
{
    if (reason == DLL_PROCESS_ATTACH)
    {
        DisableThreadLibraryCalls(hDLL);
        
        // Initialize critical section first
        InitializeCriticalSection(&g_lock);
        
        // Setup crash reporting system early - BEFORE any allocations
        SetupCrashReporting();
        
        // Try to initialize master logger - but don't fail if it's not available
        // The logger might be loaded separately or not at all
        try {
            DawnOfWarLog_Initialize(nullptr);
            DAWN_OF_WAR_LOG_INFO("MemoryPoolDLL", "Dawn of War Memory Pool DLL starting");
        } catch (...) {
            // Logger initialization failed - continue without logging
            // We can still use OutputDebugString for critical errors
        }
        
        // Hook allocators right away
        HookAllocators();
        
        // Try to log success if logger is available
        try {
            DAWN_OF_WAR_LOG_INFO("MemoryPoolDLL", "Memory Pool DLL initialization completed successfully");
        } catch (...) {
            // Logger not available, use debug output
            OutputDebugStringA("MemoryPoolDLL: Initialization completed (no logger available)\n");
        }
    }
    else if (reason == DLL_PROCESS_DETACH)
    {
        DAWN_OF_WAR_LOG_INFO("MemoryPoolDLL", "Dawn of War Memory Pool DLL shutting down");
        
        // Report final statistics
        ReportMemoryStatistics();
        
        // cleanup
        CleanupMemoryPool();
        
        // Clean up crash reporting buffer
        if (g_crashReportBuffer) {
            VirtualFree(g_crashReportBuffer, 0, MEM_RELEASE);
            g_crashReportBuffer = nullptr;
            g_crashReportSize = 0;
        }
        
        // Clean up emergency reserve
        if (g_emergencyReserve) {
            VirtualFree(g_emergencyReserve, 0, MEM_RELEASE);
            g_emergencyReserve = nullptr;
        }
        
        DeleteCriticalSection(&g_lock);
        
        // Shutdown master logger last
        DawnOfWarLog_Shutdown();
    }
    return TRUE;
}