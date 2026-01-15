#include "pch.h"
#include <chrono>

// Force GPU usage
extern "C" __declspec(dllexport) DWORD NvOptimusEnablement = 1;
extern "C" __declspec(dllexport) DWORD AmdPowerXpressRequestHighPerformance = 1;

// Memory pool configuration (2GB total) - Enhanced for Dawn of War Soulstorm
constexpr size_t PRIVATE_MEMORY_SIZE = 1ull * 1024 * 1024 * 1024;  // 1GB
constexpr size_t TEXTURE_MEMORY_SIZE = 1ull * 1024 * 1024 * 1024; // 1GB
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
    
    MemoryPool() : pool(nullptr), offset(0), head(nullptr), totalAllocated(0), peakUsage(0), fragmentationCount(0),
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
static MemoryPool tempPool;       // For temporary allocations (enhanced)
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
extern "C" __declspec(dllexport) void* TempMalloc(size_t size);

// Forward declarations for specialized free functions
extern "C" __declspec(dllexport) void LogFree(void* ptr);
extern "C" __declspec(dllexport) void FileFree(void* ptr);
extern "C" __declspec(dllexport) void GuiFree(void* ptr);
extern "C" __declspec(dllexport) void SmallObjFree(void* ptr);
extern "C" __declspec(dllexport) void LinkedListFree(void* ptr);
extern "C" __declspec(dllexport) void StringFree(void* ptr);
extern "C" __declspec(dllexport) void BatchLinkedListFree(void** ptrs, size_t count);
extern "C" __declspec(dllexport) void ExecutableFree(void* ptr);
extern "C" __declspec(dllexport) void TempFree(void* ptr);

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
            for (int i = 0; i < NUM_SIZE_CLASSES; ++i) {
                logPool.freeLists[i].store(nullptr, std::memory_order_relaxed);
            }
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
            for (int i = 0; i < NUM_SIZE_CLASSES; ++i) {
                filePool.freeLists[i].store(nullptr, std::memory_order_relaxed);
            }
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
            for (int i = 0; i < NUM_SIZE_CLASSES; ++i) {
                guiPool.freeLists[i].store(nullptr, std::memory_order_relaxed);
            }
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
            for (int i = 0; i < NUM_SIZE_CLASSES; ++i) {
                smallObjPool.freeLists[i].store(nullptr, std::memory_order_relaxed);
            }
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
            for (int i = 0; i < NUM_SIZE_CLASSES; ++i) {
                linkedListPool.freeLists[i].store(nullptr, std::memory_order_relaxed);
            }
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
            for (int i = 0; i < NUM_SIZE_CLASSES; ++i) {
                stringPool.freeLists[i].store(nullptr, std::memory_order_relaxed);
            }
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
            for (int i = 0; i < NUM_SIZE_CLASSES; ++i) {
                executablePool.freeLists[i].store(nullptr, std::memory_order_relaxed);
            }
        }
    }
}

void InitMemoryPool() {
    static bool initialized = false;
    if (!initialized) {
        char* p = static_cast<char*>(VirtualAlloc(nullptr, TOTAL_POOL_SIZE, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));
        if (!p) return;
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
        
        // Initialize specialized pools
        InitSpecializedPools();
        
        initialized = true;
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

extern "C" __declspec(dllexport) void* CustomMalloc(size_t size) {
    if (size == 0) return nullptr;
    
    // Get calling address for context determination
    void* caller = _ReturnAddress();
    
    // Route to specialized pools based on call patterns and size
    if (size <= 256) {
        // Small allocations - likely utility functions (sub_69A7E0, sub_69A810)
        return SmallObjMalloc(size);
    } else if (size <= 1024) {
        // Medium allocations - check if likely logging related
        // This would ideally use call stack analysis, but we'll use heuristics
        return LogMalloc(size);
    } else if (size <= 8192) {
        // Larger allocations - could be file buffers or GUI objects
        return FileMalloc(size);
    } else if (size <= 65536) {
        // Even larger - likely GUI/window management
        return GuiMalloc(size);
    } else {
        // Very large allocations - use main pool implementation directly
        if (size < 1024 * 1024 && size < (TOTAL_POOL_SIZE / 3)) {
            // Use original main pool implementation for large blocks
            EnterCriticalSection(&g_lock);
            InitMemoryPool();
            size_t alignedSize = (size + 15) & ~static_cast<size_t>(15);
            
            // For very large allocations, consider guard pages
            bool useGuardPages = (alignedSize >= MAX_BLOCK_SIZE);
            if (useGuardPages) {
                alignedSize += GUARD_PAGE_SIZE * 2; // Guard pages before and after
            }
            
            // Try to find a suitable free block first
            MemoryBlock* block = PopFreeBlock(alignedSize);
            if (block) {
                gameMemoryPool.totalAllocated.fetch_add(alignedSize, std::memory_order_relaxed);
                size_t currentUsage = gameMemoryPool.totalAllocated.load(std::memory_order_relaxed);
                size_t peakUsage = gameMemoryPool.peakUsage.load(std::memory_order_relaxed);
                if (currentUsage > peakUsage) {
                    gameMemoryPool.peakUsage.store(currentUsage, std::memory_order_relaxed);
                }
                
                if (useGuardPages) {
                    // Set up guard pages
                    DWORD oldProtect;
                    VirtualProtect(static_cast<char*>(block->address), GUARD_PAGE_SIZE, PAGE_NOACCESS, &oldProtect);
                    VirtualProtect(static_cast<char*>(block->address) + alignedSize - GUARD_PAGE_SIZE, GUARD_PAGE_SIZE, PAGE_NOACCESS, &oldProtect);
                    // Return pointer after first guard page
                    void* userPtr = static_cast<char*>(block->address) + GUARD_PAGE_SIZE;
                    LeaveCriticalSection(&g_lock);
                    return userPtr;
                }
                
                LeaveCriticalSection(&g_lock);
                return block->address;
            }
            
            // No suitable free block, allocate from pool
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
                // Set up guard pages
                DWORD oldProtect;
                VirtualProtect(allocatedMemory, GUARD_PAGE_SIZE, PAGE_NOACCESS, &oldProtect);
                VirtualProtect(static_cast<char*>(allocatedMemory) + alignedSize - GUARD_PAGE_SIZE, GUARD_PAGE_SIZE, PAGE_NOACCESS, &oldProtect);
                // Return pointer after first guard page
                void* userPtr = static_cast<char*>(allocatedMemory) + GUARD_PAGE_SIZE;
                LeaveCriticalSection(&g_lock);
                return userPtr;
            }
            
            LeaveCriticalSection(&g_lock);
            return allocatedMemory;
        }
    }
    
    // Fallback to original malloc
    return s_origMalloc ? s_origMalloc(size) : nullptr;
}

extern "C" __declspec(dllexport) void* LogMalloc(size_t size) {
    // Optimized for logging allocations (sub_577C91, sub_577CB8, sub_577D40, sub_57AC40)
    if (size == 0 || size > LOG_BUFFER_SIZE / 4) return s_origMalloc ? s_origMalloc(size) : nullptr;
    
    EnterCriticalSection(&g_lock);
    if (!logPool.pool) {
        InitSpecializedPools();
        if (!logPool.pool) {
            LeaveCriticalSection(&g_lock);
            return s_origMalloc ? s_origMalloc(size) : nullptr;
        }
    }
    
    size_t alignedSize = (size + 7) & ~static_cast<size_t>(7); // 8-byte alignment for strings
    size_t currentOffset = logPool.offset.fetch_add(alignedSize, std::memory_order_relaxed);
    
    if (currentOffset + alignedSize > LOG_BUFFER_SIZE) {
        logPool.offset.fetch_sub(alignedSize, std::memory_order_relaxed);
        LeaveCriticalSection(&g_lock);
        return s_origMalloc ? s_origMalloc(size) : nullptr;
    }
    
    void* allocatedMemory = logPool.pool + currentOffset;
    logPool.totalAllocated.fetch_add(alignedSize, std::memory_order_relaxed);
    logPool.logAllocCount.fetch_add(1, std::memory_order_relaxed);
    
    size_t currentUsage = logPool.totalAllocated.load(std::memory_order_relaxed);
    size_t peakUsage = logPool.peakUsage.load(std::memory_order_relaxed);
    if (currentUsage > peakUsage) {
        logPool.peakUsage.store(currentUsage, std::memory_order_relaxed);
    }
    
    LeaveCriticalSection(&g_lock);
    return allocatedMemory;
}

extern "C" __declspec(dllexport) void* FileMalloc(size_t size) {
    // Optimized for file operations (sub_6082D0, sub_819C55)
    if (size == 0 || size > FILE_BUFFER_SIZE / 2) return s_origMalloc ? s_origMalloc(size) : nullptr;
    
    EnterCriticalSection(&g_lock);
    if (!filePool.pool) {
        InitSpecializedPools();
        if (!filePool.pool) {
            LeaveCriticalSection(&g_lock);
            return s_origMalloc ? s_origMalloc(size) : nullptr;
        }
    }
    
    size_t alignedSize = (size + 511) & ~static_cast<size_t>(511); // 512-byte alignment for file buffers
    size_t currentOffset = filePool.offset.fetch_add(alignedSize, std::memory_order_relaxed);
    
    if (currentOffset + alignedSize > FILE_BUFFER_SIZE) {
        filePool.offset.fetch_sub(alignedSize, std::memory_order_relaxed);
        LeaveCriticalSection(&g_lock);
        return s_origMalloc ? s_origMalloc(size) : nullptr;
    }
    
    void* allocatedMemory = filePool.pool + currentOffset;
    filePool.totalAllocated.fetch_add(alignedSize, std::memory_order_relaxed);
    filePool.fileAllocCount.fetch_add(1, std::memory_order_relaxed);
    
    size_t currentUsage = filePool.totalAllocated.load(std::memory_order_relaxed);
    size_t peakUsage = filePool.peakUsage.load(std::memory_order_relaxed);
    if (currentUsage > peakUsage) {
        filePool.peakUsage.store(currentUsage, std::memory_order_relaxed);
    }
    
    LeaveCriticalSection(&g_lock);
    return allocatedMemory;
}

extern "C" __declspec(dllexport) void* GuiMalloc(size_t size) {
    // Optimized for GUI/window management (sub_6A4CC0, sub_6A4FB0)
    if (size == 0 || size > GUI_POOL_SIZE / 8) return s_origMalloc ? s_origMalloc(size) : nullptr;
    
    EnterCriticalSection(&g_lock);
    if (!guiPool.pool) {
        InitSpecializedPools();
        if (!guiPool.pool) {
            LeaveCriticalSection(&g_lock);
            return s_origMalloc ? s_origMalloc(size) : nullptr;
        }
    }
    
    size_t alignedSize = (size + 31) & ~static_cast<size_t>(31); // 32-byte alignment for GUI objects
    size_t currentOffset = guiPool.offset.fetch_add(alignedSize, std::memory_order_relaxed);
    
    if (currentOffset + alignedSize > GUI_POOL_SIZE) {
        guiPool.offset.fetch_sub(alignedSize, std::memory_order_relaxed);
        LeaveCriticalSection(&g_lock);
        return s_origMalloc ? s_origMalloc(size) : nullptr;
    }
    
    void* allocatedMemory = guiPool.pool + currentOffset;
    guiPool.totalAllocated.fetch_add(alignedSize, std::memory_order_relaxed);
    guiPool.guiAllocCount.fetch_add(1, std::memory_order_relaxed);
    
    size_t currentUsage = guiPool.totalAllocated.load(std::memory_order_relaxed);
    size_t peakUsage = guiPool.peakUsage.load(std::memory_order_relaxed);
    if (currentUsage > peakUsage) {
        guiPool.peakUsage.store(currentUsage, std::memory_order_relaxed);
    }
    
    LeaveCriticalSection(&g_lock);
    return allocatedMemory;
} // Added missing closing brace

extern "C" __declspec(dllexport) void* SmallObjMalloc(size_t size) {
    // Optimized for small frequent allocations (sub_69A7E0, sub_69A810)
    if (size == 0 || size > 4096) return s_origMalloc ? s_origMalloc(size) : nullptr;
    
    EnterCriticalSection(&g_lock);
    if (!smallObjPool.pool) {
        InitSpecializedPools();
        if (!smallObjPool.pool) {
            LeaveCriticalSection(&g_lock);
            return s_origMalloc ? s_origMalloc(size) : nullptr;
        }
    }
    
    size_t alignedSize = (size + 15) & ~static_cast<size_t>(15); // 16-byte alignment
    size_t currentOffset = smallObjPool.offset.fetch_add(alignedSize, std::memory_order_relaxed);
    
    if (currentOffset + alignedSize > SMALL_OBJ_POOL_SIZE) {
        smallObjPool.offset.fetch_sub(alignedSize, std::memory_order_relaxed);
        LeaveCriticalSection(&g_lock);
        return s_origMalloc ? s_origMalloc(size) : nullptr;
    }
    
    void* allocatedMemory = smallObjPool.pool + currentOffset;
    smallObjPool.totalAllocated.fetch_add(alignedSize, std::memory_order_relaxed);
    smallObjPool.smallObjAllocCount.fetch_add(1, std::memory_order_relaxed);
    
    size_t currentUsage = smallObjPool.totalAllocated.load(std::memory_order_relaxed);
    size_t peakUsage = smallObjPool.peakUsage.load(std::memory_order_relaxed);
    if (currentUsage > peakUsage) {
        smallObjPool.peakUsage.store(currentUsage, std::memory_order_relaxed);
    }
    
    LeaveCriticalSection(&g_lock);
    return allocatedMemory;
}

extern "C" __declspec(dllexport) void* LinkedListMalloc(size_t size) {
    // Optimized for linked list structures (sub_698CF0, sub_6A35F0, sub_6A3840, sub_6A3AA0)
    if (size == 0 || size > LINKED_LIST_POOL_SIZE / 16) return s_origMalloc ? s_origMalloc(size) : nullptr;
    
    EnterCriticalSection(&g_lock);
    if (!linkedListPool.pool) {
        InitSpecializedPools();
        if (!linkedListPool.pool) {
            LeaveCriticalSection(&g_lock);
            return s_origMalloc ? s_origMalloc(size) : nullptr;
        }
    }
    
    size_t alignedSize = (size + 7) & ~static_cast<size_t>(7); // 8-byte alignment for pointers
    size_t currentOffset = linkedListPool.offset.fetch_add(alignedSize, std::memory_order_relaxed);
    
    if (currentOffset + alignedSize > LINKED_LIST_POOL_SIZE) {
        linkedListPool.offset.fetch_sub(alignedSize, std::memory_order_relaxed);
        LeaveCriticalSection(&g_lock);
        return s_origMalloc ? s_origMalloc(size) : nullptr;
    }
    
    void* allocatedMemory = linkedListPool.pool + currentOffset;
    linkedListPool.totalAllocated.fetch_add(alignedSize, std::memory_order_relaxed);
    linkedListPool.linkedListAllocCount.fetch_add(1, std::memory_order_relaxed);
    
    size_t currentUsage = linkedListPool.totalAllocated.load(std::memory_order_relaxed);
    size_t peakUsage = linkedListPool.peakUsage.load(std::memory_order_relaxed);
    if (currentUsage > peakUsage) {
        linkedListPool.peakUsage.store(currentUsage, std::memory_order_relaxed);
    }
    
    LeaveCriticalSection(&g_lock);
    return allocatedMemory;
}

extern "C" __declspec(dllexport) void* StringMalloc(size_t size) {
    // Optimized for string operations (sub_6A0AB0, sub_6A3840, sub_6A3AA0, sub_6A35F0, sub_6CB980)
    if (size == 0 || size > STRING_POOL_SIZE / 32) return s_origMalloc ? s_origMalloc(size) : nullptr;
    
    EnterCriticalSection(&g_lock);
    if (!stringPool.pool) {
        InitSpecializedPools();
        if (!stringPool.pool) {
            LeaveCriticalSection(&g_lock);
            return s_origMalloc ? s_origMalloc(size) : nullptr;
        }
    }
    
    size_t alignedSize = (size + 7) & ~static_cast<size_t>(7); // 8-byte alignment for strings
    size_t currentOffset = stringPool.offset.fetch_add(alignedSize, std::memory_order_relaxed);
    
    if (currentOffset + alignedSize > STRING_POOL_SIZE) {
        stringPool.offset.fetch_sub(alignedSize, std::memory_order_relaxed);
        LeaveCriticalSection(&g_lock);
        return s_origMalloc ? s_origMalloc(size) : nullptr;
    }
    
    void* allocatedMemory = stringPool.pool + currentOffset;
    stringPool.totalAllocated.fetch_add(alignedSize, std::memory_order_relaxed);
    stringPool.stringAllocCount.fetch_add(1, std::memory_order_relaxed);
    
    size_t currentUsage = stringPool.totalAllocated.load(std::memory_order_relaxed);
    size_t peakUsage = stringPool.peakUsage.load(std::memory_order_relaxed);
    if (currentUsage > peakUsage) {
        stringPool.peakUsage.store(currentUsage, std::memory_order_relaxed);
    }
    
    LeaveCriticalSection(&g_lock);
    return allocatedMemory;
}

extern "C" __declspec(dllexport) void* ExecutableMalloc(size_t size) {
    // Optimized for executable memory allocations (sub_9AE540) with PAGE_EXECUTE_READWRITE
    if (size == 0 || size > EXECUTABLE_POOL_SIZE / 16) return s_origVirtualAlloc ? s_origVirtualAlloc(nullptr, size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE) : nullptr;
    
    EnterCriticalSection(&g_lock);
    if (!executablePool.pool) {
        InitSpecializedPools();
        if (!executablePool.pool) {
            LeaveCriticalSection(&g_lock);
            return s_origVirtualAlloc ? s_origVirtualAlloc(nullptr, size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE) : nullptr;
        }
    }
    
    size_t alignedSize = (size + 15) & ~static_cast<size_t>(15); // 16-byte alignment for executable code
    size_t currentOffset = executablePool.offset.fetch_add(alignedSize, std::memory_order_relaxed);
    
    if (currentOffset + alignedSize > EXECUTABLE_POOL_SIZE) {
        executablePool.offset.fetch_sub(alignedSize, std::memory_order_relaxed);
        LeaveCriticalSection(&g_lock);
        return s_origVirtualAlloc ? s_origVirtualAlloc(nullptr, size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE) : nullptr;
    }
    
    void* allocatedMemory = executablePool.pool + currentOffset;
    executablePool.totalAllocated.fetch_add(alignedSize, std::memory_order_relaxed);
    executablePool.executableAllocCount.fetch_add(1, std::memory_order_relaxed);
    
    size_t currentUsage = executablePool.totalAllocated.load(std::memory_order_relaxed);
    size_t peakUsage = executablePool.peakUsage.load(std::memory_order_relaxed);
    if (currentUsage > peakUsage) {
        executablePool.peakUsage.store(currentUsage, std::memory_order_relaxed);
    }
    
    LeaveCriticalSection(&g_lock);
    return allocatedMemory;
}

extern "C" __declspec(dllexport) void LogFree(void* ptr) {
    // Optimized for logging memory deallocation (sub_577C91, sub_577CB8, sub_577D40, sub_57AC40)
    if (!ptr) return;
    
    // Simple pool-based free for logging - no tracking needed for performance
    // Just mark as available for reuse
    EnterCriticalSection(&g_lock);
    if (logPool.pool && ptr >= logPool.pool && ptr < logPool.pool + LOG_BUFFER_SIZE) {
        // For pool-based allocations, we don't actually free individual blocks
        // The pool is reset as a whole when needed
        logPool.freeCount.fetch_add(1, std::memory_order_relaxed);
    } else {
        // Fallback to original free
        if (s_origFree) s_origFree(ptr);
    }
    LeaveCriticalSection(&g_lock);
}

extern "C" __declspec(dllexport) void FileFree(void* ptr) {
    // Optimized for file memory deallocation (sub_6082D0, sub_819C55)
    if (!ptr) return;
    
    EnterCriticalSection(&g_lock);
    if (filePool.pool && ptr >= filePool.pool && ptr < filePool.pool + FILE_BUFFER_SIZE) {
        filePool.freeCount.fetch_add(1, std::memory_order_relaxed);
    } else {
        if (s_origFree) s_origFree(ptr);
    }
    LeaveCriticalSection(&g_lock);
}

extern "C" __declspec(dllexport) void GuiFree(void* ptr) {
    // Optimized for GUI memory deallocation (sub_6A4CC0, sub_6A4FB0)
    if (!ptr) return;
    
    EnterCriticalSection(&g_lock);
    if (guiPool.pool && ptr >= guiPool.pool && ptr < guiPool.pool + GUI_POOL_SIZE) {
        guiPool.freeCount.fetch_add(1, std::memory_order_relaxed);
    } else {
        if (s_origFree) s_origFree(ptr);
    }
    LeaveCriticalSection(&g_lock);
}

extern "C" __declspec(dllexport) void SmallObjFree(void* ptr) {
    // Optimized for small object deallocation (sub_69A7E0, sub_69A810)
    if (!ptr) return;
    
    EnterCriticalSection(&g_lock);
    if (smallObjPool.pool && ptr >= smallObjPool.pool && ptr < smallObjPool.pool + SMALL_OBJ_POOL_SIZE) {
        smallObjPool.freeCount.fetch_add(1, std::memory_order_relaxed);
    } else {
        if (s_origFree) s_origFree(ptr);
    }
    LeaveCriticalSection(&g_lock);
}

extern "C" __declspec(dllexport) void LinkedListFree(void* ptr) {
    // Optimized for linked list deallocation (sub_698CF0, sub_6A35F0, sub_6A3840, sub_6A3AA0)
    if (!ptr) return;
    
    EnterCriticalSection(&g_lock);
    if (linkedListPool.pool && ptr >= linkedListPool.pool && ptr < linkedListPool.pool + LINKED_LIST_POOL_SIZE) {
        linkedListPool.freeCount.fetch_add(1, std::memory_order_relaxed);
    } else {
        if (s_origFree) s_origFree(ptr);
    }
    LeaveCriticalSection(&g_lock);
}

extern "C" __declspec(dllexport) void StringFree(void* ptr) {
    // Optimized for string deallocation (sub_6A0AB0, sub_6A3840, sub_6A3AA0, sub_6A35F0, sub_6CB980)
    if (!ptr) return;
    
    EnterCriticalSection(&g_lock);
    if (stringPool.pool && ptr >= stringPool.pool && ptr < stringPool.pool + STRING_POOL_SIZE) {
        stringPool.freeCount.fetch_add(1, std::memory_order_relaxed);
    } else {
        if (s_origFree) s_origFree(ptr);
    }
    LeaveCriticalSection(&g_lock);
}

extern "C" __declspec(dllexport) void ExecutableFree(void* ptr) {
    // Optimized for executable memory deallocation (sub_9AE540)
    if (!ptr) return;
    
    EnterCriticalSection(&g_lock);
    if (executablePool.pool && ptr >= executablePool.pool && ptr < executablePool.pool + EXECUTABLE_POOL_SIZE) {
        executablePool.freeCount.fetch_add(1, std::memory_order_relaxed);
    } else {
        if (s_origVirtualFree) s_origVirtualFree(ptr, 0, MEM_RELEASE);
    }
    LeaveCriticalSection(&g_lock);
}

extern "C" __declspec(dllexport) void BatchLinkedListFree(void** ptrs, size_t count) {
    // Optimized batch deallocation for linked lists (sub_698CF0, sub_6A35F0, sub_6A3840, sub_6A3AA0)
    if (!ptrs || count == 0) return;
    
    EnterCriticalSection(&g_lock);
    size_t freedCount = 0;
    
    for (size_t i = 0; i < count; ++i) {
        void* ptr = ptrs[i];
        if (ptr && linkedListPool.pool && ptr >= linkedListPool.pool && ptr < linkedListPool.pool + LINKED_LIST_POOL_SIZE) {
            freedCount++;
        } else if (ptr) {
            // Defer non-pool frees to avoid holding lock too long
            ptrs[i] = nullptr; // Mark for later processing
        }
    }
    
    linkedListPool.freeCount.fetch_add(freedCount, std::memory_order_relaxed);
    LeaveCriticalSection(&g_lock);
    
    // Process non-pool frees outside the lock
    for (size_t i = 0; i < count; ++i) {
        if (ptrs[i] == nullptr && s_origFree) {
            s_origFree(ptrs[i]);
        }
    }
}

extern "C" __declspec(dllexport) void CustomFree(void* p) {
    if (!p || !gameMemoryPool.pool) return;
    
    // Enhanced free routing based on the 11 specific free patterns
    
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
        LogFree(p);
        return;
    }
    
    if (filePool.pool && p >= filePool.pool && p < filePool.pool + FILE_BUFFER_SIZE) {
        FileFree(p);
        return;
    }
    
    if (guiPool.pool && p >= guiPool.pool && p < guiPool.pool + GUI_POOL_SIZE) {
        GuiFree(p);
        return;
    }
    
    if (smallObjPool.pool && p >= smallObjPool.pool && p < smallObjPool.pool + SMALL_OBJ_POOL_SIZE) {
        SmallObjFree(p);
        return;
    }
    
    if (linkedListPool.pool && p >= linkedListPool.pool && p < linkedListPool.pool + LINKED_LIST_POOL_SIZE) {
        LinkedListFree(p);
        return;
    }
    
    if (stringPool.pool && p >= stringPool.pool && p < stringPool.pool + STRING_POOL_SIZE) {
        StringFree(p);
        return;
    }
    
    if (executablePool.pool && p >= executablePool.pool && p < executablePool.pool + EXECUTABLE_POOL_SIZE) {
        ExecutableFree(p);
        return;
    }
    
    // Check if in main custom pool
    if (IsInCustomPool(p)) {
        EnterCriticalSection(&g_lock);
        MemoryBlock* targetBlock = nullptr;
        MemoryBlock* current = gameMemoryPool.head.load(std::memory_order_acquire);
        
        while (current) {
            if (current->address == p) {
                if (!current->used || current->magic != BLOCK_MAGIC) {
                    // Double free or corruption detected - enhanced error reporting
                    ++gameMemoryPool.fragmentationCount;
                    char errorBuffer[256];
                    sprintf_s(errorBuffer, sizeof(errorBuffer), 
                        "MEMORY CORRUPTION: Double free or invalid magic at %p (magic: 0x%08X)\n", 
                        p, current->magic);
                    OutputDebugStringA(errorBuffer);
                    LeaveCriticalSection(&g_lock);
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
        } else {
            // Block not found in tracking - possible corruption
            ++gameMemoryPool.fragmentationCount;
            char errorBuffer[256];
            sprintf_s(errorBuffer, sizeof(errorBuffer), 
                "MEMORY CORRUPTION: Block not found in tracking at %p\n", p);
            OutputDebugStringA(errorBuffer);
        }
        LeaveCriticalSection(&g_lock);
    } else {
        // Not in our pools, use original free
        if (s_origFree) s_origFree(p);
    }
}

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
    g_inited = true;

    InitializeCriticalSection(&g_lock);
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
}

BOOL WINAPI DllMain(HINSTANCE hDLL, DWORD reason, LPVOID)
{
    if (reason == DLL_PROCESS_ATTACH)
    {
        DisableThreadLibraryCalls(hDLL);
        // Hook allocators right away
        HookAllocators();
    }
    else if (reason == DLL_PROCESS_DETACH)
    {
        // cleanup
        CleanupMemoryPool();
        DeleteCriticalSection(&g_lock);
    }
    return TRUE;
}