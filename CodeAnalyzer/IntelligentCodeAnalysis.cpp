// Dawn of War Soulstorm Intelligent Code Analysis Implementation
// Automated detection of unused code, dead code, validation issues, and performance bottlenecks

#include "IntelligentCodeAnalysis.h"

// Global analysis manager
class IntelligentAnalysisManager {
private:
    static bool initialized;
    static HANDLE analysisThread;
    static DWORD analysisInterval;
    static bool shutdownRequested;

public:
    // Initialize the intelligent analysis system
    static bool Initialize(DWORD intervalMs = 30000) { // 30 seconds default
        if (initialized) return true;
        
        ANALYSIS_INFO("Initializing Intelligent Analysis Manager");
        
        // Initialize subsystems
        if (!FunctionCallTracker::Initialize()) {
            ANALYSIS_ERROR("Failed to initialize Function Call Tracker");
            return false;
        }
        
        if (!ValidationSystem::Initialize()) {
            ANALYSIS_ERROR("Failed to initialize Validation System");
            return false;
        }
        
        analysisInterval = intervalMs;
        shutdownRequested = false;
        
        // Start analysis thread
        DWORD threadId;
        analysisThread = CreateThread(nullptr, 0, AnalysisThreadProc, nullptr, 0, &threadId);
        
        if (!analysisThread) {
            ANALYSIS_ERROR("Failed to create analysis thread. Error: %lu", GetLastError());
            return false;
        }
        
        initialized = true;
        ANALYSIS_INFO("Intelligent Analysis Manager initialized successfully");
        return true;
    }

    // Shutdown the analysis system
    static void Shutdown() {
        if (!initialized) return;
        
        ANALYSIS_INFO("Shutting down Intelligent Analysis Manager");
        
        shutdownRequested = true;
        
        if (analysisThread) {
            WaitForSingleObject(analysisThread, 5000);
            CloseHandle(analysisThread);
            analysisThread = nullptr;
        }
        
        // Shutdown subsystems
        FunctionCallTracker::Shutdown();
        ValidationSystem::Shutdown();
        
        initialized = false;
        ANALYSIS_INFO("Intelligent Analysis Manager shutdown complete");
    }

    // Force immediate analysis report
    static void GenerateImmediateReport() {
        ANALYSIS_INFO("Generating immediate analysis report");
        
        FunctionCallTracker::GenerateAnalysisReport();
        ValidationSystem::GenerateValidationReport();
        
        ANALYSIS_INFO("Immediate analysis report complete");
    }

private:
    // Analysis thread procedure
    static DWORD WINAPI AnalysisThreadProc(LPVOID lpParam) {
        ANALYSIS_DEBUG("Intelligent analysis thread started");
        
        while (!shutdownRequested) {
            // Wait for analysis interval
            if (WaitForSingleObject(GetCurrentThread(), analysisInterval) == WAIT_OBJECT_0) {
                break; // Shutdown requested
            }
            
            if (shutdownRequested) break;
            
            // Perform periodic analysis
            PerformPeriodicAnalysis();
        }
        
        ANALYSIS_DEBUG("Intelligent analysis thread stopped");
        return 0;
    }

    // Perform periodic analysis
    static void PerformPeriodicAnalysis() {
        ANALYSIS_DEBUG("Performing periodic intelligent analysis");
        
        // 1. Check for memory leaks in tracked functions
        CheckForMemoryLeaks();
        
        // 2. Analyze function call patterns
        AnalyzeCallPatterns();
        
        // 3. Check for performance regressions
        CheckPerformanceRegressions();
        
        // 4. Validate system health
        ValidateSystemHealth();
        
        ANALYSIS_DEBUG("Periodic analysis complete");
    }

    // Check for potential memory leaks
    static void CheckForMemoryLeaks() {
        // This would integrate with the memory pool system
        // For now, we'll simulate detection
        
        static size_t lastMemoryUsage = 0;
        size_t currentMemoryUsage = GetCurrentMemoryUsage();
        
        if (lastMemoryUsage > 0) {
            if (currentMemoryUsage > lastMemoryUsage * 1.1) { // 10% increase
                ANALYSIS_WARN("Potential memory leak detected: Usage increased from %zu to %zu bytes",
                             lastMemoryUsage, currentMemoryUsage);
            }
        }
        
        lastMemoryUsage = currentMemoryUsage;
    }

    // Analyze function call patterns
    static void AnalyzeCallPatterns() {
        // This would analyze the function metrics for patterns
        // For now, we'll provide a placeholder implementation
        
        ANALYSIS_DEBUG("Analyzing function call patterns");
        
        // Example: Check for functions that are called too frequently
        // This would require integration with the function tracking system
    }

    // Check for performance regressions
    static void CheckPerformanceRegressions() {
        static std::unordered_map<std::string, size_t> baselinePerformance;
        
        // This would compare current performance against baselines
        // For now, provide placeholder implementation
        
        ANALYSIS_DEBUG("Checking for performance regressions");
    }

    // Validate overall system health
    static void ValidateSystemHealth() {
        ANALYSIS_DEBUG("Validating system health");
        
        // Check system resources
        MEMORYSTATUSEX memStatus;
        memStatus.dwLength = sizeof(memStatus);
        
        if (GlobalMemoryStatusEx(&memStatus)) {
            if (memStatus.dwMemoryLoad > 90) {
                ANALYSIS_WARN("High system memory usage: %u%%", memStatus.dwMemoryLoad);
            }
            
            if (memStatus.ullAvailPhys < 100 * 1024 * 1024) { // Less than 100MB available
                ANALYSIS_ERROR("Critical system memory shortage: %zu MB available",
                             memStatus.ullAvailPhys / (1024 * 1024));
            }
        }
        
        // Check handle count
        DWORD handleCount = 0;
        GetProcessHandleCount(GetCurrentProcess(), &handleCount);
        
        if (handleCount > 10000) {
            ANALYSIS_WARN("High handle count: %lu (potential handle leak)", handleCount);
        }
    }

    // Get current memory usage
    static size_t GetCurrentMemoryUsage() {
        PROCESS_MEMORY_COUNTERS_EX pmc;
        if (GetProcessMemoryInfo(GetCurrentProcess(), sizeof(pmc), (PROCESS_MEMORY_COUNTERS*)&pmc)) {
            return pmc.WorkingSetSize;
        }
        return 0;
    }
};

// Static member definitions
bool IntelligentAnalysisManager::initialized = false;
HANDLE IntelligentAnalysisManager::analysisThread = nullptr;
DWORD IntelligentAnalysisManager::analysisInterval = 30000;
bool IntelligentAnalysisManager::shutdownRequested = false;

// Auto-initialization helper
struct IntelligentAnalysisAutoInit {
    IntelligentAnalysisAutoInit() {
        // Initialize the intelligent analysis system
        IntelligentAnalysisManager::Initialize(30000); // 30 second intervals
        
        ANALYSIS_INFO("Intelligent Code Analysis auto-initialization complete");
    }
    
    ~IntelligentAnalysisAutoInit() {
        // Cleanup on shutdown
        IntelligentAnalysisManager::Shutdown();
        
        ANALYSIS_INFO("Intelligent Code Analysis auto-cleanup complete");
    }
};

// Global instance for auto-initialization
static IntelligentAnalysisAutoInit g_autoAnalysisInit;

// Integration helper functions for easy use throughout the codebase
namespace DawnOfWarIntelligentAnalysis {
    // Initialize the intelligent analysis system
    inline bool Initialize(DWORD intervalMs = 30000) {
        return IntelligentAnalysisManager::Initialize(intervalMs);
    }
    
    // Shutdown the analysis system
    inline void Shutdown() {
        IntelligentAnalysisManager::Shutdown();
    }
    
    // Generate immediate analysis report
    inline void GenerateReport() {
        IntelligentAnalysisManager::GenerateImmediateReport();
    }
    
    // Advanced validation helpers
    inline void ValidateFunctionPointer(const char* functionName, void* funcPtr, 
                                      const char* fileName = nullptr, int lineNumber = 0) {
        if (!funcPtr) {
            ValidationSystem::ValidateParameter(functionName, "functionPointer", funcPtr, fileName, lineNumber);
        }
    }
    
    inline void ValidateArrayBounds(const char* functionName, size_t index, size_t maxSize,
                                  const char* fileName = nullptr, int lineNumber = 0) {
        if (index >= maxSize) {
            std::string errorMsg = "Array index out of bounds: " + std::to_string(index) + 
                                " >= " + std::to_string(maxSize);
            ValidationSystem::ValidateState(functionName, "arrayBounds", false, 
                                      errorMsg.c_str(), fileName, lineNumber);
        }
    }
    
    inline void ValidateStringLength(const char* functionName, const char* str, size_t maxLength,
                                 const char* fileName = nullptr, int lineNumber = 0) {
        if (!str) {
            ValidationSystem::ValidateParameter(functionName, "string", str, fileName, lineNumber);
            return;
        }
        
        size_t len = strlen(str);
        if (len >= maxLength) {
            std::string errorMsg = "String too long: " + std::to_string(len) + 
                                " >= " + std::to_string(maxLength);
            ValidationSystem::ValidateState(functionName, "stringLength", false, 
                                      errorMsg.c_str(), fileName, lineNumber);
        }
    }
    
    inline void ValidateResourceHandle(const char* functionName, HANDLE handle, const char* handleType,
                                   const char* fileName = nullptr, int lineNumber = 0) {
        if (handle == INVALID_HANDLE_VALUE || handle == nullptr) {
            std::string errorMsg = "Invalid " + std::string(handleType) + " handle";
            ValidationSystem::ValidateParameter(functionName, handleType, handle, fileName, lineNumber);
        }
    }
    
    // Performance monitoring helpers
    inline void TrackCriticalOperation(const char* operationName, std::function<void()> operation) {
        auto startTime = std::chrono::high_resolution_clock::now();
        
        try {
            ANALYSIS_INFO("Starting critical operation: %s", operationName);
            operation();
            
            auto endTime = std::chrono::high_resolution_clock::now();
            auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(endTime - startTime).count();
            
            if (duration > 1000) { // > 1 second
                ANALYSIS_WARN("Critical operation took %lu ms: %s", duration, operationName);
            } else {
                ANALYSIS_INFO("Critical operation completed in %lu ms: %s", duration, operationName);
            }
        }
        catch (const std::exception& e) {
            auto endTime = std::chrono::high_resolution_clock::now();
            auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(endTime - startTime).count();
            
            ANALYSIS_ERROR("Critical operation failed after %lu ms: %s - %s", 
                          duration, operationName, e.what());
            throw;
        }
        catch (...) {
            auto endTime = std::chrono::high_resolution_clock::now();
            auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(endTime - startTime).count();
            
            ANALYSIS_ERROR("Critical operation failed after %lu ms: %s - Unknown exception", 
                          duration, operationName);
            throw;
        }
    }
    
    // Memory pressure monitoring
    inline void MonitorMemoryPressure(const char* context) {
        size_t currentUsage = GetCurrentProcessMemoryUsage();
        MEMORYSTATUSEX memStatus;
        memStatus.dwLength = sizeof(memStatus);
        
        if (GlobalMemoryStatusEx(&memStatus)) {
            double usagePercent = ((double)currentUsage / memStatus.ullTotalPhys) * 100.0;
            
            if (usagePercent > 80) {
                ANALYSIS_ERROR("High memory pressure in %s: %.1f%% (%zu MB used)", 
                              context, usagePercent, currentUsage / (1024 * 1024));
            } else if (usagePercent > 60) {
                ANALYSIS_WARN("Moderate memory pressure in %s: %.1f%% (%zu MB used)", 
                             context, usagePercent, currentUsage / (1024 * 1024));
            } else {
                ANALYSIS_DEBUG("Memory usage in %s: %.1f%% (%zu MB used)", 
                            context, usagePercent, currentUsage / (1024 * 1024));
            }
        }
    }
    
    // Get current process memory usage
    inline size_t GetCurrentProcessMemoryUsage() {
        PROCESS_MEMORY_COUNTERS_EX pmc;
        if (GetProcessMemoryInfo(GetCurrentProcess(), sizeof(pmc), (PROCESS_MEMORY_COUNTERS*)&pmc)) {
            return pmc.WorkingSetSize;
        }
        return 0;
    }
}
