// Dawn of War Soulstorm Intelligent Code Analysis & Validation System
// Automated detection of unused code, dead code, validation issues, and performance bottlenecks

#pragma once
#include <windows.h>
#include <vector>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <chrono>
#include <functional>
#include <algorithm>
#include "../MasterLoggerDLL/include/Logger.h"

// Analysis logging macros
#define ANALYSIS_TRACE(...) DAWN_OF_WAR_LOG_TRACE("CodeAnalysis", __VA_ARGS__)
#define ANALYSIS_DEBUG(...) DAWN_OF_WAR_LOG_DEBUG("CodeAnalysis", __VA_ARGS__)
#define ANALYSIS_INFO(...) DAWN_OF_WAR_LOG_INFO("CodeAnalysis", __VA_ARGS__)
#define ANALYSIS_WARN(...) DAWN_OF_WAR_LOG_WARN("CodeAnalysis", __VA_ARGS__)
#define ANALYSIS_ERROR(...) DAWN_OF_WAR_LOG_ERROR("CodeAnalysis", __VA_ARGS__)

// Code analysis metrics
struct CodeMetrics {
    std::string functionName;
    std::string fileName;
    int lineNumber;
    size_t callCount;
    size_t executionTimeUs;
    size_t minExecutionTime;
    size_t maxExecutionTime;
    bool isEntryPoint;
    bool isNeverCalled;
    bool isDeadCode;
    std::string deadCodeReason;
    std::chrono::steady_clock::time_point firstCallTime;
    std::chrono::steady_clock::time_point lastCallTime;
};

struct ValidationIssue {
    std::string type;           // "PARAMETER", "STATE", "MEMORY", "NULL_POINTER"
    std::string severity;        // "ERROR", "WARNING", "INFO"
    std::string description;
    std::string functionName;
    std::string fileName;
    int lineNumber;
    std::chrono::steady_clock::time_point detectedTime;
};

struct PerformanceBottleneck {
    std::string functionName;
    std::string fileName;
    size_t totalExecutionTime;
    size_t averageExecutionTime;
    size_t callCount;
    double bottleneckScore;     // 0.0 - 1.0, higher is worse
    std::string bottleneckType;  // "FREQUENT_SLOW", "OCCASIONAL_SLOW", "MEMORY_INTENSIVE"
};

// Function call tracker for analysis
class FunctionCallTracker {
private:
    static std::unordered_map<std::string, CodeMetrics> functionMetrics;
    static std::unordered_set<std::string> registeredFunctions;
    static CRITICAL_SECTION analysisLock;
    static bool initialized;

public:
    // Initialize the analysis system
    static bool Initialize() {
        if (initialized) return true;
        
        InitializeCriticalSection(&analysisLock);
        initialized = true;
        
        ANALYSIS_INFO("Intelligent Code Analysis System initialized");
        return true;
    }

    // Register a function for tracking
    static void RegisterFunction(const char* functionName, const char* fileName = nullptr, int lineNumber = 0) {
        if (!initialized) Initialize();
        
        EnterCriticalSection(&analysisLock);
        
        std::string funcKey = functionName;
        if (functionMetrics.find(funcKey) == functionMetrics.end()) {
            CodeMetrics metrics = {};
            metrics.functionName = functionName;
            metrics.fileName = fileName ? fileName : "unknown";
            metrics.lineNumber = lineNumber;
            metrics.callCount = 0;
            metrics.executionTimeUs = 0;
            metrics.minExecutionTime = SIZE_MAX;
            metrics.maxExecutionTime = 0;
            metrics.isEntryPoint = false;
            metrics.isNeverCalled = true;
            metrics.isDeadCode = false;
            metrics.deadCodeReason = "";
            metrics.firstCallTime = std::chrono::steady_clock::now();
            metrics.lastCallTime = std::chrono::steady_clock::now();
            
            functionMetrics[funcKey] = metrics;
            registeredFunctions.insert(funcKey);
            
            ANALYSIS_DEBUG("Registered function for analysis: %s", functionName);
        }
        
        LeaveCriticalSection(&analysisLock);
    }

    // Mark function as entry point
    static void MarkEntryPoint(const char* functionName) {
        EnterCriticalSection(&analysisLock);
        
        auto it = functionMetrics.find(functionName);
        if (it != functionMetrics.end()) {
            it->second.isEntryPoint = true;
            ANALYSIS_DEBUG("Marked as entry point: %s", functionName);
        }
        
        LeaveCriticalSection(&analysisLock);
    }

    // Track function execution
    static void TrackExecution(const char* functionName, size_t executionTimeUs) {
        if (!initialized) return;
        
        EnterCriticalSection(&analysisLock);
        
        auto it = functionMetrics.find(functionName);
        if (it != functionMetrics.end()) {
            CodeMetrics& metrics = it->second;
            
            if (metrics.isNeverCalled) {
                metrics.isNeverCalled = false;
                ANALYSIS_INFO("First execution detected: %s (%zu μs)", functionName, executionTimeUs);
            }
            
            metrics.callCount++;
            metrics.executionTimeUs += executionTimeUs;
            metrics.lastCallTime = std::chrono::steady_clock::now();
            
            if (executionTimeUs < metrics.minExecutionTime) {
                metrics.minExecutionTime = executionTimeUs;
            }
            if (executionTimeUs > metrics.maxExecutionTime) {
                metrics.maxExecutionTime = executionTimeUs;
            }
            
            // Check for performance issues
            if (executionTimeUs > 10000) { // > 10ms
                ANALYSIS_WARN("Slow function execution: %s took %zu μs", functionName, executionTimeUs);
            }
        }
        
        LeaveCriticalSection(&analysisLock);
    }

    // Generate comprehensive analysis report
    static void GenerateAnalysisReport() {
        if (!initialized) return;
        
        ANALYSIS_INFO("=== INTELLIGENT CODE ANALYSIS REPORT ===");
        
        EnterCriticalSection(&analysisLock);
        
        // 1. Unused Code Detection
        ANALYSIS_INFO("--- UNUSED CODE ANALYSIS ---");
        size_t unusedCount = 0;
        for (std::unordered_map<std::string, CodeMetrics>::const_iterator pair = functionMetrics.begin(); pair != functionMetrics.end(); ++pair) {
            const CodeMetrics& metrics = pair->second;
            if (metrics.isNeverCalled && !metrics.isEntryPoint) {
                ANALYSIS_WARN("UNUSED FUNCTION: %s (%s:%d)", 
                             metrics.functionName.c_str(), 
                             metrics.fileName.c_str(), 
                             metrics.lineNumber);
                unusedCount++;
            }
        }
        ANALYSIS_INFO("Found %zu unused functions", unusedCount);
        
        // 2. Dead Code Detection
        ANALYSIS_INFO("--- DEAD CODE ANALYSIS ---");
        size_t deadCodeCount = 0;
        for (std::unordered_map<std::string, CodeMetrics>::const_iterator pair = functionMetrics.begin(); pair != functionMetrics.end(); ++pair) {
            const CodeMetrics& metrics = pair->second;
            if (metrics.isDeadCode) {
                ANALYSIS_ERROR("DEAD CODE: %s (%s:%d) - %s", 
                              metrics.functionName.c_str(),
                              metrics.fileName.c_str(),
                              metrics.lineNumber,
                              metrics.deadCodeReason.c_str());
                deadCodeCount++;
            }
        }
        ANALYSIS_INFO("Found %zu dead code sections", deadCodeCount);
        
        // 3. Performance Bottleneck Analysis
        ANALYSIS_INFO("--- PERFORMANCE BOTTLENECK ANALYSIS ---");
        std::vector<PerformanceBottleneck> bottlenecks = IdentifyBottlenecks();
        
        for (std::vector<PerformanceBottleneck>::const_iterator bottleneck = bottlenecks.begin(); bottleneck != bottlenecks.end(); ++bottleneck) {
            if (bottleneck->bottleneckScore > 0.8) {
                ANALYSIS_ERROR("CRITICAL BOTTLENECK: %s - Score: %.2f, Type: %s, Avg: %zu μs, Calls: %zu",
                              bottleneck->functionName.c_str(),
                              bottleneck->bottleneckScore,
                              bottleneck->bottleneckType.c_str(),
                              bottleneck->averageExecutionTime,
                              bottleneck->callCount);
            } else if (bottleneck->bottleneckScore > 0.5) {
                ANALYSIS_WARN("PERFORMANCE BOTTLENECK: %s - Score: %.2f, Type: %s, Avg: %zu μs, Calls: %zu",
                             bottleneck->functionName.c_str(),
                             bottleneck->bottleneckScore,
                             bottleneck->bottleneckType.c_str(),
                             bottleneck->averageExecutionTime,
                             bottleneck->callCount);
            } else {
                ANALYSIS_INFO("Performance Note: %s - Score: %.2f, Avg: %zu μs, Calls: %zu",
                            bottleneck->functionName.c_str(),
                            bottleneck->bottleneckScore,
                            bottleneck->averageExecutionTime,
                            bottleneck->callCount);
            }
        }
        
        // 4. Function Usage Statistics
        ANALYSIS_INFO("--- FUNCTION USAGE STATISTICS ---");
        std::vector<std::pair<std::string, CodeMetrics>> sortedFunctions;
        for (std::unordered_map<std::string, CodeMetrics>::const_iterator pair = functionMetrics.begin(); pair != functionMetrics.end(); ++pair) {
            sortedFunctions.push_back(*pair);
        }
        
        // Sort by total execution time (most expensive first)
        std::sort(sortedFunctions.begin(), sortedFunctions.end(), 
                 [](const std::pair<std::string, CodeMetrics>& a, const std::pair<std::string, CodeMetrics>& b) {
                     return a.second.executionTimeUs > b.second.executionTimeUs;
                 });
        
        ANALYSIS_INFO("Top 10 Most Expensive Functions:");
        size_t maxItems = (sortedFunctions.size() < 10) ? sortedFunctions.size() : 10;
        for (size_t i = 0; i < maxItems; ++i) {
            const CodeMetrics& metrics = sortedFunctions[i].second;
            ANALYSIS_INFO("%2zu. %s - Total: %zu μs, Calls: %zu, Avg: %zu μs",
                         i + 1,
                         metrics.functionName.c_str(),
                         metrics.executionTimeUs,
                         metrics.callCount,
                         metrics.callCount > 0 ? metrics.executionTimeUs / metrics.callCount : 0);
        }
        
        // Sort by call count (most called first)
        std::sort(sortedFunctions.begin(), sortedFunctions.end(),
                 [](const std::pair<std::string, CodeMetrics>& a, const std::pair<std::string, CodeMetrics>& b) {
                     return a.second.callCount > b.second.callCount;
                 });
        
        ANALYSIS_INFO("Top 10 Most Called Functions:");
        for (size_t i = 0; i < maxItems; ++i) {
            const CodeMetrics& metrics = sortedFunctions[i].second;
            ANALYSIS_INFO("%2zu. %s - Calls: %zu, Total: %zu μs, Avg: %zu μs",
                         i + 1,
                         metrics.functionName.c_str(),
                         metrics.callCount,
                         metrics.executionTimeUs,
                         metrics.callCount > 0 ? metrics.executionTimeUs / metrics.callCount : 0);
        }
        
        LeaveCriticalSection(&analysisLock);
        
        ANALYSIS_INFO("=== END ANALYSIS REPORT ===");
    }

    // Mark code as dead
    static void MarkDeadCode(const char* functionName, const char* reason) {
        EnterCriticalSection(&analysisLock);
        
        std::unordered_map<std::string, CodeMetrics>::iterator it = functionMetrics.find(functionName);
        if (it != functionMetrics.end()) {
            it->second.isDeadCode = true;
            ANALYSIS_WARN("Dead code detected: %s - Reason: %s", functionName, reason);
        }
        
        LeaveCriticalSection(&analysisLock);
    }

private:
    // Identify performance bottlenecks
    static std::vector<PerformanceBottleneck> IdentifyBottlenecks() {
        std::vector<PerformanceBottleneck> bottlenecks;
        
        for (std::unordered_map<std::string, CodeMetrics>::const_iterator pair = functionMetrics.begin(); pair != functionMetrics.end(); ++pair) {
            const CodeMetrics& metrics = pair->second;
            
            if (metrics.callCount == 0) continue;
            
            PerformanceBottleneck bottleneck = {};
            bottleneck.functionName = metrics.functionName;
            bottleneck.fileName = metrics.fileName;
            bottleneck.totalExecutionTime = metrics.executionTimeUs;
            bottleneck.averageExecutionTime = metrics.executionTimeUs / metrics.callCount;
            bottleneck.callCount = metrics.callCount;
            
            // Calculate bottleneck score
            double avgTimeMs = bottleneck.averageExecutionTime / 1000.0;
            double totalTimeMs = bottleneck.totalExecutionTime / 1000.0;
            
            if (avgTimeMs > 50.0) { // > 50ms average
                bottleneck.bottleneckScore = (avgTimeMs / 100.0 < 1.0) ? avgTimeMs / 100.0 : 1.0;
                bottleneck.bottleneckType = "FREQUENT_SLOW";
            } else if (totalTimeMs > 1000.0) { // > 1s total
                bottleneck.bottleneckScore = (totalTimeMs / 2000.0 < 1.0) ? totalTimeMs / 2000.0 : 1.0;
                bottleneck.bottleneckType = "OCCASIONAL_SLOW";
            } else if (metrics.callCount > 10000 && avgTimeMs > 5.0) { // High frequency, somewhat slow
                bottleneck.bottleneckScore = ((metrics.callCount / 10000.0) * (avgTimeMs / 20.0) < 1.0) ? (metrics.callCount / 10000.0) * (avgTimeMs / 20.0) : 1.0;
                bottleneck.bottleneckType = "MEMORY_INTENSIVE";
            } else {
                bottleneck.bottleneckScore = 0.0;
                bottleneck.bottleneckType = "NORMAL";
            }
            
            if (bottleneck.bottleneckScore > 0.1) {
                bottlenecks.push_back(bottleneck);
            }
        }
        
        // Sort by bottleneck score (worst first)
        std::sort(bottlenecks.begin(), bottlenecks.end(),
                 [](const PerformanceBottleneck& a, const PerformanceBottleneck& b) {
                     return a.bottleneckScore > b.bottleneckScore;
                 });
        
        return bottlenecks;
    }

public:
    // Cleanup
    static void Shutdown() {
        if (!initialized) return;
        
        GenerateAnalysisReport();
        
        DeleteCriticalSection(&analysisLock);
        initialized = false;
        
        ANALYSIS_INFO("Intelligent Code Analysis System shutdown complete");
    }
};

// Static member definitions
std::unordered_map<std::string, CodeMetrics> FunctionCallTracker::functionMetrics;
std::unordered_set<std::string> FunctionCallTracker::registeredFunctions;
CRITICAL_SECTION FunctionCallTracker::analysisLock;
bool FunctionCallTracker::initialized = false;

// RAII Function execution tracker with intelligent analysis
class IntelligentFunctionTracker {
private:
    const char* functionName;
    std::chrono::high_resolution_clock::time_point startTime;
    bool valid;

public:
    IntelligentFunctionTracker(const char* funcName, const char* fileName = nullptr, int lineNumber = 0) 
        : functionName(funcName), valid(false) {
        
        // Register function if not already registered
        FunctionCallTracker::RegisterFunction(functionName, fileName, lineNumber);
        
        startTime = std::chrono::high_resolution_clock::now();
        valid = true;
        
        ANALYSIS_TRACE("Entering function: %s", functionName);
    }
    
    ~IntelligentFunctionTracker() {
        if (!valid) return;
        
        std::chrono::high_resolution_clock::time_point endTime = std::chrono::high_resolution_clock::now();
        long long duration = std::chrono::duration_cast<std::chrono::microseconds>(endTime - startTime).count();
        
        // Track execution
        FunctionCallTracker::TrackExecution(functionName, static_cast<size_t>(duration));
        
        ANALYSIS_TRACE("Exiting function: %s (%zu μs)", functionName, static_cast<size_t>(duration));
    }
    
    void MarkAsDead(const char* reason) {
        if (valid) {
            FunctionCallTracker::MarkDeadCode(functionName, reason);
            valid = false;
        }
    }
};

// Validation system for parameter and state checking
class ValidationSystem {
private:
    static std::vector<ValidationIssue> validationIssues;
    static CRITICAL_SECTION validationLock;

public:
    // Initialize validation system
    static bool Initialize() {
        InitializeCriticalSection(&validationLock);
        ANALYSIS_INFO("Validation System initialized");
        return true;
    }

    // Log parameter validation
    static void ValidateParameter(const char* functionName, const char* paramName, 
                              void* value, const char* fileName = nullptr, int lineNumber = 0) {
        if (!value) {
            LogValidationIssue("PARAMETER", "ERROR", 
                             std::string("Null parameter: ") + paramName,
                             functionName, fileName, lineNumber);
        }
    }

    // Log state validation
    static void ValidateState(const char* functionName, const char* stateName, 
                           bool condition, const char* errorMessage, 
                           const char* fileName = nullptr, int lineNumber = 0) {
        if (!condition) {
            LogValidationIssue("STATE", "ERROR",
                             std::string("Invalid state: ") + stateName + " - " + errorMessage,
                             functionName, fileName, lineNumber);
        }
    }

    // Log memory validation
    static void ValidateMemory(const char* functionName, void* address, size_t size, 
                           bool isValid, const char* errorMessage = nullptr,
                           const char* fileName = nullptr, int lineNumber = 0) {
        if (!isValid) {
            std::string desc = "Memory validation failed";
            if (errorMessage) {
                desc += std::string(" - ") + errorMessage;
            }
            desc += std::string(" (Address: 0x") + std::to_string(reinterpret_cast<uintptr_t>(address)) + 
                      std::string(", Size: ") + std::to_string(size) + ")";
            
            LogValidationIssue("MEMORY", "ERROR", desc, functionName, fileName, lineNumber);
        }
    }

    // Generate validation report
    static void GenerateValidationReport() {
        if (validationIssues.empty()) {
            ANALYSIS_INFO("No validation issues detected");
            return;
        }
        
        // Group by severity
        size_t errorCount = 0, warningCount = 0, infoCount = 0;
        
        for (std::vector<ValidationIssue>::const_iterator issue = validationIssues.begin(); issue != validationIssues.end(); ++issue) {
            if (issue->severity == "ERROR") errorCount++;
            else if (issue->severity == "WARNING") warningCount++;
            else infoCount++;
            
            ANALYSIS_ERROR("[%s] %s: %s - %s (%s:%d)",
                         issue->severity.c_str(),
                         issue->type.c_str(),
                         issue->description.c_str(),
                         issue->functionName.c_str(),
                         issue->fileName.c_str(),
                         issue->lineNumber);
        }
        
        ANALYSIS_INFO("Validation Summary: %zu errors, %zu warnings, %zu info", 
                     errorCount, warningCount, infoCount);
        ANALYSIS_INFO("=== END VALIDATION REPORT ===");
    }

    // Cleanup
    static void Shutdown() {
        GenerateValidationReport();
        DeleteCriticalSection(&validationLock);
        validationIssues.clear();
        ANALYSIS_INFO("Validation System shutdown complete");
    }

private:
    static void LogValidationIssue(const char* type, const char* severity, 
                               const std::string& description,
                               const char* functionName, 
                               const char* fileName, int lineNumber) {
        EnterCriticalSection(&validationLock);
        
        ValidationIssue issue = {};
        issue.type = type;
        issue.severity = severity;
        issue.description = description;
        issue.functionName = functionName;
        issue.fileName = fileName ? fileName : "unknown";
        issue.lineNumber = lineNumber;
        issue.detectedTime = std::chrono::steady_clock::now();
        
        validationIssues.push_back(issue);
        
        // Also log to main system
        if (strcmp(severity, "ERROR") == 0) {
            ANALYSIS_ERROR("[%s] %s: %s", type, functionName, description.c_str());
        } else if (strcmp(severity, "WARNING") == 0) {
            ANALYSIS_WARN("[%s] %s: %s", type, functionName, description.c_str());
        } else {
            ANALYSIS_INFO("[%s] %s: %s", type, functionName, description.c_str());
        }
        
        LeaveCriticalSection(&validationLock);
    }
};

// Static member definitions
std::vector<ValidationIssue> ValidationSystem::validationIssues;
CRITICAL_SECTION ValidationSystem::validationLock;

// Convenience macros for easy integration
#define INTELLIGENT_TRACK_FUNCTION() \
    static IntelligentFunctionTracker __tracker(__FUNCTION__, __FILE__, __LINE__);

#define INTELLIGENT_TRACK_FUNCTION_NAMED(name) \
    static IntelligentFunctionTracker __tracker(name, __FILE__, __LINE__);

#define VALIDATE_PARAMETER(param) \
    ValidationSystem::ValidateParameter(__FUNCTION__, #param, param, __FILE__, __LINE__);

#define VALIDATE_STATE(condition, message) \
    ValidationSystem::ValidateState(__FUNCTION__, #condition, condition, message, __FILE__, __LINE__);

#define VALIDATE_MEMORY(addr, size, isValid, message) \
    ValidationSystem::ValidateMemory(__FUNCTION__, addr, size, isValid, message, __FILE__, __LINE__);

#define MARK_ENTRY_POINT() \
    FunctionCallTracker::MarkEntryPoint(__FUNCTION__);

#define MARK_DEAD_CODE(reason) \
    FunctionCallTracker::MarkDeadCode(__FUNCTION__, reason);
