# Dawn of War Performance Patch - Clean Architecture

## 🎯 **Fixed Architecture Overview**

The project has been cleaned up to follow a proper, focused architecture with clear separation of concerns.

## 📁 **Project Structure & Responsibilities**

### **Redone (Overdrive Patcher)**
- **Purpose**: Patches the game executable and injects DLLs
- **Dependencies**: GDIInterceptor, VulkanRenderer, MemoryPoolDLL
- **Output**: `OverdrivePatcher.exe`
- **Role**: Entry point and injection manager

### **GDIInterceptor (GDI Hooking DLL)**
- **Purpose**: Hooks GDI calls and delegates rendering to VulkanRenderer
- **Dependencies**: VulkanRenderer (dynamic loading), Logger
- **Output**: `GDIInterceptor.dll`
- **Role**: GDI interception and rendering delegation

### **VulkanRenderer (SDL3 + Vulkan DLL)**
- **Purpose**: Handles SDL3 initialization and Vulkan rendering
- **Dependencies**: SDL3, Vulkan SDK
- **Output**: `VulkanRenderer.dll`
- **Role**: Low-level rendering backend

### **MemoryPoolDLL (Memory Management)**
- **Purpose**: Provides optimized memory allocation for performance
- **Dependencies**: SDL3 (for basic operations)
- **Output**: `MemoryPoolDLL.dll`
- **Role**: Optional performance optimization

## 🔄 **Execution Flow**

```
1. Redone.exe patches game executable
2. Redone.exe injects GDIInterceptor.dll
3. GDIInterceptor.dll loads VulkanRenderer.dll
4. GDIInterceptor.dll installs GDI hooks
5. GDI calls are intercepted and delegated to VulkanRenderer
6. VulkanRenderer uses SDL3 + Vulkan for rendering
7. Optional: MemoryPoolDLL provides optimized memory management
```

## 🗑️ **Removed Components**

### **GameDetector (REMOVED)**
- **Why removed**: Unnecessary complexity for a focused performance patch
- **Alternative**: You already have SDL3.dll, indicating a specific target game
- **Files deleted**: `Common/GameDetector.h`, `Common/GameDetector.cpp`

### **Complex Vulkan Loading (REMOVED)**
- **Why removed**: VulkanRenderer handles this properly
- **Alternative**: Dynamic loading of VulkanRenderer.dll with clean interface
- **Simplified**: GDIInterceptor now focuses on GDI hooking only

## 🔗 **Project Dependencies**

### **Build Order** (automatically handled by Visual Studio):
1. **VulkanRenderer** (no dependencies)
2. **MemoryPoolDLL** (no dependencies)
3. **GDIInterceptor** → depends on VulkanRenderer
4. **Redone** → depends on all three DLLs

### **Runtime Dependencies**:
- **GDIInterceptor** dynamically loads `VulkanRenderer.dll`
- **Redone** injects `GDIInterceptor.dll` into target process
- **MemoryPoolDLL** is optional and loaded if needed

## 📂 **Clean File Structure**

```
Dawn-of-war-overdrive-performance/
├── Properties/              # Professional property sheets
├── Common/                  # Shared components
│   ├── Config.h            # Configuration constants
│   ├── Logger.h/.cpp       # Logging system
│   └── pch.h/.cpp          # Precompiled headers
├── GDIInterceptor/         # GDI hooking DLL
├── VulkanRenderer/         # SDL3 + Vulkan rendering DLL
├── MemoryPoolDLL/          # Memory management DLL
├── Redone/                 # Game patcher application
├── external/               # External dependencies
│   ├── SDL3/              # SDL3 headers and libraries
│   └── VulkanSDK/         # Vulkan SDK headers and libraries
└── SDL3.dll               # Your existing SDL3 runtime
```

## 🎮 **How It Works**

### **For Dawn of War Performance**:
1. **Redone.exe** patches the Dawn of War executable
2. **GDIInterceptor.dll** intercepts Direct3D/GDI calls
3. **VulkanRenderer.dll** provides modern SDL3 + Vulkan rendering
4. **MemoryPoolDLL.dll** optimizes memory allocation
5. **SDL3.dll** provides the SDL3 runtime (you already have this)

### **Benefits**:
- **Modern Rendering**: SDL3 + Vulkan instead of old Direct3D
- **Better Performance**: Optimized memory management
- **Clean Architecture**: Each component has a single responsibility
- **Maintainable**: Easy to modify individual components
- **Professional Setup**: Proper Visual Studio solution structure

## 🔧 **Usage**

1. **Build the solution** in Visual Studio
2. **Run Redone.exe** to patch the game
3. **Game will use modern rendering** through the injected DLLs

## 📝 **Notes**

- The architecture now properly separates concerns
- Each project has a clear, single responsibility
- Dependencies are properly managed
- No unnecessary complexity or redundant code
- Uses your existing SDL3.dll effectively
