# Dawn of War Overdrive Performance

A performance enhancement project for Warhammer 40,000: Dawn of War that provides modern graphics API support and optimizations.

## Overview

This project consists of several components that work together to enhance the performance and compatibility of Dawn of War:

- **GDI Hooking DLL**: Provides DirectX 9 to Vulkan translation layer using SDL3
- **Memory Pool DLL**: Custom memory management for improved performance
- **Overdrive EXE Patcher**: Main executable patcher and loader
- **SDL3 Vulkan Integration**: Modern graphics API support

## Features

- **Vulkan Rendering**: Translates DirectX 9 calls to Vulkan for better performance on modern hardware
- **SDL3 Integration**: Uses SDL3 for cross-platform window management and input
- **Memory Optimization**: Custom memory pool allocator for reduced fragmentation
- **Debug Logging**: Comprehensive logging system for troubleshooting
- **IAT Hooking**: Import Address Table hooking for API interception

## Architecture

```
Dawn of War Game
    ↓
Overdrive EXE Patcher
    ↓
GDI Hooking DLL (DirectX 9 → Vulkan)
    ↓
SDL3 + Vulkan
    ↓
GPU Driver
```

## Components

### 1. GDI Hooking DLL
- Implements IDirect3D9 and IDirect3DDevice9 interfaces
- Translates DirectX 9 calls to Vulkan operations
- Uses SDL3 for window management and surface creation
- Located in `GDI HOOKING DLL/`

### 2. Memory Pool DLL
- Custom memory allocator for performance optimization
- Reduces memory fragmentation and allocation overhead
- Located in `MemoryPoolDLL/`

### 3. Overdrive EXE Patcher
- Main executable that patches and loads the game
- Handles DLL injection and initialization
- Located in `Redone/`

### 4. SDL3 Vulkan Integration
- Provides modern graphics API support
- Cross-platform compatibility layer
- Located in `SDL3Vulkan/`

## Building

### Prerequisites
- Visual Studio 2017 or later
- Windows SDK
- Vulkan SDK
- SDL3 development libraries

### Build Steps
1. Open `DawnOfWarOverdrivePerformance.sln` in Visual Studio
2. Configure build settings (Debug/Release, x86/x64)
3. Build solution (F7)

The output files will be placed in the `Output/` directory:
- `Output/DLL/` - Built DLLs
- `Output/GDI AND RENDER/` - Graphics DLLs
- `Output/Patcher/` - Main patcher executable

## Usage

1. Ensure all required DLLs are in the game directory
2. Run `Overdrive exe patcher.exe` instead of the original game executable
3. The patcher will automatically load and inject the performance enhancements

## Configuration

The project supports various configuration options through:
- Debug logging (enabled in Debug builds)
- Memory pool settings
- Graphics API preferences

## Debugging

Debug builds include comprehensive logging:
- Log files are created with timestamp: `patch_debug_YYYYMMDD_HHMMSS.log`
- Logs include INFO, WARNING, and CRITICAL levels
- Use `DebugLogger` class for custom logging

## License

This project is provided for educational and research purposes. Please ensure compliance with the original game's terms of service.

## Contributing

When contributing to this project:
1. Follow existing code style and conventions
2. Add appropriate logging for new features
3. Test both Debug and Release configurations
4. Document any API changes

## Technical Details

### DirectX 9 to Vulkan Translation
The project implements a subset of the DirectX 9 interface, translating calls to equivalent Vulkan operations:
- Device creation and management
- Resource creation (textures, buffers)
- Rendering pipeline setup
- Present operations

### Memory Management
Custom memory pool allocator provides:
- Reduced allocation overhead
- Better cache locality
- Configurable pool sizes
- Debug statistics in Debug builds

### Hooking Mechanism
Uses Import Address Table (IAT) hooking to:
- Intercept DirectX API calls
- Redirect to custom implementations
- Maintain compatibility with existing code

## Troubleshooting

### Common Issues
- **Vulkan initialization failure**: Ensure Vulkan drivers are up to date
- **SDL3 loading errors**: Verify SDL3.dll is in the correct path
- **Memory allocation failures**: Check available system memory

### Debug Information
Enable debug logging by using Debug builds or modifying logging levels.

## Dependencies

- **Windows API**: Core system functionality
- **DirectX 9**: Original game API (for compatibility)
- **Vulkan**: Modern graphics API
- **SDL3**: Cross-platform multimedia library
- **Visual C++ Runtime**: C++ standard library support
