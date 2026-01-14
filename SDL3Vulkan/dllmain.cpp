#include "pch.h"

// SDL3 Vulkan Rendering DLL
// This DLL provides SDL3 + Vulkan rendering capabilities for injection

extern "C" __declspec(dllexport) void InitializeSDL3Vulkan()
{
    // Initialize SDL3 with Vulkan support
    if (SDL_Init(SDL_INIT_VIDEO) != 0)
    {
        OutputDebugStringA("[SDL3Vulkan] SDL_Init failed\n");
        return;
    }
    
    OutputDebugStringA("[SDL3Vulkan] SDL3 with Vulkan initialized successfully\n");
}

extern "C" __declspec(dllexport) void ShutdownSDL3Vulkan()
{
    SDL_Quit();
    OutputDebugStringA("[SDL3Vulkan] SDL3 with Vulkan shutdown\n");
}

extern "C" __declspec(dllexport) bool IsSDL3VulkanReady()
{
    return SDL_WasInit(SDL_INIT_VIDEO);
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        DisableThreadLibraryCalls(hModule);
        break;
    case DLL_THREAD_ATTACH:
        break;
    case DLL_THREAD_DETACH:
        break;
    case DLL_PROCESS_DETACH:
        SDL_Quit();
        break;
    }
    return TRUE;
}
