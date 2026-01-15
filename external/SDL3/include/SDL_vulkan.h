#pragma once

#include "SDL.h"

// Minimal SDL3 Vulkan stub for compilation
// Replace with actual SDL3 headers when available

#ifdef __cplusplus
extern "C" {
#endif

// Vulkan-related functions
extern void* SDL_GetWindowNative(SDL_Window* window, const char* property);
extern void* SDL_GetNativeWindow(SDL_Window* window, const char* nativeWindowType);

#ifdef __cplusplus
}
#endif
