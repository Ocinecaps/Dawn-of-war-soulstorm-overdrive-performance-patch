#pragma once

#include <stdint.h>

// Minimal SDL3 stub for compilation
// Replace with actual SDL3 headers when available

#ifdef __cplusplus
extern "C" {
#endif

// Basic SDL types
typedef struct SDL_Window SDL_Window;
typedef struct SDL_Renderer SDL_Renderer;
typedef struct SDL_Texture SDL_Texture;

// SDL constants
#define SDL_INIT_VIDEO 0x00000020
#define SDL_INIT_TIMER 0x00000001
#define SDL_WINDOW_VULKAN 0x00000001
#define SDL_WINDOW_SHOWN 0x00000004
#define SDL_WINDOWPOS_UNDEFINED -1

// Basic SDL functions
extern int SDL_Init(uint32_t flags);
extern void SDL_Quit(void);
extern void SDL_Delay(uint32_t ms);
extern int SDL_ShowCursor(void);
extern int SDL_HideCursor(void);

// Window functions
extern SDL_Window* SDL_CreateWindow(const char* title, int x, int y, int w, int h, uint32_t flags);
extern void SDL_DestroyWindow(SDL_Window* window);
extern void SDL_SetWindowSize(SDL_Window* window, int w, int h);

// Renderer functions
extern int SDL_SetRenderDrawColor(SDL_Renderer* renderer, uint8_t r, uint8_t g, uint8_t b, uint8_t a);
extern int SDL_RenderClear(SDL_Renderer* renderer);
extern void SDL_RenderPresent(SDL_Renderer* renderer);

#ifdef __cplusplus
}
#endif
