// pch.h: This is a precompiled header file.
// Files listed below are compiled only once, improving build performance for future builds.
// This also affects IntelliSense performance, including code completion and many code browsing features.
// However, files listed here are ALL re-compiled if any one of them is updated between builds.
// Do not add files here that you will be updating frequently as this negates the performance advantage.

#ifndef PCH_H
#define PCH_H

#define _WIN32_WINNT 0x0600
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX

// Windows headers
#include <windows.h>
#include <memoryapi.h>

// C++ standard library headers
#include <cstdint>
#include <mutex>
#include <atomic>
#include <thread>
#include <cstdio>
#include <cstring>
#include <algorithm>
#include <vector>

#endif //PCH_H
