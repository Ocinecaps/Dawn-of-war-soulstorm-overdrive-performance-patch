#include <windows.h>
#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include "../MasterLoggerDLL/include/Logger.h"

#define SOULSTORM_CONFIG_PATH "Local.ini"
#define DEFAULT_WIDTH 1920
#define DEFAULT_HEIGHT 1080

struct Resolution {
    int width;
    int height;
};

inline Resolution GetNativeResolution() {
    DEVMODE dm;
    memset(&dm, 0, sizeof(dm));
    dm.dmSize = sizeof(dm);
    if (EnumDisplaySettings(NULL, ENUM_CURRENT_SETTINGS, &dm)) {
        return { static_cast<int>(dm.dmPelsWidth), static_cast<int>(dm.dmPelsHeight) };
    }
    return { DEFAULT_WIDTH, DEFAULT_HEIGHT }; // Fallback to 1080p if unknown
}

static bool UpdateResolutionConfig(const std::string& filePath, const Resolution& res) {
    std::ifstream inFile(filePath);
    if (!inFile.is_open()) {
        Log_Write(LOG_ERROR, "Resolution", "Failed to open config file: %s", filePath.c_str());
        return false;
    }

    std::vector<std::string> lines;
    std::string line;
    bool resolutionFound = false;

    while (std::getline(inFile, line)) {
        if (line.find("screenwidth") != std::string::npos) {
            line = "screenwidth=" + std::to_string(res.width);
            resolutionFound = true;
        }
        else if (line.find("screenheight") != std::string::npos) {
            line = "screenheight=" + std::to_string(res.height);
            resolutionFound = true;
        }
        lines.push_back(line);
    }
    inFile.close();

    if (!resolutionFound) {
        Log_Write(LOG_WARN, "Resolution", "Resolution settings not found in config. Adding manually.");
        lines.push_back("screenwidth=" + std::to_string(res.width));
        lines.push_back("screenheight=" + std::to_string(res.height));
    }

    std::ofstream outFile(filePath);
    if (!outFile.is_open()) {
        Log_Write(LOG_ERROR, "Resolution", "Failed to write to config file: %s", filePath.c_str());
        return false;
    }

    for (const auto& l : lines) {
        outFile << l << "\n";
    }
    outFile.close();
    Log_Write(LOG_INFO, "Resolution", "Resolution set to %dx%d in config file.", res.width, res.height);
    return true;
}

static void ApplyUltrawidePatch() {
    Log_Write(LOG_INFO, "Resolution", "Applying ultrawide patch...");
    Resolution nativeRes = GetNativeResolution();
    Log_Write(LOG_INFO, "Resolution", "Detected native resolution: %dx%d", nativeRes.width, nativeRes.height);

    if (!UpdateResolutionConfig(SOULSTORM_CONFIG_PATH, nativeRes)) {
        MessageBoxA(nullptr, "Failed to update resolution settings.", "Error", MB_ICONERROR);
    }
    else {
        MessageBoxA(nullptr, "Ultrawide patch applied successfully!", "Success", MB_OK);
    }
}

#ifndef BUILD_AS_DLL
int main() {
    Log_Initialize();
    ApplyUltrawidePatch();
    Log_Shutdown();
    return 0;
}
#endif