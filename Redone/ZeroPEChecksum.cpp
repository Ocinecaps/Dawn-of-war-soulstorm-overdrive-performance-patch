#include "ZeroPEChecksum.h"
#include "../MasterLoggerDLL/include/Logger.h"
#include <fstream>
#include <windows.h>

// Implementation of Dawn of War PE Checksum Zeroing
bool ZeroDawnOfWarPEChecksum(const std::string& executablePath) {
    Log_Write(DAWN_OF_WAR_LOG_INFO, "ZeroDawnOfWarPEChecksum", "Opening Dawn of War executable file %s", executablePath.c_str());

    std::fstream executableFile(executablePath, std::ios::in | std::ios::out | std::ios::binary);
    if (!executableFile.is_open()) {
        Log_Write(DAWN_OF_WAR_LOG_ERROR, "ZeroDawnOfWarPEChecksum", "Failed to open Dawn of War executable file.");
        return false;
    }

    IMAGE_DOS_HEADER dosHeader = {};
    executableFile.read(reinterpret_cast<char*>(&dosHeader), sizeof(dosHeader));
    if (dosHeader.e_magic != IMAGE_DOS_SIGNATURE) {
        Log_Write(DAWN_OF_WAR_LOG_ERROR, "ZeroDawnOfWarPEChecksum", "Invalid DOS signature in Dawn of War executable.");
        executableFile.close();
        return false;
    }

    executableFile.seekg(dosHeader.e_lfanew, std::ios::beg);
    IMAGE_NT_HEADERS32 ntHeaders = {};
    executableFile.read(reinterpret_cast<char*>(&ntHeaders), sizeof(ntHeaders));

    if (ntHeaders.Signature != IMAGE_NT_SIGNATURE ||
        ntHeaders.OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
        Log_Write(DAWN_OF_WAR_LOG_ERROR, "ZeroDawnOfWarPEChecksum", "Invalid NT header in Dawn of War executable.");
        executableFile.close();
        return false;
    }

    // Clear PE checksum and debug information for Dawn of War executable
    ntHeaders.FileHeader.TimeDateStamp = 0;
    ntHeaders.OptionalHeader.CheckSum = 0;

    if (ntHeaders.OptionalHeader.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_DEBUG) {
        ntHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress = 0;
        ntHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].Size = 0;
    }

    executableFile.clear();
    executableFile.seekp(dosHeader.e_lfanew, std::ios::beg);
    executableFile.write(reinterpret_cast<const char*>(&ntHeaders), sizeof(ntHeaders));
    executableFile.close();

    Log_Write(DAWN_OF_WAR_LOG_INFO, "ZeroDawnOfWarPEChecksum", "Dawn of War PE checksum zeroing completed successfully.");
    return true;
}
