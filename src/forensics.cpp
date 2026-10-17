#include "forensics.hpp"
#include <shlobj.h>
#include <filesystem>
#include <fstream>

namespace fs = std::filesystem;

std::string ForensicsScanner::NormalizeDevicePath(const std::string& path) {
    // Converts \Device\HarddiskVolume3\... to C:\...
    std::string result = path;
    if (result.rfind("\\Device\\HarddiskVolume", 0) == 0) {
        size_t nextSlash = result.find('\\', 22);
        if (nextSlash != std::string::npos) {
            // Assume system drive or replace with C:
            result = "C:" + result.substr(nextSlash);
        }
    }
    return result;
}

static std::string FindPrefetchTimeForExe(const std::string& fullPath) {
    try {
        size_t lastSlash = fullPath.find_last_of("\\/");
        std::string filename = (lastSlash != std::string::npos) ? fullPath.substr(lastSlash + 1) : fullPath;
        size_t dot = filename.find_last_of('.');
        std::string base = (dot != std::string::npos) ? filename.substr(0, dot) : filename;
        
        std::wstring searchPattern = L"C:\\Windows\\Prefetch\\" + StringToWide(base) + L"*.pf";
        WIN32_FIND_DATAW fd;
        HANDLE hFind = FindFirstFileW(searchPattern.c_str(), &fd);
        if (hFind != INVALID_HANDLE_VALUE) {
            std::string t = FileTimeToDateTimeString(fd.ftLastWriteTime);
            FindClose(hFind);
            if (t != "N/A" && !t.empty()) return t;
        }
    } catch (...) {}
    return "";
}

static std::string ResolveExecutionTime(const std::string& fullPath, const FILETIME& keyFallback) {
    // 1. Check file on disk
    HANDLE hFile = CreateFileA(fullPath.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
    if (hFile != INVALID_HANDLE_VALUE) {
        FILETIME ftWrite;
        if (GetFileTime(hFile, NULL, NULL, &ftWrite)) {
            std::string t = FileTimeToDateTimeString(ftWrite);
            CloseHandle(hFile);
            if (t != "N/A" && !t.empty()) return t;
        }
        CloseHandle(hFile);
    }

    // 2. Check Prefetch
    std::string pfTime = FindPrefetchTimeForExe(fullPath);
    if (!pfTime.empty()) return pfTime;

    // 3. Fallback to Registry Key Last Write
    std::string regTime = FileTimeToDateTimeString(keyFallback);
    if (regTime != "N/A" && !regTime.empty()) {
        return regTime + " (Registry Trace)";
    }

    return "Historical Execution";
}

void ForensicsScanner::ScanMuiCache(std::vector<DetectionItem>& detections, ScanStats& stats) {
    const wchar_t* subKey = L"Software\\Classes\\Local Settings\\Software\\Microsoft\\Windows\\Shell\\MuiCache";
    HKEY hKey;
    if (RegOpenKeyExW(HKEY_CURRENT_USER, subKey, 0, KEY_READ, &hKey) != ERROR_SUCCESS) {
        return;
    }

    FILETIME ftKeyLastWrite = {0, 0};
    RegQueryInfoKeyW(hKey, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, &ftKeyLastWrite);

    wchar_t valName[2048];
    DWORD valSize = sizeof(valName) / sizeof(wchar_t);
    DWORD valIndex = 0;
    DWORD type;

    while (RegEnumValueW(hKey, valIndex, valName, &valSize, NULL, &type, NULL, NULL) == ERROR_SUCCESS) {
        stats.totalArtifactsScanned++;
        std::wstring rawName(valName);
        std::string fullPath = WideToString(rawName);

        // Strip suffixes like .FriendlyAppName or .ApplicationCompany
        size_t dotPos = fullPath.find(".FriendlyAppName");
        if (dotPos != std::string::npos) fullPath = fullPath.substr(0, dotPos);
        dotPos = fullPath.find(".ApplicationCompany");
        if (dotPos != std::string::npos) fullPath = fullPath.substr(0, dotPos);

        std::string matchedKw;
        if (MatchesCheatKeyword(fullPath, matchedKw)) {
            DetectionItem item;
            item.category = "Execution History (MuiCache)";
            item.target = fullPath;
            item.detail = "Matched cheat keyword: '" + matchedKw + "'";
            item.timestamp = ResolveExecutionTime(fullPath, ftKeyLastWrite);
            item.severity = Severity::CRITICAL;
            detections.push_back(item);
            stats.cheatDetections++;
            stats.riskScore += 25;

            // Live stream discovery to console
            std::cout << "\033[1;31m    >> [LIVE FIND] \033[0m\033[1;37m" << fullPath 
                      << "\033[0m \033[1;33m[ " << item.timestamp << " ]\033[0m\n";
            Sleep(35);
        }

        valSize = sizeof(valName) / sizeof(wchar_t);
        valIndex++;
    }

    RegCloseKey(hKey);
}

void ForensicsScanner::ScanPcaStore(std::vector<DetectionItem>& detections, ScanStats& stats) {
    const std::vector<std::wstring> pcaKeys = {
        L"Software\\Microsoft\\Windows NT\\CurrentVersion\\AppCompatFlags\\Compatibility Assistant\\Store",
        L"Software\\Microsoft\\Windows NT\\CurrentVersion\\AppCompatFlags\\Compatibility Assistant\\Persisted"
    };

    for (const auto& keyPath : pcaKeys) {
        HKEY hKey;
        if (RegOpenKeyExW(HKEY_CURRENT_USER, keyPath.c_str(), 0, KEY_READ, &hKey) != ERROR_SUCCESS) {
            continue;
        }

        FILETIME ftKeyLastWrite = {0, 0};
        RegQueryInfoKeyW(hKey, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, &ftKeyLastWrite);

        wchar_t valName[2048];
        DWORD valSize = sizeof(valName) / sizeof(wchar_t);
        DWORD valIndex = 0;
        DWORD type;
        BYTE data[512];
        DWORD dataSize = sizeof(data);

        while (RegEnumValueW(hKey, valIndex, valName, &valSize, NULL, &type, data, &dataSize) == ERROR_SUCCESS) {
            stats.totalArtifactsScanned++;
            std::string exePath = WideToString(std::wstring(valName));
            std::string timeStr = ExtractFileTimeFromBuffer(data, dataSize);
            if (timeStr.empty() || timeStr == "N/A") {
                timeStr = ResolveExecutionTime(exePath, ftKeyLastWrite);
            }

            std::string matchedKw;
            if (MatchesCheatKeyword(exePath, matchedKw)) {
                DetectionItem item;
                item.category = "Execution History (PCA Store)";
                item.target = exePath;
                item.detail = "Matched cheat keyword: '" + matchedKw + "'";
                item.timestamp = timeStr;
                item.severity = Severity::CRITICAL;
                detections.push_back(item);
                stats.cheatDetections++;
                stats.riskScore += 25;

                // Live stream discovery to console
                std::cout << "\033[1;31m    >> [LIVE FIND] \033[0m\033[1;37m" << exePath 
                          << "\033[0m \033[1;33m[ " << item.timestamp << " ]\033[0m\n";
                Sleep(35);
            } else {
                std::string lowerPath = ToLower(exePath);
                if (lowerPath.find("\\appdata\\local\\temp\\") != std::string::npos &&
                    lowerPath.rfind(".exe") == lowerPath.length() - 4) {
                    if (lowerPath.find("setup") == std::string::npos && 
                        lowerPath.find("install") == std::string::npos &&
                        lowerPath.find("update") == std::string::npos) {
                        DetectionItem item;
                        item.category = "Suspicious Execution (PCA Store)";
                        item.target = exePath;
                        item.detail = "Executed directly from Temp directory";
                        item.timestamp = timeStr;
                        item.severity = Severity::MEDIUM;
                        detections.push_back(item);
                        stats.suspiciousWarnings++;
                        stats.riskScore += 10;
                    }
                }
            }

            valSize = sizeof(valName) / sizeof(wchar_t);
            dataSize = sizeof(data);
            valIndex++;
        }

        RegCloseKey(hKey);
    }
}

void ForensicsScanner::ScanBam(std::vector<DetectionItem>& detections, ScanStats& stats) {
    const std::vector<std::wstring> baseKeys = {
        L"SYSTEM\\CurrentControlSet\\Services\\bam\\State\\UserSettings",
        L"SYSTEM\\CurrentControlSet\\Services\\dam\\State\\UserSettings",
        L"SYSTEM\\CurrentControlSet\\Services\\bam\\UserSettings",
        L"SYSTEM\\CurrentControlSet\\Services\\dam\\UserSettings"
    };

    for (const auto& baseKey : baseKeys) {
        HKEY hKey;
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, baseKey.c_str(), 0, KEY_READ, &hKey) != ERROR_SUCCESS) {
            continue;
        }

        FILETIME ftKeyLastWrite = {0, 0};
        RegQueryInfoKeyW(hKey, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, &ftKeyLastWrite);

        wchar_t sidName[256];
        DWORD sidSize = sizeof(sidName) / sizeof(wchar_t);
        DWORD sidIndex = 0;

        while (RegEnumKeyExW(hKey, sidIndex, sidName, &sidSize, NULL, NULL, NULL, NULL) == ERROR_SUCCESS) {
            HKEY hSidKey;
            if (RegOpenKeyExW(hKey, sidName, 0, KEY_READ, &hSidKey) == ERROR_SUCCESS) {
                wchar_t valName[2048];
                DWORD valSize = sizeof(valName) / sizeof(wchar_t);
                DWORD valIndex = 0;
                DWORD type;
                BYTE data[256];
                DWORD dataSize = sizeof(data);

                while (RegEnumValueW(hSidKey, valIndex, valName, &valSize, NULL, &type, data, &dataSize) == ERROR_SUCCESS) {
                    stats.totalArtifactsScanned++;
                    std::string rawPath = WideToString(std::wstring(valName));
                    std::string normalizedPath = NormalizeDevicePath(rawPath);

                    std::string timeStr = ExtractFileTimeFromBuffer(data, dataSize);
                    if (timeStr.empty() || timeStr == "N/A") {
                        timeStr = ResolveExecutionTime(normalizedPath, ftKeyLastWrite);
                    }

                    std::string matchedKw;
                    if (MatchesCheatKeyword(normalizedPath, matchedKw)) {
                        DetectionItem item;
                        item.category = "Execution History (BAM / DAM)";
                        item.target = normalizedPath;
                        item.detail = "Matched cheat keyword: '" + matchedKw + "'";
                        item.timestamp = timeStr;
                        item.severity = Severity::CRITICAL;
                        detections.push_back(item);
                        stats.cheatDetections++;
                        stats.riskScore += 30;

                        // Live stream discovery to console
                        std::cout << "\033[1;31m    >> [LIVE FIND] \033[0m\033[1;37m" << normalizedPath 
                                  << "\033[0m \033[1;33m[ " << item.timestamp << " ]\033[0m\n";
                        Sleep(35);
                    }

                    valSize = sizeof(valName) / sizeof(wchar_t);
                    dataSize = sizeof(data);
                    valIndex++;
                }
                RegCloseKey(hSidKey);
            }
            sidSize = sizeof(sidName) / sizeof(wchar_t);
            sidIndex++;
        }
        RegCloseKey(hKey);
    }
}

void ForensicsScanner::ScanUserAssist(std::vector<DetectionItem>& detections, ScanStats& stats) {
    const wchar_t* baseKey = L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist";
    HKEY hKey;
    if (RegOpenKeyExW(HKEY_CURRENT_USER, baseKey, 0, KEY_READ, &hKey) != ERROR_SUCCESS) {
        return;
    }

    wchar_t guidName[256];
    DWORD guidSize = sizeof(guidName) / sizeof(wchar_t);
    DWORD guidIndex = 0;

    while (RegEnumKeyExW(hKey, guidIndex, guidName, &guidSize, NULL, NULL, NULL, NULL) == ERROR_SUCCESS) {
        std::wstring countSubKey = std::wstring(guidName) + L"\\Count";
        HKEY hCountKey;
        if (RegOpenKeyExW(hKey, countSubKey.c_str(), 0, KEY_READ, &hCountKey) == ERROR_SUCCESS) {
            wchar_t valName[2048];
            DWORD valSize = sizeof(valName) / sizeof(wchar_t);
            DWORD valIndex = 0;
            DWORD type;
            BYTE data[256];
            DWORD dataSize = sizeof(data);

            while (RegEnumValueW(hCountKey, valIndex, valName, &valSize, NULL, &type, data, &dataSize) == ERROR_SUCCESS) {
                stats.totalArtifactsScanned++;
                std::wstring decodedValName = Rot13(std::wstring(valName));
                std::string decodedPath = WideToString(decodedValName);

                // Strip prefix like UEME_RUN: or UEME_RUNPATH:
                size_t colonPos = decodedPath.find(':');
                if (colonPos != std::string::npos && colonPos < 12) {
                    decodedPath = decodedPath.substr(colonPos + 1);
                }

                std::string timeStr = "Recorded in UserAssist";
                DWORD runCount = 0;
                if (type == REG_BINARY && dataSize >= 68) {
                    memcpy(&runCount, data + 4, sizeof(DWORD));
                    FILETIME ft;
                    memcpy(&ft, data + 60, sizeof(FILETIME));
                    std::string parsedTime = FileTimeToDateTimeString(ft);
                    if (parsedTime != "N/A" && parsedTime.rfind("1601", 0) != 0) {
                        timeStr = parsedTime + " (Run count: " + std::to_string(runCount) + ")";
                    }
                }

                std::string matchedKw;
                if (MatchesCheatKeyword(decodedPath, matchedKw)) {
                    DetectionItem item;
                    item.category = "Execution History (UserAssist)";
                    item.target = decodedPath;
                    item.detail = "Matched cheat keyword: '" + matchedKw + "'";
                    item.timestamp = timeStr;
                    item.severity = Severity::CRITICAL;
                    detections.push_back(item);
                    stats.cheatDetections++;
                    stats.riskScore += 25;

                    std::cout << "\033[1;31m    >> [LIVE FIND] \033[0m\033[1;37m" << decodedPath 
                              << "\033[0m \033[1;33m[ " << item.timestamp << " ]\033[0m\n";
                    Sleep(35);
                }

                valSize = sizeof(valName) / sizeof(wchar_t);
                dataSize = sizeof(data);
                valIndex++;
            }
            RegCloseKey(hCountKey);
        }
        guidSize = sizeof(guidName) / sizeof(wchar_t);
        guidIndex++;
    }
    RegCloseKey(hKey);
}

void ForensicsScanner::ScanPrefetch(std::vector<DetectionItem>& detections, ScanStats& stats, int& prefetchCount) {
    prefetchCount = 0;
    WIN32_FIND_DATAW fd;
    HANDLE hFind = FindFirstFileW(L"C:\\Windows\\Prefetch\\*.pf", &fd);
    if (hFind == INVALID_HANDLE_VALUE) {
        return;
    }

    do {
        if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
            prefetchCount++;
            stats.totalArtifactsScanned++;

            std::wstring fileNameW = fd.cFileName;
            std::string fileName = WideToString(fileNameW);
            std::string timeStr = FileTimeToDateTimeString(fd.ftLastWriteTime);

            std::string matchedKw;
            if (MatchesCheatKeyword(fileName, matchedKw)) {
                DetectionItem item;
                item.category = "Forensic Artifact (Windows Prefetch)";
                item.target = "C:\\Windows\\Prefetch\\" + fileName;
                item.detail = "Execution record of cheat: '" + matchedKw + "'";
                item.timestamp = timeStr;
                item.severity = Severity::CRITICAL;
                detections.push_back(item);
                stats.cheatDetections++;
                stats.riskScore += 35;

                std::cout << "\033[1;31m    >> [LIVE FIND] \033[0m\033[1;37m" << fileName 
                          << "\033[0m \033[1;33m[ " << item.timestamp << " ]\033[0m\n";
                Sleep(35);
            }
        }
    } while (FindNextFileW(hFind, &fd));

    FindClose(hFind);
}

void ForensicsScanner::ScanRecentItems(std::vector<DetectionItem>& detections, ScanStats& stats) {
    wchar_t recentPath[MAX_PATH];
    if (SHGetFolderPathW(NULL, CSIDL_RECENT, NULL, 0, recentPath) != S_OK) {
        return;
    }

    std::wstring searchPattern = std::wstring(recentPath) + L"\\*.*";
    WIN32_FIND_DATAW fd;
    HANDLE hFind = FindFirstFileW(searchPattern.c_str(), &fd);
    if (hFind == INVALID_HANDLE_VALUE) {
        return;
    }

    do {
        if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
            stats.totalArtifactsScanned++;
            std::wstring fileNameW = fd.cFileName;
            std::string fileName = WideToString(fileNameW);
            std::string timeStr = FileTimeToDateTimeString(fd.ftLastWriteTime);

            std::string matchedKw;
            if (MatchesCheatKeyword(fileName, matchedKw)) {
                DetectionItem item;
                item.category = "Recent File History";
                item.target = fileName;
                item.detail = "Recent shortcut/file linked to cheat: '" + matchedKw + "'";
                item.timestamp = timeStr;
                item.severity = Severity::HIGH;
                detections.push_back(item);
                stats.cheatDetections++;
                stats.riskScore += 20;

                std::cout << "\033[1;31m    >> [LIVE FIND] \033[0m\033[1;37m" << fileName 
                          << "\033[0m \033[1;33m[ " << item.timestamp << " ]\033[0m\n";
                Sleep(35);
            }
        }
    } while (FindNextFileW(hFind, &fd));

    FindClose(hFind);
}

void ForensicsScanner::ScanHighRiskFolders(std::vector<DetectionItem>& detections, ScanStats& stats) {
    std::vector<std::wstring> targetDirs;

    // User Profile dirs
    wchar_t userProfile[MAX_PATH];
    if (GetEnvironmentVariableW(L"USERPROFILE", userProfile, MAX_PATH) > 0) {
        targetDirs.push_back(std::wstring(userProfile) + L"\\Downloads");
        targetDirs.push_back(std::wstring(userProfile) + L"\\Desktop");
    }

    wchar_t tempDir[MAX_PATH];
    if (GetTempPathW(MAX_PATH, tempDir) > 0) {
        targetDirs.push_back(std::wstring(tempDir));
    }

    for (const auto& dirPath : targetDirs) {
        try {
            if (!fs::exists(dirPath)) continue;

            // Iterate 1 level shallow to avoid deep recursion performance issues
            for (const auto& entry : fs::directory_iterator(dirPath, fs::directory_options::skip_permission_denied)) {
                stats.totalArtifactsScanned++;
                if (!entry.is_regular_file()) continue;

                std::string filename = entry.path().filename().string();
                std::string extension = ToLower(entry.path().extension().string());

                // Check for cheat files
                std::string matchedKw;
                if (MatchesCheatKeyword(filename, matchedKw)) {
                    DetectionItem item;
                    item.category = "File System (High-Risk Directory)";
                    item.target = entry.path().string();
                    item.detail = "Cheat file found: '" + matchedKw + "'";
                    
                    auto ftime = fs::last_write_time(entry);
                    auto sctp = std::chrono::time_point_cast<std::chrono::system_clock::duration>(
                        ftime - fs::file_time_type::clock::now() + std::chrono::system_clock::now());
                    std::time_t cftime = std::chrono::system_clock::to_time_t(sctp);
                    char timeBuf[64];
                    std::strftime(timeBuf, sizeof(timeBuf), "%Y-%m-%d %H:%M:%S", std::localtime(&cftime));
                    item.timestamp = timeBuf;

                    item.severity = Severity::CRITICAL;
                    detections.push_back(item);
                    stats.cheatDetections++;
                    stats.riskScore += 30;

                    // Live stream discovery to console
                    std::cout << "\033[1;31m    >> [LIVE FIND] \033[0m\033[1;33m[ " << item.timestamp << " ] \033[1;37m" 
                              << filename << "\033[0m \033[1;35m(Storage: " << entry.path().parent_path().filename().string() << ")\033[0m\n";
                    Sleep(35);
                }

                // Check for cheat configuration files (.ini, .cfg) with aimbot/esp keys
                if (extension == ".cfg" || extension == ".ini" || extension == ".json") {
                    try {
                        std::ifstream file(entry.path(), std::ios::in | std::ios::binary);
                        if (file.is_open()) {
                            std::string content((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
                            file.close();

                            if (content.size() < 100000) { // Limit to 100KB
                                std::string lowerContent = ToLower(content);
                                int cheatSignals = 0;
                                if (lowerContent.find("aimbot") != std::string::npos) cheatSignals++;
                                if (lowerContent.find("silentaim") != std::string::npos) cheatSignals++;
                                if (lowerContent.find("fov") != std::string::npos && lowerContent.find("smooth") != std::string::npos) cheatSignals++;
                                if (lowerContent.find("esp_box") != std::string::npos || lowerContent.find("chams") != std::string::npos) cheatSignals++;
                                if (lowerContent.find("triggerbot") != std::string::npos) cheatSignals++;

                                if (cheatSignals >= 2) {
                                    DetectionItem item;
                                    item.category = "Cheat Configuration File";
                                    item.target = entry.path().string();
                                    item.detail = "File contains game cheat parameters (aimbot, esp, smooth, fov)";
                                    item.timestamp = "Existing File";
                                    item.severity = Severity::HIGH;
                                    detections.push_back(item);
                                    stats.cheatDetections++;
                                    stats.riskScore += 25;

                                    std::cout << "\033[1;31m    >> [LIVE FIND] \033[0m\033[1;33m[ Config ] \033[1;37m" 
                                              << filename << "\033[0m \033[1;35m(Cheat Config)\033[0m\n";
                                    Sleep(35);
                                }
                            }
                        }
                    } catch (...) {}
                }
            }
        } catch (...) {
            // Skip access denied or inaccessible folders
        }
    }
}

void ForensicsScanner::ScanRecycleBin(std::vector<DetectionItem>& detections, ScanStats& stats) {
    try {
        const std::string recyclePath = "C:\\$Recycle.Bin";
        if (!fs::exists(recyclePath)) return;

        for (const auto& entry : fs::recursive_directory_iterator(recyclePath, fs::directory_options::skip_permission_denied)) {
            stats.totalArtifactsScanned++;
            if (!entry.is_regular_file()) continue;

            std::string filename = entry.path().filename().string();
            std::string matchedKw;
            if (MatchesCheatKeyword(filename, matchedKw)) {
                DetectionItem item;
                item.category = "Recycle Bin Forensics";
                item.target = entry.path().string();
                item.detail = "Deleted cheat file located in Recycle Bin: '" + matchedKw + "'";
                item.timestamp = "In Recycle Bin";
                item.severity = Severity::CRITICAL;
                detections.push_back(item);
                stats.cheatDetections++;
                stats.riskScore += 25;

                // Live stream discovery to console
                std::cout << "\033[1;31m    >> [LIVE FIND] \033[0m\033[1;33m[ Recycle Bin ] \033[1;37m" 
                          << filename << "\033[0m \033[1;35m(Deleted Cheat)\033[0m\n";
                Sleep(35);
            }
        }
    } catch (...) {}
}
