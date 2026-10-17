#include "reg_scanner.hpp"
#include <tlhelp32.h>
#include <iostream>
#include <algorithm>

static std::string ExtractStringFromBinaryPidl(const std::vector<BYTE>& data) {
    // Scan for printable ASCII strings of length >= 4
    std::string result = "";
    std::string current = "";

    for (size_t i = 0; i < data.size(); ++i) {
        char c = (char)data[i];
        if (c >= 32 && c <= 126) {
            current += c;
        } else {
            if (current.length() >= 4) {
                std::string lower = ToLower(current);
                if (lower.find(".exe") != std::string::npos ||
                    lower.find(".dll") != std::string::npos ||
                    lower.find(".sys") != std::string::npos ||
                    lower.find(".zip") != std::string::npos ||
                    lower.find(".rar") != std::string::npos) {
                    return current;
                }
            }
            current = "";
        }
    }

    // Also scan for UTF-16LE strings
    std::wstring wcurrent = L"";
    for (size_t i = 0; i + 1 < data.size(); i += 2) {
        wchar_t wc = (wchar_t)(data[i] | (data[i + 1] << 8));
        if (wc >= 32 && wc <= 126) {
            wcurrent += wc;
        } else {
            if (wcurrent.length() >= 4) {
                std::string s = WideToString(wcurrent);
                std::string lower = ToLower(s);
                if (lower.find(".exe") != std::string::npos ||
                    lower.find(".dll") != std::string::npos ||
                    lower.find(".sys") != std::string::npos ||
                    lower.find(".zip") != std::string::npos ||
                    lower.find(".rar") != std::string::npos) {
                    return s;
                }
            }
            wcurrent = L"";
        }
    }

    return "";
}

void RegistryScanner::CheckRegeditActivity(RegAuditResult& result,
                                          std::vector<DetectionItem>& detections,
                                          std::vector<BypassItem>& bypassItems,
                                          ScanStats& stats) {
    stats.totalArtifactsScanned++;

    // 1. Check if regedit window or process is currently active
    HWND hRegWnd = FindWindowW(L"RegEdit_RegEdit", NULL);
    if (hRegWnd != NULL) {
        result.regeditCurrentlyRunning = true;
    } else {
        HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hSnap != INVALID_HANDLE_VALUE) {
            PROCESSENTRY32W pe;
            pe.dwSize = sizeof(PROCESSENTRY32W);
            if (Process32FirstW(hSnap, &pe)) {
                do {
                    std::string pName = ToLower(WideToString(pe.szExeFile));
                    if (pName == "regedit.exe") {
                        result.regeditCurrentlyRunning = true;
                        break;
                    }
                } while (Process32NextW(hSnap, &pe));
            }
            CloseHandle(hSnap);
        }
    }

    if (result.regeditCurrentlyRunning) {
        DetectionItem item;
        item.category = "Windows Registry Editor (Regedit Live)";
        item.target = "regedit.exe";
        item.detail = "Windows Registry Editor is currently running! Potential registry tampering or log wiping in progress.";
        item.timestamp = "Currently Active";
        item.severity = Severity::HIGH;
        detections.push_back(item);
        stats.cheatDetections++;
        stats.riskScore += 25;

        std::cout << "\033[1;31m    >> [LIVE ALERT] \033[0m\033[1;33m[ Regedit Active ] \033[1;37mregedit.exe is currently running on the system!\033[0m\n";
        Sleep(35);
    }

    // 2. Query Regedit Applet LastKey
    HKEY hKey;
    if (RegOpenKeyExW(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Applets\\Regedit", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        wchar_t buf[1024];
        DWORD bufSize = sizeof(buf);
        DWORD type = REG_SZ;
        if (RegQueryValueExW(hKey, L"LastKey", NULL, &type, (LPBYTE)buf, &bufSize) == ERROR_SUCCESS) {
            result.regeditLastKey = WideToString(buf);
            std::string lkLower = ToLower(result.regeditLastKey);

            std::string matchedKw;
            if (MatchesCheatKeyword(lkLower, matchedKw)) {
                result.lastKeySuspicious = true;
                result.lastKeySuspicionReason = "Contains cheat signature keyword: '" + matchedKw + "'";
            } else if (lkLower.find("bam") != std::string::npos || lkLower.find("usersettings") != std::string::npos) {
                result.lastKeySuspicious = true;
                result.lastKeySuspicionReason = "Targeted BAM execution history key - likely BAM log wiping!";
            } else if (lkLower.find("pcasvc") != std::string::npos || lkLower.find("compatibility assistant") != std::string::npos) {
                result.lastKeySuspicious = true;
                result.lastKeySuspicionReason = "Targeted PCA Store compatibility key - potential PCA tamper!";
            } else if (lkLower.find("windows defender") != std::string::npos || lkLower.find("windefend") != std::string::npos) {
                result.lastKeySuspicious = true;
                result.lastKeySuspicionReason = "Targeted Windows Defender policies - potential antivirus evasion!";
            } else if (lkLower.find("appinit_dlls") != std::string::npos) {
                result.lastKeySuspicious = true;
                result.lastKeySuspicionReason = "Targeted AppInit_DLLs global injection key!";
            } else if (lkLower.find("image file execution options") != std::string::npos) {
                result.lastKeySuspicious = true;
                result.lastKeySuspicionReason = "Targeted IFEO debugger redirection key!";
            } else if (lkLower.find("tcpip\\parameters") != std::string::npos || lkLower.find("systemprofile") != std::string::npos) {
                result.lastKeySuspicious = true;
                result.lastKeySuspicionReason = "Targeted network throttling / TCP latency tweak keys!";
            }

            if (result.lastKeySuspicious) {
                BypassItem bItem;
                bItem.component = "Windows Registry Editor (Regedit LastKey)";
                bItem.status = "SUSPICIOUS REGISTRY TARGET VISITED";
                bItem.evidence = "LastKey: " + result.regeditLastKey + " (" + result.lastKeySuspicionReason + ")";
                bItem.severity = Severity::HIGH;
                bypassItems.push_back(bItem);
                stats.bypassDetections++;
                stats.riskScore += 30;

                std::cout << "\033[1;31m    >> [LIVE ALERT] \033[0m\033[1;33m[ Regedit LastKey ] \033[1;37m" 
                          << result.regeditLastKey << " \033[1;31m(" << result.lastKeySuspicionReason << ")\033[0m\n";
                Sleep(35);
            }
        }
        RegCloseKey(hKey);
    }

    // 3. Check historical executions of regedit in Prefetch
    WIN32_FIND_DATAW fd;
    HANDLE hFind = FindFirstFileW(L"C:\\Windows\\Prefetch\\REGEDIT.EXE-*.pf", &fd);
    if (hFind != INVALID_HANDLE_VALUE) {
        do {
            std::string pfTime = FileTimeToDateTimeString(fd.ftLastWriteTime);
            result.regeditExecutionHistory.push_back(pfTime);
        } while (FindNextFileW(hFind, &fd));
        FindClose(hFind);
    }
}

void RegistryScanner::CheckAppInitDlls(RegAuditResult& result,
                                      std::vector<BypassItem>& bypassItems,
                                      ScanStats& stats) {
    stats.totalArtifactsScanned++;

    const wchar_t* keys[2] = {
        L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows",
        L"SOFTWARE\\WOW6432Node\\Microsoft\\Windows NT\\CurrentVersion\\Windows"
    };

    for (int i = 0; i < 2; ++i) {
        HKEY hKey;
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, keys[i], 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
            wchar_t dllBuf[1024];
            DWORD dllSize = sizeof(dllBuf);
            DWORD type = REG_SZ;
            if (RegQueryValueExW(hKey, L"AppInit_DLLs", NULL, &type, (LPBYTE)dllBuf, &dllSize) == ERROR_SUCCESS) {
                std::wstring wDll(dllBuf);
                if (!wDll.empty()) {
                    std::string dllStr = WideToString(wDll);
                    result.appInitDlls.push_back(dllStr);

                    BypassItem item;
                    item.component = "Global Process Injection (AppInit_DLLs)";
                    item.status = "ACTIVE GLOBAL DLL HOOK";
                    item.evidence = "AppInit_DLLs set to: '" + dllStr + "' in " + WideToString(keys[i]);
                    item.severity = Severity::CRITICAL;
                    bypassItems.push_back(item);
                    stats.bypassDetections++;
                    stats.riskScore += 45;

                    std::cout << "\033[1;31m    >> [LIVE ALERT] \033[0m\033[1;33m[ AppInit_DLLs ] \033[1;31m" 
                              << dllStr << " (Global Injection Hook!)\033[0m\n";
                    Sleep(35);
                }
            }

            DWORD loadAppInit = 0;
            DWORD loadSize = sizeof(DWORD);
            if (RegQueryValueExW(hKey, L"LoadAppInit_DLLs", NULL, NULL, (LPBYTE)&loadAppInit, &loadSize) == ERROR_SUCCESS) {
                if (loadAppInit == 1) {
                    BypassItem item;
                    item.component = "Global Injection (LoadAppInit_DLLs)";
                    item.status = "ENABLED (LoadAppInit_DLLs = 1)";
                    item.evidence = "System configured to load third-party DLLs into all user processes.";
                    item.severity = Severity::HIGH;
                    bypassItems.push_back(item);
                    stats.bypassDetections++;
                    stats.riskScore += 25;
                }
            }

            RegCloseKey(hKey);
        }
    }
}

void RegistryScanner::CheckIfeoDebuggerHijacks(RegAuditResult& result,
                                              std::vector<BypassItem>& bypassItems,
                                              ScanStats& stats) {
    stats.totalArtifactsScanned++;

    const std::vector<std::wstring> targets = {
        L"EasyAntiCheat.exe", L"EasyAntiCheat_EOS.exe", L"BEService.exe",
        L"vgc.exe", L"taskmgr.exe", L"regedit.exe", L"cmd.exe", L"powershell.exe",
        L"cs2.exe", L"FiveM.exe", L"FortniteClient-Win64-Shipping.exe", L"VALORANT-Win64-Shipping.exe"
    };

    std::wstring basePath = L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\";

    for (const auto& target : targets) {
        std::wstring fullKey = basePath + target;
        HKEY hKey;
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, fullKey.c_str(), 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
            wchar_t dbgBuf[1024];
            DWORD dbgSize = sizeof(dbgBuf);
            DWORD type = REG_SZ;
            if (RegQueryValueExW(hKey, L"Debugger", NULL, &type, (LPBYTE)dbgBuf, &dbgSize) == ERROR_SUCCESS) {
                std::string dbgStr = WideToString(dbgBuf);
                std::string targetStr = WideToString(target);
                result.ifeoHijacks.push_back(targetStr + " -> " + dbgStr);

                BypassItem item;
                item.component = "IFEO Debugger Hijacking (" + targetStr + ")";
                item.status = "CRITICAL BINARY INTERCEPT";
                item.evidence = "Binary execution redirected to debugger: '" + dbgStr + "'";
                item.severity = Severity::CRITICAL;
                bypassItems.push_back(item);
                stats.bypassDetections++;
                stats.riskScore += 50;

                std::cout << "\033[1;31m    >> [LIVE ALERT] \033[0m\033[1;33m[ IFEO Hijack ] \033[1;37m" 
                          << targetStr << " \033[1;31m-> Redirected to: " << dbgStr << "\033[0m\n";
                Sleep(35);
            }
            RegCloseKey(hKey);
        }
    }
}

void RegistryScanner::CheckAppCompatFlagsLayers(RegAuditResult& result,
                                               std::vector<DetectionItem>& detections,
                                               ScanStats& stats) {
    const struct {
        HKEY root;
        const wchar_t* path;
    } layerKeys[2] = {
        { HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows NT\\CurrentVersion\\AppCompatFlags\\Layers" },
        { HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\AppCompatFlags\\Layers" }
    };

    for (int k = 0; k < 2; ++k) {
        HKEY hKey;
        if (RegOpenKeyExW(layerKeys[k].root, layerKeys[k].path, 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
            DWORD valCount = 0;
            DWORD maxValNameLen = 0;
            if (RegQueryInfoKeyW(hKey, NULL, NULL, NULL, NULL, NULL, NULL, &valCount, &maxValNameLen, NULL, NULL, NULL) == ERROR_SUCCESS) {
                std::vector<wchar_t> nameBuf(maxValNameLen + 2);
                for (DWORD i = 0; i < valCount; ++i) {
                    DWORD nameLen = (DWORD)nameBuf.size();
                    wchar_t dataBuf[512];
                    DWORD dataLen = sizeof(dataBuf);
                    DWORD type = REG_SZ;

                    if (RegEnumValueW(hKey, i, nameBuf.data(), &nameLen, NULL, &type, (LPBYTE)dataBuf, &dataLen) == ERROR_SUCCESS) {
                        stats.totalArtifactsScanned++;
                        std::string exePath = WideToString(std::wstring(nameBuf.data(), nameLen));
                        std::string flags = WideToString(dataBuf);

                        std::string matchedKw;
                        if (MatchesCheatKeyword(exePath, matchedKw) ||
                            ToLower(exePath).find("cheat") != std::string::npos ||
                            ToLower(exePath).find("injector") != std::string::npos ||
                            ToLower(exePath).find("spoofer") != std::string::npos ||
                            ToLower(exePath).find("cs2esp") != std::string::npos) {

                            result.appCompatLayers.push_back(exePath + " (" + flags + ")");

                            DetectionItem item;
                            item.category = "AppCompatFlags Layers (Registry)";
                            item.target = exePath;
                            item.detail = "Cheat binary configured with compatibility flags: '" + flags + "' [Matched: " + matchedKw + "]";
                            item.timestamp = "Registry Layer Record";
                            item.severity = Severity::CRITICAL;
                            detections.push_back(item);
                            stats.cheatDetections++;
                            stats.riskScore += 30;

                            std::cout << "\033[1;31m    >> [LIVE FIND] \033[0m\033[1;37m" << exePath 
                                      << " \033[1;35m(AppCompat Flags: " << flags << ")\033[0m\n";
                            Sleep(35);
                        }
                    }
                }
            }
            RegCloseKey(hKey);
        }
    }
}

void RegistryScanner::CheckComDlgOpenSaveMRU(RegAuditResult& result,
                                            std::vector<DetectionItem>& detections,
                                            ScanStats& stats) {
    const wchar_t* baseSubKey = L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ComDlg32\\OpenSavePidlMRU";
    HKEY hBase;
    if (RegOpenKeyExW(HKEY_CURRENT_USER, baseSubKey, 0, KEY_READ, &hBase) != ERROR_SUCCESS) return;

    DWORD subKeys = 0;
    DWORD maxSubKeyLen = 0;
    RegQueryInfoKeyW(hBase, NULL, NULL, NULL, &subKeys, &maxSubKeyLen, NULL, NULL, NULL, NULL, NULL, NULL);

    std::vector<wchar_t> keyNameBuf(maxSubKeyLen + 2);
    for (DWORD s = 0; s < subKeys; ++s) {
        DWORD keyLen = (DWORD)keyNameBuf.size();
        if (RegEnumKeyExW(hBase, s, keyNameBuf.data(), &keyLen, NULL, NULL, NULL, NULL) == ERROR_SUCCESS) {
            std::wstring extKey = std::wstring(keyNameBuf.data(), keyLen);
            std::wstring fullSubPath = std::wstring(baseSubKey) + L"\\" + extKey;

            HKEY hExt;
            if (RegOpenKeyExW(HKEY_CURRENT_USER, fullSubPath.c_str(), 0, KEY_READ, &hExt) == ERROR_SUCCESS) {
                DWORD valCount = 0;
                RegQueryInfoKeyW(hExt, NULL, NULL, NULL, NULL, NULL, NULL, &valCount, NULL, NULL, NULL, NULL);

                for (DWORD v = 0; v < valCount; ++v) {
                    wchar_t valName[64];
                    DWORD valNameLen = 64;
                    DWORD type = 0;
                    BYTE data[2048];
                    DWORD dataSize = sizeof(data);

                    if (RegEnumValueW(hExt, v, valName, &valNameLen, NULL, &type, data, &dataSize) == ERROR_SUCCESS) {
                        if (type == REG_BINARY && dataSize > 0) {
                            stats.totalArtifactsScanned++;
                            std::vector<BYTE> dataVec(data, data + dataSize);
                            std::string foundStr = ExtractStringFromBinaryPidl(dataVec);

                            if (!foundStr.empty()) {
                                std::string matchedKw;
                                if (MatchesCheatKeyword(foundStr, matchedKw) ||
                                    ToLower(foundStr).find("cheat") != std::string::npos ||
                                    ToLower(foundStr).find("injector") != std::string::npos ||
                                    ToLower(foundStr).find("spoofer") != std::string::npos) {

                                    result.openSaveCheats.push_back(foundStr);

                                    DetectionItem item;
                                    item.category = "Explorer File Dialog History (OpenSavePidlMRU)";
                                    item.target = foundStr;
                                    item.detail = "File chosen via Windows Explorer Open/Save file dialog: '" + matchedKw + "'";
                                    item.timestamp = "Explorer MRU Trace";
                                    item.severity = Severity::HIGH;
                                    detections.push_back(item);
                                    stats.cheatDetections++;
                                    stats.riskScore += 25;

                                    std::cout << "\033[1;31m    >> [LIVE FIND] \033[0m\033[1;37m" << foundStr 
                                              << " \033[1;35m(OpenSave MRU Dialog Record)\033[0m\n";
                                    Sleep(35);
                                }
                            }
                        }
                    }
                }
                RegCloseKey(hExt);
            }
        }
    }

    RegCloseKey(hBase);
}

void RegistryScanner::CheckWordWheelQueries(RegAuditResult& result,
                                           std::vector<DetectionItem>& detections,
                                           ScanStats& stats) {
    HKEY hKey;
    if (RegOpenKeyExW(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\WordWheelQuery", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        DWORD valCount = 0;
        RegQueryInfoKeyW(hKey, NULL, NULL, NULL, NULL, NULL, NULL, &valCount, NULL, NULL, NULL, NULL);

        for (DWORD i = 0; i < valCount; ++i) {
            wchar_t valName[64];
            DWORD valNameLen = 64;
            DWORD type = 0;
            BYTE data[512];
            DWORD dataSize = sizeof(data);

            if (RegEnumValueW(hKey, i, valName, &valNameLen, NULL, &type, data, &dataSize) == ERROR_SUCCESS) {
                if (type == REG_BINARY && dataSize > 1) {
                    stats.totalArtifactsScanned++;
                    // Decode UTF-16LE query
                    std::wstring wQuery((wchar_t*)data, dataSize / sizeof(wchar_t));
                    // Remove trailing nulls
                    while (!wQuery.empty() && wQuery.back() == L'\0') wQuery.pop_back();

                    std::string queryStr = WideToString(wQuery);
                    std::string matchedKw;
                    if (MatchesCheatKeyword(queryStr, matchedKw) ||
                        ToLower(queryStr).find("cheat") != std::string::npos ||
                        ToLower(queryStr).find("spoofer") != std::string::npos ||
                        ToLower(queryStr).find("aimbot") != std::string::npos ||
                        ToLower(queryStr).find("injector") != std::string::npos ||
                        ToLower(queryStr).find("cs2esp") != std::string::npos) {

                        result.searchQueries.push_back(queryStr);

                        DetectionItem item;
                        item.category = "Windows Explorer Search Query (WordWheelQuery)";
                        item.target = "\"" + queryStr + "\"";
                        item.detail = "User typed cheat search query into Windows Explorer search: '" + matchedKw + "'";
                        item.timestamp = "Explorer Search Query";
                        item.severity = Severity::MEDIUM;
                        detections.push_back(item);
                        stats.cheatDetections++;
                        stats.riskScore += 20;

                        std::cout << "\033[1;31m    >> [LIVE FIND] \033[0m\033[1;37m\"" << queryStr 
                                  << "\" \033[1;35m(Explorer Search Record)\033[0m\n";
                        Sleep(35);
                    }
                }
            }
        }
        RegCloseKey(hKey);
    }
}

void RegistryScanner::CheckStartupRunKeys(RegAuditResult& result,
                                         std::vector<DetectionItem>& detections,
                                         ScanStats& stats) {
    const struct {
        HKEY root;
        const wchar_t* path;
    } runKeys[4] = {
        { HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Run" },
        { HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce" },
        { HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" },
        { HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce" }
    };

    for (int k = 0; k < 4; ++k) {
        HKEY hKey;
        if (RegOpenKeyExW(runKeys[k].root, runKeys[k].path, 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
            DWORD valCount = 0;
            DWORD maxValName = 0;
            DWORD maxData = 0;
            if (RegQueryInfoKeyW(hKey, NULL, NULL, NULL, NULL, NULL, NULL, &valCount, &maxValName, &maxData, NULL, NULL) == ERROR_SUCCESS) {
                std::vector<wchar_t> nameBuf(maxValName + 2);
                std::vector<BYTE> dataBuf(maxData + 2);

                for (DWORD i = 0; i < valCount; ++i) {
                    DWORD nLen = (DWORD)nameBuf.size();
                    DWORD dLen = (DWORD)dataBuf.size();
                    DWORD type = 0;

                    if (RegEnumValueW(hKey, i, nameBuf.data(), &nLen, NULL, &type, dataBuf.data(), &dLen) == ERROR_SUCCESS) {
                        stats.totalArtifactsScanned++;
                        std::string valName = WideToString(std::wstring(nameBuf.data(), nLen));
                        std::string cmdLine = "";
                        if (type == REG_SZ || type == REG_EXPAND_SZ) {
                            cmdLine = WideToString((wchar_t*)dataBuf.data());
                        }

                        std::string matchedKw;
                        if (MatchesCheatKeyword(valName, matchedKw) || MatchesCheatKeyword(cmdLine, matchedKw) ||
                            ToLower(cmdLine).find("cheat") != std::string::npos ||
                            ToLower(cmdLine).find("spoofer") != std::string::npos ||
                            ToLower(cmdLine).find("injector") != std::string::npos) {

                            result.startupRunCheats.push_back(valName + " = " + cmdLine);

                            DetectionItem item;
                            item.category = "Windows Startup Run Persistence (Registry)";
                            item.target = valName + " (" + cmdLine + ")";
                            item.detail = "Startup auto-launch entry linked to cheat: '" + matchedKw + "'";
                            item.timestamp = "Active Startup Key";
                            item.severity = Severity::CRITICAL;
                            detections.push_back(item);
                            stats.cheatDetections++;
                            stats.riskScore += 35;

                            std::cout << "\033[1;31m    >> [LIVE ALERT] \033[0m\033[1;33m[ Startup Cheat ] \033[1;37m" 
                                      << valName << " \033[1;31m(" << cmdLine << ")\033[0m\n";
                            Sleep(35);
                        }
                    }
                }
            }
            RegCloseKey(hKey);
        }
    }
}

void RegistryScanner::CheckGamingRegistryTweaks(RegAuditResult& result,
                                                std::vector<BypassItem>& bypassItems,
                                                ScanStats& stats) {
    stats.totalArtifactsScanned++;

    // 1. Network Throttling Index (Multimedia SystemProfile)
    HKEY hProfile;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Multimedia\\SystemProfile", 0, KEY_READ, &hProfile) == ERROR_SUCCESS) {
        DWORD netIndex = 0;
        DWORD size = sizeof(DWORD);
        if (RegQueryValueExW(hProfile, L"NetworkThrottlingIndex", NULL, NULL, (LPBYTE)&netIndex, &size) == ERROR_SUCCESS) {
            if (netIndex == 0xffffffff) {
                RegTweakItem twk;
                twk.keyPath = "HKLM\\...\\Multimedia\\SystemProfile";
                twk.valueName = "NetworkThrottlingIndex";
                twk.currentValue = "0xFFFFFFFF (Disabled)";
                twk.expectedOrNormal = "10 (Default)";
                twk.description = "Network throttling completely disabled (frequently used in competitive games for packet desync tweaks)";
                twk.severity = Severity::MEDIUM;
                result.detectedTweaks.push_back(twk);

                BypassItem bItem;
                bItem.component = "Registry Tweak: NetworkThrottlingIndex";
                bItem.status = "THROTTLING DISABLED (0xFFFFFFFF)";
                bItem.evidence = twk.description;
                bItem.severity = Severity::MEDIUM;
                bypassItems.push_back(bItem);
                stats.bypassDetections++;
                stats.riskScore += 10;
            }
        }

        DWORD resp = 0;
        size = sizeof(DWORD);
        if (RegQueryValueExW(hProfile, L"SystemResponsiveness", NULL, NULL, (LPBYTE)&resp, &size) == ERROR_SUCCESS) {
            if (resp == 0) {
                RegTweakItem twk;
                twk.keyPath = "HKLM\\...\\Multimedia\\SystemProfile";
                twk.valueName = "SystemResponsiveness";
                twk.currentValue = "0 (Priority Gaming)";
                twk.expectedOrNormal = "20 (Default)";
                twk.description = "System responsiveness set to 0% background reservation (Gaming tweak)";
                twk.severity = Severity::INFO;
                result.detectedTweaks.push_back(twk);
            }
        }
        RegCloseKey(hProfile);
    }

    // 2. TCP No Delay & TCP Ack Frequency (Network Interfaces)
    HKEY hInterfaces;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces", 0, KEY_READ, &hInterfaces) == ERROR_SUCCESS) {
        DWORD subKeys = 0;
        DWORD maxKeyLen = 0;
        RegQueryInfoKeyW(hInterfaces, NULL, NULL, NULL, &subKeys, &maxKeyLen, NULL, NULL, NULL, NULL, NULL, NULL);

        std::vector<wchar_t> keyBuf(maxKeyLen + 2);
        for (DWORD i = 0; i < subKeys; ++i) {
            DWORD kLen = (DWORD)keyBuf.size();
            if (RegEnumKeyExW(hInterfaces, i, keyBuf.data(), &kLen, NULL, NULL, NULL, NULL) == ERROR_SUCCESS) {
                std::wstring guidKey = std::wstring(keyBuf.data(), kLen);
                std::wstring ifacePath = L"SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces\\" + guidKey;

                HKEY hIf;
                if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, ifacePath.c_str(), 0, KEY_READ, &hIf) == ERROR_SUCCESS) {
                    DWORD tcpAck = 0;
                    DWORD size = sizeof(DWORD);
                    if (RegQueryValueExW(hIf, L"TcpAckFrequency", NULL, NULL, (LPBYTE)&tcpAck, &size) == ERROR_SUCCESS && tcpAck == 1) {
                        RegTweakItem twk;
                        twk.keyPath = "Tcpip\\Interfaces\\" + WideToString(guidKey);
                        twk.valueName = "TcpAckFrequency";
                        twk.currentValue = "1 (Immediate ACK)";
                        twk.expectedOrNormal = "2 (Default Delayed ACK)";
                        twk.description = "TCP ACK Frequency forced to immediate ACK (Nagle algorithm bypass / gaming packet tweak)";
                        twk.severity = Severity::MEDIUM;
                        result.detectedTweaks.push_back(twk);

                        BypassItem bItem;
                        bItem.component = "Registry Tweak: TcpAckFrequency";
                        bItem.status = "FORCED IMMEDIATE ACK (1)";
                        bItem.evidence = twk.description;
                        bItem.severity = Severity::MEDIUM;
                        bypassItems.push_back(bItem);
                        stats.bypassDetections++;
                        stats.riskScore += 10;
                    }

                    DWORD tcpNoDelay = 0;
                    size = sizeof(DWORD);
                    if (RegQueryValueExW(hIf, L"TCPNoDelay", NULL, NULL, (LPBYTE)&tcpNoDelay, &size) == ERROR_SUCCESS && tcpNoDelay == 1) {
                        RegTweakItem twk;
                        twk.keyPath = "Tcpip\\Interfaces\\" + WideToString(guidKey);
                        twk.valueName = "TCPNoDelay";
                        twk.currentValue = "1 (No Delay)";
                        twk.expectedOrNormal = "0 (Default)";
                        twk.description = "TCP Nagle algorithm disabled to eliminate packet delay";
                        twk.severity = Severity::MEDIUM;
                        result.detectedTweaks.push_back(twk);
                    }
                    RegCloseKey(hIf);
                }
            }
        }
        RegCloseKey(hInterfaces);
    }
}

RegAuditResult RegistryScanner::AuditRegistry(std::vector<DetectionItem>& detections,
                                             std::vector<BypassItem>& bypassItems,
                                             ScanStats& stats,
                                             bool isAdmin) {
    RegAuditResult result;

    // 1. Regedit live & LastKey inspection
    CheckRegeditActivity(result, detections, bypassItems, stats);

    // 2. Global Injection AppInit_DLLs
    CheckAppInitDlls(result, bypassItems, stats);

    // 3. IFEO Debugger Hijacking
    CheckIfeoDebuggerHijacks(result, bypassItems, stats);

    // 4. AppCompatFlags Layers
    CheckAppCompatFlagsLayers(result, detections, stats);

    // 5. Explorer ComDlg OpenSave MRU
    CheckComDlgOpenSaveMRU(result, detections, stats);

    // 6. Explorer WordWheelQuery Search Queries
    CheckWordWheelQueries(result, detections, stats);

    // 7. Startup Run Keys Persistence
    CheckStartupRunKeys(result, detections, stats);

    // 8. Gaming / Network registry tweaks
    CheckGamingRegistryTweaks(result, bypassItems, stats);

    return result;
}
