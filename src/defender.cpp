#include "defender.hpp"
#include <array>
#include <memory>
#include <sstream>

static std::string CleanIsoDate(const std::string& raw) {
    // 2026-09-02T14:10:51.0360000Z -> 2026-09-02 14:10:51
    if (raw.empty()) return "N/A";
    std::string s = raw;
    size_t tPos = s.find('T');
    if (tPos != std::string::npos) {
        std::string datePart = s.substr(0, tPos);
        std::string timePart = s.substr(tPos + 1);
        size_t dotPos = timePart.find('.');
        if (dotPos != std::string::npos) {
            timePart = timePart.substr(0, dotPos);
        } else {
            size_t zPos = timePart.find('Z');
            if (zPos != std::string::npos) timePart = timePart.substr(0, zPos);
        }
        return datePart + " " + timePart;
    }
    return s;
}

static std::string CleanPath(const std::string& raw) {
    std::string s = raw;
    size_t pos;
    while ((pos = s.find("file:_")) != std::string::npos) s.erase(pos, 6);
    while ((pos = s.find("file:")) != std::string::npos) s.erase(pos, 5);
    while ((pos = s.find("CmdLine:_")) != std::string::npos) s.erase(pos, 9);
    // Trim whitespace
    size_t start = s.find_first_not_of(" \t\r\n");
    if (start != std::string::npos) s = s.substr(start);
    size_t end = s.find_last_not_of(" \t\r\n");
    if (end != std::string::npos) s = s.substr(0, end + 1);
    return s;
}

void DefenderScanner::CheckDefenderService(DefenderAuditResult& result) {
    SC_HANDLE scm = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
    if (!scm) return;

    SC_HANDLE hSvc = OpenServiceW(scm, L"WinDefend", SERVICE_QUERY_STATUS | SERVICE_QUERY_CONFIG);
    if (hSvc) {
        SERVICE_STATUS_PROCESS ssp;
        DWORD bytesNeeded = 0;
        if (QueryServiceStatusEx(hSvc, SC_STATUS_PROCESS_INFO, (LPBYTE)&ssp, sizeof(ssp), &bytesNeeded)) {
            if (ssp.dwCurrentState == SERVICE_RUNNING) {
                result.serviceRunning = true;
                result.serviceStateStr = "RUNNING";
            } else if (ssp.dwCurrentState == SERVICE_STOPPED) {
                result.serviceRunning = false;
                result.serviceStateStr = "STOPPED";
            } else {
                result.serviceRunning = false;
                result.serviceStateStr = "STATE_" + std::to_string(ssp.dwCurrentState);
            }
        }

        DWORD configNeeded = 0;
        QueryServiceConfigW(hSvc, NULL, 0, &configNeeded);
        if (GetLastError() == ERROR_INSUFFICIENT_BUFFER) {
            std::vector<BYTE> buffer(configNeeded);
            LPQUERY_SERVICE_CONFIGW config = (LPQUERY_SERVICE_CONFIGW)buffer.data();
            if (QueryServiceConfigW(hSvc, config, configNeeded, &configNeeded)) {
                if (config->dwStartType == SERVICE_DISABLED) {
                    result.serviceStateStr += " (DISABLED)";
                    result.serviceRunning = false;
                }
            }
        }
        CloseServiceHandle(hSvc);
    } else {
        result.serviceRunning = false;
        result.serviceStateStr = "ACCESS_RESTRICTED / NOT_FOUND";
    }

    CloseServiceHandle(scm);
}

void DefenderScanner::CheckDefenderRegistryPolicies(DefenderAuditResult& result,
                                                   std::vector<BypassItem>& bypassItems,
                                                   ScanStats& stats) {
    stats.totalArtifactsScanned++;

    // 1. Check Policy: DisableAntiSpyware
    HKEY hKey;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Policies\\Microsoft\\Windows Defender", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        DWORD val = 0;
        DWORD size = sizeof(DWORD);
        if (RegQueryValueExW(hKey, L"DisableAntiSpyware", NULL, NULL, (LPBYTE)&val, &size) == ERROR_SUCCESS && val == 1) {
            result.antivirusEnabled = false;
            BypassItem item;
            item.component = "Windows Defender Antivirus Policy";
            item.status = "PERMANENTLY DISABLED (DisableAntiSpyware=1)";
            item.evidence = "Group Policy has completely disabled Microsoft Defender Antivirus.";
            item.severity = Severity::CRITICAL;
            bypassItems.push_back(item);
            stats.bypassDetections++;
            stats.riskScore += 50;

            std::cout << "\033[1;31m    >> [LIVE ALERT] \033[0m\033[1;33m[ Defender Tamper ] \033[1;31mDisableAntiSpyware Policy is ACTIVE!\033[0m\n";
            Sleep(35);
        }
        RegCloseKey(hKey);
    }

    // 2. Check Policy: Real-Time Protection
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        DWORD val = 0;
        DWORD size = sizeof(DWORD);
        if (RegQueryValueExW(hKey, L"DisableRealtimeMonitoring", NULL, NULL, (LPBYTE)&val, &size) == ERROR_SUCCESS && val == 1) {
            result.realtimeProtection = false;
            BypassItem item;
            item.component = "Windows Defender Real-Time Protection Policy";
            item.status = "DISABLED (DisableRealtimeMonitoring=1)";
            item.evidence = "Real-Time Protection is forcibly disabled via Group Policy.";
            item.severity = Severity::CRITICAL;
            bypassItems.push_back(item);
            stats.bypassDetections++;
            stats.riskScore += 45;

            std::cout << "\033[1;31m    >> [LIVE ALERT] \033[0m\033[1;33m[ Defender Tamper ] \033[1;31mDisableRealtimeMonitoring Policy is ACTIVE!\033[0m\n";
            Sleep(35);
        }
        RegCloseKey(hKey);
    }

    // 3. Check Tamper Protection status
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows Defender\\Features", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        DWORD val = 0;
        DWORD size = sizeof(DWORD);
        if (RegQueryValueExW(hKey, L"TamperProtection", NULL, NULL, (LPBYTE)&val, &size) == ERROR_SUCCESS) {
            if (val == 0 || val == 4) {
                result.tamperProtection = false;
                BypassItem item;
                item.component = "Windows Defender Tamper Protection";
                item.status = "DISABLED (TamperProtection=0)";
                item.evidence = "Tamper Protection is disabled, allowing malware/cheats to alter defender registry and services.";
                item.severity = Severity::HIGH;
                bypassItems.push_back(item);
                stats.bypassDetections++;
                stats.riskScore += 30;

                std::cout << "\033[1;31m    >> [LIVE ALERT] \033[0m\033[1;33m[ Defender Tamper ] \033[1;31mTamper Protection is DISABLED!\033[0m\n";
                Sleep(35);
            }
        }
        RegCloseKey(hKey);
    }
}

void DefenderScanner::CheckDefenderPowerShellStatus(DefenderAuditResult& result, bool isAdmin) {
    // Run PowerShell one-liner to get live runtime preferences and exclusions
    std::string cmd = "powershell -NoProfile -ExecutionPolicy Bypass -Command \""
                      "$s = Get-MpComputerStatus -ErrorAction SilentlyContinue; "
                      "if ($s) { Write-Output ('STATUS_AV:' + $s.AntivirusEnabled); Write-Output ('STATUS_RTP:' + $s.RealTimeProtectionEnabled); Write-Output ('STATUS_IOAV:' + $s.IoavProtectionEnabled); } "
                      "$p = Get-MpPreference -ErrorAction SilentlyContinue; "
                      "if ($p) { "
                      "foreach ($e in $p.ExclusionPath) { Write-Output ('EXCL_PATH:' + $e); } "
                      "foreach ($pr in $p.ExclusionProcess) { Write-Output ('EXCL_PROC:' + $pr); } "
                      "foreach ($ex in $p.ExclusionExtension) { Write-Output ('EXCL_EXT:' + $ex); } "
                      "}\"";

    std::array<char, 512> buffer;
    std::string psOutput;
    FILE* pipe = _popen(cmd.c_str(), "r");
    if (!pipe) return;

    while (fgets(buffer.data(), buffer.size(), pipe) != nullptr) {
        psOutput += buffer.data();
    }
    _pclose(pipe);

    std::istringstream stream(psOutput);
    std::string line;
    while (std::getline(stream, line)) {
        // Trim line
        size_t s = line.find_first_not_of(" \t\r\n");
        if (s == std::string::npos) continue;
        size_t e = line.find_last_not_of(" \t\r\n");
        line = line.substr(s, e - s + 1);

        if (line.find("STATUS_AV:") == 0) {
            std::string val = ToLower(line.substr(10));
            result.antivirusEnabled = (val == "true");
        } else if (line.find("STATUS_RTP:") == 0) {
            std::string val = ToLower(line.substr(11));
            result.realtimeProtection = (val == "true");
        } else if (line.find("STATUS_IOAV:") == 0) {
            std::string val = ToLower(line.substr(12));
            result.ioavProtection = (val == "true");
        } else if (line.find("EXCL_PATH:") == 0) {
            std::string path = line.substr(10);
            if (!path.empty() && path.find("N/A:") == std::string::npos) {
                result.exclusionPaths.push_back(path);
            }
        } else if (line.find("EXCL_PROC:") == 0) {
            std::string proc = line.substr(10);
            if (!proc.empty() && proc.find("N/A:") == std::string::npos) {
                result.exclusionProcesses.push_back(proc);
            }
        } else if (line.find("EXCL_EXT:") == 0) {
            std::string ext = line.substr(9);
            if (!ext.empty() && ext.find("N/A:") == std::string::npos) {
                result.exclusionExtensions.push_back(ext);
            }
        }
    }
}

void DefenderScanner::CheckDefenderEventLog(DefenderAuditResult& result,
                                          std::vector<DetectionItem>& detections,
                                          std::vector<BypassItem>& bypassItems,
                                          ScanStats& stats) {
    // 1. Query Event 1116 & 1117 (Detections and Remediation/Quarantine)
    std::string cmd1 = "wevtutil qe \"Microsoft-Windows-Windows Defender/Operational\" \"/q:*[System[(EventID=1116 or EventID=1117)]]\" /c:15 /rd:true /f:text";
    FILE* pipe1 = _popen(cmd1.c_str(), "r");
    if (pipe1) {
        std::array<char, 1024> buffer;
        std::string outStr;
        while (fgets(buffer.data(), buffer.size(), pipe1) != nullptr) {
            outStr += buffer.data();
        }
        _pclose(pipe1);

        std::istringstream stream(outStr);
        std::string line;
        DefenderThreat currentThreat;
        bool inEvent = false;

        auto SaveThreat = [&]() {
            if (!currentThreat.threatName.empty() || !currentThreat.targetPath.empty()) {
                result.threatHistory.push_back(currentThreat);
                stats.totalArtifactsScanned++;

                DetectionItem item;
                item.category = "Windows Defender Threat History";
                item.target = currentThreat.targetPath.empty() ? currentThreat.threatName : currentThreat.targetPath;
                item.detail = "Defender Detection: " + currentThreat.threatName + " (" + currentThreat.action + ")";
                item.timestamp = currentThreat.timestamp;
                item.severity = Severity::CRITICAL;
                detections.push_back(item);
                stats.cheatDetections++;
                stats.riskScore += 35;

                // Live stream discovery
                std::cout << "\033[1;31m    >> [LIVE FIND] \033[0m\033[1;33m[ " << item.timestamp << " ] \033[1;37m" 
                          << currentThreat.threatName << "\033[0m \033[1;35m(Defender Quarantined Threat)\033[0m\n";
                Sleep(35);
            }
            currentThreat = DefenderThreat();
        };

        while (std::getline(stream, line)) {
            if (line.find("Event[") == 0) {
                if (inEvent) SaveThreat();
                inEvent = true;
                continue;
            }

            size_t s = line.find_first_not_of(" \t\r\n");
            if (s == std::string::npos) continue;
            std::string trimmed = line.substr(s);

            if (trimmed.find("Date: ") == 0) {
                currentThreat.timestamp = CleanIsoDate(trimmed.substr(6));
            } else if (trimmed.find("Name: ") == 0) {
                currentThreat.threatName = trimmed.substr(6);
            } else if (trimmed.find("Path: ") == 0) {
                currentThreat.targetPath = CleanPath(trimmed.substr(6));
            } else if (trimmed.find("Action: ") == 0) {
                currentThreat.action = trimmed.substr(8);
            } else if (trimmed.find("Severity: ") == 0) {
                currentThreat.severity = trimmed.substr(10);
            } else if (trimmed.find("User: ") == 0 && trimmed.find("User Name:") == std::string::npos) {
                currentThreat.user = trimmed.substr(6);
            }
        }
        if (inEvent) SaveThreat();
    }

    // 2. Query Event 5001 (Real-Time Protection Disabled)
    std::string cmd2 = "wevtutil qe \"Microsoft-Windows-Windows Defender/Operational\" \"/q:*[System[(EventID=5001)]]\" /c:10 /rd:true /f:text";
    FILE* pipe2 = _popen(cmd2.c_str(), "r");
    if (pipe2) {
        std::array<char, 1024> buffer;
        std::string outStr;
        while (fgets(buffer.data(), buffer.size(), pipe2) != nullptr) {
            outStr += buffer.data();
        }
        _pclose(pipe2);

        std::istringstream stream(outStr);
        std::string line;
        DefenderTamperEvent currentTamper;
        bool inEvent = false;

        auto SaveTamper = [&]() {
            if (!currentTamper.timestamp.empty()) {
                currentTamper.eventId = 5001;
                currentTamper.description = "Real-Time Protection was turned OFF by user/tool";
                result.tamperHistory.push_back(currentTamper);
                stats.totalArtifactsScanned++;

                BypassItem item;
                item.component = "Windows Defender Real-Time Protection";
                item.status = "EVENT 5001: RTP DISABLED";
                item.evidence = "Real-Time Protection scanning was disabled at " + currentTamper.timestamp + ". Cheaters frequently disable RTP before injecting.";
                item.severity = Severity::HIGH;
                bypassItems.push_back(item);
                stats.bypassDetections++;
                stats.riskScore += 25;

                // Live stream discovery
                std::cout << "\033[1;31m    >> [LIVE ALERT] \033[0m\033[1;33m[ " << currentTamper.timestamp 
                          << " ] \033[1;31mDefender Real-Time Protection was DISABLED (Event ID 5001)\033[0m\n";
                Sleep(35);
            }
            currentTamper = DefenderTamperEvent();
        };

        while (std::getline(stream, line)) {
            if (line.find("Event[") == 0) {
                if (inEvent) SaveTamper();
                inEvent = true;
                continue;
            }

            size_t s = line.find_first_not_of(" \t\r\n");
            if (s == std::string::npos) continue;
            std::string trimmed = line.substr(s);

            if (trimmed.find("Date: ") == 0) {
                currentTamper.timestamp = CleanIsoDate(trimmed.substr(6));
            }
        }
        if (inEvent) SaveTamper();
    }
}

DefenderAuditResult DefenderScanner::AuditDefender(std::vector<DetectionItem>& detections,
                                                 std::vector<BypassItem>& bypassItems,
                                                 ScanStats& stats,
                                                 bool isAdmin) {
    DefenderAuditResult result;

    // 1. Service check
    CheckDefenderService(result);
    if (!result.serviceRunning) {
        BypassItem item;
        item.component = "Windows Defender Service (WinDefend)";
        item.status = "SERVICE " + result.serviceStateStr;
        item.evidence = "Windows Defender antimalware core service is not running or disabled.";
        item.severity = Severity::CRITICAL;
        bypassItems.push_back(item);
        stats.bypassDetections++;
        stats.riskScore += 40;
    }

    // 2. Registry Policies check
    CheckDefenderRegistryPolicies(result, bypassItems, stats);

    // 3. PowerShell preferences & exclusions
    CheckDefenderPowerShellStatus(result, isAdmin);

    // Process exclusions against cheat signatures
    for (const auto& exclPath : result.exclusionPaths) {
        stats.totalArtifactsScanned++;
        std::string matchedKw;
        if (MatchesCheatKeyword(exclPath, matchedKw) || 
            ToLower(exclPath).find("temp") != std::string::npos ||
            ToLower(exclPath).find("desktop") != std::string::npos) {
            
            DetectionItem item;
            item.category = "Windows Defender Antivirus Exclusion";
            item.target = exclPath;
            item.detail = "Suspicious folder/file excluded from Defender scans: '" + matchedKw + "'";
            item.timestamp = "Active Exclusion";
            item.severity = Severity::CRITICAL;
            detections.push_back(item);
            stats.cheatDetections++;
            stats.riskScore += 35;

            std::cout << "\033[1;31m    >> [LIVE ALERT] \033[0m\033[1;33m[ Defender Exclusion ] \033[1;37m" 
                      << exclPath << " \033[1;31m(Excluded Cheat Path!)\033[0m\n";
            Sleep(35);
        }
    }

    // 4. Event Log check for quarantined cheats & RTP disabled events
    CheckDefenderEventLog(result, detections, bypassItems, stats);

    return result;
}
