#include "bypass.hpp"
#include <winioctl.h>
#include <winevt.h>
#include <filesystem>
#include <fstream>

namespace fs = std::filesystem;

static void RecordBypass(std::vector<BypassItem>& bypassItems, ScanStats& stats, const BypassItem& item, int scoreAdd) {
    bypassItems.push_back(item);
    stats.bypassDetections++;
    stats.riskScore += scoreAdd;
    std::cout << "\033[1;31m    >> [LIVE ALERT] \033[0m\033[1;33m[ Tamper Detected ] \033[1;37m" 
              << item.component << " \033[1;31m(" << item.status << ")\033[0m\n";
    Sleep(35);
}

void BypassDetector::CheckPrefetchTampering(int prefetchCount, std::vector<BypassItem>& bypassItems, ScanStats& stats) {
    stats.totalArtifactsScanned++;
    HKEY hKey;
    const wchar_t* regPath = L"SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Memory Management\\PrefetchParameters";
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, regPath, 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        DWORD enablePrefetcher = 3;
        DWORD size = sizeof(DWORD);
        if (RegQueryValueExW(hKey, L"EnablePrefetcher", NULL, NULL, (LPBYTE)&enablePrefetcher, &size) == ERROR_SUCCESS) {
            if (enablePrefetcher == 0) {
                BypassItem item;
                item.component = "Windows Prefetch Configuration";
                item.status = "DISABLED (ANTI-FORENSICS)";
                item.evidence = "Registry EnablePrefetcher is set to 0. Prefetch execution logging is intentionally disabled to hide run history.";
                item.severity = Severity::CRITICAL;
                RecordBypass(bypassItems, stats, item, 30);
            }
        }
        RegCloseKey(hKey);
    }

    // Check if prefetch folder was wiped recently
    if (prefetchCount >= 0 && prefetchCount < 10 && CheckIsAdmin()) {
        BypassItem item;
        item.component = "Windows Prefetch Directory";
        item.status = "SUSPICIOUSLY EMPTY / WIPED";
        item.evidence = "Prefetch folder contains only " + std::to_string(prefetchCount) + " file(s). Classic sign of prefetch wiper / batch cleaner used.";
        item.severity = Severity::HIGH;
        RecordBypass(bypassItems, stats, item, 25);
    }
}

void BypassDetector::CheckUsnJournal(std::vector<BypassItem>& bypassItems, ScanStats& stats) {
    stats.totalArtifactsScanned++;
    HANDLE hVol = CreateFileW(L"\\\\.\\C:", GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
    if (hVol == INVALID_HANDLE_VALUE) {
        // Requires Administrator
        return;
    }

    USN_JOURNAL_DATA usnData;
    DWORD bytesReturned = 0;
    if (DeviceIoControl(hVol, FSCTL_QUERY_USN_JOURNAL, NULL, 0, &usnData, sizeof(usnData), &bytesReturned, NULL)) {
        // Check if journal was wiped (e.g. NextUsn is very low or FirstUsn equals NextUsn)
        if (usnData.NextUsn < 0x100000) {
            BypassItem item;
            item.component = "NTFS USN Change Journal";
            item.status = "RECENTLY WIPED";
            item.evidence = "USN Change Journal NextUsn is abnormally low (" + std::to_string(usnData.NextUsn) + "). Journal was likely cleared via 'fsutil usn deletejournal'.";
            item.severity = Severity::HIGH;
            RecordBypass(bypassItems, stats, item, 30);
        }
    } else {
        DWORD err = GetLastError();
        if (err == ERROR_JOURNAL_NOT_ACTIVE || err == ERROR_JOURNAL_DELETE_IN_PROGRESS) {
            BypassItem item;
            item.component = "NTFS USN Change Journal";
            item.status = "DISABLED / DELETED";
            item.evidence = "USN Journal is not active on C:. File deletion tracking is destroyed (fsutil usn deletejournal).";
            item.severity = Severity::CRITICAL;
            RecordBypass(bypassItems, stats, item, 35);
        }
    }

    CloseHandle(hVol);
}

void BypassDetector::CheckEventLogClearing(std::vector<BypassItem>& bypassItems, ScanStats& stats) {
    stats.totalArtifactsScanned++;

    // Check Event ID 1102 in Security Channel (The audit log was cleared)
    EVT_HANDLE hQuerySec = EvtQuery(NULL, L"Security", L"*[System[(EventID=1102)]]", EvtQueryChannelPath | EvtQueryReverseDirection);
    if (hQuerySec) {
        EVT_HANDLE hEvent;
        DWORD returned = 0;
        if (EvtNext(hQuerySec, 1, &hEvent, 1000, 0, &returned) && returned > 0) {
            BypassItem item;
            item.component = "Windows Security Event Log";
            item.status = "CLEARED / TAMPERED (Event ID 1102)";
            item.evidence = "Audit log was intentionally cleared using wevtutil or Event Viewer to destroy evidence.";
            item.severity = Severity::CRITICAL;
            RecordBypass(bypassItems, stats, item, 40);
            EvtClose(hEvent);
        }
        EvtClose(hQuerySec);
    }

    stats.totalArtifactsScanned++;
    // Check Event ID 104 in System Channel (The log file was cleared)
    EVT_HANDLE hQuerySys = EvtQuery(NULL, L"System", L"*[System[(EventID=104)]]", EvtQueryChannelPath | EvtQueryReverseDirection);
    if (hQuerySys) {
        EVT_HANDLE hEvent;
        DWORD returned = 0;
        if (EvtNext(hQuerySys, 1, &hEvent, 1000, 0, &returned) && returned > 0) {
            BypassItem item;
            item.component = "Windows System Event Log";
            item.status = "CLEARED / TAMPERED (Event ID 104)";
            item.evidence = "System event log was cleared to hide driver loading or service tampering.";
            item.severity = Severity::CRITICAL;
            RecordBypass(bypassItems, stats, item, 35);
            EvtClose(hEvent);
        }
        EvtClose(hQuerySys);
    }
}

void BypassDetector::CheckServiceStatus(std::vector<BypassItem>& bypassItems, ScanStats& stats) {
    SC_HANDLE scm = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
    if (!scm) return;

    struct ServiceCheck {
        std::wstring serviceName;
        std::string displayName;
        bool isCritical;
    };

    std::vector<ServiceCheck> servicesToCheck = {
        { L"PcaSvc", "Program Compatibility Assistant (PcaSvc)", true },
        { L"DPS", "Diagnostic Policy Service (DPS)", false },
        { L"EventLog", "Windows Event Log (EventLog)", true }
    };

    for (const auto& svc : servicesToCheck) {
        stats.totalArtifactsScanned++;
        SC_HANDLE hSvc = OpenServiceW(scm, svc.serviceName.c_str(), SERVICE_QUERY_STATUS | SERVICE_QUERY_CONFIG);
        if (hSvc) {
            SERVICE_STATUS_PROCESS ssp;
            DWORD bytesNeeded;
            if (QueryServiceStatusEx(hSvc, SC_STATUS_PROCESS_INFO, (LPBYTE)&ssp, sizeof(ssp), &bytesNeeded)) {
                if (ssp.dwCurrentState == SERVICE_STOPPED) {
                    BypassItem item;
                    item.component = "Windows Service: " + svc.displayName;
                    item.status = "SERVICE STOPPED";
                    item.evidence = "Service is not running. Cheaters frequently stop PcaSvc/DPS to evade execution tracking.";
                    item.severity = svc.isCritical ? Severity::HIGH : Severity::MEDIUM;
                    RecordBypass(bypassItems, stats, item, svc.isCritical ? 25 : 15);
                }
            }

            DWORD configNeeded = 0;
            QueryServiceConfigW(hSvc, NULL, 0, &configNeeded);
            if (GetLastError() == ERROR_INSUFFICIENT_BUFFER) {
                std::vector<BYTE> buffer(configNeeded);
                LPQUERY_SERVICE_CONFIGW config = (LPQUERY_SERVICE_CONFIGW)buffer.data();
                if (QueryServiceConfigW(hSvc, config, configNeeded, &configNeeded)) {
                    if (config->dwStartType == SERVICE_DISABLED) {
                        BypassItem item;
                        item.component = "Windows Service: " + svc.displayName;
                        item.status = "SERVICE DISABLED";
                        item.evidence = "Service startup type is set to DISABLED to permanently avoid forensic logging.";
                        item.severity = Severity::CRITICAL;
                        RecordBypass(bypassItems, stats, item, 30);
                    }
                }
            }

            CloseServiceHandle(hSvc);
        }
    }

    CloseServiceHandle(scm);
}

void BypassDetector::CheckTestSigningAndDebugger(std::vector<BypassItem>& bypassItems, ScanStats& stats) {
    stats.totalArtifactsScanned++;
    HKEY hKey;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        wchar_t opts[1024];
        DWORD size = sizeof(opts);
        if (RegQueryValueExW(hKey, L"SystemStartOptions", NULL, NULL, (LPBYTE)opts, &size) == ERROR_SUCCESS) {
            std::string startOpts = ToLower(WideToString(std::wstring(opts)));
            if (startOpts.find("testsigning") != std::string::npos) {
                BypassItem item;
                item.component = "Driver Signature Enforcement";
                item.status = "TESTSIGNING ENABLED";
                item.evidence = "Windows is in TestSigning mode ('bcdedit /set testsigning on'). Allows loading unsigned kernel drivers / cheats.";
                item.severity = Severity::CRITICAL;
                RecordBypass(bypassItems, stats, item, 40);
            }
            if (startOpts.find("nointegritychecks") != std::string::npos) {
                BypassItem item;
                item.component = "Driver Signature Enforcement";
                item.status = "INTEGRITY CHECKS DISABLED";
                item.evidence = "'nointegritychecks' option is enabled in BCD. Signature enforcement completely bypassed.";
                item.severity = Severity::CRITICAL;
                RecordBypass(bypassItems, stats, item, 45);
            }
        }
        RegCloseKey(hKey);
    }
}

void BypassDetector::CheckVulnerableDrivers(std::vector<BypassItem>& bypassItems, ScanStats& stats) {
    const std::string driversDir = "C:\\Windows\\System32\\drivers";
    const auto& vulnDrivers = GetVulnerableDrivers();

    for (const auto& driverName : vulnDrivers) {
        stats.totalArtifactsScanned++;
        std::string fullPath = driversDir + "\\" + driverName;
        if (fs::exists(fullPath)) {
            BypassItem item;
            item.component = "Vulnerable Kernel Driver (BYOVD)";
            item.status = "DETECTED ON DISK";
            item.evidence = "Found known vulnerable driver '" + driverName + "' abused by kdmapper and cheat bypasses for read/write access to game memory.";
            item.severity = Severity::CRITICAL;
            RecordBypass(bypassItems, stats, item, 35);
        }
    }
}

void BypassDetector::CheckAntiForensicScripts(std::vector<BypassItem>& bypassItems, ScanStats& stats) {
    std::vector<std::wstring> dirsToCheck;
    wchar_t userProfile[MAX_PATH];
    if (GetEnvironmentVariableW(L"USERPROFILE", userProfile, MAX_PATH) > 0) {
        dirsToCheck.push_back(std::wstring(userProfile) + L"\\Desktop");
        dirsToCheck.push_back(std::wstring(userProfile) + L"\\Downloads");
    }

    wchar_t tempPath[MAX_PATH];
    if (GetTempPathW(MAX_PATH, tempPath) > 0) {
        dirsToCheck.push_back(std::wstring(tempPath));
    }

    for (const auto& dir : dirsToCheck) {
        try {
            if (!fs::exists(dir)) continue;

            for (const auto& entry : fs::directory_iterator(dir, fs::directory_options::skip_permission_denied)) {
                stats.totalArtifactsScanned++;
                if (!entry.is_regular_file()) continue;

                std::string ext = ToLower(entry.path().extension().string());
                if (ext == ".bat" || ext == ".cmd" || ext == ".ps1" || ext == ".vbs") {
                    std::ifstream file(entry.path(), std::ios::in | std::ios::binary);
                    if (file.is_open()) {
                        std::string content((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
                        file.close();

                        if (content.size() < 50000) { // Limit to 50KB
                            std::string lowerContent = ToLower(content);
                            std::string antiForensicKeyword = "";

                            if (lowerContent.find("fsutil usn deletejournal") != std::string::npos) antiForensicKeyword = "fsutil usn deletejournal";
                            else if (lowerContent.find("wevtutil cl") != std::string::npos) antiForensicKeyword = "wevtutil cl (clear event logs)";
                            else if (lowerContent.find("prefetch") != std::string::npos && lowerContent.find("del") != std::string::npos) antiForensicKeyword = "Prefetch wiper";
                            else if (lowerContent.find("net stop pcasvc") != std::string::npos || lowerContent.find("sc stop pcasvc") != std::string::npos) antiForensicKeyword = "Stop PcaSvc";

                            if (!antiForensicKeyword.empty()) {
                                BypassItem item;
                                item.component = "Anti-Forensics Cleaner Script";
                                item.status = "DETECTED SCRIPT FILE";
                                item.evidence = "Script '" + entry.path().filename().string() + "' contains anti-forensic wiper commands (" + antiForensicKeyword + ").";
                                item.severity = Severity::CRITICAL;
                                RecordBypass(bypassItems, stats, item, 35);
                            }
                        }
                    }
                }
            }
        } catch (...) {}
    }
}
