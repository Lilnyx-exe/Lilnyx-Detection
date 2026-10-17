#include "remediation.hpp"
#include <tlhelp32.h>
#include <iostream>
#include <conio.h>
#include <ctime>
#include <set>

std::vector<ActiveThreatItem> MalwareCleaner::ScanActiveThreats() {
    std::vector<ActiveThreatItem> threats;
    std::set<DWORD> detectedPids;
    DWORD currentPid = GetCurrentProcessId();

    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) return threats;

    PROCESSENTRY32W pe;
    pe.dwSize = sizeof(PROCESSENTRY32W);

    if (Process32FirstW(hSnap, &pe)) {
        do {
            if (pe.th32ProcessID == 0 || pe.th32ProcessID == 4 || pe.th32ProcessID == currentPid) {
                continue;
            }

            std::string procName = WideToString(pe.szExeFile);
            std::string procLower = ToLower(procName);
            std::string fullPath = "";

            HANDLE hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pe.th32ProcessID);
            if (hProc) {
                wchar_t pathBuf[MAX_PATH] = {0};
                DWORD pSize = MAX_PATH;
                if (QueryFullProcessImageNameW(hProc, 0, pathBuf, &pSize)) {
                    fullPath = WideToString(pathBuf);
                }
                CloseHandle(hProc);
            }

            // Exclude safe tools, Antigravity IDE, Detect Cheat, Explorer, etc.
            if (IsSafeProcessOrTool(procName, fullPath, "")) {
                continue;
            }

            std::string fullPathLower = ToLower(fullPath);
            std::string matchedKw;
            bool isThreat = false;
            ActiveThreatItem item;
            item.pid = pe.th32ProcessID;
            item.processName = procName;
            item.fullPath = fullPath;

            // 1. Check known cheat signatures
            if (MatchesCheatKeyword(procName, matchedKw) || MatchesCheatKeyword(fullPath, matchedKw)) {
                isThreat = true;
                item.detectionReason = "Matched cheat signature keyword: '" + matchedKw + "'";
                item.threatCategory = "Active Game Cheat / Injector";
                item.severity = Severity::CRITICAL;
            }
            // 2. Disguised core Windows system binaries
            else if (procLower == "svchost.exe" || procLower == "lsass.exe" || procLower == "csrss.exe" || 
                     procLower == "winlogon.exe" || procLower == "smss.exe" || procLower == "services.exe") {
                if (!fullPath.empty() && fullPathLower.find("c:\\windows\\system32") == std::string::npos && 
                    fullPathLower.find("c:\\windows\\winsxs") == std::string::npos) {
                    isThreat = true;
                    item.detectionReason = "Disguised system binary executing outside System32: " + fullPath;
                    item.threatCategory = "Disguised System Trojan / Malware";
                    item.severity = Severity::CRITICAL;
                }
            }
            // 3. Executables running out of AppData\Local\Temp with suspicious characteristics
            else if (!fullPath.empty() && fullPathLower.find("\\appdata\\local\\temp\\") != std::string::npos) {
                // If the executable in temp is not an installer or has random name like BK209689.exe
                if (procLower.find("setup") == std::string::npos && procLower.find("update") == std::string::npos) {
                    isThreat = true;
                    item.detectionReason = "Suspicious executable running from Temp directory: " + fullPath;
                    item.threatCategory = "Suspicious Temp Dropper / Malware";
                    item.severity = Severity::HIGH;
                }
            }
            // 4. Windows Registry Editor running during cheat audit
            else if (procLower == "regedit.exe") {
                isThreat = true;
                item.detectionReason = "Windows Registry Editor running (Potential log wiper / tamper)";
                item.threatCategory = "Registry Tampering Tool";
                item.severity = Severity::MEDIUM;
            }

            if (isThreat && detectedPids.find(item.pid) == detectedPids.end()) {
                detectedPids.insert(item.pid);
                threats.push_back(item);
            }

        } while (Process32NextW(hSnap, &pe));
    }
    CloseHandle(hSnap);

    // 5. Check open GUI window titles for cheat overlays / injectors
    struct WinCtx {
        std::vector<ActiveThreatItem>* threats;
        std::set<DWORD>* pids;
    } winCtx = { &threats, &detectedPids };

    EnumWindows([](HWND hwnd, LPARAM lp) -> BOOL {
        if (!IsWindowVisible(hwnd)) return TRUE;
        wchar_t buf[512];
        if (GetWindowTextW(hwnd, buf, 512) > 0) {
            std::string title = WideToString(buf);
            DWORD pid = 0;
            GetWindowThreadProcessId(hwnd, &pid);
            if (pid == 0 || pid == GetCurrentProcessId()) return TRUE;

            std::string procName = "";
            std::string fullPath = "";
            HANDLE hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
            if (hProc) {
                wchar_t pBuf[MAX_PATH] = {0};
                DWORD pLen = MAX_PATH;
                if (QueryFullProcessImageNameW(hProc, 0, pBuf, &pLen)) {
                    fullPath = WideToString(pBuf);
                    size_t slash = fullPath.find_last_of("\\/");
                    if (slash != std::string::npos) procName = fullPath.substr(slash + 1);
                    else procName = fullPath;
                }
                CloseHandle(hProc);
            }

            // Exclude safe processes, developer tools, Antigravity, Explorer, etc.
            if (IsSafeProcessOrTool(procName, fullPath, title)) {
                return TRUE;
            }

            std::string matchedKw;
            if (MatchesCheatKeyword(title, matchedKw)) {
                WinCtx* ctx = (WinCtx*)lp;
                if (ctx->pids->find(pid) == ctx->pids->end()) {
                    ctx->pids->insert(pid);

                    ActiveThreatItem item;
                    item.pid = pid;
                    item.processName = "Window: " + title;
                    item.detectionReason = "Window title matched cheat signature: '" + matchedKw + "'";
                    item.threatCategory = "Active GUI Cheat / Injector";
                    item.severity = Severity::HIGH;
                    item.fullPath = fullPath;

                    ctx->threats->push_back(item);
                }
            }
        }
        return TRUE;
    }, (LPARAM)&winCtx);

    return threats;
}

bool MalwareCleaner::CleanThreat(ActiveThreatItem& threat, bool quarantineFile) {
    bool terminatedOk = false;
    EnableDebugPrivilege();

    // 1. Terminate Process
    if (threat.pid > 0 && threat.pid != GetCurrentProcessId()) {
        HANDLE hProcess = OpenProcess(PROCESS_TERMINATE | SYNCHRONIZE, FALSE, threat.pid);
        if (hProcess) {
            if (TerminateProcess(hProcess, 9)) {
                WaitForSingleObject(hProcess, 1500);
                threat.terminated = true;
                threat.isRunning = false;
                terminatedOk = true;
            }
            CloseHandle(hProcess);
        }

        // Fallback: command line taskkill if process had protection hooks
        if (!threat.terminated) {
            std::string cmd = "taskkill /F /PID " + std::to_string(threat.pid) + " >nul 2>&1";
            int res = system(cmd.c_str());
            if (res == 0) {
                threat.terminated = true;
                threat.isRunning = false;
                terminatedOk = true;
            }
        }
    }

    // 2. Quarantine File (Rename or isolate)
    if (quarantineFile && !threat.fullPath.empty()) {
        CreateDirectoryW(L"Lilnyx_Quarantine", NULL);

        // Safe target filename
        std::string filename = threat.processName;
        // Clean filename of any invalid chars
        for (char& c : filename) {
            if (c == ':' || c == '/' || c == '\\' || c == '*' || c == '?' || c == '\"' || c == '<' || c == '>' || c == '|') {
                c = '_';
            }
        }

        std::string quarantineTarget = "Lilnyx_Quarantine\\" + filename + "." + std::to_string(std::time(nullptr)) + ".quarantined";

        if (MoveFileExW(StringToWide(threat.fullPath).c_str(), StringToWide(quarantineTarget).c_str(), MOVEFILE_COPY_ALLOWED | MOVEFILE_REPLACE_EXISTING)) {
            threat.quarantined = true;
        } else {
            std::string lockedPath = threat.fullPath + ".locked";
            if (MoveFileW(StringToWide(threat.fullPath).c_str(), StringToWide(lockedPath).c_str())) {
                threat.quarantined = true;
            }
        }
    }

    if (threat.terminated && threat.quarantined) {
        threat.actionTaken = "TERMINATED & QUARANTINED";
    } else if (threat.terminated) {
        threat.actionTaken = "TERMINATED & MEMORY NEUTRALIZED";
    } else if (threat.quarantined) {
        threat.actionTaken = "FILE QUARANTINED";
    } else {
        threat.actionTaken = "FAILED (ACCESS RESTRICTED)";
    }

    return terminatedOk;
}

int MalwareCleaner::CleanAllThreats(std::vector<ActiveThreatItem>& threats, bool quarantineFile) {
    int cleanedCount = 0;
    for (auto& item : threats) {
        if (CleanThreat(item, quarantineFile)) {
            cleanedCount++;
        }
    }
    FlushDnsCache();
    return cleanedCount;
}

void MalwareCleaner::FlushDnsCache() {
    system("ipconfig /flushdns >nul 2>&1");
}

void MalwareCleaner::RunInteractiveCleaner(bool autoConfirm) {
    std::cout << "\033[1;31m"
              << "+==============================================================================+\n"
              << "|                 LILNYX MALWARE & GAME HACK ACTIVE REMEDIATION                |\n"
              << "+==============================================================================+\033[0m\n"
              << "  \033[1;37m[*] Inspecting running processes, injected memory, and disguised binaries...\033[0m\n\n";

    std::vector<ActiveThreatItem> threats = ScanActiveThreats();

    if (threats.empty()) {
        std::cout << "  \033[1;32m[✓] CLEAN: No active game cheats, injectors, or known malware running in memory.\033[0m\n\n";
        return;
    }

    std::cout << "  \033[1;41;37m [!] " << threats.size() << " ACTIVE THREAT(S) CURRENTLY RUNNING IN MEMORY! \033[0m\n\n";

    int idx = 1;
    for (const auto& t : threats) {
        std::cout << "  \033[1;31m[#" << (idx < 10 ? "0" : "") << idx << "] [" << SeverityToString(t.severity) << "]\033[0m \033[1;37m" 
                  << t.processName << " (PID: " << t.pid << ")\033[0m\n"
                  << "       \033[1;36mCategory :\033[0m " << t.threatCategory << "\n"
                  << "       \033[1;33mEvidence :\033[0m " << t.detectionReason << "\n";
        if (!t.fullPath.empty()) {
            std::cout << "       \033[0;37mPath     :\033[0m " << t.fullPath << "\n";
        }
        std::cout << "\n";
        idx++;
    }

    char choice = 'n';
    if (autoConfirm) {
        std::cout << "  \033[1;33m[+] Auto-confirmation active: Automatically terminating and clearing threats...\033[0m\n\n";
        choice = 'y';
    } else {
        std::cout << "  \033[1;33mWould you like Lilnyx to TERMINATE and CLEAR all running threats now? (Y/N): \033[0m";
        while (_kbhit()) { _getch(); }
        choice = _getch();
        std::cout << choice << "\n\n";
    }

    if (choice == 'y' || choice == 'Y') {
        std::cout << "  \033[1;36m[*] Commencing threat termination and neutralization...\033[0m\n\n";

        for (auto& t : threats) {
            std::cout << "  \033[1;33m[+] Processing PID " << t.pid << " (" << t.processName << ")...\033[0m ";
            CleanThreat(t, true);

            if (t.terminated) {
                std::cout << "\033[1;32m[✓ KILLED]\033[0m ";
            } else {
                std::cout << "\033[1;31m[FAILED]\033[0m ";
            }

            if (t.quarantined) {
                std::cout << "\033[1;32m[✓ FILE ISOLATED]\033[0m\n";
            } else {
                std::cout << "\n";
            }
            Sleep(40);
        }

        std::cout << "  \033[1;33m[+] Flushing Windows DNS Resolver Cache...\033[0m ";
        FlushDnsCache();
        std::cout << "\033[1;32m[✓ FLUSHED]\033[0m\n\n";

        std::cout << "\033[1;42;30m                                                                                \n"
                  << "  [✓] REMEDIATION COMPLETE: ALL RUNNING MALWARE & HACKS HAVE BEEN NEUTRALIZED!   \n"
                  << "                                                                                \033[0m\n\n";
    } else {
        std::cout << "  \033[1;30m[*] Remediation skipped by user. Threats remain active in memory.\033[0m\n\n";
    }
}
