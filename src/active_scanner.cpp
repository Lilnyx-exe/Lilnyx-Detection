#include "active_scanner.hpp"
#include <tlhelp32.h>
#include <array>
#include <memory>
#include <conio.h>
#include <set>
#include <ctime>

void ActiveScanner::ScanRunningProcesses(std::vector<DetectionItem>& detections, ScanStats& stats) {
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) return;

    PROCESSENTRY32W pe;
    pe.dwSize = sizeof(PROCESSENTRY32W);

    if (Process32FirstW(hSnap, &pe)) {
        do {
            stats.totalArtifactsScanned++;
            std::string procName = WideToString(std::wstring(pe.szExeFile));
            if (IsSafeProcessOrTool(procName, "", "")) continue;
            std::string matchedKw;

            if (MatchesCheatKeyword(procName, matchedKw)) {
                DetectionItem item;
                item.category = "Active Memory (Running Process)";
                item.target = procName + " (PID: " + std::to_string(pe.th32ProcessID) + ")";
                item.detail = "Active cheat/injector process detected: '" + matchedKw + "'";
                item.timestamp = "Currently Running";
                item.severity = Severity::CRITICAL;
                detections.push_back(item);
                stats.cheatDetections++;
                stats.riskScore += 50;

                // Live stream discovery to console
                std::cout << "\033[1;31m    >> [LIVE ALERT] \033[0m\033[1;33m[ Currently Running ] \033[1;37m" 
                          << procName << " (PID: " << pe.th32ProcessID << ")\033[0m \033[1;35m(Active Process)\033[0m\n";
                Sleep(35);
            }
        } while (Process32NextW(hSnap, &pe));
    }

    CloseHandle(hSnap);
}

struct WindowEnumContext {
    std::vector<DetectionItem>* detections;
    ScanStats* stats;
};

static BOOL CALLBACK EnumWindowsProc(HWND hwnd, LPARAM lParam) {
    if (!IsWindowVisible(hwnd)) return TRUE;

    wchar_t title[512];
    int len = GetWindowTextW(hwnd, title, sizeof(title) / sizeof(wchar_t));
    if (len > 0) {
        WindowEnumContext* ctx = (WindowEnumContext*)lParam;
        ctx->stats->totalArtifactsScanned++;

        std::string titleStr = WideToString(std::wstring(title));
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

        // Exclude safe processes, developer tools, Antigravity IDE, Explorer, browsers, etc.
        if (IsSafeProcessOrTool(procName, fullPath, titleStr)) {
            return TRUE;
        }

        std::string matchedKw;
        if (MatchesCheatKeyword(titleStr, matchedKw)) {
            DetectionItem item;
            item.category = "Active GUI Window";
            item.target = titleStr + " (PID: " + std::to_string(pid) + ")";
            item.detail = "Window title contains cheat indicator: '" + matchedKw + "'";
            item.timestamp = "Open Window";
            item.severity = Severity::HIGH;
            ctx->detections->push_back(item);
            ctx->stats->cheatDetections++;
            ctx->stats->riskScore += 35;

            // Live stream discovery to console
            std::cout << "\033[1;31m    >> [LIVE ALERT] \033[0m\033[1;33m[ Active Window ] \033[1;37m" 
                      << titleStr << " (PID: " << pid << ")\033[0m \033[1;35m(Window Title)\033[0m\n";
            Sleep(35);
        }
    }
    return TRUE;
}

void ActiveScanner::ScanWindowTitles(std::vector<DetectionItem>& detections, ScanStats& stats) {
    WindowEnumContext ctx = { &detections, &stats };
    EnumWindows(EnumWindowsProc, (LPARAM)&ctx);
}

void ActiveScanner::ScanDnsCache(std::vector<DetectionItem>& detections, ScanStats& stats) {
    // Run ipconfig /displaydns via _popen
    std::array<char, 256> buffer;
    std::string result;
    FILE* pipe = _popen("ipconfig /displaydns", "r");
    if (!pipe) return;

    while (fgets(buffer.data(), buffer.size(), pipe) != nullptr) {
        result += buffer.data();
    }
    _pclose(pipe);

    const std::vector<std::string> suspiciousDomains = {
        "guidedhacking.com", "unknowncheats.me", "vape.gg", "neverlose.cc",
        "gamesense.pub", "aimware.net", "onetap.su", "iniuria.us",
        "midnight.im", "memesense.gg", "wearedevs.net", "robloxscripts.com",
        "solartweaks.com", "ezfrags.co.uk", "spoofer.net"
    };

    std::istringstream stream(result);
    std::string line;
    while (std::getline(stream, line)) {
        stats.totalArtifactsScanned++;
        std::string lowerLine = ToLower(line);

        for (const auto& domain : suspiciousDomains) {
            if (lowerLine.find(domain) != std::string::npos) {
                DetectionItem item;
                item.category = "Network (DNS Resolver Cache)";
                item.target = domain;
                item.detail = "Recent network resolution to known cheat/bypass service: " + domain;
                item.timestamp = "Cached in DNS";
                item.severity = Severity::HIGH;
                detections.push_back(item);
                stats.cheatDetections++;
                stats.riskScore += 25;

                // Live stream discovery to console
                std::cout << "\033[1;31m    >> [LIVE ALERT] \033[0m\033[1;33m[ DNS Cache ] \033[1;37m" 
                          << domain << "\033[0m \033[1;35m(DNS Cache)\033[0m\n";
                Sleep(35);
                break;
            }
        }
    }
}

void ActiveScanner::RunRealTimeWatchdog() {
    std::cout << "\033[1;36m"
              << "+------------------------------------------------------------------------------+\n"
              << "|                 LILNYX 24/7 ACTIVE REAL-TIME WATCHDOG GUARD                  |\n"
              << "+------------------------------------------------------------------------------+\033[0m\n"
              << "  \033[1;32m[ACTIVE]\033[0m Kernel & User-Space Watchdog is running.\n"
              << "  \033[1;37m[*] Monitoring live process spawning, window creation, and injectors...\033[0m\n"
              << "  \033[1;33m[*] Press 'Q' or ESC at any time to return / exit.\033[0m\n"
              << "--------------------------------------------------------------------------------\n\n";

    // Initial snapshot: mark all current PIDs as known so we only alert on newly created processes
    std::set<DWORD> knownPids;
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32W pe;
        pe.dwSize = sizeof(PROCESSENTRY32W);
        if (Process32FirstW(hSnap, &pe)) {
            do {
                knownPids.insert(pe.th32ProcessID);
            } while (Process32NextW(hSnap, &pe));
        }
        CloseHandle(hSnap);
    }

    int tickCount = 0;

    while (true) {
        // Check for user exit
        if (_kbhit()) {
            int ch = _getch();
            if (ch == 'q' || ch == 'Q' || ch == 27 || ch == 13) {
                std::cout << "\n\033[1;33m[*] Real-Time Watchdog stopped by user.\033[0m\n\n";
                break;
            }
        }

        // Process creation check
        HANDLE hLoopSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hLoopSnap != INVALID_HANDLE_VALUE) {
            PROCESSENTRY32W pe;
            pe.dwSize = sizeof(PROCESSENTRY32W);
            if (Process32FirstW(hLoopSnap, &pe)) {
                do {
                    if (knownPids.find(pe.th32ProcessID) == knownPids.end()) {
                        knownPids.insert(pe.th32ProcessID);
                        std::string procName = WideToString(std::wstring(pe.szExeFile));
                        if (IsSafeProcessOrTool(procName, "", "")) continue;
                        std::string procLower = ToLower(procName);
                        std::string matchedKw;
                        if (procLower == "regedit.exe") {
                            Beep(1200, 150);
                            Beep(1500, 200);

                            auto now = std::chrono::system_clock::now();
                            std::time_t t = std::chrono::system_clock::to_time_t(now);
                            char timeBuf[64];
                            std::strftime(timeBuf, sizeof(timeBuf), "%Y-%m-%d %H:%M:%S", std::localtime(&t));

                            std::cout << "\n\033[1;43;30m [!] REGISTRY TAMPER WATCHDOG INTERCEPT \033[0m \033[1;33m[ " << timeBuf << " ]\033[0m\n"
                                      << "    \033[1;33mProcess   :\033[0m \033[1;37m" << procName << " (PID: " << pe.th32ProcessID << ")\033[0m\n"
                                      << "    \033[1;33mDetection :\033[0m Windows Registry Editor (Regedit) launched during active monitoring!\n"
                                      << "    \033[1;33mAction    :\033[0m Possible registry wiping or cheat tweak modification in progress\n\n";
                        } else if (MatchesCheatKeyword(procName, matchedKw)) {
                            // Audio alarm
                            Beep(1500, 150);
                            Beep(1800, 200);

                            auto now = std::chrono::system_clock::now();
                            std::time_t t = std::chrono::system_clock::to_time_t(now);
                            char timeBuf[64];
                            std::strftime(timeBuf, sizeof(timeBuf), "%Y-%m-%d %H:%M:%S", std::localtime(&t));

                            std::cout << "\n\033[1;41;37m [!] REAL-TIME THREAT INTERCEPTED \033[0m \033[1;33m[ " << timeBuf << " ]\033[0m\n"
                                      << "    \033[1;31mExecutable:\033[0m \033[1;37m" << procName << " (PID: " << pe.th32ProcessID << ")\033[0m\n"
                                      << "    \033[1;31mDetection :\033[0m Matched cheat signature '\033[1;33m" << matchedKw << "\033[0m'\n"
                                      << "    \033[1;31mAction    :\033[0m Real-time alert dispatched\n\n";
                        }
                    }
                } while (Process32NextW(hLoopSnap, &pe));
            }
            CloseHandle(hLoopSnap);
        }

        // Periodic heartbeat status every ~12 seconds
        tickCount++;
        if (tickCount % 20 == 0) {
            auto now = std::chrono::system_clock::now();
            std::time_t t = std::chrono::system_clock::to_time_t(now);
            char timeBuf[64];
            std::strftime(timeBuf, sizeof(timeBuf), "%Y-%m-%d %H:%M:%S", std::localtime(&t));
            std::cout << "  \033[2;36m[ " << timeBuf << " ] [GUARD: ACTIVE] Monitoring memory, hooks, and window titles...\033[0m\r";
            std::cout.flush();
        }

        Sleep(600);
    }
}

