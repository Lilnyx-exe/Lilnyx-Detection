#pragma once

#include <windows.h>
#include <iostream>
#include <string>
#include <vector>
#include <algorithm>
#include <sstream>
#include <iomanip>
#include <chrono>

enum class Severity {
    INFO,
    LOW,
    MEDIUM,
    HIGH,
    CRITICAL
};

inline std::string SeverityToString(Severity s) {
    switch (s) {
        case Severity::INFO: return "INFO";
        case Severity::LOW: return "LOW";
        case Severity::MEDIUM: return "MEDIUM";
        case Severity::HIGH: return "HIGH";
        case Severity::CRITICAL: return "CRITICAL";
    }
    return "UNKNOWN";
}

struct DetectionItem {
    std::string category;
    std::string target;
    std::string detail;
    std::string timestamp;
    Severity severity;
};

struct BypassItem {
    std::string component;
    std::string status;
    std::string evidence;
    Severity severity;
};

struct ScanStats {
    int totalArtifactsScanned = 0;
    int cheatDetections = 0;
    int bypassDetections = 0;
    int suspiciousWarnings = 0;
    int riskScore = 0; // 0 - 100+
};

// Global cheat & bypass keyword database
inline const std::vector<std::string>& GetCheatKeywords() {
    static const std::vector<std::string> keywords = {
        // Injectors & Hooking
        "gh injector", "extreme injector", "xenos", "injector", "inject",
        "kiero", "minhook", "blackbone", "kdmapper", "hook.exe", "hook.dll",
        "dumper", "memorydump", "memwrite", "vmt_hook", "unhooker", "loadlib",

        // Cheat Features & Concepts
        "aimbot", "silentaim", "triggerbot", "aimlock", "aimassist",
        "wallhack", "chams", "glow_esp", "box_esp", "bone_esp", "esp.exe", "esp.dll",
        "speedhack", "nofall", "bhop", "bunnyhop", "antirecoil", "norecoil",
        "rapidfire", "flyhack", "noclip", "teleport", "spinbot", "fakelag",
        "lagswitch", "magicbullet", "fastequip", "radarhack",

        // Reverse Engineering & Memory Tampering
        "cheatengine", "cheat engine", "cheat_engine", "processhacker", "process hacker",
        "systeminformer", "x64dbg", "x32dbg", "ida64", "httpdebugger",
        "charles proxy", "fiddler", "dnspy", "scyllahide",

        // Game Clients & Public Cheats
        "vape v4", "vape lite", "vape.gg", "meteor client", "future client",
        "liquidbounce", "solartweaks", "raven b+", "raven b3", "kura", "darksiders",
        "skript", "redline", "osiris", "ezfrags", "neverlose", "onetap", "gamesense",
        "skeet", "fatality", "aimware", "iniuria", "midnight", "interwebz",
        "novoline", "drip lite", "aristois", "wurst", "inercia",

        // Spoofers & Bypass Cleaners
        "spoofer", "hwid spoofer", "hwid_spoofer", "cleaner.bat", "dps_cleaner",
        "usn_cleaner", "journal_cleaner", "prefetch_cleaner", "bypass",
        "anticheat_bypass", "ac_bypass", "driver_loader", "byovd", "log_cleaner",
        "flush_usn", "clear_eventlog", "eac_bypass", "be_bypass", "vanguard_bypass",

        // Generic & Specific Cheat Loaders
        "gamecheat", "game cheat", "gamehack", "game hack", "cheat_engine",
        "cheatengine", "cheatloader", "cheat loader", "cheat_loader", "trainer",
        "modmenu", "mod menu"
    };
    return keywords;
}

// Known vulnerable BYOVD drivers abused for kernel memory manipulation
inline const std::vector<std::string>& GetVulnerableDrivers() {
    static const std::vector<std::string> drivers = {
        "gdrv.sys",          // GIGABYTE
        "capcom.sys",        // Capcom
        "mhyprot2.sys",      // Genshin / miHoYo
        "kprocesshacker.sys",// Process Hacker
        "iqvw64e.sys",       // Intel Network Driver (used by kdmapper)
        "dbutil_2_3.sys",    // Dell
        "rtcore64.sys",      // Realtek / MSI Afterburner
        "ene.sys",           // ENE Technology
        "atsiv.sys",         // Linchpin Labs
        "asio.sys",          // ASUS
        "procexp.sys",       // Sysinternals (when abused)
        "cpuz141.sys",       // CPU-Z older vulnerable builds
        "gdrv2.sys"
    };
    return drivers;
}

// Helper: convert string to lowercase
inline std::string ToLower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) {
        return (char)std::tolower(c);
    });
    return s;
}

inline std::wstring ToLower(std::wstring s) {
    std::transform(s.begin(), s.end(), s.begin(), [](wchar_t c) {
        return (wchar_t)std::towlower(c);
    });
    return s;
}

// Helper: wide string to UTF-8 string
inline std::string WideToString(const std::wstring& wstr) {
    if (wstr.empty()) return std::string();
    int sizeNeeded = WideCharToMultiByte(CP_UTF8, 0, wstr.data(), (int)wstr.size(), NULL, 0, NULL, NULL);
    std::string strTo(sizeNeeded, 0);
    WideCharToMultiByte(CP_UTF8, 0, wstr.data(), (int)wstr.size(), &strTo[0], sizeNeeded, NULL, NULL);
    return strTo;
}

// Helper: UTF-8 string to wide string
inline std::wstring StringToWide(const std::string& str) {
    if (str.empty()) return std::wstring();
    int sizeNeeded = MultiByteToWideChar(CP_UTF8, 0, str.data(), (int)str.size(), NULL, 0);
    std::wstring wstrTo(sizeNeeded, 0);
    MultiByteToWideChar(CP_UTF8, 0, str.data(), (int)str.size(), &wstrTo[0], sizeNeeded);
    return wstrTo;
}

// Helper: Convert FILETIME to readable string with year validation
inline std::string FileTimeToDateTimeString(const FILETIME& ft) {
    if (ft.dwLowDateTime == 0 && ft.dwHighDateTime == 0) return "N/A";
    
    SYSTEMTIME stUTC, stLocal;
    if (!FileTimeToSystemTime(&ft, &stUTC)) return "N/A";
    if (!SystemTimeToTzSpecificLocalTime(NULL, &stUTC, &stLocal)) return "N/A";
    if (stLocal.wYear < 2012 || stLocal.wYear > 2035) return "N/A";

    char buf[64];
    snprintf(buf, sizeof(buf), "%04d-%02d-%02d %02d:%02d:%02d",
        stLocal.wYear, stLocal.wMonth, stLocal.wDay,
        stLocal.wHour, stLocal.wMinute, stLocal.wSecond);
    return std::string(buf);
}

// Helper: Scan binary buffer for valid FILETIME across all 4-byte boundaries
inline std::string ExtractFileTimeFromBuffer(const BYTE* data, DWORD size) {
    if (!data || size < 8) return "";
    for (DWORD offset = 0; offset + 8 <= size; offset += 4) {
        FILETIME ft;
        memcpy(&ft, data + offset, sizeof(FILETIME));
        std::string res = FileTimeToDateTimeString(ft);
        if (res != "N/A" && !res.empty()) {
            return res;
        }
    }
    return "";
}

// Helper: ROT13 for UserAssist
inline std::wstring Rot13(const std::wstring& input) {
    std::wstring result = input;
    for (wchar_t& c : result) {
        if (c >= L'a' && c <= L'z') {
            c = L'a' + (c - L'a' + 13) % 26;
        } else if (c >= L'A' && c <= L'Z') {
            c = L'A' + (c - L'A' + 13) % 26;
        }
    }
    return result;
}

// Whitelist helper to protect critical Windows services, Developer IDEs, and Browsers
inline bool IsSafeProcessOrTool(const std::string& procName, const std::string& fullPath, const std::string& windowTitle = "") {
    std::string pName = ToLower(procName);
    std::string path = ToLower(fullPath);
    std::string title = ToLower(windowTitle);

    // 1. Antigravity IDE and Detect Cheat application
    if (pName.find("antigravity") != std::string::npos || path.find("antigravity") != std::string::npos || title.find("antigravity") != std::string::npos) {
        return true;
    }
    if (pName.find("detectcheat") != std::string::npos || path.find("detect cheat") != std::string::npos || title.find("detect cheat") != std::string::npos) {
        return true;
    }

    // 2. Developer IDEs & Editors
    static const std::vector<std::string> safeDevExes = {
        "code.exe", "devenv.exe", "visualstudio.exe", "clion64.exe",
        "idea64.exe", "pycharm64.exe", "sublime_text.exe", "notepad++.exe",
        "notepad.exe", "g++.exe", "gcc.exe", "make.exe", "git.exe"
    };
    for (const auto& dev : safeDevExes) {
        if (pName == dev) return true;
    }

    // 3. Web Browsers (titles frequently contain open search tabs)
    static const std::vector<std::string> safeBrowsers = {
        "chrome.exe", "msedge.exe", "firefox.exe", "brave.exe", "opera.exe", "vivaldi.exe"
    };
    for (const auto& b : safeBrowsers) {
        if (pName == b) return true;
    }

    // 4. Windows Core Shell & Explorer
    if (pName == "explorer.exe" || pName == "taskmgr.exe" || pName == "cmd.exe" || 
        pName == "powershell.exe" || pName == "conhost.exe" || pName == "dwm.exe" ||
        pName == "runtimebroker.exe" || pName == "searchhost.exe") {
        return true;
    }

    return false;
}

// Helper: check if a text contains any cheat keyword
inline bool MatchesCheatKeyword(const std::string& text, std::string& matchedKeyword) {
    std::string lowerText = ToLower(text);

    // Explicitly exclude self-application and IDE project folder
    if (lowerText.find("detect cheat") != std::string::npos ||
        lowerText.find("detectcheat") != std::string::npos ||
        lowerText.find("antigravity") != std::string::npos) {
        return false;
    }

    for (const auto& kw : GetCheatKeywords()) {
        if (lowerText.find(kw) != std::string::npos) {
            matchedKeyword = kw;
            return true;
        }
    }
    return false;
}

// Helper: enable SeDebugPrivilege for terminating guarded processes
inline bool EnableDebugPrivilege() {
    HANDLE hToken;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        return false;
    }
    LUID luid;
    if (!LookupPrivilegeValueW(NULL, L"SeDebugPrivilege", &luid)) {
        CloseHandle(hToken);
        return false;
    }
    TOKEN_PRIVILEGES tp;
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    BOOL ok = AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL);
    CloseHandle(hToken);
    return ok && (GetLastError() == ERROR_SUCCESS);
}

// Helper: check if running as Administrator
inline bool CheckIsAdmin() {
    BOOL isAdmin = FALSE;
    PSID adminGroup = NULL;
    SID_IDENTIFIER_AUTHORITY ntAuthority = SECURITY_NT_AUTHORITY;
    if (AllocateAndInitializeSid(&ntAuthority, 2,
        SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS,
        0, 0, 0, 0, 0, 0, &adminGroup)) {
        CheckTokenMembership(NULL, adminGroup, &isAdmin);
        FreeSid(adminGroup);
    }
    return isAdmin == TRUE;
}

// Helper: Relaunch application with UAC runas elevation
inline bool RelaunchAsAdmin(int argc, char* argv[]) {
    wchar_t szPath[MAX_PATH];
    if (GetModuleFileNameW(NULL, szPath, ARRAYSIZE(szPath))) {
        std::wstring args = L"";
        for (int i = 1; i < argc; ++i) {
            args += StringToWide(argv[i]) + L" ";
        }
        HINSTANCE hInst = ShellExecuteW(NULL, L"runas", szPath, args.c_str(), NULL, SW_SHOWNORMAL);
        return (INT_PTR)hInst > 32;
    }
    return false;
}
