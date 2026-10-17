#include "report.hpp"
#include <fstream>
#include <ctime>
#include <shellapi.h>

std::string ReportGenerator::GetCurrentTimestamp() {
    auto now = std::chrono::system_clock::now();
    std::time_t now_time = std::chrono::system_clock::to_time_t(now);
    char buf[64];
    std::strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", std::localtime(&now_time));
    return std::string(buf);
}

std::string ReportGenerator::GetSystemInfoString() {
    char compName[MAX_COMPUTERNAME_LENGTH + 1];
    DWORD compSize = sizeof(compName);
    GetComputerNameA(compName, &compSize);

    char userName[256];
    DWORD userSize = sizeof(userName);
    GetUserNameA(userName, &userSize);

    return std::string(compName) + " | User: " + std::string(userName);
}

void ReportGenerator::OpenInBrowser(const std::string& filePath) {
    ShellExecuteA(NULL, "open", filePath.c_str(), NULL, NULL, SW_SHOWNORMAL);
}

void ReportGenerator::PrintConsoleSummary(const std::vector<DetectionItem>& detections,
                                         const std::vector<BypassItem>& bypassItems,
                                         const DefenderAuditResult& defenderResult,
                                         const RegAuditResult& regResult,
                                         const ScanStats& stats,
                                         bool isAdmin,
                                         int auditMode) {
    // Enable ANSI Virtual Terminal Processing for colors
    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD dwMode = 0;
    if (GetConsoleMode(hOut, &dwMode)) {
        dwMode |= ENABLE_VIRTUAL_TERMINAL_PROCESSING;
        SetConsoleMode(hOut, dwMode);
    }

    std::string bannerTitle = "LILNYX FORENSIC AUDIT // FULL SYSTEM AUDIT SUMMARY";
    if (auditMode == 2) bannerTitle = "LILNYX FORENSIC AUDIT // GAME CHEATS AUDIT SUMMARY";
    else if (auditMode == 3) bannerTitle = "LILNYX FORENSIC AUDIT // BYPASS & TAMPER AUDIT SUMMARY";
    else if (auditMode == 4) bannerTitle = "LILNYX FORENSIC AUDIT // WINDOWS DEFENDER AUDIT SUMMARY";
    else if (auditMode == 5) bannerTitle = "LILNYX FORENSIC AUDIT // REGISTRY & REGEDIT AUDIT SUMMARY";

    std::cout << "\n\033[1;36m"
              << "+==============================================================================+\n"
              << "| " << std::left << std::setw(76) << bannerTitle << " |\n"
              << "+==============================================================================+\033[0m\n\n";

    std::cout << "  \033[1;37mSystem Host:\033[0m      " << GetSystemInfoString() << "\n";
    std::cout << "  \033[1;37mScan Timestamp:\033[0m   \033[1;33m" << GetCurrentTimestamp() << "\033[0m\n";
    std::cout << "  \033[1;37mPrivilege Level:\033[0m  " << (isAdmin ? "\033[1;32mAdministrator (Deep Forensics Unlocked)\033[0m" : "\033[1;33mStandard User (Prefetch/EventLog/BAM limited)\033[0m") << "\n";
    std::cout << "  \033[1;37mArtifacts Tested:\033[0m " << stats.totalArtifactsScanned << " scanned\n";
    if (auditMode == 1 || auditMode == 2) {
        std::cout << "  \033[1;37mCheat Detections:\033[0m " << (stats.cheatDetections > 0 ? "\033[1;31m" : "\033[1;32m") << stats.cheatDetections << " found\033[0m\n";
    }
    if (auditMode == 1 || auditMode == 3) {
        std::cout << "  \033[1;37mBypass / Tamper:\033[0m  " << (stats.bypassDetections > 0 ? "\033[1;31m" : "\033[1;32m") << stats.bypassDetections << " found\033[0m\n";
    }
    std::cout << "  \033[1;37mForensic Risk:\033[0m    " << (stats.riskScore >= 40 ? "\033[1;31m" : (stats.riskScore > 0 ? "\033[1;33m" : "\033[1;32m")) << stats.riskScore << " / 100\033[0m\n\n";

    // Verdict Banner
    if (stats.cheatDetections > 0 || stats.bypassDetections > 0 || stats.riskScore >= 40) {
        std::cout << "\033[1;41;37m                                                                                \n"
                  << "  [!] POSITIVE VERDICT: ACTIVE / HISTORICAL GAME CHEATS & BYPASS DETECTED!      \n"
                  << "                                                                                \033[0m\n\n";
    } else if (stats.suspiciousWarnings > 0 || stats.riskScore > 10) {
        std::cout << "\033[1;43;30m                                                                                \n"
                  << "  [?] VERDICT: SUSPICIOUS - POTENTIAL BYPASS OR ABNORMAL ARTIFACTS FOUND        \n"
                  << "                                                                                \033[0m\n\n";
    } else {
        std::cout << "\033[1;42;30m                                                                                \n"
                  << "  [✓] CLEAN VERDICT: NO ACTIVE CHEATS OR KNOWN TAMPERING ARTIFACTS FOUND       \n"
                  << "                                                                                \033[0m\n\n";
    }

    // -------------------------------------------------------------------------
    // CATEGORY 1: GAME CHEATS (Modes 1 and 2)
    // -------------------------------------------------------------------------
    if (auditMode == 1 || auditMode == 2) {
        if (!detections.empty()) {
            std::cout << "\033[1;31m+==============================================================================+\n"
                      << "|   [CATEGORY 1] HISTORICAL CHEATS // EXECUTION TIMELINE & ARTIFACTS (" << std::setw(2) << detections.size() << ")     |\n"
                      << "+==============================================================================+\033[0m\n\n";

            int cIdx = 1;
            for (const auto& item : detections) {
                std::string timeDisplay = item.timestamp;
                if (timeDisplay.empty()) timeDisplay = "Historical Record";

                std::cout << "  \033[1;31m+----------------------------------------------------------------------------\033[0m\n"
                          << "  \033[1;31m|\033[0m \033[1;31m[#" << (cIdx < 10 ? "0" : "") << cIdx << "] [" 
                          << SeverityToString(item.severity) << "]\033[0m  "
                          << "\033[1;43;30m 🕒 TIME: " << timeDisplay << " \033[0m\n"
                          << "  \033[1;31m|\033[0m  \033[1;36mTarget   :\033[0m \033[1;37m" << item.target << "\033[0m\n"
                          << "  \033[1;31m|\033[0m  \033[1;36mArtifact :\033[0m \033[0;37m" << item.category << "\033[0m\n"
                          << "  \033[1;31m|\033[0m  \033[1;36mEvidence :\033[0m \033[1;33m" << item.detail << "\033[0m\n"
                          << "  \033[1;31m|\033[0m  \033[1;36mStatus   :\033[0m \033[1;32mEXECUTED CHEAT ARTIFACT CONFIRMED\033[0m\n"
                          << "  \033[1;31m+----------------------------------------------------------------------------\033[0m\n\n";

                cIdx++;
                Sleep(50);
            }
        } else if (auditMode == 2) {
            std::cout << "  \033[1;32m[✓] No game cheat executions or residual artifacts found in inspected areas.\033[0m\n\n";
        }
    }

    // -------------------------------------------------------------------------
    // CATEGORY 2: ANTI-FORENSICS & SYSTEM TAMPERING (Modes 1 and 3)
    // -------------------------------------------------------------------------
    if (auditMode == 1 || auditMode == 3) {
        if (!bypassItems.empty()) {
            std::cout << "\033[1;35m+==============================================================================+\n"
                      << "|   [CATEGORY 2] ANTI-FORENSICS & SYSTEM TAMPERING AUDIT (" << std::setw(2) << bypassItems.size() << ")                 |\n"
                      << "+==============================================================================+\033[0m\n\n";
            
            int bIdx = 1;
            for (const auto& item : bypassItems) {
                std::cout << "  \033[1;31m[#" << (bIdx < 10 ? "0" : "") << bIdx << "] [" << SeverityToString(item.severity) << "]\033[0m \033[1;37m" << item.component << "\033[0m\n"
                          << "       \033[1;33mStatus   :\033[0m " << item.status << "\n"
                          << "       \033[1;30mEvidence :\033[0m \033[0;37m" << item.evidence << "\033[0m\n\n";
                bIdx++;
                Sleep(40);
            }
        } else if (auditMode == 3) {
            std::cout << "  \033[1;32m[✓] No anti-forensic tampering, service stops, or log wipers detected.\033[0m\n\n";
        }
    }

    // -------------------------------------------------------------------------
    // CATEGORY 3: WINDOWS DEFENDER (Modes 1 and 4)
    // -------------------------------------------------------------------------
    if (auditMode == 1 || auditMode == 4) {
        std::cout << "\033[1;34m+==============================================================================+\n"
                  << "|   [CATEGORY 3] WINDOWS DEFENDER & SECURITY SUBSYSTEM FORENSICS AUDIT         |\n"
                  << "+==============================================================================+\033[0m\n\n";

        std::cout << "  \033[1;37mReal-Time Protection :\033[0m " 
                  << (defenderResult.realtimeProtection ? "\033[1;32m[ ENABLED & MONITORING ]\033[0m" : "\033[1;41;37m [ DISABLED / TAMPERED ] \033[0m") << "\n";
        std::cout << "  \033[1;37mAntivirus Core Engine:\033[0m " 
                  << (defenderResult.antivirusEnabled ? "\033[1;32m[ OPERATIONAL ]\033[0m" : "\033[1;41;37m [ BLOCKED BY POLICY ] \033[0m") 
                  << " (" << defenderResult.serviceStateStr << ")\n";
        std::cout << "  \033[1;37mTamper Protection    :\033[0m " 
                  << (defenderResult.tamperProtection ? "\033[1;32m[ ACTIVE ]\033[0m" : "\033[1;31m[ DISABLED ]\033[0m") << "\n";
        std::cout << "  \033[1;37mIOAV / Cloud Shield  :\033[0m " 
                  << (defenderResult.ioavProtection ? "\033[1;32m[ ACTIVE ]\033[0m" : "\033[1;33m[ INACTIVE ]\033[0m") << "\n\n";

        // Defender Exclusions
        std::cout << "  \033[1;36m--- [ DEFENDER EXCLUSION AUDIT (CHEAT EVASION) ] ---\033[0m\n";
        if (defenderResult.exclusionPaths.empty() && defenderResult.exclusionProcesses.empty() && defenderResult.exclusionExtensions.empty()) {
            std::cout << "    \033[0;37mNo active file/process exclusions registered.\033[0m\n";
        } else {
            for (const auto& ep : defenderResult.exclusionPaths) {
                std::cout << "    \033[1;31m[EXCLUDED PATH]    \033[1;37m" << ep << "\033[0m\n";
            }
            for (const auto& epr : defenderResult.exclusionProcesses) {
                std::cout << "    \033[1;31m[EXCLUDED PROCESS] \033[1;37m" << epr << "\033[0m\n";
            }
            for (const auto& ex : defenderResult.exclusionExtensions) {
                std::cout << "    \033[1;31m[EXCLUDED EXT]     \033[1;37m" << ex << "\033[0m\n";
            }
        }
        std::cout << "\n";

        // Defender Quarantined / Detected Threats
        if (!defenderResult.threatHistory.empty()) {
            std::cout << "  \033[1;31m--- [ DEFENDER DETECTED / QUARANTINED CHEATS & THREATS (" << defenderResult.threatHistory.size() << ") ] ---\033[0m\n";
            int tIdx = 1;
            for (const auto& t : defenderResult.threatHistory) {
                std::cout << "    \033[1;31m[#" << (tIdx < 10 ? "0" : "") << tIdx << "] \033[1;43;30m 🕒 TIME: " << t.timestamp << " \033[0m\n"
                          << "         \033[1;33mThreat:\033[0m " << t.threatName << "\n"
                          << "         \033[1;37mTarget:\033[0m " << t.targetPath << "\n"
                          << "         \033[1;32mAction:\033[0m " << t.action << "\n\n";
                tIdx++;
                Sleep(35);
            }
        }

        // Defender Real-Time Protection Kill Events (Event 5001)
        if (!defenderResult.tamperHistory.empty()) {
            std::cout << "  \033[1;33m--- [ DEFENDER REAL-TIME PROTECTION KILL EVENTS (EVENT ID 5001) (" << defenderResult.tamperHistory.size() << ") ] ---\033[0m\n";
            int kIdx = 1;
            for (const auto& ev : defenderResult.tamperHistory) {
                std::cout << "    \033[1;33m[#" << (kIdx < 10 ? "0" : "") << kIdx << "] \033[1;33m🕒 " << ev.timestamp 
                          << "\033[0m \033[1;31m| REAL-TIME PROTECTION WAS FORCIBLY DISABLED\033[0m\n";
                kIdx++;
                Sleep(25);
            }
            std::cout << "\n";
        }
    }

    // -------------------------------------------------------------------------
    // CATEGORY 4: WINDOWS REGISTRY & REGEDIT FORENSICS (Modes 1 and 5)
    // -------------------------------------------------------------------------
    if (auditMode == 1 || auditMode == 5) {
        std::cout << "\033[1;35m+==============================================================================+\n"
                  << "|   [CATEGORY 4] WINDOWS REGISTRY & REGEDIT FORENSICS AUDIT                     |\n"
                  << "+==============================================================================+\033[0m\n\n";

        std::cout << "  Regedit Live Active   : " << (regResult.regeditCurrentlyRunning ? "\033[1;41;37m [ ACTIVE / RUNNING! POSSIBLE TAMPERING ] \033[0m" : "\033[1;32m[ NOT RUNNING ]\033[0m") << "\n";
        
        if (!regResult.regeditLastKey.empty()) {
            std::cout << "  Regedit LastKey Target: " << (regResult.lastKeySuspicious ? "\033[1;31m" : "\033[1;37m") << regResult.regeditLastKey << "\033[0m\n";
            if (regResult.lastKeySuspicious) {
                std::cout << "  LastKey Suspicion     : \033[1;33m" << regResult.lastKeySuspicionReason << "\033[0m\n";
            }
        }
        std::cout << "\n";

        if (!regResult.regeditExecutionHistory.empty()) {
            std::cout << "  --- [ REGEDIT HISTORICAL EXECUTIONS (" << regResult.regeditExecutionHistory.size() << ") ] ---\n";
            for (const auto& ts : regResult.regeditExecutionHistory) {
                std::cout << "    🕒 " << ts << " | Windows Registry Editor executed\n";
            }
            std::cout << "\n";
        }

        if (!regResult.appInitDlls.empty()) {
            std::cout << "  \033[1;31m--- [ APPINIT_DLLS GLOBAL INJECTION HOOKS (" << regResult.appInitDlls.size() << ") ] ---\033[0m\n";
            for (const auto& dll : regResult.appInitDlls) {
                std::cout << "    \033[1;31m[!] DLL: " << dll << " (Injected into every process)\033[0m\n";
            }
            std::cout << "\n";
        }

        if (!regResult.ifeoHijacks.empty()) {
            std::cout << "  \033[1;31m--- [ IFEO DEBUGGER BINARY HIJACKS (" << regResult.ifeoHijacks.size() << ") ] ---\033[0m\n";
            for (const auto& ifeo : regResult.ifeoHijacks) {
                std::cout << "    \033[1;31m[!] " << ifeo << "\033[0m\n";
            }
            std::cout << "\n";
        }

        if (!regResult.appCompatLayers.empty()) {
            std::cout << "  \033[1;33m--- [ REGISTRY APPCOMPAT FLAGS ON CHEATS (" << regResult.appCompatLayers.size() << ") ] ---\033[0m\n";
            for (const auto& layer : regResult.appCompatLayers) {
                std::cout << "    \033[1;33m[*] " << layer << "\033[0m\n";
            }
            std::cout << "\n";
        }

        if (!regResult.openSaveCheats.empty()) {
            std::cout << "  \033[1;33m--- [ EXPLORER OPENSAVE DIALOG CHEAT TRACES (" << regResult.openSaveCheats.size() << ") ] ---\033[0m\n";
            for (const auto& mru : regResult.openSaveCheats) {
                std::cout << "    \033[1;33m[*] " << mru << "\033[0m\n";
            }
            std::cout << "\n";
        }

        if (!regResult.searchQueries.empty()) {
            std::cout << "  \033[1;33m--- [ EXPLORER CHEAT SEARCH QUERIES (" << regResult.searchQueries.size() << ") ] ---\033[0m\n";
            for (const auto& q : regResult.searchQueries) {
                std::cout << "    \033[1;33m[*] Search: \"" << q << "\"\033[0m\n";
            }
            std::cout << "\n";
        }

        if (!regResult.detectedTweaks.empty()) {
            std::cout << "  \033[1;36m--- [ GAMING & NETWORK REGISTRY TWEAKS (" << regResult.detectedTweaks.size() << ") ] ---\033[0m\n";
            for (const auto& twk : regResult.detectedTweaks) {
                std::cout << "    [*] \033[1;37m" << twk.valueName << "\033[0m: " << twk.currentValue 
                          << " (Normal: " << twk.expectedOrNormal << ")\n"
                          << "        \033[0;37m" << twk.description << "\033[0m\n";
            }
            std::cout << "\n";
        }

        if (regResult.appInitDlls.empty() && regResult.ifeoHijacks.empty() && 
            regResult.appCompatLayers.empty() && regResult.openSaveCheats.empty() && 
            regResult.searchQueries.empty() && !regResult.lastKeySuspicious && !regResult.regeditCurrentlyRunning) {
            std::cout << "  \033[1;32m[✓] No malicious registry injection, IFEO hijacks, or cheat layers detected.\033[0m\n\n";
        }
    }
}

std::string ReportGenerator::GenerateTextReport(const std::vector<DetectionItem>& detections,
                                               const std::vector<BypassItem>& bypassItems,
                                               const DefenderAuditResult& defenderResult,
                                               const RegAuditResult& regResult,
                                               const ScanStats& stats,
                                               bool isAdmin) {
    std::string filename = "Lilnyx_Report_" + std::to_string(std::time(nullptr)) + ".txt";
    std::ofstream out(filename);
    if (!out.is_open()) return "";

    out << "======================================================================\n";
    out << "        LILNYX DETECTION // GAME CHEAT & BYPASS FORENSIC REPORT       \n";
    out << "======================================================================\n\n";

    out << "System:          " << GetSystemInfoString() << "\n";
    out << "Scan Timestamp:  " << GetCurrentTimestamp() << "\n";
    out << "Privilege:       " << (isAdmin ? "Administrator (Full Deep Forensics)" : "Standard User") << "\n";
    out << "Artifacts Tested:" << stats.totalArtifactsScanned << "\n";
    out << "Cheat Finds:     " << stats.cheatDetections << "\n";
    out << "Bypass Finds:    " << stats.bypassDetections << "\n";
    out << "Risk Score:      " << stats.riskScore << " / 100\n\n";

    if (stats.cheatDetections > 0 || stats.bypassDetections > 0 || stats.riskScore >= 40) {
        out << "VERDICT: POSITIVE - GAME CHEAT / BYPASS ARTIFACTS DETECTED\n\n";
    } else if (stats.suspiciousWarnings > 0 || stats.riskScore > 10) {
        out << "VERDICT: SUSPICIOUS - ANOMALIES FOUND\n\n";
    } else {
        out << "VERDICT: CLEAN - NO KNOWN CHEATS OR BYPASS ARTIFACTS FOUND\n\n";
    }

    out << "=== [ WINDOWS DEFENDER & SECURITY SUBSYSTEM AUDIT ] ===\n";
    out << "Real-Time Protection: " << (defenderResult.realtimeProtection ? "ENABLED" : "DISABLED / TAMPERED") << "\n";
    out << "Antivirus Core:       " << (defenderResult.antivirusEnabled ? "OPERATIONAL" : "BLOCKED BY POLICY") << " (" << defenderResult.serviceStateStr << ")\n";
    out << "Tamper Protection:    " << (defenderResult.tamperProtection ? "ACTIVE" : "DISABLED") << "\n";
    out << "IOAV Protection:      " << (defenderResult.ioavProtection ? "ACTIVE" : "INACTIVE") << "\n\n";

    if (!defenderResult.exclusionPaths.empty() || !defenderResult.exclusionProcesses.empty()) {
        out << "Defender Exclusions:\n";
        for (const auto& ep : defenderResult.exclusionPaths) out << "  - Path:    " << ep << "\n";
        for (const auto& epr : defenderResult.exclusionProcesses) out << "  - Process: " << epr << "\n";
        out << "\n";
    }

    if (!defenderResult.threatHistory.empty()) {
        out << "Defender Quarantined & Detected Threats (" << defenderResult.threatHistory.size() << "):\n";
        for (const auto& t : defenderResult.threatHistory) {
            out << "  - [" << t.timestamp << "] " << t.threatName << " | Action: " << t.action << "\n"
                << "    Target: " << t.targetPath << "\n";
        }
        out << "\n";
    }

    if (!defenderResult.tamperHistory.empty()) {
        out << "Defender Real-Time Protection Kill History (" << defenderResult.tamperHistory.size() << "):\n";
        for (const auto& ev : defenderResult.tamperHistory) {
            out << "  - [" << ev.timestamp << "] Real-Time Protection Disabled\n";
        }
        out << "\n";
    }

    out << "=== [ WINDOWS REGISTRY & REGEDIT FORENSICS ] ===\n";
    out << "Regedit Active Status: " << (regResult.regeditCurrentlyRunning ? "RUNNING (ACTIVE)" : "NOT RUNNING") << "\n";
    if (!regResult.regeditLastKey.empty()) {
        out << "Regedit LastKey:       " << regResult.regeditLastKey << "\n";
        if (regResult.lastKeySuspicious) {
            out << "LastKey Suspicion:     " << regResult.lastKeySuspicionReason << "\n";
        }
    }
    if (!regResult.appInitDlls.empty()) {
        out << "AppInit_DLLs:          " << regResult.appInitDlls.size() << " hook(s)\n";
        for (const auto& dll : regResult.appInitDlls) out << "  - " << dll << "\n";
    }
    if (!regResult.ifeoHijacks.empty()) {
        out << "IFEO Hijacks:          " << regResult.ifeoHijacks.size() << "\n";
        for (const auto& ifeo : regResult.ifeoHijacks) out << "  - " << ifeo << "\n";
    }
    if (!regResult.detectedTweaks.empty()) {
        out << "Gaming Tweaks:         " << regResult.detectedTweaks.size() << "\n";
        for (const auto& twk : regResult.detectedTweaks) out << "  - " << twk.valueName << ": " << twk.currentValue << " (" << twk.description << ")\n";
    }
    out << "\n";

    if (!bypassItems.empty()) {
        out << "=== [ ANTI-FORENSICS & BYPASS DETECTIONS ] ===\n";
        for (const auto& item : bypassItems) {
            out << "[" << SeverityToString(item.severity) << "] " << item.component << "\n";
            out << "  Status:   " << item.status << "\n";
            out << "  Evidence: " << item.evidence << "\n\n";
        }
    }

    if (!detections.empty()) {
        out << "=== [ CHEAT EXECUTION & FILE DETECTIONS ] ===\n";
        for (const auto& item : detections) {
            out << "[" << SeverityToString(item.severity) << "] " << item.category << "\n";
            out << "  Target:    " << item.target << "\n";
            out << "  Detail:    " << item.detail << "\n";
            out << "  Timestamp: " << item.timestamp << "\n\n";
        }
    }

    out.close();
    return filename;
}

std::string ReportGenerator::GenerateHtmlReport(const std::vector<DetectionItem>& detections,
                                               const std::vector<BypassItem>& bypassItems,
                                               const DefenderAuditResult& defenderResult,
                                               const RegAuditResult& regResult,
                                               const ScanStats& stats,
                                               bool isAdmin) {
    std::string filename = "Lilnyx_Report_" + std::to_string(std::time(nullptr)) + ".html";
    std::ofstream out(filename);
    if (!out.is_open()) return "";

    std::string verdictTitle = "SYSTEM VERDICT: CLEAN";
    std::string verdictColor = "#10b981"; // emerald-500
    std::string verdictDesc = "No active cheat processes, execution artifacts, or known anti-forensic bypasses were detected during this audit.";
    std::string badgeClass = "badge-clean";

    if (stats.cheatDetections > 0 || stats.bypassDetections > 0 || stats.riskScore >= 40) {
        verdictTitle = "SYSTEM VERDICT: POSITIVE / CHEATER DETECTED";
        verdictColor = "#ef4444"; // red-500
        verdictDesc = "Forensic evidence confirms the previous execution of game cheats, memory injectors, or intentional tampering with Windows logging/forensics.";
        badgeClass = "badge-danger";
    } else if (stats.suspiciousWarnings > 0 || stats.riskScore > 10) {
        verdictTitle = "SYSTEM VERDICT: SUSPICIOUS ACTIVITY";
        verdictColor = "#f59e0b"; // amber-500
        verdictDesc = "Anomalies, stopped diagnostic services, or suspicious temporary files were detected. Further manual inspection is advised.";
        badgeClass = "badge-warning";
    }

    out << R"RAWHTML(<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Lilnyx Detection - Forensic Anti-Cheat Report</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;500;600;700;800&family=JetBrains+Mono:wght@400;500;700&display=swap" rel="stylesheet">
    <style>
        :root {
            --bg-base: #090d16;
            --bg-card: rgba(18, 24, 38, 0.75);
            --bg-card-hover: rgba(26, 35, 54, 0.9);
            --border-glow: rgba(56, 189, 248, 0.2);
            --border-subtle: rgba(255, 255, 255, 0.08);
            --text-main: #f1f5f9;
            --text-muted: #94a3b8;
            --accent-cyan: #38bdf8;
            --accent-red: #ef4444;
            --accent-emerald: #10b981;
            --accent-amber: #f59e0b;
        }

        * {
            box-sizing: border-box;
            margin: 0;
            padding: 0;
        }

        body {
            font-family: 'Outfit', -apple-system, BlinkMacSystemFont, sans-serif;
            background-color: var(--bg-base);
            color: var(--text-main);
            line-height: 1.6;
            padding: 30px 20px;
            min-height: 100vh;
            background-image: 
                radial-gradient(circle at 10% 20%, rgba(56, 189, 248, 0.08) 0%, transparent 40%),
                radial-gradient(circle at 90% 80%, rgba(239, 68, 68, 0.06) 0%, transparent 40%);
        }

        .container {
            max-width: 1250px;
            margin: 0 auto;
        }

        header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding-bottom: 25px;
            border-bottom: 1px solid var(--border-subtle);
            margin-bottom: 30px;
            flex-wrap: wrap;
            gap: 15px;
        }

        .logo-area {
            display: flex;
            align-items: center;
            gap: 15px;
        }

        .logo-icon {
            width: 48px;
            height: 48px;
            background: linear-gradient(135deg, #0284c7, #38bdf8);
            border-radius: 12px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 24px;
            box-shadow: 0 0 20px rgba(56, 189, 248, 0.3);
        }

        .logo-text h1 {
            font-size: 22px;
            font-weight: 700;
            letter-spacing: -0.5px;
            color: #fff;
        }

        .logo-text p {
            font-size: 13px;
            color: var(--text-muted);
        }

        .header-actions {
            display: flex;
            gap: 10px;
        }

        .btn {
            background: rgba(255, 255, 255, 0.07);
            border: 1px solid var(--border-subtle);
            color: #fff;
            padding: 8px 18px;
            border-radius: 8px;
            font-size: 14px;
            font-weight: 500;
            cursor: pointer;
            transition: all 0.2s ease;
            display: inline-flex;
            align-items: center;
            gap: 8px;
            font-family: inherit;
        }

        .btn:hover {
            background: rgba(255, 255, 255, 0.15);
            border-color: var(--accent-cyan);
        }

        /* Verdict Banner */
        .verdict-banner {
            background: var(--bg-card);
            border-radius: 16px;
            border: 1px solid var(--border-subtle);
            padding: 25px 30px;
            margin-bottom: 30px;
            backdrop-filter: blur(16px);
            position: relative;
            overflow: hidden;
            display: flex;
            align-items: center;
            gap: 25px;
            box-shadow: 0 10px 30px -10px rgba(0, 0, 0, 0.5);
        }

        .verdict-banner::before {
            content: '';
            position: absolute;
            left: 0;
            top: 0;
            bottom: 0;
            width: 6px;
            background-color: )RAWHTML" << verdictColor << R"RAWHTML(;
        }

        .verdict-indicator {
            width: 64px;
            height: 64px;
            border-radius: 50%;
            background: )RAWHTML" << verdictColor << R"RAWHTML(22;
            border: 2px solid )RAWHTML" << verdictColor << R"RAWHTML(;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 32px;
            flex-shrink: 0;
        }

        .verdict-content h2 {
            font-size: 22px;
            color: )RAWHTML" << verdictColor << R"RAWHTML(;
            margin-bottom: 6px;
            font-weight: 700;
        }

        .verdict-content p {
            color: var(--text-muted);
            font-size: 15px;
        }

        /* Stats Grid */
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(240px, 1fr));
            gap: 20px;
            margin-bottom: 35px;
        }

        .stat-card {
            background: var(--bg-card);
            border: 1px solid var(--border-subtle);
            border-radius: 14px;
            padding: 20px 24px;
            backdrop-filter: blur(12px);
            transition: transform 0.2s ease, border-color 0.2s ease;
        }

        .stat-card:hover {
            transform: translateY(-2px);
            border-color: var(--border-glow);
        }

        .stat-label {
            font-size: 13px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            color: var(--text-muted);
            margin-bottom: 8px;
        }

        .stat-val {
            font-size: 28px;
            font-weight: 700;
            font-family: 'JetBrains Mono', monospace;
        }

        /* Tables & Sections */
        .section-card {
            background: var(--bg-card);
            border: 1px solid var(--border-subtle);
            border-radius: 16px;
            padding: 25px;
            margin-bottom: 30px;
            backdrop-filter: blur(14px);
        }

        .section-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 20px;
            flex-wrap: wrap;
            gap: 15px;
        }

        .section-title {
            font-size: 18px;
            font-weight: 600;
            display: flex;
            align-items: center;
            gap: 10px;
        }

        .search-box {
            background: rgba(0, 0, 0, 0.3);
            border: 1px solid var(--border-subtle);
            color: #fff;
            padding: 8px 14px;
            border-radius: 8px;
            font-size: 13px;
            width: 240px;
            font-family: inherit;
        }

        .search-box:focus {
            outline: none;
            border-color: var(--accent-cyan);
        }

        table {
            width: 100%;
            border-collapse: collapse;
            font-size: 14px;
        }

        th {
            text-align: left;
            padding: 12px 16px;
            color: var(--text-muted);
            font-weight: 500;
            border-bottom: 1px solid var(--border-subtle);
            text-transform: uppercase;
            font-size: 11px;
            letter-spacing: 0.5px;
        }

        td {
            padding: 14px 16px;
            border-bottom: 1px solid rgba(255, 255, 255, 0.04);
            vertical-align: top;
        }

        tr:hover td {
            background: rgba(255, 255, 255, 0.02);
        }

        .mono {
            font-family: 'JetBrains Mono', monospace;
            font-size: 12.5px;
            word-break: break-all;
        }

        .badge {
            display: inline-block;
            padding: 3px 8px;
            border-radius: 6px;
            font-size: 11px;
            font-weight: 600;
            text-transform: uppercase;
            font-family: 'JetBrains Mono', monospace;
        }

        .badge-danger {
            background: rgba(239, 68, 68, 0.15);
            color: #fca5a5;
            border: 1px solid rgba(239, 68, 68, 0.3);
        }

        .badge-warning {
            background: rgba(245, 158, 11, 0.15);
            color: #fcd34d;
            border: 1px solid rgba(245, 158, 11, 0.3);
        }

        .badge-clean {
            background: rgba(16, 185, 129, 0.15);
            color: #6ee7b7;
            border: 1px solid rgba(16, 185, 129, 0.3);
        }

        .empty-state {
            text-align: center;
            padding: 40px;
            color: var(--text-muted);
            font-size: 14px;
        }

        footer {
            text-align: center;
            font-size: 13px;
            color: var(--text-muted);
            margin-top: 50px;
            padding-top: 20px;
            border-top: 1px solid var(--border-subtle);
        }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <div class="logo-area">
                <div class="logo-icon">&#x1F6E1;</div>
                <div class="logo-text">
                    <h1>LILNYX DETECTION</h1>
                    <p>Advanced Anti-Cheat & Forensic Analysis Suite v2.5</p>
                </div>
            </div>
            <div class="header-actions">
                <button class="btn" onclick="window.print()">Print / Save PDF</button>
            </div>
        </header>

        <!-- Verdict Banner -->
        <div class="verdict-banner">
            <div class="verdict-indicator">
                )RAWHTML" << (stats.cheatDetections > 0 || stats.bypassDetections > 0 ? "&#x26A0;" : (stats.suspiciousWarnings > 0 ? "&#x2757;" : "&#x2714;")) << R"RAWHTML(
            </div>
            <div class="verdict-content">
                <h2>)RAWHTML" << verdictTitle << R"RAWHTML(</h2>
                <p>)RAWHTML" << verdictDesc << R"RAWHTML(</p>
            </div>
        </div>

        <!-- Metrics Grid -->
        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-label">Artifacts Audited</div>
                <div class="stat-val" style="color: var(--accent-cyan);">&#x1F50D; )RAWHTML" << stats.totalArtifactsScanned << R"RAWHTML(</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">Cheat Detections</div>
                <div class="stat-val" style="color: )RAWHTML" << (stats.cheatDetections > 0 ? "var(--accent-red)" : "var(--accent-emerald)") << R"RAWHTML(;">&#x1F6A8; )RAWHTML" << stats.cheatDetections << R"RAWHTML(</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">Bypass & Tamper Flags</div>
                <div class="stat-val" style="color: )RAWHTML" << (stats.bypassDetections > 0 ? "var(--accent-red)" : "var(--accent-emerald)") << R"RAWHTML(;">&#x1F6E1; )RAWHTML" << stats.bypassDetections << R"RAWHTML(</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">Calculated Risk Score</div>
                <div class="stat-val" style="color: )RAWHTML" << (stats.riskScore >= 40 ? "var(--accent-red)" : (stats.riskScore > 10 ? "var(--accent-amber)" : "var(--accent-emerald)")) << R"RAWHTML(;">&#x26A1; )RAWHTML" << stats.riskScore << R"RAWHTML( / 100</div>
            </div>
        </div>

        <!-- System & Audit Metadata -->
        <div class="section-card" style="padding: 16px 24px; margin-bottom: 25px;">
            <div style="display: flex; justify-content: space-between; flex-wrap: wrap; gap: 10px; font-size: 13.5px; color: var(--text-muted);">
                <span><strong>Target Host:</strong> )RAWHTML" << GetSystemInfoString() << R"RAWHTML(</span>
                <span><strong>Scan Timestamp:</strong> )RAWHTML" << GetCurrentTimestamp() << R"RAWHTML(</span>
                <span><strong>Forensic Access:</strong> )RAWHTML" << (isAdmin ? "<span style='color: var(--accent-emerald);'>Administrator (Deep Scan)</span>" : "<span style='color: var(--accent-amber);'>User Mode (Limited Access)</span>") << R"RAWHTML(</span>
            </div>
        </div>

        <!-- Windows Defender & Security Subsystem Audit Card -->
        <div class="section-card">
            <div class="section-header">
                <div class="section-title">
                    <span>&#x1F6E1;</span> Windows Defender & Antimalware Forensic Audit
                </div>
            </div>
            
            <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 12px; margin-bottom: 20px;">
                <div style="background: rgba(255,255,255,0.03); border: 1px solid var(--border-subtle); border-radius: 8px; padding: 12px 16px;">
                    <div style="font-size: 11px; color: var(--text-muted); text-transform: uppercase;">Real-Time Protection</div>
                    <div style="font-size: 14px; font-weight: 700; margin-top: 4px; color: )RAWHTML" 
                        << (defenderResult.realtimeProtection ? "var(--accent-emerald)" : "var(--accent-red)") << R"RAWHTML(;">)RAWHTML" 
                        << (defenderResult.realtimeProtection ? "&#x2714; ACTIVE & MONITORING" : "&#x26A0; DISABLED / TAMPERED") << R"RAWHTML(</div>
                </div>
                <div style="background: rgba(255,255,255,0.03); border: 1px solid var(--border-subtle); border-radius: 8px; padding: 12px 16px;">
                    <div style="font-size: 11px; color: var(--text-muted); text-transform: uppercase;">Antivirus Core Engine</div>
                    <div style="font-size: 14px; font-weight: 700; margin-top: 4px; color: )RAWHTML" 
                        << (defenderResult.antivirusEnabled ? "var(--accent-emerald)" : "var(--accent-red)") << R"RAWHTML(;">)RAWHTML" 
                        << (defenderResult.antivirusEnabled ? "&#x2714; OPERATIONAL" : "&#x26A0; DISABLED BY POLICY") 
                        << " (" << defenderResult.serviceStateStr << ")" << R"RAWHTML(</div>
                </div>
                <div style="background: rgba(255,255,255,0.03); border: 1px solid var(--border-subtle); border-radius: 8px; padding: 12px 16px;">
                    <div style="font-size: 11px; color: var(--text-muted); text-transform: uppercase;">Tamper Protection</div>
                    <div style="font-size: 14px; font-weight: 700; margin-top: 4px; color: )RAWHTML" 
                        << (defenderResult.tamperProtection ? "var(--accent-emerald)" : "var(--accent-amber)") << R"RAWHTML(;">)RAWHTML" 
                        << (defenderResult.tamperProtection ? "&#x2714; ACTIVE" : "&#x26A0; DISABLED") << R"RAWHTML(</div>
                </div>
                <div style="background: rgba(255,255,255,0.03); border: 1px solid var(--border-subtle); border-radius: 8px; padding: 12px 16px;">
                    <div style="font-size: 11px; color: var(--text-muted); text-transform: uppercase;">Cloud / IOAV Shield</div>
                    <div style="font-size: 14px; font-weight: 700; margin-top: 4px; color: )RAWHTML" 
                        << (defenderResult.ioavProtection ? "var(--accent-emerald)" : "var(--accent-amber)") << R"RAWHTML(;">)RAWHTML" 
                        << (defenderResult.ioavProtection ? "&#x2714; ACTIVE" : "&#x26A0; INACTIVE") << R"RAWHTML(</div>
                </div>
            </div>)RAWHTML";

    if (!defenderResult.exclusionPaths.empty() || !defenderResult.exclusionProcesses.empty()) {
        out << R"RAWHTML(<h4 style="margin: 15px 0 8px 0; color: var(--accent-amber); font-size: 13.5px;">Defender Exclusions (Cheat Evasion Forensics)</h4>
                 <table><thead><tr><th>Type</th><th>Excluded Path / Process</th><th>Risk Assessment</th></tr></thead><tbody>)RAWHTML";
        for (const auto& ep : defenderResult.exclusionPaths) {
            out << "<tr><td><span class='badge badge-danger'>EXCLUDED PATH</span></td><td class='mono'>" << ep << "</td><td>Folder whitelisted from Windows Antivirus scans</td></tr>";
        }
        for (const auto& epr : defenderResult.exclusionProcesses) {
            out << "<tr><td><span class='badge badge-danger'>EXCLUDED PROC</span></td><td class='mono'>" << epr << "</td><td>Process whitelisted from memory inspection</td></tr>";
        }
        out << R"RAWHTML(</tbody></table>)RAWHTML";
    }

    if (!defenderResult.threatHistory.empty()) {
        out << R"RAWHTML(<h4 style="margin: 20px 0 8px 0; color: var(--accent-red); font-size: 13.5px;">Quarantined Cheats & Historical Threats (Event Log 1116/1117)</h4>
                 <table><thead><tr><th>Timestamp</th><th>Threat Name</th><th>Target / File Path</th><th>Remediation Action</th></tr></thead><tbody>)RAWHTML";
        for (const auto& th : defenderResult.threatHistory) {
            out << "<tr><td style='white-space: nowrap; color: var(--text-muted); font-size: 13px;'>" << th.timestamp << "</td>"
                << "<td><strong>" << th.threatName << "</strong></td>"
                << "<td class='mono'>" << th.targetPath << "</td>"
                << "<td><span class='badge badge-danger'>" << th.action << "</span></td></tr>";
        }
        out << R"RAWHTML(</tbody></table>)RAWHTML";
    }

    if (!defenderResult.tamperHistory.empty()) {
        out << R"RAWHTML(<h4 style="margin: 20px 0 8px 0; color: var(--accent-amber); font-size: 13.5px;">Real-Time Protection Kill History (Event ID 5001)</h4>
                 <table><thead><tr><th>Date & Time</th><th>Event</th><th>Forensic Implication</th></tr></thead><tbody>)RAWHTML";
        for (const auto& ev : defenderResult.tamperHistory) {
            out << "<tr><td style='white-space: nowrap; color: var(--text-muted); font-size: 13px;'>" << ev.timestamp << "</td>"
                << "<td><span class='badge badge-warning'>EVENT 5001</span> Real-time Protection Disabled</td>"
                << "<td>Antivirus disabled by user or cheat loader to evade memory blocks</td></tr>";
        }
        out << R"RAWHTML(</tbody></table>)RAWHTML";
    }

    out << R"RAWHTML(</div>

        <!-- Bypass & Anti-Forensics Section -->
        <div class="section-card">
            <div class="section-header">
                <div class="section-title">
                    <span>&#x1F6E1;</span> Anti-Forensics & Tamper Detections
                </div>
            </div>)RAWHTML";

    if (bypassItems.empty()) {
        out << R"RAWHTML(<div class="empty-state">&#x2714; No anti-forensic tampering, log clearing, or driver bypasses detected. System integrity is intact.</div>)RAWHTML";
    } else {
        out << R"RAWHTML(<table>
                <thead>
                    <tr>
                        <th>Severity</th>
                        <th>Component</th>
                        <th>Status</th>
                        <th>Evidence / Technical Detail</th>
                    </tr>
                </thead>
                <tbody>)RAWHTML";
        for (const auto& item : bypassItems) {
            std::string bClass = (item.severity == Severity::CRITICAL || item.severity == Severity::HIGH) ? "badge-danger" : "badge-warning";
            out << "<tr>"
                << "<td><span class='badge " << bClass << "'>" << SeverityToString(item.severity) << "</span></td>"
                << "<td><strong>" << item.component << "</strong></td>"
                << "<td><span style='color: var(--accent-red); font-weight: 600;'>" << item.status << "</span></td>"
                << "<td>" << item.evidence << "</td>"
                << "</tr>";
        }
        out << R"RAWHTML(</tbody></table>)RAWHTML";
    }
    out << R"RAWHTML(</div>

        <!-- Executed Cheats & Forensic Artifacts Section -->
        <div class="section-card">
            <div class="section-header">
                <div class="section-title">
                    <span>&#x1F6A8;</span> Executed Cheats & Forensic Traces
                </div>
                <input type="text" class="search-box" id="cheatFilter" placeholder="Filter detections..." onkeyup="filterTable()">
            </div>)RAWHTML";

    if (detections.empty()) {
        out << R"RAWHTML(<div class="empty-state">&#x2714; No past or active cheat executables found in BAM, PCA, MuiCache, UserAssist, Prefetch, or Storage.</div>)RAWHTML";
    } else {
        out << R"RAWHTML(<table id="detectionsTable">
                <thead>
                    <tr>
                        <th>Severity</th>
                        <th>Category</th>
                        <th>Target File / Executable</th>
                        <th>Detection Detail</th>
                        <th>Timestamp</th>
                    </tr>
                </thead>
                <tbody>)RAWHTML";
        for (const auto& item : detections) {
            std::string bClass = (item.severity == Severity::CRITICAL) ? "badge-danger" : ((item.severity == Severity::HIGH) ? "badge-warning" : "badge-clean");
            out << "<tr>"
                << "<td><span class='badge " << bClass << "'>" << SeverityToString(item.severity) << "</span></td>"
                << "<td>" << item.category << "</td>"
                << "<td class='mono'>" << item.target << "</td>"
                << "<td>" << item.detail << "</td>"
                << "<td style='white-space: nowrap; color: var(--text-muted); font-size: 13px;'>" << item.timestamp << "</td>"
                << "</tr>";
        }
        out << R"RAWHTML(</tbody></table>)RAWHTML";
    }
    out << R"RAWHTML(</div>

        <footer>
            <p>Sentinel PC-Check & Forensic Anti-Cheat Scanner &bull; Generated )RAWHTML" << GetCurrentTimestamp() << R"RAWHTML(</p>
        </footer>
    </div>

    <script>
        function filterTable() {
            var input = document.getElementById("cheatFilter");
            var filter = input.value.toLowerCase();
            var table = document.getElementById("detectionsTable");
            if (!table) return;
            var tr = table.getElementsByTagName("tr");

            for (var i = 1; i < tr.length; i++) {
                var text = tr[i].textContent || tr[i].innerText;
                if (text.toLowerCase().indexOf(filter) > -1) {
                    tr[i].style.display = "";
                } else {
                    tr[i].style.display = "none";
                }
            }
        }
    </script>
</body>
</html>)RAWHTML";

    out.close();
    return filename;
}
