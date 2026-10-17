#include "common.hpp"
#include "forensics.hpp"
#include "bypass.hpp"
#include "active_scanner.hpp"
#include "defender.hpp"
#include "reg_scanner.hpp"
#include "remediation.hpp"
#include "report.hpp"
#include <conio.h>

static void PrintStepHeader(const std::string& stepTag, const std::string& title) {
    std::cout << "\n  \033[1;36m" << stepTag << "\033[0m \033[1;37m" << title << "\033[0m\n";
    std::cout << "        \033[1;30m[";
    for (int i = 0; i < 20; ++i) {
        std::cout << "=";
        std::cout.flush();
        Sleep(4);
    }
    std::cout << ">] \033[1;33mSCANNING...\033[0m\r";
    std::cout.flush();
}

static void PrintStepComplete(const std::string& note = "") {
    std::cout << "        \033[1;32m[====================] [ AUDIT OK ]\033[0m";
    if (!note.empty()) {
        std::cout << " \033[0;37m(" << note << ")\033[0m";
    }
    std::cout << "       \n";
    std::cout.flush();
    Sleep(30);
}

static void PrintCategoryMenu() {
    std::cout << "\033[1;35m"
              << "+==============================================================================+\n"
              << "|                 LILNYX FORENSIC AUDIT // SELECT AUDIT CATEGORY               |\n"
              << "+==============================================================================+\033[0m\n"
              << "  \033[1;36m[1]\033[0m \033[1;37mFULL COMPREHENSIVE AUDIT\033[0m\n"
              << "      \033[0;37m-> Audit all categories: Cheats + Bypass + Defender + Regedit / Registry\033[0m\n\n"
              << "  \033[1;31m[2]\033[0m \033[1;37mGAME CHEATS ONLY\033[0m\n"
              << "      \033[0;37m-> Prefetch, BAM/DAM, PCA Store, MuiCache, UserAssist, Memory & Recent\033[0m\n\n"
              << "  \033[1;35m[3]\033[0m \033[1;37mBYPASS & ANTI-FORENSICS ONLY\033[0m\n"
              << "      \033[0;37m-> Service tampering, USN Journal wipers, Security Event Log 1102, Drivers\033[0m\n\n"
              << "  \033[1;34m[4]\033[0m \033[1;37mWINDOWS DEFENDER ONLY\033[0m\n"
              << "      \033[0;37m-> Protection status, Exclusions, Quarantined Threats (1116/1117), RTP Kills\033[0m\n\n"
              << "  \033[1;33m[5]\033[0m \033[1;37mREGEDIT & REGISTRY FORENSICS ONLY\033[0m\n"
              << "      \033[0;37m-> Regedit LastKey, AppInit_DLLs, IFEO Hijacking, OpenSaveMRU, Cheat Tweaks\033[0m\n\n"
              << "  \033[1;31m[6]\033[0m \033[1;37mMALWARE & HACK CLEANER (KILL & CLEAR ACTIVE THREATS)\033[0m\n"
              << "      \033[0;37m-> Scan running memory, terminate live cheats/trojans, & quarantine files\033[0m\n\n"
              << "  \033[1;32m[7]\033[0m \033[1;37m24/7 ACTIVE REAL-TIME WATCHDOG\033[0m\n"
              << "      \033[0;37m-> Continuous live process, Regedit, injection, and window title monitor\033[0m\n\n"
              << "  \033[1;30m[Q]\033[0m \033[1;37mEXIT LILNYX DETECTION\033[0m\n"
              << "\033[1;35m+==============================================================================+\033[0m\n";
}

int main(int argc, char* argv[]) {
    // Set console title
    SetConsoleTitleW(L"Lilnyx Detection - Anti-Cheat & Bypass Forensic Suite");

    bool noBrowser = false;
    bool autoMode = false;
    int forcedMode = 0;

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--no-browser") noBrowser = true;
        if (arg == "--auto") autoMode = true;
        if (arg == "--cheats") forcedMode = 2;
        if (arg == "--bypass") forcedMode = 3;
        if (arg == "--defender") forcedMode = 4;
        if (arg == "--regedit" || arg == "--registry") forcedMode = 5;
        if (arg == "--clean" || arg == "--remediate" || arg == "--clear") forcedMode = 6;
        if (arg == "--watchdog") forcedMode = 7;
        if (arg == "--mode" && i + 1 < argc) {
            forcedMode = std::stoi(argv[++i]);
        }
        if (arg == "--elevate") {
            if (!CheckIsAdmin()) {
                RelaunchAsAdmin(argc, argv);
                return 0;
            }
        }
    }

    // Enable UTF-8 codepage and ANSI Virtual Terminal colors in Windows console
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);

    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD dwMode = 0;
    if (GetConsoleMode(hOut, &dwMode)) {
        dwMode |= ENABLE_VIRTUAL_TERMINAL_PROCESSING;
        SetConsoleMode(hOut, dwMode);
    }

    std::cout << "\033[1;35m"
              << "+------------------------------------------------------------------------------+\n"
              << "|   _     ___ _     _   ___   ____  __  ____  _____ _____ _____ ____ _____     |\n"
              << "|  | |   |_ _| |   | \\ | \\ \\ / /\\ \\/ / |  _ \\| ____|_   _| ____/ ___|_   _|    |\n"
              << "|  | |    | || |   |  \\| |\\ V /  \\  /  | | | |  _|   | | |  _|| |     | |      |\n"
              << "|  | |___ | || |___| |\\  | | |   /  \\  | |_| | |___  | | | |__| |___  | |      |\n"
              << "|  |_____|___|_____|_| \\_| |_|  /_/\\_\\ |____/|_____| |_| |_____\\____| |_|      |\n"
              << "|                                                                              |\n"
              << "|           LILNYX DETECTION // GAME CHEAT & BYPASS FORENSIC SUITE             |\n"
              << "+------------------------------------------------------------------------------+\033[0m\n\n";

    bool isAdmin = CheckIsAdmin();
    if (!isAdmin) {
        std::cout << "\033[1;33m[!] NOTICE: Running in Standard User mode.\033[0m\n"
                  << "    Deep forensic areas (Prefetch files, Security Event Log 1102, BAM Registry,\n"
                  << "    and Raw USN Journal) require elevated Administrator privileges.\n\n";

        if (!autoMode) {
            std::cout << "    Would you like to restart as Administrator for Maximum Detection? (Y/N): ";
            char choice;
            std::cin >> choice;
            if (choice == 'y' || choice == 'Y') {
                std::cout << "\n[+] Requesting UAC Administrator privileges...\n";
                if (RelaunchAsAdmin(argc, argv)) {
                    return 0;
                } else {
                    std::cout << "\033[1;31m[-] Elevation declined or failed. Continuing in Standard mode...\033[0m\n\n";
                }
            } else {
                std::cout << "[*] Continuing with user-accessible forensic modules...\n\n";
            }
        }
    } else {
        std::cout << "\033[1;32m[+] Elevated Administrator privileges confirmed. Deep Forensics unlocked.\033[0m\n\n";
    }

    ForensicsScanner forensics;
    BypassDetector bypass;
    ActiveScanner active;
    DefenderScanner defenderScanner;
    RegistryScanner registryScanner;
    MalwareCleaner cleaner;
    ReportGenerator reporter;

    bool running = true;
    while (running) {
        int auditMode = 1;

        if (forcedMode != 0) {
            auditMode = forcedMode;
        } else if (!autoMode) {
            PrintCategoryMenu();
            std::cout << "  \033[1;33mSelect Category [1-7 / Q]: \033[0m";
            while (_kbhit()) { _getch(); }
            char ch = _getch();
            std::cout << ch << "\n\n";

            if (ch == 'q' || ch == 'Q') {
                std::cout << "  \033[1;30m[*] Exiting Lilnyx Detection. Goodbye.\033[0m\n\n";
                break;
            } else if (ch == '2') {
                auditMode = 2;
            } else if (ch == '3') {
                auditMode = 3;
            } else if (ch == '4') {
                auditMode = 4;
            } else if (ch == '5') {
                auditMode = 5;
            } else if (ch == '6') {
                auditMode = 6;
            } else if (ch == '7') {
                auditMode = 7;
            } else {
                auditMode = 1;
            }
        } else {
            auditMode = 1;
        }

        // Mode 6: Active Malware & Game Hack Cleaner
        if (auditMode == 6) {
            cleaner.RunInteractiveCleaner(autoMode);
            if (autoMode || forcedMode != 0) break;
            std::cout << "  Press any key to return to Main Menu...";
            _getch();
            std::cout << "\n\n";
            continue;
        }

        // Mode 7: Watchdog guard
        if (auditMode == 7) {
            std::cout << "\033[1;32m[*] Starting Lilnyx 24/7 Active Real-Time Watchdog Guard...\033[0m\n\n";
            active.RunRealTimeWatchdog();
            if (autoMode || forcedMode != 0) break;
            std::cout << "\n  Press any key to return to Main Menu...";
            _getch();
            std::cout << "\n\n";
            continue;
        }

        ScanStats stats;
        std::vector<DetectionItem> detections;
        std::vector<BypassItem> bypassItems;
        DefenderAuditResult defResult;
        RegAuditResult regResult;
        int prefetchCount = 0;

        // Execute scan steps based on selected category
        if (auditMode == 1) {
            // FULL AUDIT (10 Steps)
            std::cout << "\033[1;36m[*] Commencing Full Comprehensive Forensic Audit (All Categories)...\033[0m\n";

            // Step 1: Active memory and running processes
            PrintStepHeader("[1/10]", "Inspecting live memory, running processes, & window titles...");
            active.ScanRunningProcesses(detections, stats);
            active.ScanWindowTitles(detections, stats);
            PrintStepComplete();

            // Step 2: Prefetch artifacts
            PrintStepHeader("[2/10]", "Analyzing Windows Prefetch execution artifacts (*.pf)...");
            forensics.ScanPrefetch(detections, stats, prefetchCount);
            PrintStepComplete(std::to_string(prefetchCount) + " prefetch files");

            // Step 3: Anti-Forensic Tamper & Bypass detection
            PrintStepHeader("[3/10]", "Checking Anti-Forensics, log wipers, & system tampering...");
            bypass.CheckPrefetchTampering(prefetchCount, bypassItems, stats);
            bypass.CheckUsnJournal(bypassItems, stats);
            bypass.CheckEventLogClearing(bypassItems, stats);
            bypass.CheckServiceStatus(bypassItems, stats);
            bypass.CheckTestSigningAndDebugger(bypassItems, stats);
            bypass.CheckVulnerableDrivers(bypassItems, stats);
            bypass.CheckAntiForensicScripts(bypassItems, stats);
            PrintStepComplete();

            // Step 4: Windows Defender & Security Subsystem Audit
            PrintStepHeader("[4/10]", "Auditing Windows Defender status, exclusions, & threat history...");
            defResult = defenderScanner.AuditDefender(detections, bypassItems, stats, isAdmin);
            PrintStepComplete();

            // Step 5: Windows Registry & Regedit Forensics Audit
            PrintStepHeader("[5/10]", "Auditing Windows Registry Editor (Regedit), IFEO, AppInit, & tweaks...");
            regResult = registryScanner.AuditRegistry(detections, bypassItems, stats, isAdmin);
            PrintStepComplete();

            // Step 6: BAM / DAM Execution History
            PrintStepHeader("[6/10]", "Scanning BAM / DAM Background Activity Moderator history...");
            forensics.ScanBam(detections, stats);
            PrintStepComplete();

            // Step 7: PCA Store (Program Compatibility Assistant)
            PrintStepHeader("[7/10]", "Scanning PCA Store & Compatibility Assistant execution records...");
            forensics.ScanPcaStore(detections, stats);
            PrintStepComplete();

            // Step 8: Shell MuiCache
            PrintStepHeader("[8/10]", "Auditing Windows Shell MuiCache execution history...");
            forensics.ScanMuiCache(detections, stats);
            PrintStepComplete();

            // Step 9: UserAssist ROT13 Records
            PrintStepHeader("[9/10]", "Decoding Explorer UserAssist ROT13 launch records...");
            forensics.ScanUserAssist(detections, stats);
            PrintStepComplete();

            // Step 10: Storage, Recent files, Recycle Bin, and DNS cache
            PrintStepHeader("[10/10]", "Scanning Recent shortcuts, High-Risk storage, & DNS cache...");
            forensics.ScanRecentItems(detections, stats);
            forensics.ScanHighRiskFolders(detections, stats);
            forensics.ScanRecycleBin(detections, stats);
            active.ScanDnsCache(detections, stats);
            PrintStepComplete();

        } else if (auditMode == 2) {
            // GAME CHEATS ONLY (7 Steps)
            std::cout << "\033[1;31m[*] Commencing Game Cheats & Execution History Audit...\033[0m\n";

            // Step 1: Active memory and running processes
            PrintStepHeader("[1/7]", "Inspecting live memory, running processes, & window titles...");
            active.ScanRunningProcesses(detections, stats);
            active.ScanWindowTitles(detections, stats);
            PrintStepComplete();

            // Step 2: Prefetch artifacts
            PrintStepHeader("[2/7]", "Analyzing Windows Prefetch execution artifacts (*.pf)...");
            forensics.ScanPrefetch(detections, stats, prefetchCount);
            PrintStepComplete(std::to_string(prefetchCount) + " prefetch files");

            // Step 3: BAM / DAM Execution History
            PrintStepHeader("[3/7]", "Scanning BAM / DAM Background Activity Moderator history...");
            forensics.ScanBam(detections, stats);
            PrintStepComplete();

            // Step 4: PCA Store (Program Compatibility Assistant)
            PrintStepHeader("[4/7]", "Scanning PCA Store & Compatibility Assistant execution records...");
            forensics.ScanPcaStore(detections, stats);
            PrintStepComplete();

            // Step 5: Shell MuiCache
            PrintStepHeader("[5/7]", "Auditing Windows Shell MuiCache execution history...");
            forensics.ScanMuiCache(detections, stats);
            PrintStepComplete();

            // Step 6: UserAssist ROT13 Records
            PrintStepHeader("[6/7]", "Decoding Explorer UserAssist ROT13 launch records...");
            forensics.ScanUserAssist(detections, stats);
            PrintStepComplete();

            // Step 7: Storage, Recent files, Recycle Bin, and DNS cache
            PrintStepHeader("[7/7]", "Scanning Recent shortcuts, High-Risk storage, & Recycle Bin...");
            forensics.ScanRecentItems(detections, stats);
            forensics.ScanHighRiskFolders(detections, stats);
            forensics.ScanRecycleBin(detections, stats);
            active.ScanDnsCache(detections, stats);
            PrintStepComplete();

        } else if (auditMode == 3) {
            // BYPASS & ANTI-FORENSICS ONLY (7 Steps)
            std::cout << "\033[1;35m[*] Commencing Bypass & Anti-Forensics Audit...\033[0m\n";

            // Step 1: Prefetch service & timestamp tampering
            PrintStepHeader("[1/7]", "Checking Prefetch service status & timestamp tampering...");
            bypass.CheckPrefetchTampering(prefetchCount, bypassItems, stats);
            PrintStepComplete();

            // Step 2: USN Change Journal wipers
            PrintStepHeader("[2/7]", "Inspecting NTFS USN Change Journal wipers & volume status...");
            bypass.CheckUsnJournal(bypassItems, stats);
            PrintStepComplete();

            // Step 3: Event Log clearing
            PrintStepHeader("[3/7]", "Checking Security & System Event Log clearing (Event 1102 / 104)...");
            bypass.CheckEventLogClearing(bypassItems, stats);
            PrintStepComplete();

            // Step 4: Diagnostic & Forensic services
            PrintStepHeader("[4/7]", "Auditing Diagnostic, EventLog, & Forensic service manipulation...");
            bypass.CheckServiceStatus(bypassItems, stats);
            PrintStepComplete();

            // Step 5: TestSigning & Debugger
            PrintStepHeader("[5/7]", "Verifying TestSigning mode, Kernel debugging, & Hypervisors...");
            bypass.CheckTestSigningAndDebugger(bypassItems, stats);
            PrintStepComplete();

            // Step 6: Vulnerable BYOVD Drivers
            PrintStepHeader("[6/7]", "Scanning for vulnerable BYOVD Kernel Drivers & blocked hashes...");
            bypass.CheckVulnerableDrivers(bypassItems, stats);
            PrintStepComplete();

            // Step 7: Anti-forensic scripts & wipers
            PrintStepHeader("[7/7]", "Checking for anti-forensic batch, PowerShell, & wiper scripts...");
            bypass.CheckAntiForensicScripts(bypassItems, stats);
            PrintStepComplete();

        } else if (auditMode == 4) {
            // WINDOWS DEFENDER ONLY
            std::cout << "\033[1;34m[*] Commencing Windows Defender & Security Subsystem Audit...\033[0m\n";

            PrintStepHeader("[1/1]", "Auditing Defender status, exclusions, quarantined threats & RTP kills...");
            defResult = defenderScanner.AuditDefender(detections, bypassItems, stats, isAdmin);
            PrintStepComplete();

        } else if (auditMode == 5) {
            // WINDOWS REGISTRY & REGEDIT FORENSICS ONLY
            std::cout << "\033[1;35m[*] Commencing Windows Registry & Regedit Forensics Audit...\033[0m\n";

            PrintStepHeader("[1/1]", "Auditing Regedit activity, AppInit_DLLs, IFEO, OpenSaveMRU, & tweaks...");
            regResult = registryScanner.AuditRegistry(detections, bypassItems, stats, isAdmin);
            PrintStepComplete();
        }

        // Print summary formatted for selected audit mode
        reporter.PrintConsoleSummary(detections, bypassItems, defResult, regResult, stats, isAdmin, auditMode);

        // Generate Reports
        std::string textReport = reporter.GenerateTextReport(detections, bypassItems, defResult, regResult, stats, isAdmin);
        std::string htmlReport = reporter.GenerateHtmlReport(detections, bypassItems, defResult, regResult, stats, isAdmin);

        std::cout << "\033[1;36m+==============================================================================+\n"
                  << "|                             FORENSIC REPORTS GENERATED                       |\n"
                  << "+==============================================================================+\033[0m\n";
        if (!textReport.empty()) {
            std::cout << "  [+] Text Report:  \033[1m" << textReport << "\033[0m\n";
        }
        if (!htmlReport.empty()) {
            std::cout << "  [+] HTML Report:  \033[1;32m" << htmlReport << "\033[0m (Interactive Cyber Dashboard)\n";
        }
        std::cout << "\033[1;36m+------------------------------------------------------------------------------+\033[0m\n\n";

        if (autoMode || forcedMode != 0) {
            if (!noBrowser && !htmlReport.empty()) {
                reporter.OpenInBrowser(htmlReport);
            }
            break;
        }

        // Post-Scan Interactive Menu
        std::vector<ActiveThreatItem> liveThreats = cleaner.ScanActiveThreats();

        std::cout << "\033[1;35m+==============================================================================+\n"
                  << "|                           AUDIT COMPLETE // NEXT ACTION                      |\n"
                  << "+==============================================================================+\033[0m\n";

        if (!liveThreats.empty()) {
            std::cout << "  \033[1;41;37m [C] CLEAR & TERMINATE " << liveThreats.size() << " RUNNING MALWARE / HACK THREAT(S) NOW! \033[0m\n\n";
        }

        std::cout << "  \033[1;36m[M]\033[0m \033[1;37mReturn to Category Selection Menu (Audit Another Category)\033[0m\n"
                  << "  \033[1;32m[O]\033[0m \033[1;37mOpen Interactive HTML Forensic Dashboard in Browser\033[0m\n"
                  << "  \033[1;31m[K]\033[0m \033[1;37mLaunch Malware & Hack Cleaner (Inspect & Clean All Threats)\033[0m\n"
                  << "  \033[1;33m[W]\033[0m \033[1;37mLaunch 24/7 Active Real-Time Watchdog Guard\033[0m\n"
                  << "  \033[1;30m[Q]\033[0m \033[1;37mExit Lilnyx Detection\033[0m\n"
                  << "\033[1;35m+==============================================================================+\033[0m\n"
                  << "  \033[1;33mSelect Action [" << (!liveThreats.empty() ? "C / " : "") << "M / O / K / W / Q]: \033[0m";

        bool waitingAction = true;
        while (waitingAction) {
            while (_kbhit()) { _getch(); }
            char actionKey = _getch();
            std::cout << actionKey << "\n\n";

            if (actionKey == 'c' || actionKey == 'C') {
                if (!liveThreats.empty()) {
                    std::cout << "  \033[1;36m[*] Terminating and neutralizing " << liveThreats.size() << " active threat(s)...\033[0m\n\n";
                    cleaner.CleanAllThreats(liveThreats, true);
                    std::cout << "  \033[1;32m[✓] All running malware and hacks have been terminated and quarantined!\033[0m\n\n";
                    std::cout << "  Press any key to return to Main Menu...";
                    _getch();
                    std::cout << "\n\n";
                    waitingAction = false;
                } else {
                    std::cout << "  \033[1;32m[✓] No active threats currently running in memory.\033[0m\n";
                    std::cout << "  \033[1;33mSelect Action [M / O / K / W / Q]: \033[0m";
                }
            } else if (actionKey == 'k' || actionKey == 'K') {
                waitingAction = false;
                std::cout << "\n\n";
                cleaner.RunInteractiveCleaner();
                std::cout << "  Press any key to return to Main Menu...";
                _getch();
                std::cout << "\n\n";
            } else if (actionKey == 'm' || actionKey == 'M') {
                waitingAction = false;
                std::cout << "\033[1;36m[*] Returning to Category Selection Menu...\033[0m\n\n";
            } else if (actionKey == 'o' || actionKey == 'O') {
                if (!htmlReport.empty()) {
                    std::cout << "  \033[1;32m[+] Opening HTML Forensic Report in default web browser...\033[0m\n";
                    reporter.OpenInBrowser(htmlReport);
                } else {
                    std::cout << "  \033[1;31m[-] HTML Report path is empty.\033[0m\n";
                }
                std::cout << "  \033[1;33mSelect Action [" << (!liveThreats.empty() ? "C / " : "") << "M / O / K / W / Q]: \033[0m";
            } else if (actionKey == 'w' || actionKey == 'W') {
                waitingAction = false;
                std::cout << "\n\n";
                active.RunRealTimeWatchdog();
                std::cout << "\n  Press any key to return to Main Menu...";
                _getch();
                std::cout << "\n\n";
            } else if (actionKey == 'q' || actionKey == 'Q' || actionKey == 27) { // 27 = ESC
                waitingAction = false;
                running = false;
                std::cout << "  \033[1;30m[*] Exiting Lilnyx Detection. Goodbye.\033[0m\n\n";
            } else {
                std::cout << "  \033[1;31m[!] Invalid selection. Please press " << (!liveThreats.empty() ? "C, " : "") << "M, O, K, W, or Q: \033[0m";
            }
        }
    }

    return 0;
}
