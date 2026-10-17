#pragma once

#include "common.hpp"
#include <vector>
#include <string>

struct ActiveThreatItem {
    DWORD pid = 0;
    std::string processName;
    std::string fullPath;
    std::string detectionReason;
    std::string threatCategory;
    Severity severity = Severity::CRITICAL;
    bool isRunning = true;
    bool terminated = false;
    bool quarantined = false;
    std::string actionTaken;
};

class MalwareCleaner {
public:
    MalwareCleaner() = default;

    // Scan for all active malware, cheat injectors, and malicious hidden tasks
    std::vector<ActiveThreatItem> ScanActiveThreats();

    // Clean a single threat (terminate process and optionally quarantine executable)
    bool CleanThreat(ActiveThreatItem& threat, bool quarantineFile = true);

    // Clean all detected threats
    int CleanAllThreats(std::vector<ActiveThreatItem>& threats, bool quarantineFile = true);

    // Flush Windows DNS resolver cache
    void FlushDnsCache();

    // Interactive Cleaner flow
    void RunInteractiveCleaner(bool autoConfirm = false);
};
