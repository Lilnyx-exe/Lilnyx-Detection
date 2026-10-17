#pragma once

#include "common.hpp"
#include <vector>

class BypassDetector {
public:
    BypassDetector() = default;

    void CheckPrefetchTampering(int prefetchCount, std::vector<BypassItem>& bypassItems, ScanStats& stats);
    void CheckUsnJournal(std::vector<BypassItem>& bypassItems, ScanStats& stats);
    void CheckEventLogClearing(std::vector<BypassItem>& bypassItems, ScanStats& stats);
    void CheckServiceStatus(std::vector<BypassItem>& bypassItems, ScanStats& stats);
    void CheckTestSigningAndDebugger(std::vector<BypassItem>& bypassItems, ScanStats& stats);
    void CheckVulnerableDrivers(std::vector<BypassItem>& bypassItems, ScanStats& stats);
    void CheckAntiForensicScripts(std::vector<BypassItem>& bypassItems, ScanStats& stats);
};
