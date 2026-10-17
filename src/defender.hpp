#pragma once

#include "common.hpp"
#include <vector>
#include <string>

struct DefenderThreat {
    std::string timestamp;
    std::string threatName;
    std::string targetPath;
    std::string action;
    std::string severity;
    std::string user;
};

struct DefenderTamperEvent {
    std::string timestamp;
    int eventId = 0;
    std::string description;
};

struct DefenderAuditResult {
    bool antivirusEnabled = true;
    bool realtimeProtection = true;
    bool ioavProtection = true;
    bool tamperProtection = true;
    bool serviceRunning = true;
    std::string serviceStateStr = "RUNNING";

    std::vector<std::string> exclusionPaths;
    std::vector<std::string> exclusionProcesses;
    std::vector<std::string> exclusionExtensions;

    std::vector<DefenderThreat> threatHistory;
    std::vector<DefenderTamperEvent> tamperHistory;
};

class DefenderScanner {
public:
    DefenderScanner() = default;

    DefenderAuditResult AuditDefender(std::vector<DetectionItem>& detections,
                                     std::vector<BypassItem>& bypassItems,
                                     ScanStats& stats,
                                     bool isAdmin);

private:
    void CheckDefenderService(DefenderAuditResult& result);
    void CheckDefenderRegistryPolicies(DefenderAuditResult& result,
                                       std::vector<BypassItem>& bypassItems,
                                       ScanStats& stats);
    void CheckDefenderPowerShellStatus(DefenderAuditResult& result, bool isAdmin);
    void CheckDefenderEventLog(DefenderAuditResult& result,
                              std::vector<DetectionItem>& detections,
                              std::vector<BypassItem>& bypassItems,
                              ScanStats& stats);
};
