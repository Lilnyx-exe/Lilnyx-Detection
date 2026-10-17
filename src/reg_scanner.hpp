#pragma once

#include "common.hpp"
#include <vector>
#include <string>

struct RegTweakItem {
    std::string keyPath;
    std::string valueName;
    std::string currentValue;
    std::string expectedOrNormal;
    std::string description;
    Severity severity = Severity::INFO;
};

struct RegAuditResult {
    bool regeditCurrentlyRunning = false;
    std::string regeditLastKey;
    bool lastKeySuspicious = false;
    std::string lastKeySuspicionReason;

    std::vector<std::string> regeditExecutionHistory;
    std::vector<std::string> appInitDlls;
    std::vector<std::string> ifeoHijacks;
    std::vector<std::string> searchQueries;
    std::vector<std::string> openSaveCheats;
    std::vector<std::string> appCompatLayers;
    std::vector<std::string> startupRunCheats;
    std::vector<RegTweakItem> detectedTweaks;
};

class RegistryScanner {
public:
    RegistryScanner() = default;

    RegAuditResult AuditRegistry(std::vector<DetectionItem>& detections,
                                std::vector<BypassItem>& bypassItems,
                                ScanStats& stats,
                                bool isAdmin);

private:
    void CheckRegeditActivity(RegAuditResult& result,
                              std::vector<DetectionItem>& detections,
                              std::vector<BypassItem>& bypassItems,
                              ScanStats& stats);

    void CheckAppInitDlls(RegAuditResult& result,
                          std::vector<BypassItem>& bypassItems,
                          ScanStats& stats);

    void CheckIfeoDebuggerHijacks(RegAuditResult& result,
                                  std::vector<BypassItem>& bypassItems,
                                  ScanStats& stats);

    void CheckAppCompatFlagsLayers(RegAuditResult& result,
                                   std::vector<DetectionItem>& detections,
                                   ScanStats& stats);

    void CheckComDlgOpenSaveMRU(RegAuditResult& result,
                                std::vector<DetectionItem>& detections,
                                ScanStats& stats);

    void CheckWordWheelQueries(RegAuditResult& result,
                               std::vector<DetectionItem>& detections,
                               ScanStats& stats);

    void CheckStartupRunKeys(RegAuditResult& result,
                             std::vector<DetectionItem>& detections,
                             ScanStats& stats);

    void CheckGamingRegistryTweaks(RegAuditResult& result,
                                   std::vector<BypassItem>& bypassItems,
                                   ScanStats& stats);
};
