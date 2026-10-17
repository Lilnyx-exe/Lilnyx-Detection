#pragma once

#include "common.hpp"
#include "defender.hpp"
#include "reg_scanner.hpp"
#include <vector>
#include <string>

class ReportGenerator {
public:
    ReportGenerator() = default;

    void PrintConsoleSummary(const std::vector<DetectionItem>& detections,
                             const std::vector<BypassItem>& bypassItems,
                             const DefenderAuditResult& defenderResult,
                             const RegAuditResult& regResult,
                             const ScanStats& stats,
                             bool isAdmin,
                             int auditMode = 1);

    std::string GenerateHtmlReport(const std::vector<DetectionItem>& detections,
                                   const std::vector<BypassItem>& bypassItems,
                                   const DefenderAuditResult& defenderResult,
                                   const RegAuditResult& regResult,
                                   const ScanStats& stats,
                                   bool isAdmin);

    std::string GenerateTextReport(const std::vector<DetectionItem>& detections,
                                   const std::vector<BypassItem>& bypassItems,
                                   const DefenderAuditResult& defenderResult,
                                   const RegAuditResult& regResult,
                                   const ScanStats& stats,
                                   bool isAdmin);

    void OpenInBrowser(const std::string& filePath);

private:
    std::string GetSystemInfoString();
    std::string GetCurrentTimestamp();
};
