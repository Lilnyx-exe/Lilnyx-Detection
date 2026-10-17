#pragma once

#include "common.hpp"
#include <vector>

class ForensicsScanner {
public:
    ForensicsScanner() = default;

    void ScanMuiCache(std::vector<DetectionItem>& detections, ScanStats& stats);
    void ScanPcaStore(std::vector<DetectionItem>& detections, ScanStats& stats);
    void ScanBam(std::vector<DetectionItem>& detections, ScanStats& stats);
    void ScanUserAssist(std::vector<DetectionItem>& detections, ScanStats& stats);
    void ScanPrefetch(std::vector<DetectionItem>& detections, ScanStats& stats, int& prefetchCount);
    void ScanRecentItems(std::vector<DetectionItem>& detections, ScanStats& stats);
    void ScanHighRiskFolders(std::vector<DetectionItem>& detections, ScanStats& stats);
    void ScanRecycleBin(std::vector<DetectionItem>& detections, ScanStats& stats);

private:
    std::string NormalizeDevicePath(const std::string& path);
};
