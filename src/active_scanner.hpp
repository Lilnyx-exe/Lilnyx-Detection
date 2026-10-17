#pragma once

#include "common.hpp"
#include <vector>

class ActiveScanner {
public:
    ActiveScanner() = default;

    void ScanRunningProcesses(std::vector<DetectionItem>& detections, ScanStats& stats);
    void ScanWindowTitles(std::vector<DetectionItem>& detections, ScanStats& stats);
    void ScanDnsCache(std::vector<DetectionItem>& detections, ScanStats& stats);
    void RunRealTimeWatchdog();
};
