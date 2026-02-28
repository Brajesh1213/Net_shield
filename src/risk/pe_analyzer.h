// pe_analyzer.h — Static PE (Portable Executable) analysis
// Inspects file headers, section entropy, imports to detect packed/malicious binaries
// This replaces simple filename-based detection with structural analysis
#pragma once

#include <windows.h>
#include <string>
#include <vector>
#include <cstdint>

namespace Asthak {

enum class PeVerdict {
    CLEAN,
    SUSPICIOUS,
    LIKELY_MALWARE,
    PACKED,          // UPX/Themida/custom packer
    ERROR_ANALYSIS,
};

struct PeAnalysis {
    PeVerdict    verdict;
    double       overallScore;       // 0.0 (clean) to 1.0 (malicious)
    double       avgEntropy;         // Average section entropy (>7.0 = packed)
    double       maxSectionEntropy;  // Highest section entropy
    uint32_t     importCount;        // Total imported functions
    uint32_t     sectionCount;
    bool         hasExecutableData;  // .data section with execute flag
    bool         hasSuspiciousImports; // VirtualAlloc+WriteProcessMemory combo
    bool         isSignedBinary;     // Has Authenticode signature
    bool         isPacked;           // Detected packer
    std::wstring packerName;         // e.g. "UPX", "Themida"
    std::wstring detail;
    std::vector<std::wstring> suspiciousAPIs;
};

class PeAnalyzer {
public:
    static PeAnalyzer& Instance();

    // Analyze a PE file on disk
    PeAnalysis AnalyzeFile(const std::wstring& filePath);

    // Quick entropy check (faster than full analysis)
    double ComputeFileEntropy(const std::wstring& filePath);

private:
    PeAnalyzer() = default;

    // Internal analysis steps
    bool ParsePEHeaders(const BYTE* data, size_t size, PeAnalysis& result);
    void AnalyzeSections(const BYTE* data, size_t size, PeAnalysis& result);
    void AnalyzeImports(const BYTE* data, size_t size, PeAnalysis& result);
    void DetectPackers(const BYTE* data, size_t size, PeAnalysis& result);
    void CheckSignature(const std::wstring& filePath, PeAnalysis& result);
    double ComputeEntropy(const BYTE* data, size_t size);
    void ScoreResult(PeAnalysis& result);
};

} // namespace Asthak
