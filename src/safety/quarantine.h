// quarantine.h — File quarantine subsystem for NetSentinel
#pragma once
#include <windows.h>
#include <string>
#include <vector>

namespace NetSentinel {

struct QuarantineEntry {
    std::wstring originalPath;    // Where the file originally lived
    std::wstring quarantinePath;  // Where it was moved inside the vault
    std::wstring reason;          // Why it was quarantined
    FILETIME     timestamp;       // When it was quarantined
};

class Quarantine {
public:
    static Quarantine& Instance();

    // Initialize quarantine vault directory
    bool Initialize(const std::wstring& vaultDirectory);

    // Move a suspicious file into the quarantine vault
    // Returns true and fills entry on success
    bool QuarantineFile(const std::wstring& filePath,
                        const std::wstring& reason,
                        QuarantineEntry&    outEntry);

    // Restore a quarantined file back to its original location
    bool RestoreFile(const std::wstring& quarantinePath);

    // Permanently delete a quarantined file
    bool DeleteQuarantined(const std::wstring& quarantinePath);

    // List all currently quarantined files
    std::vector<QuarantineEntry> ListEntries() const;

    // Check if a file path is already inside the vault
    bool IsQuarantined(const std::wstring& originalPath) const;

    const std::wstring& GetVaultPath() const { return m_vaultDir; }

private:
    Quarantine()  = default;
    ~Quarantine() = default;
    Quarantine(const Quarantine&) = delete;
    Quarantine& operator=(const Quarantine&) = delete;

    std::wstring GenerateVaultName(const std::wstring& originalPath);
    bool         WriteMetadata(const QuarantineEntry& entry);
    bool         ReadMetadata(const std::wstring& metaFile, QuarantineEntry& out);

    std::wstring                m_vaultDir;
    std::vector<QuarantineEntry> m_entries;
    bool                         m_initialized{ false };
};

} // namespace NetSentinel
