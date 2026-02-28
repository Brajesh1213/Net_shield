// quarantine.cpp — File quarantine vault implementation
#include "quarantine.h"
#include <shlobj.h>
#include <sstream>
#include <iomanip>
#include <algorithm>

namespace Asthak {

Quarantine& Quarantine::Instance() {
    static Quarantine instance;
    return instance;
}

bool Quarantine::Initialize(const std::wstring& vaultDirectory) {
    m_vaultDir = vaultDirectory;

    // Create the vault directory tree
    if (!CreateDirectoryW(m_vaultDir.c_str(), nullptr)) {
        if (GetLastError() != ERROR_ALREADY_EXISTS) return false;
    }

    // Reload existing entries from metadata files
    WIN32_FIND_DATAW fd;
    std::wstring pattern = m_vaultDir + L"\\*.meta";
    HANDLE hFind = FindFirstFileW(pattern.c_str(), &fd);
    if (hFind != INVALID_HANDLE_VALUE) {
        do {
            QuarantineEntry entry;
            if (ReadMetadata(m_vaultDir + L"\\" + fd.cFileName, entry)) {
                m_entries.push_back(entry);
            }
        } while (FindNextFileW(hFind, &fd));
        FindClose(hFind);
    }

    m_initialized = true;
    return true;
}

bool Quarantine::QuarantineFile(const std::wstring& filePath,
                                 const std::wstring& reason,
                                 QuarantineEntry&    outEntry) {
    if (!m_initialized) return false;

    // Build destination path inside vault
    std::wstring vaultName = GenerateVaultName(filePath);
    std::wstring destPath  = m_vaultDir + L"\\" + vaultName;

    // Move the file (MoveFileEx handles cross-volume via copy+delete)
    if (!MoveFileExW(filePath.c_str(), destPath.c_str(),
                     MOVEFILE_REPLACE_EXISTING | MOVEFILE_COPY_ALLOWED)) {
        return false;
    }

    // Build entry
    outEntry.originalPath   = filePath;
    outEntry.quarantinePath = destPath;
    outEntry.reason         = reason;
    GetSystemTimeAsFileTime(&outEntry.timestamp);

    WriteMetadata(outEntry);
    m_entries.push_back(outEntry);
    return true;
}

bool Quarantine::RestoreFile(const std::wstring& quarantinePath) {
    auto it = std::find_if(m_entries.begin(), m_entries.end(),
        [&quarantinePath](const QuarantineEntry& e){
            return e.quarantinePath == quarantinePath;
        });
    if (it == m_entries.end()) return false;

    if (!MoveFileExW(quarantinePath.c_str(), it->originalPath.c_str(),
                     MOVEFILE_REPLACE_EXISTING | MOVEFILE_COPY_ALLOWED)) {
        return false;
    }

    // Remove metadata file
    std::wstring metaPath = quarantinePath + L".meta";
    DeleteFileW(metaPath.c_str());
    m_entries.erase(it);
    return true;
}

bool Quarantine::DeleteQuarantined(const std::wstring& quarantinePath) {
    auto it = std::find_if(m_entries.begin(), m_entries.end(),
        [&quarantinePath](const QuarantineEntry& e){
            return e.quarantinePath == quarantinePath;
        });
    if (it == m_entries.end()) return false;

    if (!DeleteFileW(quarantinePath.c_str())) return false;

    std::wstring metaPath = quarantinePath + L".meta";
    DeleteFileW(metaPath.c_str());
    m_entries.erase(it);
    return true;
}

std::vector<QuarantineEntry> Quarantine::ListEntries() const {
    return m_entries;
}

bool Quarantine::IsQuarantined(const std::wstring& originalPath) const {
    return std::any_of(m_entries.begin(), m_entries.end(),
        [&originalPath](const QuarantineEntry& e){
            return e.originalPath == originalPath;
        });
}

// ─── Private helpers ───────────────────────────────────────────────────────

std::wstring Quarantine::GenerateVaultName(const std::wstring& originalPath) {
    // Extract filename portion
    size_t pos = originalPath.find_last_of(L"\\/");
    std::wstring filename = (pos == std::wstring::npos) ? originalPath
                                                        : originalPath.substr(pos + 1);
    // Append timestamp to ensure uniqueness
    SYSTEMTIME st;
    GetLocalTime(&st);
    std::wostringstream oss;
    oss << st.wYear << std::setw(2) << std::setfill(L'0') << st.wMonth
        << std::setw(2) << std::setfill(L'0') << st.wDay
        << L"_" << std::setw(2) << std::setfill(L'0') << st.wHour
        << std::setw(2) << std::setfill(L'0') << st.wMinute
        << std::setw(2) << std::setfill(L'0') << st.wSecond
        << L"_" << filename;
    return oss.str();
}

bool Quarantine::WriteMetadata(const QuarantineEntry& entry) {
    std::wstring metaPath = entry.quarantinePath + L".meta";
    HANDLE hFile = CreateFileW(metaPath.c_str(), GENERIC_WRITE, 0,
                               nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) return false;

    std::wstring content = L"original=" + entry.originalPath + L"\n"
                         + L"reason="   + entry.reason        + L"\n";
    DWORD written = 0;
    // Write as UTF-16 LE (native wchar_t)
    WriteFile(hFile, content.c_str(),
              static_cast<DWORD>(content.size() * sizeof(wchar_t)),
              &written, nullptr);
    CloseHandle(hFile);
    return true;
}

bool Quarantine::ReadMetadata(const std::wstring& metaFile, QuarantineEntry& out) {
    HANDLE hFile = CreateFileW(metaFile.c_str(), GENERIC_READ, FILE_SHARE_READ,
                               nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) return false;

    DWORD fileSize = GetFileSize(hFile, nullptr);
    if (fileSize == 0 || fileSize == INVALID_FILE_SIZE) {
        CloseHandle(hFile);
        return false;
    }

    std::wstring content(fileSize / sizeof(wchar_t), L'\0');
    DWORD bytesRead = 0;
    ReadFile(hFile, &content[0], fileSize, &bytesRead, nullptr);
    CloseHandle(hFile);

    // Simple key=value parsing
    std::wistringstream ss(content);
    std::wstring line;
    while (std::getline(ss, line)) {
        size_t eq = line.find(L'=');
        if (eq == std::wstring::npos) continue;
        std::wstring key = line.substr(0, eq);
        std::wstring val = line.substr(eq + 1);
        if (!val.empty() && val.back() == L'\r') val.pop_back();
        if (key == L"original") out.originalPath = val;
        else if (key == L"reason") out.reason     = val;
    }

    // Quarantine path is the meta file minus ".meta"
    out.quarantinePath = metaFile.substr(0, metaFile.size() - 5);
    return !out.originalPath.empty();
}

} // namespace Asthak
