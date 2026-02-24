#pragma once
// file_monitor.h — uses Windows native HANDLE threads (no std::thread / pthread needed)
#include <windows.h>
#include <string>
#include <vector>
#include <functional>
#include <atomic>

namespace NetSentinel {

enum class FileThreatType {
    STEGANOGRAPHY,       // Non-exe file contains PE/script header
    SUSPICIOUS_DROP,     // New executable in Downloads/Temp/Desktop
    STARTUP_PERSISTENCE, // New file added to startup folder
    SCRIPT_DROP,         // .ps1/.bat/.vbs dropped in user folder
};

struct FileThreat {
    FileThreatType type;
    std::wstring   filePath;
    std::wstring   detailMessage;
    std::wstring   folderWatched;
};

using FileThreatCallback = std::function<void(const FileThreat&)>;

class FileMonitor {
public:
    FileMonitor();
    ~FileMonitor();

    void Start(FileThreatCallback callback);
    void Stop();
    void ScanFile(const std::wstring& fullPath, const std::wstring& folder, bool isStartupScan = false);

private:
    void WatchFolder(const std::wstring& folder);
    void ScanExistingFiles(const std::wstring& folder);
    bool IsSteganography(const std::wstring& filePath, const std::wstring& ext);

    std::atomic<bool>      m_running{ false };
    FileThreatCallback     m_callback;
    std::vector<HANDLE>    m_threads;   // Windows HANDLE instead of std::thread

    static std::vector<std::wstring> GetWatchFolders();

    // Thread entry point (Windows API requires static DWORD WINAPI)
    struct WatchArgs { FileMonitor* self; std::wstring folder; };
    static DWORD WINAPI WatchThreadProc(LPVOID param);
};

} // namespace NetSentinel
