// file_monitor.cpp — MinGW 6.3 compatible, Windows native threads
#include "monitor/file_monitor.h"
#include "utils/logger.h"
#include <algorithm>
#include <shlobj.h>
#include <sstream>

#pragma comment(lib, "shell32.lib")

namespace NetSentinel {

// ── MinGW 6.3 compatible wstring number helper ────────────────────────────────
namespace {
template<typename T>
std::wstring ToWStr(T v) { std::wostringstream o; o << v; return o.str(); }
}

static const std::vector<std::wstring> kDangerousExts = {
    L".exe", L".dll", L".bat", L".cmd", L".ps1",
    L".vbs", L".js",  L".hta", L".scr", L".pif",
    L".com", L".msi", L".lnk"
};
static const std::vector<std::wstring> kImageExts = {
    L".jpg", L".jpeg", L".png", L".gif", L".webp", L".bmp", L".tiff"
};

// ── Get folders to watch — MinGW 6.3 compatible ───────────────────────────────
std::vector<std::wstring> FileMonitor::GetWatchFolders() {
    std::vector<std::wstring> folders;

    // Downloads: %USERPROFILE%\Downloads  (works on all Windows versions)
    wchar_t userProfile[MAX_PATH] = {};
    if (GetEnvironmentVariableW(L"USERPROFILE", userProfile, MAX_PATH)) {
        folders.push_back(std::wstring(userProfile) + L"\\Downloads");
    }

    // Desktop via CSIDL (works in MinGW 6.3)
    wchar_t desk[MAX_PATH] = {};
    if (SUCCEEDED(SHGetFolderPathW(nullptr, CSIDL_DESKTOPDIRECTORY, nullptr, 0, desk)))
        folders.push_back(desk);

    // Temp via GetTempPath
    wchar_t tmp[MAX_PATH] = {};
    if (GetTempPathW(MAX_PATH, tmp)) folders.push_back(tmp);

    // Startup — mark with [STARTUP] suffix so WatchFolder can flag differently
    wchar_t startup[MAX_PATH] = {};
    if (SUCCEEDED(SHGetFolderPathW(nullptr, CSIDL_STARTUP, nullptr, 0, startup)))
        folders.push_back(std::wstring(startup) + L"[STARTUP]");

    return folders;
}

FileMonitor::FileMonitor()  = default;
FileMonitor::~FileMonitor() { Stop(); }

// ── Static Windows thread entry point ────────────────────────────────────────
DWORD WINAPI FileMonitor::WatchThreadProc(LPVOID param) {
    auto* args = static_cast<WatchArgs*>(param);
    args->self->WatchFolder(args->folder);
    delete args;
    return 0;
}

void FileMonitor::Start(FileThreatCallback callback) {
    m_callback = callback;
    m_running  = true;

    auto folders = GetWatchFolders();
    for (const auto& folder : folders) {
        auto* args = new WatchArgs{ this, folder };
        HANDLE h = CreateThread(nullptr, 0, WatchThreadProc, args, 0, nullptr);
        if (h) m_threads.push_back(h);
    }

    Logger::Instance().Info(L"[FileMonitor] Watching " +
        ToWStr(folders.size()) + L" folders for malware drops & steganography");
}

void FileMonitor::Stop() {
    m_running = false;
    if (!m_threads.empty()) {
        WaitForMultipleObjects(
            static_cast<DWORD>(m_threads.size()),
            m_threads.data(), TRUE, 3000);
        for (HANDLE h : m_threads) CloseHandle(h);
        m_threads.clear();
    }
}

void FileMonitor::WatchFolder(const std::wstring& folderIn) {
    bool isStartup = (folderIn.find(L"[STARTUP]") != std::wstring::npos);
    std::wstring folder = folderIn;
    if (isStartup) folder = folder.substr(0, folder.size() - 9);

    HANDLE hDir = CreateFileW(
        folder.c_str(),
        FILE_LIST_DIRECTORY,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr, OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OVERLAPPED,
        nullptr);
    if (hDir == INVALID_HANDLE_VALUE) return;

    OVERLAPPED ov = {};
    ov.hEvent = CreateEvent(nullptr, TRUE, FALSE, nullptr);
    if (!ov.hEvent) { CloseHandle(hDir); return; }

    // INITIAL SCAN: Check files already present in this folder
    ScanExistingFiles(folderIn);

    uint8_t buffer[65536] = {};

    while (m_running) {
        DWORD bytes = 0;
        ResetEvent(ov.hEvent);

        BOOL ok = ReadDirectoryChangesW(
            hDir, buffer, sizeof(buffer), FALSE,
            FILE_NOTIFY_CHANGE_FILE_NAME | FILE_NOTIFY_CHANGE_LAST_WRITE,
            &bytes, &ov, nullptr);

        if (!ok && GetLastError() != ERROR_IO_PENDING) break;

        DWORD w = WaitForSingleObject(ov.hEvent, 500);
        if (w == WAIT_TIMEOUT) continue;
        if (w != WAIT_OBJECT_0) break;
        if (!GetOverlappedResult(hDir, &ov, &bytes, FALSE)) break;
        if (bytes == 0) continue;

        auto* info = reinterpret_cast<FILE_NOTIFY_INFORMATION*>(buffer);
        do {
            if (info->Action == FILE_ACTION_ADDED ||
                info->Action == FILE_ACTION_RENAMED_NEW_NAME) {

                std::wstring name(info->FileName, info->FileNameLength / sizeof(wchar_t));
                std::wstring full = folder + L"\\" + name;

                if (isStartup) {
                    FileThreat t;
                    t.type          = FileThreatType::STARTUP_PERSISTENCE;
                    t.filePath      = full;
                    t.folderWatched = folder;
                    t.detailMessage = L"STARTUP PERSISTENCE: New file set to run on every boot: " + name;
                    if (m_callback) m_callback(t);
                }
                ScanFile(full, folder);
            }
            if (info->NextEntryOffset == 0) break;
            info = reinterpret_cast<FILE_NOTIFY_INFORMATION*>(
                reinterpret_cast<uint8_t*>(info) + info->NextEntryOffset);
        } while (true);
    }

    CloseHandle(ov.hEvent);
    CloseHandle(hDir);
}

void FileMonitor::ScanExistingFiles(const std::wstring& folderIn) {
    bool isStartup = (folderIn.find(L"[STARTUP]") != std::wstring::npos);
    std::wstring folder = folderIn;
    if (isStartup) folder = folder.substr(0, folder.size() - 9);

    std::wstring searchPath = folder + L"\\*";
    WIN32_FIND_DATAW fd;
    HANDLE hFind = FindFirstFileW(searchPath.c_str(), &fd);
    if (hFind == INVALID_HANDLE_VALUE) return;

    do {
        if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
            std::wstring fullPath = folder + L"\\" + fd.cFileName;
            // Scan with isStartupScan = true
            ScanFile(fullPath, folder, true);
        }
    } while (FindNextFileW(hFind, &fd) != 0 && m_running);

    FindClose(hFind);
}

void FileMonitor::ScanFile(const std::wstring& fullPath, const std::wstring& folder, bool isStartupScan) {
    std::wstring ext;
    size_t dot = fullPath.rfind(L'.');
    if (dot != std::wstring::npos) {
        ext = fullPath.substr(dot);
        std::transform(ext.begin(), ext.end(), ext.begin(), ::towlower);
    }
    std::wstring name = fullPath.substr(fullPath.rfind(L'\\') + 1);

    // 1. Steganography: image extension but PE/wrong content
    bool isImage = std::find(kImageExts.begin(), kImageExts.end(), ext) != kImageExts.end();
    if (isImage && IsSteganography(fullPath, ext)) {
        FileThreat t;
        t.type          = FileThreatType::STEGANOGRAPHY;
        t.filePath      = fullPath;
        t.folderWatched = folder;
        t.detailMessage = L"STEGANOGRAPHY ALERT: '" + name +
                          L"' has an image extension but contains executable code (MZ PE header). "
                          L"Malware is hidden inside! Location: (" + fullPath + L")";
        if (m_callback) m_callback(t);
        return;
    }

    // Don't flag existing executable files in Downloads as "DROPS" during startup,
    // otherwise it will alert on every old installer the user has ever downloaded.
    if (isStartupScan) return;

    // 2. Dangerous executable/script drop in user folder
    bool isDangerous = std::find(kDangerousExts.begin(), kDangerousExts.end(), ext)
                       != kDangerousExts.end();
    if (isDangerous) {
        FileThreatType type =
            (ext==L".ps1"||ext==L".bat"||ext==L".vbs"||
             ext==L".cmd"||ext==L".js" ||ext==L".hta")
            ? FileThreatType::SCRIPT_DROP
            : FileThreatType::SUSPICIOUS_DROP;
        FileThreat t;
        t.type          = type;
        t.filePath      = fullPath;
        t.folderWatched = folder;
        t.detailMessage = L"MALWARE DROP: Executable/script appeared in user folder: '" +
                          name + L"' (" + ext + L") — possibly downloaded via WhatsApp, "
                          L"email attachment, or browser. Location: (" + fullPath + L")";
        if (m_callback) m_callback(t);
    }
}

bool FileMonitor::IsSteganography(const std::wstring& filePath, const std::wstring& ext) {
    Sleep(300); // let file finish writing

    // Use CreateFileW + ReadFile — works with wide paths in MinGW (unlike std::ifstream)
    HANDLE hFile = CreateFileW(filePath.c_str(), GENERIC_READ,
                               FILE_SHARE_READ, nullptr,
                               OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) return false;

    uint8_t header[8] = {};
    DWORD read = 0;
    ReadFile(hFile, header, sizeof(header), &read, nullptr);
    CloseHandle(hFile);
    if (read < 4) return false;

    // MZ header (0x4D 0x5A) inside ANY image = Windows PE exe disguised as image
    if (header[0] == 0x4D && header[1] == 0x5A) return true;

    // Validate the file matches its actual claimed format magic bytes
    if (ext == L".jpg" || ext == L".jpeg")
        return !(header[0]==0xFF && header[1]==0xD8 && header[2]==0xFF);
    if (ext == L".png")
        return !(header[0]==0x89 && header[1]==0x50 && header[2]==0x4E && header[3]==0x47);
    if (ext == L".gif")
        return !(header[0]==0x47 && header[1]==0x49 && header[2]==0x46);

    return false;
}

} // namespace NetSentinel
