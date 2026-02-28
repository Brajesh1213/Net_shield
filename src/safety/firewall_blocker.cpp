// firewall_blocker.cpp
#include "firewall_blocker.h"
#include "src/utils/logger.h"
#include <sstream>
#include <vector>
#include <windows.h>

namespace Asthak {

FirewallBlocker& FirewallBlocker::Instance() {
    static FirewallBlocker instance;
    return instance;
}

FirewallBlocker::~FirewallBlocker() {
    Shutdown();
}

bool FirewallBlocker::Initialize() {
    if (initialized_) {
        return true;
    }
    
    // We are using netsh, so no complex initialization needed.
    // Just verify we can execute commands (admin check is done in main).
    initialized_ = true;
    Logger::Instance().Info(L"FirewallBlocker: Initialized (using netsh)");
    return true;
}

void FirewallBlocker::Shutdown() {
    // Optional: Clean up rules created by this session
    // For now, we leave them to be persistent or manually cleaned
    initialized_ = false;
}

std::wstring FirewallBlocker::GenerateRuleName(const std::wstring& ip, uint16_t port, Protocol protocol) {
    std::wostringstream oss;
    oss << L"Asthak_Block_" << ip << L"_" << port;
    if (protocol == Protocol::TCP) {
        oss << L"_TCP";
    } else if (protocol == Protocol::UDP) {
        oss << L"_UDP";
    }
    return oss.str();
}

std::wstring FirewallBlocker::GenerateProcessRuleName(const std::wstring& processPath) {
    std::wostringstream oss;
    oss << L"Asthak_Block_Process_";
    // Extract filename from path
    size_t lastSlash = processPath.find_last_of(L"\\");
    if (lastSlash != std::wstring::npos) {
        oss << processPath.substr(lastSlash + 1);
    } else {
        oss << processPath;
    }
    return oss.str();
}

bool ExecuteCommand(const std::wstring& command) {
    // Use ShellExecute or CreateProcess to run netsh (hidden)
    // For simplicity/reliability in this context, using _wsystem is easiest but shows a window.
    // Better to use CreateProcess to hide the window.
    
    STARTUPINFOW si;
    PROCESS_INFORMATION pi;
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE; // Hide the window
    ZeroMemory(&pi, sizeof(pi));

    // command needs to be mutable for CreateProcess
    std::vector<wchar_t> cmdVec(command.begin(), command.end());
    cmdVec.push_back(0);

    if (!CreateProcessW(NULL, cmdVec.data(), NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
        return false;
    }

    // Wait for the command to complete
    WaitForSingleObject(pi.hProcess, 5000); // 5 sec timeout
    
    DWORD exitCode = 0;
    GetExitCodeProcess(pi.hProcess, &exitCode);

    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    return exitCode == 0;
}


bool FirewallBlocker::BlockIP(const std::wstring& ip, uint16_t port, Protocol protocol, const std::wstring& reason) {
    if (!initialized_ && !Initialize()) {
        return false;
    }

    std::wstring ruleName = GenerateRuleName(ip, port, protocol);
    std::wstring protocolStr = (protocol == Protocol::TCP) ? L"TCP" : L"UDP";
    
    // Command: netsh advfirewall firewall add rule name="..." dir=out action=block remoteip=... protocol=... remoteport=...
    std::wostringstream cmd;
    cmd << L"netsh advfirewall firewall add rule name=\"" << ruleName << L"\""
        << L" dir=out action=block"
        << L" remoteip=" << ip
        << L" protocol=" << protocolStr;
        
    if (port != 0) {
        cmd << L" remoteport=" << port;
    }

    Logger::Instance().Info(L"FirewallBlocker: Executing block command for IP " + ip);
    
    if (ExecuteCommand(cmd.str())) {
         Logger::Instance().Info(L"FirewallBlocker: Successfully blocked IP " + ip);
         return true;
    } else {
         Logger::Instance().Error(L"FirewallBlocker: Failed to execute block command for IP " + ip);
         return false;
    }
}

bool FirewallBlocker::BlockProcess(const std::wstring& processPath, const std::wstring& reason) {
    if (!initialized_ && !Initialize()) {
        return false;
    }
    
    std::wstring ruleName = GenerateProcessRuleName(processPath);
    
    // Command: netsh advfirewall firewall add rule name="..." dir=out action=block program="..."
    std::wostringstream cmd;
    cmd << L"netsh advfirewall firewall add rule name=\"" << ruleName << L"\""
        << L" dir=out action=block"
        << L" program=\"" << processPath << L"\"";

    Logger::Instance().Info(L"FirewallBlocker: Executing block command for process " + processPath);

    if (ExecuteCommand(cmd.str())) {
         Logger::Instance().Info(L"FirewallBlocker: Successfully blocked process " + processPath);
         return true;
    } else {
         Logger::Instance().Error(L"FirewallBlocker: Failed to execute block command for process " + processPath);
         return false;
    }
}

bool FirewallBlocker::BlockConnection(const Connection& conn, const std::wstring& reason) {
    if (conn.remoteIp.empty() || conn.remoteIp == L"*" || conn.remotePort == 0) {
        // For UDP or incomplete connection info, try blocking by process
        if (!conn.processPath.empty()) {
            return BlockProcess(conn.processPath, reason);
        }
        return false;
    }
    
    return BlockIP(conn.remoteIp, conn.remotePort, conn.protocol, reason);
}

bool FirewallBlocker::UnblockIP(const std::wstring& ip) {
    // This is trickier because we need the rule name. 
    // Ideally we'd store the rule names we created. 
    // For now, this is a best-effort that might fail if we don't know the exact rule name/port used.
    // A better approach would be to delete all rules containing the IP in the name, 
    // but netsh delete requires exact name match or rule properties.
    
    // Attempt to delete rules by IP (netsh doesn't support delete by IP directly easily without name)
    // We will need to know the rule name. 
    // TODO: Improve unblock logic by tracking created rules.
    return false; 
}

bool FirewallBlocker::UnblockProcess(const std::wstring& processPath) {
    if (!initialized_) return false;

    std::wstring ruleName = GenerateProcessRuleName(processPath);
    std::wostringstream cmd;
    cmd << L"netsh advfirewall firewall delete rule name=\"" << ruleName << L"\"";
    
    return ExecuteCommand(cmd.str());
}

bool FirewallBlocker::IsIPBlocked(const std::wstring& ip) {
    return false;
}

} // namespace Asthak

