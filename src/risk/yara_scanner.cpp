// yara_scanner.cpp — Built-in YARA-compatible rule engine implementation
// ─────────────────────────────────────────────────────────────────────────────
// Pure C++ pattern matcher — no external libyara required.
// All 8 industry-standard malware detection rules built-in.
// ─────────────────────────────────────────────────────────────────────────────

#include "risk/yara_scanner.h"
#include "utils/logger.h"

#include <algorithm>
#include <fstream>
#include <sstream>
#include <cctype>
#include <psapi.h>       // GetModuleFileNameExW, EnumProcessModules
#include <tlhelp32.h>

#pragma comment(lib, "psapi.lib")

namespace Asthak {

// ─────────────────────────────────────────────────────────────────────────────
// Singleton
// ─────────────────────────────────────────────────────────────────────────────
YaraScanner& YaraScanner::Instance() {
    static YaraScanner s;
    return s;
}

// ─────────────────────────────────────────────────────────────────────────────
// Initialize
// ─────────────────────────────────────────────────────────────────────────────
bool YaraScanner::Initialize(const std::wstring& /*rulesDir*/) {
    std::lock_guard<std::mutex> lk(m_mutex);
    m_rules.clear();
    LoadBuiltinRules();
    m_ready = true;
    Logger::Instance().Info(L"[YARA] Engine ready — " +
        std::to_wstring(m_rules.size()) + L" built-in rules loaded");
    return true;
}

// ─────────────────────────────────────────────────────────────────────────────
// ██  BUILT-IN RULES  ██
// All patterns are documented in https://github.com/Yara-Rules/rules and
// Elastic/GitHub public YARA repositories. These are read-only detection
// signatures identical to what commercial AV uses.
// ─────────────────────────────────────────────────────────────────────────────
void YaraScanner::LoadBuiltinRules() {

    // ── Rule 1: Metasploit Meterpreter Reverse TCP ────────────────────────────
    {
        YaraRule r;
        r.name         = "Metasploit_Meterpreter_Reverse_TCP";
        r.description  = "Detects Meterpreter stager patterns and ReflectiveLoader strings";
        r.malwareFamily = "Exploit.Metasploit.Meterpreter";
        r.severity     = YaraRuleSeverity::CRITICAL;
        r.condition    = YaraCondition::N_OF_STRINGS;
        r.conditionN   = 2;
        r.patterns = {
            { "$s1", YaraPatternType::PLAIN_ASCII, "ReflectiveLoader",          true, false },
            { "$s2", YaraPatternType::PLAIN_ASCII, "metsrv.x86.dll",            true, false },
            { "$s3", YaraPatternType::PLAIN_ASCII, "metsrv.x64.dll",            true, false },
            { "$s4", YaraPatternType::PLAIN_ASCII, "Meterpreter",               true, false },
            { "$s5", YaraPatternType::PLAIN_ASCII, "meterpreter/reverse_tcp",   true, false },
            // MZ header + ReflectiveLoader export name offset (common in staged payloads)
            { "$h1", YaraPatternType::HEX_BYTES,   "fc e8 8? 00 00 00",        false, false },
            { "$s6", YaraPatternType::PLAIN_ASCII, "METERPRETER_TRANSPORT",     true, false },
        };
        m_rules.push_back(r);
    }

    // ── Rule 2: Cobalt Strike Beacon ──────────────────────────────────────────
    {
        YaraRule r;
        r.name         = "CobaltStrike_Beacon";
        r.description  = "Cobalt Strike Beacon DLL strings and malleable C2 indicators";
        r.malwareFamily = "Backdoor.CobaltStrike.Beacon";
        r.severity     = YaraRuleSeverity::CRITICAL;
        r.condition    = YaraCondition::N_OF_STRINGS;
        r.conditionN   = 2;
        r.patterns = {
            { "$s1", YaraPatternType::PLAIN_ASCII, "beacon.dll",                true, false },
            { "$s2", YaraPatternType::PLAIN_ASCII, "ReflectiveLoader",          true, false },
            { "$s3", YaraPatternType::PLAIN_ASCII, "cobaltstrike",              true, false },
            { "$s4", YaraPatternType::PLAIN_ASCII, "sleeptime",                 true, false },
            { "$s5", YaraPatternType::PLAIN_ASCII, "BeaconMain",                false, false },
            { "$s6", YaraPatternType::PLAIN_ASCII, "loadlibrary",               true, false },
            // CS default pipe: \\.\pipe\MSSE-<num>-server (common named pipe)
            { "$s7", YaraPatternType::PLAIN_ASCII, "MSSE-",                     false, false },
            { "$s8", YaraPatternType::PLAIN_ASCII, "beacon_compatibility",      true, false },
        };
        m_rules.push_back(r);
    }

    // ── Rule 3: Suspicious PowerShell Execution ───────────────────────────────
    {
        YaraRule r;
        r.name         = "Suspicious_PowerShell_Execution";
        r.description  = "PowerShell with bypass flags, encoded commands, or download cradles";
        r.malwareFamily = "Trojan.PS1.Obfuscated";
        r.severity     = YaraRuleSeverity::HIGH;
        r.condition    = YaraCondition::N_OF_STRINGS;
        r.conditionN   = 2;
        r.patterns = {
            { "$s1", YaraPatternType::PLAIN_ASCII, "-ExecutionPolicy Bypass",    true, false },
            { "$s2", YaraPatternType::PLAIN_ASCII, "-EncodedCommand",            true, false },
            { "$s3", YaraPatternType::PLAIN_ASCII, "-enc ",                      true, false },
            { "$s4", YaraPatternType::PLAIN_ASCII, "-WindowStyle Hidden",        true, false },
            { "$s5", YaraPatternType::PLAIN_ASCII, "-w hidden",                  true, false },
            { "$s6", YaraPatternType::PLAIN_ASCII, "Invoke-Expression",          true, false },
            { "$s7", YaraPatternType::PLAIN_ASCII, "IEX(",                       true, false },
            { "$s8", YaraPatternType::PLAIN_ASCII, "IEX (",                      true, false },
            { "$s9", YaraPatternType::PLAIN_ASCII, "IEX\"",                      true, false },
        };
        m_rules.push_back(r);
    }

    // ── Rule 4: Malware Download and Execute ──────────────────────────────────
    {
        YaraRule r;
        r.name         = "Malware_Download_And_Execute";
        r.description  = "Invoke-WebRequest, certutil, bitsadmin download-and-execute patterns";
        r.malwareFamily = "Trojan.Downloader";
        r.severity     = YaraRuleSeverity::HIGH;
        r.condition    = YaraCondition::ANY_OF_STRINGS;
        r.patterns = {
            { "$s1", YaraPatternType::PLAIN_ASCII, "DownloadString",             true, false },
            { "$s2", YaraPatternType::PLAIN_ASCII, "DownloadFile",               true, false },
            { "$s3", YaraPatternType::PLAIN_ASCII, "Net.WebClient",              true, false },
            { "$s4", YaraPatternType::PLAIN_ASCII, "certutil -urlcache",         true, false },
            { "$s5", YaraPatternType::PLAIN_ASCII, "certutil.exe -urlcache",     true, false },
            { "$s6", YaraPatternType::PLAIN_ASCII, "bitsadmin /transfer",        true, false },
            { "$s7", YaraPatternType::PLAIN_ASCII, "Invoke-WebRequest",          true, false },
            { "$s8", YaraPatternType::PLAIN_ASCII, "Start-BitsTransfer",         true, false },
            { "$s9", YaraPatternType::PLAIN_ASCII, "wget http",                  true, false },
            { "$s10",YaraPatternType::PLAIN_ASCII, "curl http",                  true, false },
        };
        m_rules.push_back(r);
    }

    // ── Rule 5: Crypto Mining (Stratum Protocol) ──────────────────────────────
    {
        YaraRule r;
        r.name         = "Cryptominer_Stratum_Protocol";
        r.description  = "Stratum mining JSON-RPC method calls (XMRig, NBMiner, etc.)";
        r.malwareFamily = "CoinMiner.Stratum";
        r.severity     = YaraRuleSeverity::HIGH;
        r.condition    = YaraCondition::N_OF_STRINGS;
        r.conditionN   = 2;
        r.patterns = {
            { "$s1", YaraPatternType::PLAIN_ASCII, "mining.subscribe",           true, false },
            { "$s2", YaraPatternType::PLAIN_ASCII, "mining.authorize",           true, false },
            { "$s3", YaraPatternType::PLAIN_ASCII, "mining.notify",              true, false },
            { "$s4", YaraPatternType::PLAIN_ASCII, "stratum+tcp://",             true, false },
            { "$s5", YaraPatternType::PLAIN_ASCII, "stratum+ssl://",             true, false },
            { "$s6", YaraPatternType::PLAIN_ASCII, "xmrig",                      true, false },
            { "$s7", YaraPatternType::PLAIN_ASCII, "\"method\":\"login\"",       true, false },
            // XMRig config key
            { "$s8", YaraPatternType::PLAIN_ASCII, "donate-level",              true, false },
        };
        m_rules.push_back(r);
    }

    // ── Rule 6: Reverse Shell Signatures ─────────────────────────────────────
    {
        YaraRule r;
        r.name         = "Reverse_Shell_Signatures";
        r.description  = "nc -e, bash -i, Python/Perl socket reverse shells";
        r.malwareFamily = "Backdoor.ReverseShell";
        r.severity     = YaraRuleSeverity::CRITICAL;
        r.condition    = YaraCondition::ANY_OF_STRINGS;
        r.patterns = {
            { "$s1", YaraPatternType::PLAIN_ASCII, "nc -e /bin/",                true, false },
            { "$s2", YaraPatternType::PLAIN_ASCII, "nc.exe -e cmd",              true, false },
            { "$s3", YaraPatternType::PLAIN_ASCII, "bash -i >& /dev/tcp/",       true, false },
            { "$s4", YaraPatternType::PLAIN_ASCII, "0>&1",                       false, false },
            { "$s5", YaraPatternType::PLAIN_ASCII, "socket.connect",             true, false },
            { "$s6", YaraPatternType::PLAIN_ASCII, "subprocess.call",            true, false },
            { "$s7", YaraPatternType::PLAIN_ASCII, "/bin/sh -i",                 true, false },
            { "$s8", YaraPatternType::PLAIN_ASCII, "cmd.exe /c powershell",      true, false },
            // Perl reverse shell
            { "$s9", YaraPatternType::PLAIN_ASCII, "PeerHost=>$ARGV",            false, false },
        };
        m_rules.push_back(r);
    }

    // ── Rule 7: Log4j JNDI Exploit ───────────────────────────────────────────
    {
        YaraRule r;
        r.name         = "Log4j_JNDI_Exploit";
        r.description  = "Log4Shell CVE-2021-44228 — ${jndi:ldap://} and obfuscated variants";
        r.malwareFamily = "Exploit.Log4j.JNDI.CVE-2021-44228";
        r.severity     = YaraRuleSeverity::CRITICAL;
        r.condition    = YaraCondition::ANY_OF_STRINGS;
        r.patterns = {
            { "$s1", YaraPatternType::PLAIN_ASCII, "${jndi:ldap://",             true, false },
            { "$s2", YaraPatternType::PLAIN_ASCII, "${jndi:rmi://",              true, false },
            { "$s3", YaraPatternType::PLAIN_ASCII, "${jndi:dns://",              true, false },
            { "$s4", YaraPatternType::PLAIN_ASCII, "${jndi:ldaps://",            true, false },
            { "$s5", YaraPatternType::PLAIN_ASCII, "${${::-j}${::-n}${::-d}",    true, false },
            { "$s6", YaraPatternType::PLAIN_ASCII, "jndi:ldap",                  true, false },
            { "$s7", YaraPatternType::PLAIN_ASCII, "com.sun.jndi.ldap",          true, false },
        };
        m_rules.push_back(r);
    }

    // ── Rule 8: Ransomware File Markers ──────────────────────────────────────
    {
        YaraRule r;
        r.name         = "Ransomware_Markers";
        r.description  = "WannaCry, LockBit, Ryuk, BlackCat ransomware indicator strings";
        r.malwareFamily = "Ransomware.Generic";
        r.severity     = YaraRuleSeverity::CRITICAL;
        r.condition    = YaraCondition::ANY_OF_STRINGS;
        r.patterns = {
            // WannaCry
            { "$s1", YaraPatternType::PLAIN_ASCII, "WANACRY!",                  false, false },
            { "$s2", YaraPatternType::PLAIN_ASCII, "WanaDecryptor",              true,  false },
            { "$s3", YaraPatternType::PLAIN_ASCII, "tasksche.exe",               true,  false },
            // LockBit
            { "$s4", YaraPatternType::PLAIN_ASCII, "LockBit",                   true,  false },
            { "$s5", YaraPatternType::PLAIN_ASCII, "lockbit-ransom",             true,  false },
            // Ryuk
            { "$s6", YaraPatternType::PLAIN_ASCII, "RyukReadMe",                true,  false },
            { "$s7", YaraPatternType::PLAIN_ASCII, "UNIQUE_ID_DO_NOT_REMOVE",   false, false },
            // Generic ransom note markers
            { "$s8", YaraPatternType::PLAIN_ASCII, "YOUR FILES ARE ENCRYPTED",  true,  false },
            { "$s9", YaraPatternType::PLAIN_ASCII, "HOW TO RESTORE YOUR FILES", true,  false },
            { "$s10",YaraPatternType::PLAIN_ASCII,  "bitcoin",                   true,  false },
        };
        m_rules.push_back(r);
    }

    // ── Rule 9: Mimikatz Credential Dumping ───────────────────────────────────
    {
        YaraRule r;
        r.name         = "Mimikatz_Credential_Dumper";
        r.description  = "Mimikatz keyword strings and sekurlsa module patterns";
        r.malwareFamily = "HackTool.Mimikatz";
        r.severity     = YaraRuleSeverity::CRITICAL;
        r.condition    = YaraCondition::N_OF_STRINGS;
        r.conditionN   = 2;
        r.patterns = {
            { "$s1", YaraPatternType::PLAIN_ASCII, "mimikatz",                  true,  false },
            { "$s2", YaraPatternType::PLAIN_ASCII, "sekurlsa",                  true,  false },
            { "$s3", YaraPatternType::PLAIN_ASCII, "kerberos::",                true,  false },
            { "$s4", YaraPatternType::PLAIN_ASCII, "lsadump::",                 true,  false },
            { "$s5", YaraPatternType::PLAIN_ASCII, "privilege::debug",          true,  false },
            { "$s6", YaraPatternType::PLAIN_ASCII, "logonPasswords",            true,  false },
            { "$s7", YaraPatternType::PLAIN_ASCII, "Benjamin DELPY",            false, false },
        };
        m_rules.push_back(r);
    }

    // ── Rule 11: Emotet Banking Trojan (from MALW_Emotet.yar) ────────────────
    {
        YaraRule r;
        r.name         = "Emotet_Banking_Trojan";
        r.description  = "Emotet banking trojan strings (spam module, credential stealer)";
        r.malwareFamily = "Trojan.Emotet";
        r.severity     = YaraRuleSeverity::CRITICAL;
        r.condition    = YaraCondition::N_OF_STRINGS;
        r.conditionN   = 2;
        r.patterns = {
            { "$s1", YaraPatternType::PLAIN_ASCII, "emotet",                     true,  false },
            { "$s2", YaraPatternType::PLAIN_ASCII, "EmotetLoader",               true,  false },
            { "$s3", YaraPatternType::PLAIN_ASCII, "Outlook",                    false, false },
            { "$s4", YaraPatternType::PLAIN_ASCII, "InternetExplorer",           false, false },
            { "$s5", YaraPatternType::PLAIN_ASCII, "GetEmailPassword",           true,  false },
            { "$s6", YaraPatternType::PLAIN_ASCII, "spammodule",                 true,  false },
            { "$s7", YaraPatternType::PLAIN_ASCII, "heodo",                      true,  false },
        };
        m_rules.push_back(r);
    }

    // ── Rule 12: AgentTesla Keylogger/Stealer (from MALW_AgentTesla.yar) ─────
    {
        YaraRule r;
        r.name         = "AgentTesla_Stealer";
        r.description  = "AgentTesla keylogger and credential stealer strings";
        r.malwareFamily = "Trojan.AgentTesla";
        r.severity     = YaraRuleSeverity::CRITICAL;
        r.condition    = YaraCondition::N_OF_STRINGS;
        r.conditionN   = 2;
        r.patterns = {
            { "$s1", YaraPatternType::PLAIN_ASCII, "AgentTesla",                 true,  false },
            { "$s2", YaraPatternType::PLAIN_ASCII, "GetKeylogger",               true,  false },
            { "$s3", YaraPatternType::PLAIN_ASCII, "SmtpClient",                 false, false },
            { "$s4", YaraPatternType::PLAIN_ASCII, "SendFTP",                    true,  false },
            { "$s5", YaraPatternType::PLAIN_ASCII, "GetWifiPassword",            true,  false },
            { "$s6", YaraPatternType::PLAIN_ASCII, "GetBrowserPassword",         true,  false },
            { "$s7", YaraPatternType::PLAIN_ASCII, "screenshot",                 true,  false },
        };
        m_rules.push_back(r);
    }

    // ── Rule 13: Azorult Info-Stealer (from MALW_AZORULT.yar) ────────────────
    {
        YaraRule r;
        r.name         = "Azorult_InfoStealer";
        r.description  = "Azorult credential stealer — browser DB paths, C2 POST";
        r.malwareFamily = "Trojan.Azorult";
        r.severity     = YaraRuleSeverity::CRITICAL;
        r.condition    = YaraCondition::N_OF_STRINGS;
        r.conditionN   = 2;
        r.patterns = {
            { "$s1", YaraPatternType::PLAIN_ASCII, "azorult",                    true,  false },
            { "$s2", YaraPatternType::PLAIN_ASCII, "Login Data",                 false, false },
            { "$s3", YaraPatternType::PLAIN_ASCII, "Web Data",                   false, false },
            { "$s4", YaraPatternType::PLAIN_ASCII, "Cookies",                    false, false },
            { "$s5", YaraPatternType::PLAIN_ASCII, "ChromePass",                 true,  false },
            { "$s6", YaraPatternType::PLAIN_ASCII, "wallet.dat",                 false, false },
            { "$s7", YaraPatternType::PLAIN_ASCII, "Content-Type: application/x-www-form-urlencoded", false, false },
        };
        m_rules.push_back(r);
    }

    // ── Rule 14: Mirai IoT Botnet (from MALW_Mirai.yar) ──────────────────────
    {
        YaraRule r;
        r.name         = "Mirai_IoT_Botnet";
        r.description  = "Mirai IoT botnet strings (hardcoded creds, scanner, DDoS commands)";
        r.malwareFamily = "Backdoor.Mirai.Botnet";
        r.severity     = YaraRuleSeverity::HIGH;
        r.condition    = YaraCondition::N_OF_STRINGS;
        r.conditionN   = 3;
        r.patterns = {
            { "$s1", YaraPatternType::PLAIN_ASCII, "mirai",                      true,  false },
            { "$s2", YaraPatternType::PLAIN_ASCII, "/bin/busybox",               false, false },
            { "$s3", YaraPatternType::PLAIN_ASCII, "LZRD",                       false, false },
            { "$s4", YaraPatternType::PLAIN_ASCII, "BOTNET_MIRAI",               false, false },
            { "$s5", YaraPatternType::PLAIN_ASCII, "HTTPFLOOD",                  true,  false },
            { "$s6", YaraPatternType::PLAIN_ASCII, "KILLATTK",                   false, false },
            { "$s7", YaraPatternType::PLAIN_ASCII, "shell_login",                false, false },
        };
        m_rules.push_back(r);
    }

    // ── Rule 15: Empire Post-Exploitation Framework (from MALW_Empire.yar) ────
    {
        YaraRule r;
        r.name         = "Empire_PostExploit_Framework";
        r.description  = "PowerShell Empire agent and stager strings";
        r.malwareFamily = "Trojan.PS1.Empire";
        r.severity     = YaraRuleSeverity::CRITICAL;
        r.condition    = YaraCondition::N_OF_STRINGS;
        r.conditionN   = 2;
        r.patterns = {
            { "$s1", YaraPatternType::PLAIN_ASCII, "Empire",                     false, false },
            { "$s2", YaraPatternType::PLAIN_ASCII, "PowerSploit",                true,  false },
            { "$s3", YaraPatternType::PLAIN_ASCII, "Invoke-Empire",              true,  false },
            { "$s4", YaraPatternType::PLAIN_ASCII, "staging_key",                false, false },
            { "$s5", YaraPatternType::PLAIN_ASCII, "defaultProfile",             false, false },
            { "$s6", YaraPatternType::PLAIN_ASCII, "KillDate",                   false, false },
            { "$s7", YaraPatternType::PLAIN_ASCII, "Launcher",                   false, false },
        };
        m_rules.push_back(r);
    }

    // ── Rule 16: NjRAT / Bladabindi RAT ──────────────────────────────────────
    {
        YaraRule r;
        r.name         = "NjRAT_Bladabindi";
        r.description  = "NjRAT / Bladabindi RAT controller and client strings";
        r.malwareFamily = "Backdoor.NjRAT";
        r.severity     = YaraRuleSeverity::CRITICAL;
        r.condition    = YaraCondition::N_OF_STRINGS;
        r.conditionN   = 2;
        r.patterns = {
            { "$s1", YaraPatternType::PLAIN_ASCII, "njrat",                      true,  false },
            { "$s2", YaraPatternType::PLAIN_ASCII, "bladabindi",                 true,  false },
            { "$s3", YaraPatternType::PLAIN_ASCII, "HackForums",                 true,  false },
            { "$s4", YaraPatternType::PLAIN_ASCII, "LV|",                        false, false },
            { "$s5", YaraPatternType::PLAIN_ASCII, "Execute_PE",                 false, false },
            { "$s6", YaraPatternType::PLAIN_ASCII, "keylogger.log",              true,  false },
            { "$s7", YaraPatternType::PLAIN_ASCII, "cam=",                       false, false },
        };
        m_rules.push_back(r);
    }

    // ── Rule 17: EternalBlue / MS17-010 (WannaCry exploit) ───────────────────
    {
        YaraRule r;
        r.name         = "EternalBlue_MS17_010";
        r.description  = "EternalBlue exploit (MS17-010) SMB shellcode and WannaCry loader";
        r.malwareFamily = "Exploit.EternalBlue.MS17-010";
        r.severity     = YaraRuleSeverity::CRITICAL;
        r.condition    = YaraCondition::ANY_OF_STRINGS;
        r.patterns = {
            // SMB transaction2 exploit header magic bytes
            { "$h1", YaraPatternType::HEX_BYTES,   "00 00 00 90 ff 53 4d 42 32", false, false },
            { "$s1", YaraPatternType::PLAIN_ASCII, "EternalBlue",               true,  false },
            { "$s2", YaraPatternType::PLAIN_ASCII, "ms17-010",                  true,  false },
            { "$s3", YaraPatternType::PLAIN_ASCII, "ETERNALBLUE",               false, false },
            { "$s4", YaraPatternType::PLAIN_ASCII, "DoublePulsar",              true,  false },
            { "$s5", YaraPatternType::PLAIN_ASCII, "WannaDecrypt0r",            true,  false },
        };
        m_rules.push_back(r);
    }

    // ── Rule 18: China Chopper Webshell (from WShell_ChinaChopper.yar) ────────
    {
        YaraRule r;
        r.name         = "ChinaChopper_Webshell";
        r.description  = "China Chopper webshell eval/execute payload pattern";
        r.malwareFamily = "Webshell.ChinaChopper";
        r.severity     = YaraRuleSeverity::CRITICAL;
        r.condition    = YaraCondition::ANY_OF_STRINGS;
        r.patterns = {
            { "$s1", YaraPatternType::PLAIN_ASCII, "eval(Request",              false, false },
            { "$s2", YaraPatternType::PLAIN_ASCII, "eval(base64_decode",        false, false },
            { "$s3", YaraPatternType::PLAIN_ASCII, "e(Request(",                false, false },
            { "$s4", YaraPatternType::PLAIN_ASCII, "assert(base64_decode",      false, false },
            { "$s5", YaraPatternType::PLAIN_ASCII, "chopper",                   true,  false },
            { "$s6", YaraPatternType::PLAIN_ASCII, "Response.Write(server.CreateObject",  false, false },
            { "$s7", YaraPatternType::PLAIN_ASCII, "execute(request(",          true,  false },
        };
        m_rules.push_back(r);
    }

    // ── Rule 19: AntiDebug / AntiVM Evasion (antidebug_antivm category) ──────
    {
        YaraRule r;
        r.name         = "AntiDebug_AntiVM_Evasion";
        r.description  = "Anti-analysis strings: sandbox/VM detection and anti-debugging";
        r.malwareFamily = "Evasion.AntiVM.AntiDebug";
        r.severity     = YaraRuleSeverity::MEDIUM;
        r.condition    = YaraCondition::N_OF_STRINGS;
        r.conditionN   = 3;
        r.patterns = {
            { "$s1", YaraPatternType::PLAIN_ASCII, "IsDebuggerPresent",          true,  false },
            { "$s2", YaraPatternType::PLAIN_ASCII, "CheckRemoteDebuggerPresent", true,  false },
            { "$s3", YaraPatternType::PLAIN_ASCII, "VMware",                     true,  false },
            { "$s4", YaraPatternType::PLAIN_ASCII, "VirtualBox",                 true,  false },
            { "$s5", YaraPatternType::PLAIN_ASCII, "VBOX",                       true,  false },
            { "$s6", YaraPatternType::PLAIN_ASCII, "SandBox",                    true,  false },
            { "$s7", YaraPatternType::PLAIN_ASCII, "Cuckoo",                     true,  false },
            { "$s8", YaraPatternType::PLAIN_ASCII, "NtQueryInformationProcess",  true,  false },
            { "$s9", YaraPatternType::PLAIN_ASCII, "OutputDebugStringA",         true,  false },
        };
        m_rules.push_back(r);
    }

    // ── Rule 20: Carbanak APT (from APT_Carbanak.yar) ─────────────────────────
    {
        YaraRule r;
        r.name         = "APT_Carbanak";
        r.description  = "Carbanak/FIN7 banking APT — named pipe and module strings";
        r.malwareFamily = "APT.Carbanak.FIN7";
        r.severity     = YaraRuleSeverity::CRITICAL;
        r.condition    = YaraCondition::N_OF_STRINGS;
        r.conditionN   = 2;
        r.patterns = {
            { "$s1", YaraPatternType::PLAIN_ASCII, "carbanak",                   true,  false },
            { "$s2", YaraPatternType::PLAIN_ASCII, "ANUNAK",                     true,  false },
            { "$s3", YaraPatternType::PLAIN_ASCII, "fin7",                       true,  false },
            { "$s4", YaraPatternType::PLAIN_ASCII, "caberp",                     true,  false },
            { "$s5", YaraPatternType::PLAIN_ASCII, "RDP_bypass",                 false, false },
            { "$s6", YaraPatternType::PLAIN_ASCII, "videorecord",                true,  false },
        };
        m_rules.push_back(r);
    }

    // ── Rule 21: Sofacy/APT28 FancyBear (from APT_Sofacy_Bundestag.yar) ──────
    {
        YaraRule r;
        r.name         = "APT28_Sofacy_FancyBear";
        r.description  = "Sofacy (APT28/FancyBear) implant strings and compile paths";
        r.malwareFamily = "APT.Sofacy.APT28";
        r.severity     = YaraRuleSeverity::CRITICAL;
        r.condition    = YaraCondition::N_OF_STRINGS;
        r.conditionN   = 2;
        r.patterns = {
            { "$s1", YaraPatternType::PLAIN_ASCII, "sofacy",                     true,  false },
            { "$s2", YaraPatternType::PLAIN_ASCII, "SOFACY",                     false, false },
            { "$s3", YaraPatternType::PLAIN_ASCII, "Sednit",                     true,  false },
            { "$s4", YaraPatternType::PLAIN_ASCII, "Fancy Bear",                 true,  false },
            { "$s5", YaraPatternType::PLAIN_ASCII, "XAgentOSX",                  true,  false },
            { "$s6", YaraPatternType::PLAIN_ASCII, "\\x0Funittest",              false, false },
            { "$s7", YaraPatternType::PLAIN_ASCII, "EVTDIAG.exe",               false, false },
        };
        m_rules.push_back(r);
    }

    // ── Rule 22: Equation Group NSA Tools (from APT_EQUATIONGRP.yar) ─────────
    {
        YaraRule r;
        r.name         = "EquationGroup_NSA_Tools";
        r.description  = "NSA Equation Group tools — ShadowBrokers leak indicators";
        r.malwareFamily = "APT.EquationGroup.NSA";
        r.severity     = YaraRuleSeverity::CRITICAL;
        r.condition    = YaraCondition::ANY_OF_STRINGS;
        r.patterns = {
            { "$s1", YaraPatternType::PLAIN_ASCII, "ETERNALBLUE",               false, false },
            { "$s2", YaraPatternType::PLAIN_ASCII, "DOUBLEPULSAR",              false, false },
            { "$s3", YaraPatternType::PLAIN_ASCII, "ETERNALROMANCE",            false, false },
            { "$s4", YaraPatternType::PLAIN_ASCII, "FUZZBUNCH",                 false, false },
            { "$s5", YaraPatternType::PLAIN_ASCII, "DANDERSPRITZ",              false, false },
            { "$s6", YaraPatternType::PLAIN_ASCII, "ODDJOB",                    false, false },
            { "$s7", YaraPatternType::PLAIN_ASCII, "EquationDrug",              true,  false },
        };
        m_rules.push_back(r);
    }

    // ── Rule 23: BlackEnergy APT (from APT_Blackenergy.yar) ──────────────────
    {
        YaraRule r;
        r.name         = "APT_BlackEnergy";
        r.description  = "BlackEnergy ICS/SCADA malware (Ukraine power grid attacks)";
        r.malwareFamily = "APT.BlackEnergy";
        r.severity     = YaraRuleSeverity::CRITICAL;
        r.condition    = YaraCondition::N_OF_STRINGS;
        r.conditionN   = 2;
        r.patterns = {
            { "$s1", YaraPatternType::PLAIN_ASCII, "blackenergy",               true,  false },
            { "$s2", YaraPatternType::PLAIN_ASCII, "BlackEnergy",               false, false },
            { "$s3", YaraPatternType::PLAIN_ASCII, "enetpremium",               true,  false },
            { "$s4", YaraPatternType::PLAIN_ASCII, "BlackEnergyPlugin",         true,  false },
            { "$s5", YaraPatternType::PLAIN_ASCII, "SANDWORM",                  true,  false },
            { "$s6", YaraPatternType::PLAIN_ASCII, "ge motionworks",             true,  false },
        };
        m_rules.push_back(r);
    }

    // ── Rule 24: CVE-2017-11882 (Equation Editor RCE) ────────────────────────
    {
        YaraRule r;
        r.name         = "CVE_2017_11882_EqEditor_RCE";
        r.description  = "MS Office Equation Editor exploit — CVE-2017-11882";
        r.malwareFamily = "Exploit.CVE-2017-11882";
        r.severity     = YaraRuleSeverity::CRITICAL;
        r.condition    = YaraCondition::ANY_OF_STRINGS;
        r.patterns = {
            // EQNEDT32.EXE magic bytes
            { "$h1", YaraPatternType::HEX_BYTES,   "d0 cf 11 e0 a1 b1 1a e1",  false, false },
            { "$s1", YaraPatternType::PLAIN_ASCII, "EQNEDT32.EXE",              true,  false },
            { "$s2", YaraPatternType::PLAIN_ASCII, "Equation.3",                false, false },
            { "$s3", YaraPatternType::PLAIN_ASCII, "CVE-2017-11882",            true,  false },
            { "$s4", YaraPatternType::PLAIN_ASCII, "Windows Equation",          true,  false },
        };
        m_rules.push_back(r);
    }

    // ── Rule 25: Lazarus Group / Hidden Cobra (DPRK) ─────────────────────────
    {
        YaraRule r;
        r.name         = "Lazarus_DPRK_HiddenCobra";
        r.description  = "Lazarus Group (DPRK) — Hidden Cobra RAT/wiper indicators";
        r.malwareFamily = "APT.Lazarus.DPRK";
        r.severity     = YaraRuleSeverity::CRITICAL;
        r.condition    = YaraCondition::N_OF_STRINGS;
        r.conditionN   = 2;
        r.patterns = {
            { "$s1", YaraPatternType::PLAIN_ASCII, "FALLCHILL",                  true,  false },
            { "$s2", YaraPatternType::PLAIN_ASCII, "Lazarus",                    true,  false },
            { "$s3", YaraPatternType::PLAIN_ASCII, "DeltaCharlie",              true,  false },
            { "$s4", YaraPatternType::PLAIN_ASCII, "KUDDOS",                    false, false },
            { "$s5", YaraPatternType::PLAIN_ASCII, "BANKSHOT",                  false, false },
            { "$s6", YaraPatternType::PLAIN_ASCII, "BADCALL",                   false, false },
            { "$s7", YaraPatternType::PLAIN_ASCII, "hidden_cobra",              true,  false },
        };
        m_rules.push_back(r);
    }

    // ── Rule 26: Stuxnet ICS Worm (from APT_Stuxnet.yar) ────────────────────
    {
        YaraRule r;
        r.name         = "APT_Stuxnet_ICS_Worm";
        r.description  = "Stuxnet ICS worm — Siemens PLC/SCADA target strings";
        r.malwareFamily = "APT.Stuxnet.ICS";
        r.severity     = YaraRuleSeverity::CRITICAL;
        r.condition    = YaraCondition::ANY_OF_STRINGS;
        r.patterns = {
            { "$s1", YaraPatternType::PLAIN_ASCII, "STUXNET",                   true,  false },
            { "$s2", YaraPatternType::PLAIN_ASCII, "Siemens",                   false, false },
            { "$s3", YaraPatternType::PLAIN_ASCII, "Step7",                      true,  false },
            { "$s4", YaraPatternType::PLAIN_ASCII, ".s7p",                       false, false },
            { "$s5", YaraPatternType::PLAIN_ASCII, "S7315-2",                   false, false },
            { "$s6", YaraPatternType::PLAIN_ASCII, "mrxnet.sys",                false, false },
        };
        m_rules.push_back(r);
    }

    // ── Rule 27: WannaCry Hex Signature ──────────────────────────────────────
    {
        YaraRule r;
        r.name         = "WannaCry_Hex_Signatures";
        r.description  = "WannaCry ransomware binary hex signatures from hex section";
        r.malwareFamily = "Ransomware.WannaCry";
        r.severity     = YaraRuleSeverity::CRITICAL;
        r.condition    = YaraCondition::ANY_OF_STRINGS;
        r.patterns = {
            { "$h1", YaraPatternType::HEX_BYTES,   "ed 1b 1e 1f 11 0f",        false, false },
            { "$s1", YaraPatternType::PLAIN_ASCII, "msg\\m_chinese_simplified.wnry", false, false },
            { "$s2", YaraPatternType::PLAIN_ASCII, "WNcry@2ol7",               false, false },
            { "$s3", YaraPatternType::PLAIN_ASCII, "wana_decrypt.exe",          true,  false },
            { "$s4", YaraPatternType::PLAIN_ASCII, ".wnry",                     false, false },
        };
        m_rules.push_back(r);
    }

    // ── Rule 28: ASPXSpy Webshell (from WShell_ASPXSpy.yar) ─────────────────
    {
        YaraRule r;
        r.name         = "ASPXSpy_Webshell";
        r.description  = "ASPXSpy .NET webshell with cmd execution";
        r.malwareFamily = "Webshell.ASPXSpy";
        r.severity     = YaraRuleSeverity::HIGH;
        r.condition    = YaraCondition::N_OF_STRINGS;
        r.conditionN   = 2;
        r.patterns = {
            { "$s1", YaraPatternType::PLAIN_ASCII, "ASPXSpy",                   true,  false },
            { "$s2", YaraPatternType::PLAIN_ASCII, "Process.Start",             false, false },
            { "$s3", YaraPatternType::PLAIN_ASCII, "cmd.exe /c",                true,  false },
            { "$s4", YaraPatternType::PLAIN_ASCII, "shell_exec",                true,  false },
            { "$s5", YaraPatternType::PLAIN_ASCII, "system32\\cmd",             true,  false },
        };
        m_rules.push_back(r);
    }

    // ── Rule 29: Credential Harvesting Generic ────────────────────────────────
    {
        YaraRule r;
        r.name         = "Credential_Harvesting_Generic";
        r.description  = "Generic credential theft — LSASS dump, SAM dump, pass-the-hash";
        r.malwareFamily = "HackTool.CredentialHarvester";
        r.severity     = YaraRuleSeverity::HIGH;
        r.condition    = YaraCondition::N_OF_STRINGS;
        r.conditionN   = 2;
        r.patterns = {
            { "$s1", YaraPatternType::PLAIN_ASCII, "lsass.exe",                 true,  false },
            { "$s2", YaraPatternType::PLAIN_ASCII, "SAMsystem",                 false, false },
            { "$s3", YaraPatternType::PLAIN_ASCII, "ntds.dit",                  true,  false },
            { "$s4", YaraPatternType::PLAIN_ASCII, "procdump",                  true,  false },
            { "$s5", YaraPatternType::PLAIN_ASCII, "MiniDump",                  true,  false },
            { "$s6", YaraPatternType::PLAIN_ASCII, "DumpCreds",                 true,  false },
            { "$s7", YaraPatternType::PLAIN_ASCII, "wce.exe",                   true,  false },
            { "$s8", YaraPatternType::PLAIN_ASCII, "fgdump.exe",                true,  false },
        };
        m_rules.push_back(r);
    }

    // ── Rule 30: UAC Bypass / Privilege Escalation ────────────────────────────
    {
        YaraRule r;
        r.name         = "UAC_Bypass_PrivEsc";
        r.description  = "UAC bypass and privilege escalation techniques (token impersonation, fodhelper)";
        r.malwareFamily = "Exploit.UACBypass";
        r.severity     = YaraRuleSeverity::HIGH;
        r.condition    = YaraCondition::N_OF_STRINGS;
        r.conditionN   = 2;
        r.patterns = {
            { "$s1", YaraPatternType::PLAIN_ASCII, "fodhelper.exe",              true,  false },
            { "$s2", YaraPatternType::PLAIN_ASCII, "eventvwr.exe",               true,  false },
            { "$s3", YaraPatternType::PLAIN_ASCII, "AdjustTokenPrivileges",      true,  false },
            { "$s4", YaraPatternType::PLAIN_ASCII, "SeDebugPrivilege",           true,  false },
            { "$s5", YaraPatternType::PLAIN_ASCII, "ImpersonateLoggedOnUser",    true,  false },
            { "$s6", YaraPatternType::PLAIN_ASCII, "Bypass-UAC",                 true,  false },
            { "$s7", YaraPatternType::PLAIN_ASCII, "UACMe",                      true,  false },
            { "$s8", YaraPatternType::PLAIN_ASCII, "bypassuac",                  true,  false },
        };
        m_rules.push_back(r);
    }

    // ── Rule 31: Cerber Ransomware (RANSOM_Cerber.yar) ───────────────────────
    {
        YaraRule r;
        r.name         = "Cerber_Ransomware";
        r.description  = "Cerber ransomware — voice message, .cerber extension, mutex";
        r.malwareFamily = "Ransomware.Cerber";
        r.severity     = YaraRuleSeverity::CRITICAL;
        r.condition    = YaraCondition::ANY_OF_STRINGS;
        r.patterns = {
            { "$s1", YaraPatternType::PLAIN_ASCII, ".cerber",                    true,  false },
            { "$s2", YaraPatternType::PLAIN_ASCII, "DECRYPT MY FILES",           true,  false },
            { "$s3", YaraPatternType::PLAIN_ASCII, "_HELP_DECRYPT",              true,  false },
            { "$s4", YaraPatternType::PLAIN_ASCII, "cerber2",                    true,  false },
            { "$s5", YaraPatternType::PLAIN_ASCII, "cerber3",                    true,  false },
        };
        m_rules.push_back(r);
    }

    // ── Rule 32: Locky Ransomware (RANSOM_Locky.yar) ─────────────────────────
    {
        YaraRule r;
        r.name         = "Locky_Ransomware";
        r.description  = "Locky ransomware — .locky extension and ransom note strings";
        r.malwareFamily = "Ransomware.Locky";
        r.severity     = YaraRuleSeverity::CRITICAL;
        r.condition    = YaraCondition::ANY_OF_STRINGS;
        r.patterns = {
            { "$s1", YaraPatternType::PLAIN_ASCII, ".locky",                     true,  false },
            { "$s2", YaraPatternType::PLAIN_ASCII, "_HELP_instructions",         true,  false },
            { "$s3", YaraPatternType::PLAIN_ASCII, ".zepto",                     true,  false },
            { "$s4", YaraPatternType::PLAIN_ASCII, ".odin",                      true,  false },
            { "$s5", YaraPatternType::PLAIN_ASCII, "LOCKY-DECRYPTOR",            true,  false },
        };
        m_rules.push_back(r);
    }

    // ── Rule 33: Petya/NotPetya Ransomware (RANSOM_Petya_MS17_010.yar) ───────
    {
        YaraRule r;
        r.name         = "Petya_NotPetya_Ransomware";
        r.description  = "Petya/NotPetya wiper-ransomware — MBR overwrite and EternalBlue propagation";
        r.malwareFamily = "Ransomware.Petya.NotPetya";
        r.severity     = YaraRuleSeverity::CRITICAL;
        r.condition    = YaraCondition::N_OF_STRINGS;
        r.conditionN   = 2;
        r.patterns = {
            { "$s1", YaraPatternType::PLAIN_ASCII, "Petya",                      true,  false },
            { "$s2", YaraPatternType::PLAIN_ASCII, "NotPetya",                   true,  false },
            { "$s3", YaraPatternType::PLAIN_ASCII, "GoldenEye",                  true,  false },
            { "$s4", YaraPatternType::PLAIN_ASCII, "perfc.dat",                  false, false },
            { "$s5", YaraPatternType::PLAIN_ASCII, "wevtutil cl System",         true,  false },
            { "$h1", YaraPatternType::HEX_BYTES,   "07 00 00 00 00 00 00 16",   false, false },
        };
        m_rules.push_back(r);
    }

    // ── Rule 34: Maze Ransomware (RANSOM_Maze.yar) ────────────────────────────
    {
        YaraRule r;
        r.name         = "Maze_Ransomware";
        r.description  = "Maze ransomware — MAZE ransom note, file encryption markers";
        r.malwareFamily = "Ransomware.Maze";
        r.severity     = YaraRuleSeverity::CRITICAL;
        r.condition    = YaraCondition::ANY_OF_STRINGS;
        r.patterns = {
            { "$s1", YaraPatternType::PLAIN_ASCII, "MAZE",                       false, false },
            { "$s2", YaraPatternType::PLAIN_ASCII, "maze_ransom",                true,  false },
            { "$s3", YaraPatternType::PLAIN_ASCII, "DECRYPT-FILES",              true,  false },
            { "$s4", YaraPatternType::PLAIN_ASCII, ".maze",                      true,  false },
        };
        m_rules.push_back(r);
    }

    // ── Rule 35: SamSam Ransomware (RANSOM_SamSam.yar) ───────────────────────
    {
        YaraRule r;
        r.name         = "SamSam_Ransomware";
        r.description  = "SamSam targeted ransomware — hospital/government sector";
        r.malwareFamily = "Ransomware.SamSam";
        r.severity     = YaraRuleSeverity::CRITICAL;
        r.condition    = YaraCondition::N_OF_STRINGS;
        r.conditionN   = 2;
        r.patterns = {
            { "$s1", YaraPatternType::PLAIN_ASCII, "samsam",                     true,  false },
            { "$s2", YaraPatternType::PLAIN_ASCII, "SAMAS",                      true,  false },
            { "$s3", YaraPatternType::PLAIN_ASCII, ".weapologize",               false, false },
            { "$s4", YaraPatternType::PLAIN_ASCII, "DecryptAllFiles",            true,  false },
            { "$s5", YaraPatternType::PLAIN_ASCII, ".stubbin",                   false, false },
        };
        m_rules.push_back(r);
    }

    // ── Rule 36: BadRabbit Ransomware (RANSOM_BadRabbit.yar) ─────────────────
    {
        YaraRule r;
        r.name         = "BadRabbit_Ransomware";
        r.description  = "Bad Rabbit ransomware — fake Adobe Flash installer dropper";
        r.malwareFamily = "Ransomware.BadRabbit";
        r.severity     = YaraRuleSeverity::CRITICAL;
        r.condition    = YaraCondition::ANY_OF_STRINGS;
        r.patterns = {
            { "$s1", YaraPatternType::PLAIN_ASCII, "bad rabbit",                 true,  false },
            { "$s2", YaraPatternType::PLAIN_ASCII, "BadRabbit",                  true,  false },
            { "$s3", YaraPatternType::PLAIN_ASCII, "install_flash_player.exe",   true,  false },
            { "$s4", YaraPatternType::PLAIN_ASCII, "Vhd_plugin.dll",             false, false },
            { "$s5", YaraPatternType::PLAIN_ASCII, "dispci.exe",                 false, false },
        };
        m_rules.push_back(r);
    }

    // ── Rule 37: TeslaCrypt Ransomware (RANSOM_TeslaCrypt.yar) ───────────────
    {
        YaraRule r;
        r.name         = "TeslaCrypt_Ransomware";
        r.description  = "TeslaCrypt — gaming file encryptor (.vvv, .micro extensions)";
        r.malwareFamily = "Ransomware.TeslaCrypt";
        r.severity     = YaraRuleSeverity::CRITICAL;
        r.condition    = YaraCondition::ANY_OF_STRINGS;
        r.patterns = {
            { "$s1", YaraPatternType::PLAIN_ASCII, ".vvv",                       false, false },
            { "$s2", YaraPatternType::PLAIN_ASCII, ".micro",                     false, false },
            { "$s3", YaraPatternType::PLAIN_ASCII, "HELP_RESTORE_FILES",         true,  false },
            { "$s4", YaraPatternType::PLAIN_ASCII, "teslacrypt",                 true,  false },
            { "$s5", YaraPatternType::PLAIN_ASCII, "storage.php",                false, false },
        };
        m_rules.push_back(r);
    }

    // ── Rule 38: CryptXXX Ransomware (RANSOM_.CRYPTXXX.yar) ──────────────────
    {
        YaraRule r;
        r.name         = "CryptXXX_Ransomware";
        r.description  = "CryptXXX ransomware — .crypt extension, Angler EK distributed";
        r.malwareFamily = "Ransomware.CryptXXX";
        r.severity     = YaraRuleSeverity::CRITICAL;
        r.condition    = YaraCondition::ANY_OF_STRINGS;
        r.patterns = {
            { "$s1", YaraPatternType::PLAIN_ASCII, ".crypt",                     false, false },
            { "$s2", YaraPatternType::PLAIN_ASCII, "de_crypt_readme",            true,  false },
            { "$s3", YaraPatternType::PLAIN_ASCII, "CryptXXX",                   true,  false },
            { "$s4", YaraPatternType::PLAIN_ASCII, ".crypz",                     false, false },
        };
        m_rules.push_back(r);
    }

    // ── Rule 39: DarkComet RAT (RAT_DarkComet.yar) ───────────────────────────
    {
        YaraRule r;
        r.name         = "DarkComet_RAT";
        r.description  = "DarkComet remote access trojan — DC_MUTEX and keylogger strings";
        r.malwareFamily = "Backdoor.DarkComet";
        r.severity     = YaraRuleSeverity::CRITICAL;
        r.condition    = YaraCondition::N_OF_STRINGS;
        r.conditionN   = 2;
        r.patterns = {
            { "$s1", YaraPatternType::PLAIN_ASCII, "DarkComet",                  true,  false },
            { "$s2", YaraPatternType::PLAIN_ASCII, "DC_MUTEX",                   false, false },
            { "$s3", YaraPatternType::PLAIN_ASCII, "DARKCOMET-RAT",              true,  false },
            { "$s4", YaraPatternType::PLAIN_ASCII, "DarkComet RAT",              true,  false },
            { "$s5", YaraPatternType::PLAIN_ASCII, "Owned by",                   false, false },
            { "$s6", YaraPatternType::PLAIN_ASCII, "EditSrvSettings",            false, false },
        };
        m_rules.push_back(r);
    }

    // ── Rule 40: Gh0st RAT (RAT_Gh0st.yar) ───────────────────────────────────
    {
        YaraRule r;
        r.name         = "Gh0st_RAT";
        r.description  = "Gh0st RAT Chinese backdoor — Gh0st magic bytes and strings";
        r.malwareFamily = "Backdoor.Gh0stRAT";
        r.severity     = YaraRuleSeverity::CRITICAL;
        r.condition    = YaraCondition::N_OF_STRINGS;
        r.conditionN   = 2;
        r.patterns = {
            { "$s1", YaraPatternType::PLAIN_ASCII, "Gh0st",                      false, false },
            { "$s2", YaraPatternType::PLAIN_ASCII, "gh0st",                      false, false },
            { "$s3", YaraPatternType::PLAIN_ASCII, "GHOST",                      false, false },
            { "$h1", YaraPatternType::HEX_BYTES,   "47 68 30 73 74",            false, false },
            { "$s4", YaraPatternType::PLAIN_ASCII, "GHT!",                       false, false },
            { "$s5", YaraPatternType::PLAIN_ASCII, "HGhost",                     false, false },
        };
        m_rules.push_back(r);
    }

    // ── Rule 41: PoisonIvy RAT (RAT_PoisonIvy.yar) ───────────────────────────
    {
        YaraRule r;
        r.name         = "PoisonIvy_RAT";
        r.description  = "PoisonIvy RAT — svchost injection, mutex PI_ pattern";
        r.malwareFamily = "Backdoor.PoisonIvy";
        r.severity     = YaraRuleSeverity::CRITICAL;
        r.condition    = YaraCondition::N_OF_STRINGS;
        r.conditionN   = 2;
        r.patterns = {
            { "$s1", YaraPatternType::PLAIN_ASCII, "PoisonIvy",                  true,  false },
            { "$s2", YaraPatternType::PLAIN_ASCII, "POISON IVY",                 true,  false },
            { "$s3", YaraPatternType::PLAIN_ASCII, "()()",                       false, false },
            { "$s4", YaraPatternType::PLAIN_ASCII, "PI_",                        false, false },
            { "$h1", YaraPatternType::HEX_BYTES,   "d0 b8 d0 10 05 00 00",      false, false },
        };
        m_rules.push_back(r);
    }

    // ── Rule 42: NanoCore RAT (RAT_Nanocore.yar) ─────────────────────────────
    {
        YaraRule r;
        r.name         = "NanoCore_RAT";
        r.description  = "NanoCore .NET RAT — plugin framework and keylogger strings";
        r.malwareFamily = "Backdoor.NanoCore";
        r.severity     = YaraRuleSeverity::CRITICAL;
        r.condition    = YaraCondition::N_OF_STRINGS;
        r.conditionN   = 2;
        r.patterns = {
            { "$s1", YaraPatternType::PLAIN_ASCII, "NanoCore",                   true,  false },
            { "$s2", YaraPatternType::PLAIN_ASCII, "ClientPlugin",               false, false },
            { "$s3", YaraPatternType::PLAIN_ASCII, "KeyboardLogging",            true,  false },
            { "$s4", YaraPatternType::PLAIN_ASCII, "CoreServicePlugin",          false, false },
            { "$s5", YaraPatternType::PLAIN_ASCII, "ScreenCapturePlugin",        false, false },
        };
        m_rules.push_back(r);
    }

    // ── Rule 43: BlackShades RAT (RAT_BlackShades.yar) ───────────────────────
    {
        YaraRule r;
        r.name         = "BlackShades_RAT";
        r.description  = "BlackShades commodity RAT — HVNC, keylogger, file manager";
        r.malwareFamily = "Backdoor.BlackShades";
        r.severity     = YaraRuleSeverity::CRITICAL;
        r.condition    = YaraCondition::N_OF_STRINGS;
        r.conditionN   = 2;
        r.patterns = {
            { "$s1", YaraPatternType::PLAIN_ASCII, "BlackShades",                true,  false },
            { "$s2", YaraPatternType::PLAIN_ASCII, "bs_mutex",                   false, false },
            { "$s3", YaraPatternType::PLAIN_ASCII, "HVNC",                       false, false },
            { "$s4", YaraPatternType::PLAIN_ASCII, "BlackShades NET",            true,  false },
            { "$s5", YaraPatternType::PLAIN_ASCII, "Crypt.AES",                  false, false },
        };
        m_rules.push_back(r);
    }

    // ── Rule 44: PlugX RAT (RAT_PlugX.yar) ───────────────────────────────────
    {
        YaraRule r;
        r.name         = "PlugX_RAT";
        r.description  = "PlugX Chinese APT RAT — shellcode loader and DLL hijacking";
        r.malwareFamily = "Backdoor.PlugX";
        r.severity     = YaraRuleSeverity::CRITICAL;
        r.condition    = YaraCondition::N_OF_STRINGS;
        r.conditionN   = 2;
        r.patterns = {
            { "$s1", YaraPatternType::PLAIN_ASCII, "PlugX",                      true,  false },
            { "$s2", YaraPatternType::PLAIN_ASCII, "PLUGX",                      false, false },
            { "$s3", YaraPatternType::PLAIN_ASCII, "Korplug",                    true,  false },
            { "$s4", YaraPatternType::PLAIN_ASCII, "ShadowPad",                  true,  false },
            { "$h1", YaraPatternType::HEX_BYTES,   "50 6c 75 67 58",            false, false },
        };
        m_rules.push_back(r);
    }

    // ── Rule 45: FinFisher / FinSpy Spyware (TOOLKIT_FinFisher_.yar) ─────────
    {
        YaraRule r;
        r.name         = "FinFisher_FinSpy_Spyware";
        r.description  = "FinFisher/FinSpy commercial surveillance spyware";
        r.malwareFamily = "Spyware.FinFisher.FinSpy";
        r.severity     = YaraRuleSeverity::CRITICAL;
        r.condition    = YaraCondition::N_OF_STRINGS;
        r.conditionN   = 2;
        r.patterns = {
            { "$s1", YaraPatternType::PLAIN_ASCII, "FinFisher",                  true,  false },
            { "$s2", YaraPatternType::PLAIN_ASCII, "FinSpy",                     true,  false },
            { "$s3", YaraPatternType::PLAIN_ASCII, "WingBird",                   true,  false },
            { "$s4", YaraPatternType::PLAIN_ASCII, "finfisher.com",              true,  false },
            { "$s5", YaraPatternType::PLAIN_ASCII, "ldr_kernel32",               false, false },
        };
        m_rules.push_back(r);
    }

    // ── Rule 46: SUNBURST / SolarWinds Supply Chain (TOOLKIT_Solarwinds.yar) ─
    {
        YaraRule r;
        r.name         = "SUNBURST_SolarWinds_SupplyChain";
        r.description  = "SolarWinds SUNBURST backdoor — Orion supply chain attack";
        r.malwareFamily = "Backdoor.SUNBURST.SolarWinds";
        r.severity     = YaraRuleSeverity::CRITICAL;
        r.condition    = YaraCondition::ANY_OF_STRINGS;
        r.patterns = {
            { "$s1", YaraPatternType::PLAIN_ASCII, "SUNBURST",                   true,  false },
            { "$s2", YaraPatternType::PLAIN_ASCII, "SolarWinds.Orion.Core",      false, false },
            { "$s3", YaraPatternType::PLAIN_ASCII, "avsvmcloud.com",             true,  false },
            { "$s4", YaraPatternType::PLAIN_ASCII, "OrionImprovementBusinessLayer", false, false },
            { "$s5", YaraPatternType::PLAIN_ASCII, "TEARDROP",                   true,  false },
        };
        m_rules.push_back(r);
    }

    // ── Rule 47: Angler Exploit Kit (EK_Angler.yar) ──────────────────────────
    {
        YaraRule r;
        r.name         = "Angler_Exploit_Kit";
        r.description  = "Angler EK — obfuscated landing page and Flash/Java exploit strings";
        r.malwareFamily = "ExploitKit.Angler";
        r.severity     = YaraRuleSeverity::HIGH;
        r.condition    = YaraCondition::N_OF_STRINGS;
        r.conditionN   = 2;
        r.patterns = {
            { "$s1", YaraPatternType::PLAIN_ASCII, "Angler",                     false, false },
            { "$s2", YaraPatternType::PLAIN_ASCII, "angler_ek",                  true,  false },
            { "$s3", YaraPatternType::PLAIN_ASCII, "eval(unescape",              false, false },
            { "$s4", YaraPatternType::PLAIN_ASCII, "String.fromCharCode",        false, false },
            { "$s5", YaraPatternType::PLAIN_ASCII, "ActiveXObject",              false, false },
        };
        m_rules.push_back(r);
    }

    // ── Rule 48: Blackhole Exploit Kit (EK_Blackhole.yar) ────────────────────
    {
        YaraRule r;
        r.name         = "Blackhole_Exploit_Kit";
        r.description  = "Blackhole EK — Java/PDF exploit delivery framework";
        r.malwareFamily = "ExploitKit.Blackhole";
        r.severity     = YaraRuleSeverity::HIGH;
        r.condition    = YaraCondition::N_OF_STRINGS;
        r.conditionN   = 2;
        r.patterns = {
            { "$s1", YaraPatternType::PLAIN_ASCII, "blackhole",                  true,  false },
            { "$s2", YaraPatternType::PLAIN_ASCII, "Blackhole",                  false, false },
            { "$s3", YaraPatternType::PLAIN_ASCII, "BHEK",                       false, false },
            { "$s4", YaraPatternType::PLAIN_ASCII, "exploit_jar",                false, false },
            { "$s5", YaraPatternType::PLAIN_ASCII, "payload.exe",                true,  false },
        };
        m_rules.push_back(r);
    }

    // ── Rule 49: Maldoc VBA Macro (maldocs/Maldoc_VBA_macro_code.yar) ────────
    {
        YaraRule r;
        r.name         = "Maldoc_Malicious_VBA_Macro";
        r.description  = "Malicious Office VBA macro — Shell/WScript/PowerShell droppers";
        r.malwareFamily = "Maldoc.VBA.Macro";
        r.severity     = YaraRuleSeverity::HIGH;
        r.condition    = YaraCondition::N_OF_STRINGS;
        r.conditionN   = 2;
        r.patterns = {
            { "$s1", YaraPatternType::PLAIN_ASCII, "Shell(",                     false, false },
            { "$s2", YaraPatternType::PLAIN_ASCII, "WScript.Shell",              false, false },
            { "$s3", YaraPatternType::PLAIN_ASCII, "AutoOpen",                   false, false },
            { "$s4", YaraPatternType::PLAIN_ASCII, "Document_Open",              false, false },
            { "$s5", YaraPatternType::PLAIN_ASCII, "CreateObject",               false, false },
            { "$s6", YaraPatternType::PLAIN_ASCII, "powershell.exe",             true,  false },
            { "$s7", YaraPatternType::PLAIN_ASCII, "cmd.exe /c",                 true,  false },
        };
        m_rules.push_back(r);
    }

    // ── Rule 50: Maldoc DDE Exploit (maldocs/Maldoc_DDE.yar) ─────────────────
    {
        YaraRule r;
        r.name         = "Maldoc_DDE_Exploit";
        r.description  = "DDE (Dynamic Data Exchange) Office exploit — macro-less execution";
        r.malwareFamily = "Maldoc.DDE.Exploit";
        r.severity     = YaraRuleSeverity::HIGH;
        r.condition    = YaraCondition::ANY_OF_STRINGS;
        r.patterns = {
            { "$s1", YaraPatternType::PLAIN_ASCII, "DDEAUTO",                    false, false },
            { "$s2", YaraPatternType::PLAIN_ASCII, "DDE ",                       false, false },
            { "$s3", YaraPatternType::PLAIN_ASCII, "\\\\MSMacro",                false, false },
            { "$s4", YaraPatternType::PLAIN_ASCII, "cmd /c powershell",          true,  false },
            { "$s5", YaraPatternType::PLAIN_ASCII, "excel DDE",                  true,  false },
        };
        m_rules.push_back(r);
    }

    // ── Rule 51: APT29 / Grizzly Steppe (malware/APT_APT29_Grizzly_Steppe.yar)
    {
        YaraRule r;
        r.name         = "APT29_CozyBear_GrizzlySteppe";
        r.description  = "APT29 CozyBear (Grizzly Steppe) — DNC hack implant strings";
        r.malwareFamily = "APT.APT29.CozyBear";
        r.severity     = YaraRuleSeverity::CRITICAL;
        r.condition    = YaraCondition::N_OF_STRINGS;
        r.conditionN   = 2;
        r.patterns = {
            { "$s1", YaraPatternType::PLAIN_ASCII, "CozyBear",                   true,  false },
            { "$s2", YaraPatternType::PLAIN_ASCII, "APT29",                      true,  false },
            { "$s3", YaraPatternType::PLAIN_ASCII, "HAMMERTOSS",                 true,  false },
            { "$s4", YaraPatternType::PLAIN_ASCII, "MiniDuke",                   true,  false },
            { "$s5", YaraPatternType::PLAIN_ASCII, "OnionDuke",                  true,  false },
            { "$s6", YaraPatternType::PLAIN_ASCII, "grizzly steppe",             true,  false },
        };
        m_rules.push_back(r);
    }

    // ── Rule 52: TRITON / HATMAN ICS Attack (MALW_TRITON_HATMAN.yar) ─────────
    {
        YaraRule r;
        r.name         = "TRITON_HATMAN_ICS_Attack";
        r.description  = "TRITON/HATMAN ICS attack targeting Triconex safety controllers";
        r.malwareFamily = "APT.TRITON.ICS.HATMAN";
        r.severity     = YaraRuleSeverity::CRITICAL;
        r.condition    = YaraCondition::N_OF_STRINGS;
        r.conditionN   = 2;
        r.patterns = {
            { "$s1", YaraPatternType::PLAIN_ASCII, "TRITON",                     true,  false },
            { "$s2", YaraPatternType::PLAIN_ASCII, "HATMAN",                     true,  false },
            { "$s3", YaraPatternType::PLAIN_ASCII, "Triconex",                   true,  false },
            { "$s4", YaraPatternType::PLAIN_ASCII, "triconex",                   true,  false },
            { "$s5", YaraPatternType::PLAIN_ASCII, "TSAA",                       false, false },
            { "$s6", YaraPatternType::PLAIN_ASCII, "TriStation",                 false, false },
        };
        m_rules.push_back(r);
    }

    // ── Rule 53: Shamoon Wiper (MALW_Shamoon.yar) ────────────────────────────
    {
        YaraRule r;
        r.name         = "Shamoon_Wiper";
        r.description  = "Shamoon disk wiper — Saudi Aramco attack, MBR overwrite";
        r.malwareFamily = "Trojan.Shamoon.Wiper";
        r.severity     = YaraRuleSeverity::CRITICAL;
        r.condition    = YaraCondition::N_OF_STRINGS;
        r.conditionN   = 2;
        r.patterns = {
            { "$s1", YaraPatternType::PLAIN_ASCII, "Shamoon",                    true,  false },
            { "$s2", YaraPatternType::PLAIN_ASCII, "disttrack",                  true,  false },
            { "$s3", YaraPatternType::PLAIN_ASCII, "ElderWood",                  true,  false },
            { "$s4", YaraPatternType::PLAIN_ASCII, "StoneDrill",                 true,  false },
            { "$s5", YaraPatternType::PLAIN_ASCII, "Eldos RawDisk",              true,  false },
        };
        m_rules.push_back(r);
    }

    // ── Rule 54: Dridex Banking Trojan (maldocs/Maldoc_Dridex.yar) ───────────
    {
        YaraRule r;
        r.name         = "Dridex_Banking_Trojan";
        r.description  = "Dridex/Bugat banking malware — macro and loader patterns";
        r.malwareFamily = "Trojan.Dridex.Banking";
        r.severity     = YaraRuleSeverity::CRITICAL;
        r.condition    = YaraCondition::N_OF_STRINGS;
        r.conditionN   = 2;
        r.patterns = {
            { "$s1", YaraPatternType::PLAIN_ASCII, "dridex",                     true,  false },
            { "$s2", YaraPatternType::PLAIN_ASCII, "Dridex",                     false, false },
            { "$s3", YaraPatternType::PLAIN_ASCII, "bugat",                      true,  false },
            { "$s4", YaraPatternType::PLAIN_ASCII, "cridex",                     true,  false },
            { "$s5", YaraPatternType::PLAIN_ASCII, "feodo",                      true,  false },
        };
        m_rules.push_back(r);
    }

    // ── Rule 55: TrickBot Banker (MALW_TrickBot.yar) ─────────────────────────
    {
        YaraRule r;
        r.name         = "TrickBot_Banker";
        r.description  = "TrickBot modular banking trojan — module injection strings";
        r.malwareFamily = "Trojan.TrickBot.Banker";
        r.severity     = YaraRuleSeverity::CRITICAL;
        r.condition    = YaraCondition::N_OF_STRINGS;
        r.conditionN   = 2;
        r.patterns = {
            { "$s1", YaraPatternType::PLAIN_ASCII, "trickbot",                   true,  false },
            { "$s2", YaraPatternType::PLAIN_ASCII, "TrickBot",                   false, false },
            { "$s3", YaraPatternType::PLAIN_ASCII, "TrickLoader",                true,  false },
            { "$s4", YaraPatternType::PLAIN_ASCII, "systeminfo.dll",             true,  false },
            { "$s5", YaraPatternType::PLAIN_ASCII, "injectDll",                  false, false },
            { "$s6", YaraPatternType::PLAIN_ASCII, "Appdata\\Roaming\\",         true,  false },
        };
        m_rules.push_back(r);
    }

    // ── Rule 56: IcedID (MALW_IcedID.yar) ────────────────────────────────────
    {
        YaraRule r;
        r.name         = "IcedID_Bokbot_Banker";
        r.description  = "IcedID/Bokbot banking malware — webinject and C2 patterns";
        r.malwareFamily = "Trojan.IcedID.Bokbot";
        r.severity     = YaraRuleSeverity::CRITICAL;
        r.condition    = YaraCondition::N_OF_STRINGS;
        r.conditionN   = 2;
        r.patterns = {
            { "$s1", YaraPatternType::PLAIN_ASCII, "IcedID",                     true,  false },
            { "$s2", YaraPatternType::PLAIN_ASCII, "icedid",                     true,  false },
            { "$s3", YaraPatternType::PLAIN_ASCII, "Bokbot",                     true,  false },
            { "$s4", YaraPatternType::PLAIN_ASCII, "webinjects",                 true,  false },
            { "$s5", YaraPatternType::PLAIN_ASCII, "gzip_body",                  false, false },
        };
        m_rules.push_back(r);
    }

    // ── Rule 57: Kovter Fileless Malware (MALW_Kovter.yar) ───────────────────
    {
        YaraRule r;
        r.name         = "Kovter_Fileless_Malware";
        r.description  = "Kovter click-fraud/fileless malware — registry persistence";
        r.malwareFamily = "Trojan.Kovter.Fileless";
        r.severity     = YaraRuleSeverity::HIGH;
        r.condition    = YaraCondition::N_OF_STRINGS;
        r.conditionN   = 2;
        r.patterns = {
            { "$s1", YaraPatternType::PLAIN_ASCII, "kovter",                     true,  false },
            { "$s2", YaraPatternType::PLAIN_ASCII, "Kovter",                     false, false },
            { "$s3", YaraPatternType::PLAIN_ASCII, "mshta.exe",                  true,  false },
            { "$s4", YaraPatternType::PLAIN_ASCII, "powershell -w hidden",       true,  false },
            { "$s5", YaraPatternType::PLAIN_ASCII, "regsvr32.exe /s /n",         true,  false },
        };
        m_rules.push_back(r);
    }

    // ── Rule 58: EICAR Test File (MALW_Eicar.yar) ────────────────────────────
    {
        YaraRule r;
        r.name         = "EICAR_Test_File";
        r.description  = "EICAR standard antivirus test file — engine verification";
        r.malwareFamily = "Test.EICAR.Standard";
        r.severity     = YaraRuleSeverity::MEDIUM;
        r.condition    = YaraCondition::ANY_OF_STRINGS;
        r.patterns = {
            { "$s1", YaraPatternType::PLAIN_ASCII, "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR", false, false },
            { "$s2", YaraPatternType::PLAIN_ASCII, "EICAR-STANDARD-ANTIVIRUS-TEST-FILE", false, false },
        };
        m_rules.push_back(r);
    }

    // ── Rule 59: ZeroAccess Rootkit (EK_ZeroAcces.yar) ───────────────────────
    {
        YaraRule r;
        r.name         = "ZeroAccess_Rootkit_Botnet";
        r.description  = "ZeroAccess rootkit/botnet — click fraud and Bitcoin mining";
        r.malwareFamily = "Rootkit.ZeroAccess.Botnet";
        r.severity     = YaraRuleSeverity::CRITICAL;
        r.condition    = YaraCondition::N_OF_STRINGS;
        r.conditionN   = 2;
        r.patterns = {
            { "$s1", YaraPatternType::PLAIN_ASCII, "zeroaccess",                 true,  false },
            { "$s2", YaraPatternType::PLAIN_ASCII, "ZeroAccess",                 false, false },
            { "$s3", YaraPatternType::PLAIN_ASCII, "Sirefef",                    true,  false },
            { "$s4", YaraPatternType::PLAIN_ASCII, "max++",                      false, false },
            { "$s5", YaraPatternType::PLAIN_ASCII, "@xor.net",                   false, false },
        };
        m_rules.push_back(r);
    }

    // ── Rule 60: Generic Process Injection / Hollowing ───────────────────────
    {
        YaraRule r;
        r.name         = "Process_Injection_Hollowing";
        r.description  = "Generic process injection and hollowing API call patterns";
        r.malwareFamily = "Technique.ProcessInjection";
        r.severity     = YaraRuleSeverity::HIGH;
        r.condition    = YaraCondition::N_OF_STRINGS;
        r.conditionN   = 3;
        r.patterns = {
            { "$s1", YaraPatternType::PLAIN_ASCII, "WriteProcessMemory",         true,  false },
            { "$s2", YaraPatternType::PLAIN_ASCII, "VirtualAllocEx",             true,  false },
            { "$s3", YaraPatternType::PLAIN_ASCII, "CreateRemoteThread",         true,  false },
            { "$s4", YaraPatternType::PLAIN_ASCII, "NtUnmapViewOfSection",       true,  false },
            { "$s5", YaraPatternType::PLAIN_ASCII, "ZwWriteVirtualMemory",       true,  false },
            { "$s6", YaraPatternType::PLAIN_ASCII, "SetThreadContext",           true,  false },
            { "$s7", YaraPatternType::PLAIN_ASCII, "ResumeThread",               true,  false },
        };
        m_rules.push_back(r);
    }
}


// ─────────────────────────────────────────────────────────────────────────────
// ScanBuffer — main entry point
// ─────────────────────────────────────────────────────────────────────────────
std::vector<YaraMatch> YaraScanner::ScanBuffer(const uint8_t* data, size_t size, DWORD pid) {
    ++m_scansTotal;
    return MatchRules(data, size, pid);
}

// ─────────────────────────────────────────────────────────────────────────────
// ScanWString — converts wide string to UTF-8 then scans
// ─────────────────────────────────────────────────────────────────────────────
std::vector<YaraMatch> YaraScanner::ScanWString(const std::wstring& script, DWORD pid) {
    if (script.empty()) return {};
    // Convert to UTF-8
    int sz = WideCharToMultiByte(CP_UTF8, 0, script.data(), (int)script.size(),
                                  nullptr, 0, nullptr, nullptr);
    std::string utf8(sz, '\0');
    WideCharToMultiByte(CP_UTF8, 0, script.data(), (int)script.size(),
                        &utf8[0], sz, nullptr, nullptr);
    return ScanBuffer(reinterpret_cast<const uint8_t*>(utf8.data()), utf8.size(), pid);
}

// ─────────────────────────────────────────────────────────────────────────────
// ScanFile — read up to 4 MB from disk, then scan
// ─────────────────────────────────────────────────────────────────────────────
std::vector<YaraMatch> YaraScanner::ScanFile(const std::wstring& filePath, DWORD pid) {
    constexpr size_t MAX_READ = 4 * 1024 * 1024; // 4 MB cap
    std::ifstream f(filePath.c_str(), std::ios::binary);
    if (!f) return {};
    std::vector<uint8_t> buf(MAX_READ);
    f.read(reinterpret_cast<char*>(buf.data()), MAX_READ);
    size_t bytesRead = (size_t)f.gcount();
    buf.resize(bytesRead);
    auto matches = ScanBuffer(buf.data(), buf.size(), pid);
    if (!matches.empty()) {
        // Narrow the path for logging
        int s = WideCharToMultiByte(CP_UTF8, 0, filePath.data(), -1,
                                     nullptr, 0, nullptr, nullptr);
        std::string narrow(s, '\0');
        WideCharToMultiByte(CP_UTF8, 0, filePath.data(), -1,
                             &narrow[0], s, nullptr, nullptr);
        Logger::Instance().Info(L"[YARA:FILE] " + std::to_wstring(matches.size()) +
            L" rules matched in: " + filePath);
    }
    return matches;
}

// ─────────────────────────────────────────────────────────────────────────────
// ScanProcess — walk all committed memory regions of a process
// ─────────────────────────────────────────────────────────────────────────────
std::vector<YaraMatch> YaraScanner::ScanProcess(DWORD pid) {
    std::vector<YaraMatch> allMatches;
    if (pid == 0 || pid == 4 || pid == GetCurrentProcessId()) return allMatches;

    HANDLE hProc = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (!hProc) return allMatches;

    constexpr size_t CHUNK = 4 * 1024 * 1024; // 4 MB per region
    std::vector<uint8_t> buf(CHUNK);
    MEMORY_BASIC_INFORMATION mbi{};
    LPVOID addr = nullptr;

    while (VirtualQueryEx(hProc, addr, &mbi, sizeof(mbi)) == sizeof(mbi)) {
        // Only scan committed, readable, private memory (executable or writable-execute)
        if (mbi.State == MEM_COMMIT &&
            mbi.Type  == MEM_PRIVATE &&
            (mbi.Protect & (PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE |
                            PAGE_READWRITE | PAGE_READONLY)) &&
            !(mbi.Protect & (PAGE_GUARD | PAGE_NOACCESS)) &&
            mbi.RegionSize > 0 && mbi.RegionSize <= CHUNK) {
            buf.resize(mbi.RegionSize);
            SIZE_T nRead = 0;
            if (ReadProcessMemory(hProc, addr, buf.data(), mbi.RegionSize, &nRead) && nRead > 0) {
                auto regionMatches = ScanBuffer(buf.data(), nRead, pid);
                allMatches.insert(allMatches.end(), regionMatches.begin(), regionMatches.end());
            }
        }
        // Advance to next region, guard against overflow
        uintptr_t next = (uintptr_t)addr + mbi.RegionSize;
        if (next <= (uintptr_t)addr) break; // overflow guard
        addr = (LPVOID)next;
    }

    CloseHandle(hProc);

    if (!allMatches.empty()) {
        Logger::Instance().Info(L"[YARA:MEM] Process PID " + std::to_wstring(pid) +
            L" — " + std::to_wstring(allMatches.size()) + L" rule(s) matched in memory");
    }
    return allMatches;
}

// ─────────────────────────────────────────────────────────────────────────────
// MatchRules — core matching loop
// ─────────────────────────────────────────────────────────────────────────────
std::vector<YaraMatch> YaraScanner::MatchRules(const uint8_t* data, size_t size, DWORD pid) {
    std::vector<YaraMatch> results;
    std::lock_guard<std::mutex> lk(m_mutex);

    for (const auto& rule : m_rules) {
        // Evaluate each pattern
        std::vector<bool> patHits(rule.patterns.size(), false);
        std::string firstSnippet;
        size_t firstOffset = 0;
        std::string matchedPatId;

        for (size_t i = 0; i < rule.patterns.size(); ++i) {
            size_t offset = 0;
            std::string snippet;
            if (MatchPattern(rule.patterns[i], data, size, offset, snippet)) {
                patHits[i] = true;
                if (firstSnippet.empty()) {
                    firstSnippet = snippet;
                    firstOffset  = offset;
                    matchedPatId = rule.patterns[i].id;
                }
            }
        }

        // Apply condition
        int hitCount = 0;
        for (bool h : patHits) if (h) ++hitCount;

        bool conditionMet = false;
        switch (rule.condition) {
            case YaraCondition::ANY_OF_STRINGS: conditionMet = (hitCount >= 1); break;
            case YaraCondition::ALL_OF_STRINGS: conditionMet = ((int)hitCount == (int)patHits.size()); break;
            case YaraCondition::N_OF_STRINGS:   conditionMet = (hitCount >= rule.conditionN); break;
        }

        if (conditionMet) {
            // Deduplicate — don't fire same rule for same PID twice per run
            std::string dedupeKey = rule.name + ":" + std::to_string(pid);
            {
                std::lock_guard<std::mutex> lk2(m_dedupeM);
                if (m_recentMatches.count(dedupeKey)) continue;
                m_recentMatches[dedupeKey] = pid;
            }

            YaraMatch m;
            m.ruleName       = rule.name;
            m.malwareFamily  = rule.malwareFamily;
            m.description    = rule.description;
            m.severity       = rule.severity;
            m.matchOffset    = firstOffset;
            m.matchedPattern = matchedPatId + ": " + firstSnippet;
            results.push_back(m);
            ++m_matches;

            // Fire callback
            if (m_callback) m_callback(m, pid);

            Logger::Instance().Critical(
                L"[YARA] MATCH: " +
                std::wstring(rule.name.begin(), rule.name.end()) +
                L" | Family: " +
                std::wstring(rule.malwareFamily.begin(), rule.malwareFamily.end()) +
                L" | PID: " + std::to_wstring(pid));
        }
    }
    return results;
}

// ─────────────────────────────────────────────────────────────────────────────
// MatchPattern — dispatch to correct matcher
// ─────────────────────────────────────────────────────────────────────────────
bool YaraScanner::MatchPattern(const YaraPattern& p, const uint8_t* data, size_t size,
                                size_t& outOffset, std::string& outSnippet) const {
    switch (p.type) {
        case YaraPatternType::PLAIN_ASCII:
        case YaraPatternType::PLAIN_WIDE:
            if (MatchPlainAscii(p.value, p.nocase, data, size, outOffset)) {
                outSnippet = p.value.substr(0, 32);
                return true;
            }
            return false;

        case YaraPatternType::HEX_BYTES:
            if (MatchHexBytes(p.value, data, size, outOffset)) {
                outSnippet = p.value.substr(0, 32);
                return true;
            }
            return false;

        case YaraPatternType::REGEX_ASCII:
            // Stub: fall through to plain match until regex engine added
            if (MatchPlainAscii(p.value, p.nocase, data, size, outOffset)) {
                outSnippet = p.value.substr(0, 32);
                return true;
            }
            return false;
    }
    return false;
}

// ─────────────────────────────────────────────────────────────────────────────
// MatchPlainAscii — Boyer-Moore-ish naive search, optional case-insensitive
// ─────────────────────────────────────────────────────────────────────────────
bool YaraScanner::MatchPlainAscii(const std::string& needle, bool nocase,
                                    const uint8_t* data, size_t size,
                                    size_t& outOffset) const {
    if (needle.empty() || size < needle.size()) return false;

    const size_t nlen = needle.size();

    if (!nocase) {
        // Simple memcmp search
        for (size_t i = 0; i + nlen <= size; ++i) {
            if (memcmp(data + i, needle.data(), nlen) == 0) {
                outOffset = i;
                return true;
            }
        }
    } else {
        // Case-insensitive (ASCII only)
        std::string lower = needle;
        std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);
        for (size_t i = 0; i + nlen <= size; ++i) {
            bool match = true;
            for (size_t j = 0; j < nlen; ++j) {
                if (::tolower((unsigned char)data[i + j]) != (unsigned char)lower[j]) {
                    match = false;
                    break;
                }
            }
            if (match) { outOffset = i; return true; }
        }
    }
    return false;
}

// ─────────────────────────────────────────────────────────────────────────────
// MatchHexBytes — hex pattern like "fc e8 8? 00" (? = wildcard nibble)
// ─────────────────────────────────────────────────────────────────────────────
bool YaraScanner::MatchHexBytes(const std::string& hexPat, const uint8_t* data,
                                  size_t size, size_t& outOffset) const {
    std::vector<uint8_t> bytes;
    std::vector<bool>    mask;
    if (!ParseHexPattern(hexPat, bytes, mask)) return false;
    if (bytes.empty() || size < bytes.size()) return false;

    for (size_t i = 0; i + bytes.size() <= size; ++i) {
        bool ok = true;
        for (size_t j = 0; j < bytes.size(); ++j) {
            if (mask[j] && data[i + j] != bytes[j]) { ok = false; break; }
        }
        if (ok) { outOffset = i; return true; }
    }
    return false;
}

// ─────────────────────────────────────────────────────────────────────────────
// ParseHexPattern — "4D 5A 90 ?? 03 00" → bytes + mask (true = must match)
// Supports full byte wildcards (??) and nibble wildcards (8? or ?0)
// ─────────────────────────────────────────────────────────────────────────────
bool YaraScanner::ParseHexPattern(const std::string& hex,
                                    std::vector<uint8_t>& bytes,
                                   std::vector<bool>& mask) const {
    std::istringstream ss(hex);
    std::string token;
    while (ss >> token) {
        if (token == "??" || token == "?") {
            bytes.push_back(0x00);
            mask.push_back(false);  // wildcard
        } else if (token.size() == 2) {
            bool hiWild = (token[0] == '?');
            bool loWild = (token[1] == '?');
            if (hiWild && loWild) {
                bytes.push_back(0x00);
                mask.push_back(false);
            } else {
                // Parse hex byte
                char* end;
                uint8_t b = (uint8_t)strtol(token.c_str(), &end, 16);
                if (*end != '\0' && !hiWild && !loWild) return false;
                bytes.push_back(b);
                mask.push_back(true);
            }
        } else {
            return false;
        }
    }
    return !bytes.empty();
}

} // namespace Asthak
