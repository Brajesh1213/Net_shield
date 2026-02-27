rule Metasploit_Meterpreter_Reverse_TCP {
    meta:
        description = "Detects Metasploit Meterpreter Reverse TCP stager/payload"
        threat_level = "Critical"
    strings:
        // Common MZ header and meterpreter strings
        $s1 = "metsrv.dll" ascii wide
        $s2 = "ReflectiveLoader" ascii wide
        $s3 = "meterpreter" ascii nocase
        // Common byte sequence in windows meterpreter reverse tcp (call ebp, WS2_32.dll)
        $hex1 = { 81 C4 54 F2 00 00 8B 5D }
    condition:
        any of them
}

rule CobaltStrike_Beacon {
    meta:
        description = "Detects Cobalt Strike Beacon patterns in memory or packets"
        threat_level = "Critical"
    strings:
        // Default malleable C2 profile strings or beacon strings
        $s1 = ".bxark" ascii
        $s2 = "beacon.dll" ascii nocase
        $s3 = "postscript.dll" ascii nocase
        $hex1 = { 73 70 72 6E 67 00 } // sprint
        $hex2 = { 69 6A 69 31 32 30 30 00 } // iji1200
        $user_agent = "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; WOW64; Trident/5.0; BOIE9;ENUS)"
    condition:
        any of ($s*) or any of ($hex*) or $user_agent
}

rule Suspicious_Powershell_Execution {
    meta:
        description = "Detects severe PowerShell execution commands often used in fileless malware"
        threat_level = "High"
    strings:
        $ps1 = "powershell" nocase
        $ps2 = "pwsh" nocase
        
        $flag1 = "-ExecutionPolicy Bypass" nocase
        $flag2 = "-ep bypass" nocase
        $flag3 = "-WindowStyle Hidden" nocase
        $flag4 = "-w hidden" nocase
        $flag5 = "-EncodedCommand" nocase
        $flag6 = "-enc" nocase
        $flag7 = "-nop -w hidden" nocase
    condition:
        ($ps1 or $ps2) and any of ($flag*)
}

rule Malware_Download_And_Execute {
    meta:
        description = "Detects common remote file download and execute patterns"
        threat_level = "High"
    strings:
        // PowerShell downloaders
        $ps_dl1 = "Invoke-WebRequest" nocase
        $ps_dl2 = "Net.WebClient" nocase
        $ps_dl3 = ".DownloadString(" nocase
        $ps_dl4 = ".DownloadFile(" nocase
        $ps_dl5 = "IEX(" nocase
        $ps_dl6 = "Invoke-Expression" nocase
        
        // Command-line downloaders
        $cmd_dl1 = "certutil.exe -urlcache -split -f" nocase
        $cmd_dl2 = "bitsadmin /transfer" nocase
        $cmd_dl3 = "curl " nocase
        $cmd_dl4 = "wget " nocase
    condition:
        any of ($ps_dl*) or any of ($cmd_dl*)
}

rule WebShell_Traffic_Indicators {
    meta:
        description = "Detects common generic web shell commands in HTTP traffic"
        threat_level = "High"
    strings:
        $w1 = "cmd.exe /c" nocase
        $w2 = "/bin/sh -c" nocase
        $w3 = "/bin/bash -c" nocase
        $w4 = "eval(base64_decode("
        $w5 = "system($_GET[" 
        $w6 = "passthru($_POST["
        $w7 = "exec($_REQUEST["
    condition:
        any of them
}

rule Cryptominer_Stratum_Protocol {
    meta:
        description = "Detects Stratum protocol used by cryptominers (e.g., XMRig)"
        threat_level = "High"
    strings:
        $str1 = "\"method\": \"login\"" nocase
        $str2 = "\"method\": \"submit\"" ascii
        $str3 = "\"jsonrpc\": \"2.0\"" ascii
        $str4 = "mining.subscribe" ascii
        $str5 = "mining.authorize" ascii
        $xmrig = "XMRig" nocase
    condition:
        ($str1 and $str3) or ($str4 and $str5) or $xmrig
}

rule Reverse_Shell_Signatures {
    meta:
        description = "Detects common reverse shell commands in plain text"
        threat_level = "Critical"
    strings:
        $nc1 = "nc -e /bin/sh" ascii
        $nc2 = "nc -e /bin/bash" ascii
        $nc3 = "nc -e cmd.exe" ascii nocase
        
        $bash = "bash -i >& /dev/tcp/" ascii
        
        $py1 = "import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)" ascii
        $py2 = "pty.spawn(\"/bin/sh\")" ascii
        $py3 = "os.dup2(s.fileno()" ascii
        
        $ruby = "f=TCPSocket.open(" ascii
        $perl = "use Socket;$i=" ascii
    condition:
        any of them
}

rule Ransomware_File_Extensions_In_Traffic {
    meta:
        description = "Detects mentions of common ransomware extensions in traffic (could indicate ransom note or activity)"
        threat_level = "Medium"
    strings:
        $r1 = ".wannacry" nocase
        $r2 = ".lockbit" nocase
        $r3 = ".ryuk" nocase
        $r4 = ".phobos" nocase
        $r5 = ".cerber" nocase
        $note = "YOUR FILES HAVE BEEN ENCRYPTED" nocase
        $btc = "bitcoin address" nocase
    condition:
        any of them
}

rule Nmap_Scanner_UserAgent {
    meta:
        description = "Detects Nmap scanner HTTP probes"
        threat_level = "Low"
    strings:
        $ua = "Nmap Scripting Engine" ascii
    condition:
        $ua
}

rule Log4j_JNDI_Exploit {
    meta:
        description = "Detects Log4j JNDI lookup attempt in payload"
        threat_level = "Critical"
    strings:
        $jndi1 = "${jndi:ldap://" nocase
        $jndi2 = "${jndi:rmi://" nocase
        $jndi3 = "${jndi:dns://" nocase
        $jndi4 = "${jndi:${lower:" nocase
    condition:
        any of them
}
