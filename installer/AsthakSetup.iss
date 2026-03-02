; ═══════════════════════════════════════════════════════════════════════════
; Asthak EDR — Professional Installer Script
; Built with Inno Setup 6.x  (https://jrsoftware.org/isinfo.php)
; ═══════════════════════════════════════════════════════════════════════════

#define AppName      "Asthak EDR"
#define AppVersion   "1.0.0"
#define AppPublisher "Asthak Security"
#define AppURL       "https://asthaksecurity.com"
#define AppExeName   "Asthak.exe"
#define ServiceName  "AsthakEDR"

[Setup]
; App Identification
AppId={{A3F8C2D1-7E45-4B9A-8C3F-2D1E5A7B9C0F}
AppName={#AppName}
AppVersion={#AppVersion}
AppVerName={#AppName} {#AppVersion}
AppPublisher={#AppPublisher}
AppPublisherURL={#AppURL}
AppSupportURL={#AppURL}/support
AppUpdatesURL={#AppURL}/updates

; Installer Settings
DefaultDirName={autopf}\AsthakEDR
DefaultGroupName={#AppName}
AllowNoIcons=yes
LicenseFile=..\legal\EULA.txt
InfoBeforeFile=..\legal\PRIVACY_POLICY.txt
OutputDir=..\dist\installer
OutputBaseFilename=AsthakEDR_Setup_v{#AppVersion}
SetupIconFile=..\app\icon.ico
UninstallDisplayIcon={app}\Asthak.exe

; Compression
Compression=lzma2/ultra64
SolidCompression=yes
LZMAUseSeparateProcess=yes

; Windows Version Requirements
MinVersion=10.0
ArchitecturesAllowed=x64
ArchitecturesInstallIn64BitMode=x64

; Privileges (required for service installation)
PrivilegesRequired=admin
PrivilegesRequiredOverridesAllowed=dialog

; Appearance
WizardStyle=modern
WizardSizePercent=120
ShowLanguageDialog=no
ShowTasksTreeLines=yes

; Uninstall
UninstallDisplayName={#AppName}
CreateUninstallRegKey=yes
Uninstallable=yes

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon";    Description: "Create a &desktop shortcut";           GroupDescription: "Additional icons:"
Name: "startupicon";   Description: "Start with &Windows (recommended)";    GroupDescription: "Startup:"; Flags: checkedonce
Name: "systemtray";    Description: "Run in system &tray";                   GroupDescription: "Options:"; Flags: checkedonce

[Files]
; Main executable
Source: "..\build\Asthak.exe";            DestDir: "{app}";              Flags: ignoreversion

; YARA rules file
Source: "..\rules.yar";                    DestDir: "{app}\rules";        Flags: ignoreversion

; Web dashboard (React build)
Source: "..\web\build\*";                  DestDir: "{app}\dashboard";    Flags: ignoreversion recursesubdirs createallsubdirs

; Backend
Source: "..\backend\*";                    DestDir: "{app}\backend";      Flags: ignoreversion recursesubdirs createallsubdirs excludes node_modules,.git

; Visual C++ Runtime (if needed)
; Source: "vcredist_x64.exe";             DestDir: "{tmp}"; Flags: deleteafterinstall

; Legal docs
Source: "..\legal\EULA.txt";              DestDir: "{app}\legal";        Flags: ignoreversion
Source: "..\legal\PRIVACY_POLICY.txt";    DestDir: "{app}\legal";        Flags: ignoreversion

; Config template
Source: "..\installer\config_template.json"; DestDir: "{app}"; DestName: "config.json"; Flags: onlyifdoesntexist

[Dirs]
; Directories needed by the app
Name: "{app}\logs";         Permissions: everyone-readwriteexec
Name: "{app}\quarantine";   Permissions: everyone-readwriteexec
Name: "{app}\rules";        Permissions: everyone-readwriteexec
Name: "{commonappdata}\AsthakEDR"; Permissions: everyone-readwriteexec

[Icons]
Name: "{group}\{#AppName}";              Filename: "{app}\{#AppExeName}"
Name: "{group}\Uninstall {#AppName}";   Filename: "{uninstallexe}"
Name: "{autodesktop}\{#AppName}";        Filename: "{app}\{#AppExeName}"; Tasks: desktopicon

[Run]
; Install as Windows Service
Filename: "{app}\{#AppExeName}"; Parameters: "--install-service"; \
    Flags: runhidden waituntilterminated; \
    StatusMsg: "Installing Asthak EDR service..."; \
    Check: ShouldInstallService

; Start the service
Filename: "net"; Parameters: "start {#ServiceName}"; \
    Flags: runhidden waituntilterminated; \
    StatusMsg: "Starting Asthak EDR service..."; \
    Check: ShouldInstallService

; Optional: Launch dashboard
Filename: "{app}\{#AppExeName}"; Description: "Launch {#AppName} dashboard"; \
    Flags: nowait postinstall skipifsilent unchecked

[UninstallRun]
; Stop and remove service on uninstall
Filename: "net";            Parameters: "stop {#ServiceName}";    Flags: runhidden waituntilterminated
Filename: "{app}\{#AppExeName}"; Parameters: "--uninstall-service"; Flags: runhidden waituntilterminated

[Registry]
; Run at startup if task selected
Root: HKCU; Subkey: "Software\Microsoft\Windows\CurrentVersion\Run"; \
    ValueType: string; ValueName: "{#AppName}"; \
    ValueData: """{app}\{#AppExeName}"" --tray"; \
    Flags: uninsdeletevalue; Tasks: startupicon

; Store install path
Root: HKLM; Subkey: "SOFTWARE\AsthakEDR"; ValueType: string; \
    ValueName: "InstallPath"; ValueData: "{app}"; Flags: uninsdeletekey

Root: HKLM; Subkey: "SOFTWARE\AsthakEDR"; ValueType: string; \
    ValueName: "Version"; ValueData: "{#AppVersion}"

[Code]
// ─────────────────────────────────────────────────────────────────────────────
// Custom code for installer logic
// ─────────────────────────────────────────────────────────────────────────────

function ShouldInstallService(): Boolean;
begin
  Result := True; // Always install as service
end;

function InitializeSetup(): Boolean;
var
  Version: TWindowsVersion;
begin
  GetWindowsVersionEx(Version);
  
  // Require Windows 10 build 17763+ (1809)
  if (Version.Major < 10) or 
     ((Version.Major = 10) and (Version.Build < 17763)) then
  begin
    MsgBox('Asthak EDR requires Windows 10 (version 1809) or later.' + #13#10 +
           'Your system does not meet this requirement.', 
           mbCriticalError, MB_OK);
    Result := False;
    Exit;
  end;
  
  Result := True;
end;

procedure CurStepChanged(CurStep: TSetupStep);
begin
  if CurStep = ssPostInstall then
  begin
    // Create default config if none exists
    if not FileExists(ExpandConstant('{app}\config.json')) then
    begin
      // Config created from template via [Files] section
    end;
  end;
end;

function PrepareToInstall(var NeedsRestart: Boolean): String;
var
  ResultCode: Integer;
begin
  // Stop existing service if running (upgrade scenario)
  Exec('net', 'stop AsthakEDR', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  Result := ''; // Return empty = proceed with install
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
begin
  if CurUninstallStep = usPostUninstall then
  begin
    // Clean up registry
    RegDeleteKeyIncludingSubkeys(HKLM, 'SOFTWARE\AsthakEDR');
    // Clean up logs (optional - ask user)
    if MsgBox('Do you want to remove all Asthak EDR logs and quarantine data?',
              mbConfirmation, MB_YESNO) = IDYES then
    begin
      DelTree(ExpandConstant('{app}\logs'), True, True, True);
      DelTree(ExpandConstant('{app}\quarantine'), True, True, True);
    end;
  end;
end;
