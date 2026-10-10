#ifndef AppVersion
  #error AppVersion is required
#endif
#ifndef PackageDir
  #error PackageDir is required
#endif
#ifndef OutputDir
  #error OutputDir is required
#endif
#ifndef OutputBaseFilename
  #error OutputBaseFilename is required
#endif
#ifndef IconPath
  #error IconPath is required
#endif

#define AppName "ida-agent"
#define GatewayName "ida-mcp.exe"
#define PluginName "ida-agent-plugin.dll"

[Setup]
AppId={{A09DB64A-916C-4D9E-A9AE-99629A14A0BC}
AppName={#AppName}
AppVersion={#AppVersion}
AppPublisher=ida-agent
AppVerName={#AppName} {#AppVersion}
VersionInfoVersion={#AppWindowsVersion}
VersionInfoProductName={#AppName}
VersionInfoDescription=ida-agent Windows x64 installer
DefaultDirName={localappdata}\Programs\ida-agent
DefaultGroupName=ida-agent
DisableProgramGroupPage=yes
AllowNoIcons=yes
PrivilegesRequired=lowest
ArchitecturesAllowed=x64compatible
OutputDir={#OutputDir}
OutputBaseFilename={#OutputBaseFilename}
SetupIconFile={#IconPath}
UninstallDisplayIcon={app}\{#GatewayName}
Compression=lzma2
SolidCompression=yes
WizardStyle=modern dynamic
CloseApplications=yes
CloseApplicationsFilter={#GatewayName}
RestartApplications=no
ChangesAssociations=no
ChangesEnvironment=no

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "Create a &desktop shortcut"; GroupDescription: "Additional shortcuts:"; Flags: unchecked

[Files]
Source: "{#PackageDir}\{#GatewayName}"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#PackageDir}\ida-agent.ico"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#PackageDir}\README.txt"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#PackageDir}\skills\*"; DestDir: "{app}\skills"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "{#PackageDir}\plugins\{#PluginName}"; DestDir: "{userappdata}\Hex-Rays\IDA Pro\plugins"; Flags: ignoreversion restartreplace uninsneveruninstall

[Registry]
Root: HKCU; Subkey: "Software\ida-agent"; ValueType: string; ValueName: "PluginOwnedSHA256"; ValueData: "{#PluginSHA256}"; Flags: uninsdeletevalue uninsdeletekeyifempty

[Icons]
Name: "{group}\ida-mcp Manager"; Filename: "{app}\{#GatewayName}"; Parameters: "-web"; WorkingDir: "{app}"; IconFilename: "{app}\{#GatewayName}"
Name: "{autodesktop}\ida-mcp Manager"; Filename: "{app}\{#GatewayName}"; Parameters: "-web"; WorkingDir: "{app}"; IconFilename: "{app}\{#GatewayName}"; Tasks: desktopicon

[Run]
Filename: "{app}\{#GatewayName}"; Parameters: "-web"; Description: "Launch ida-mcp Manager"; Flags: nowait postinstall skipifsilent

[UninstallRun]
Filename: "{app}\{#GatewayName}"; Parameters: "-remove-skill-links"; Flags: runhidden waituntilterminated skipifdoesntexist; RunOnceId: "RemoveManagedSkillLinks"

[Code]
const
  InvalidFileAttributes = $FFFFFFFF;
  FileAttributeReparsePoint = $00000400;
  FileAttributeDirectory = $00000010;

var
  PluginBackedUp: Boolean;
  InstallCompleted: Boolean;

function GetFileAttributesW(FileName: String): LongWord;
  external 'GetFileAttributesW@kernel32.dll stdcall';

function PluginPath: String;
begin
  Result := ExpandConstant('{userappdata}\Hex-Rays\IDA Pro\plugins\{#PluginName}');
end;

function PluginBackupPath: String;
begin
  Result := PluginPath + '.pre-ida-agent';
end;

function IsReparsePoint(const Path: String): Boolean;
var
  Attributes: LongWord;
begin
  Attributes := GetFileAttributesW(Path);
  Result := (Attributes <> InvalidFileAttributes) and
    ((Attributes and FileAttributeReparsePoint) <> 0);
end;

function TreeContainsReparsePoint(const Path: String): Boolean;
var
  FindRec: TFindRec;
  Child: String;
begin
  Result := IsReparsePoint(Path);
  if Result or not DirExists(Path) then
    Exit;

  if FindFirst(AddBackslash(Path) + '*', FindRec) then
  begin
    try
      repeat
        if (FindRec.Name <> '.') and (FindRec.Name <> '..') then
        begin
          Child := AddBackslash(Path) + FindRec.Name;
          if (FindRec.Attributes and FileAttributeReparsePoint) <> 0 then
          begin
            Result := True;
            Exit;
          end;
          if ((FindRec.Attributes and FileAttributeDirectory) <> 0) and
             TreeContainsReparsePoint(Child) then
          begin
            Result := True;
            Exit;
          end;
        end;
      until not FindNext(FindRec);
    finally
      FindClose(FindRec);
    end;
  end;
end;

function TryFileSHA256(const Path: String; var Digest: String): Boolean;
begin
  Result := False;
  try
    Digest := GetSHA256OfFile(Path);
    Result := True;
  except
    Log('Unable to hash file: ' + Path);
  end;
end;

function PrepareCurrentPlugin: String;
var
  AppPath: String;
  CurrentHash: String;
  OwnedHash: String;
begin
  Result := '';
  AppPath := ExpandConstant('{app}');
  if TreeContainsReparsePoint(AppPath) then
  begin
    Result := 'The ida-agent application or skills path is a reparse point. Choose a normal local directory.';
    Exit;
  end;

  if RegQueryStringValue(HKCU, 'Software\ida-agent', 'PluginOwnedSHA256', OwnedHash) then
  begin
    if FileExists(PluginPath) then
    begin
      if not TryFileSHA256(PluginPath, CurrentHash) then
      begin
        Result := 'The existing IDA Plugin cannot be verified. Close IDA and retry.';
        Exit;
      end;
      if CompareText(CurrentHash, OwnedHash) <> 0 then
      begin
        Result := 'The installed IDA Plugin was modified outside ida-agent. It will not be overwritten.';
        Exit;
      end;
    end;
    Exit;
  end;

  if FileExists(PluginPath) then
  begin
    if FileExists(PluginBackupPath) then
    begin
      Result := 'An IDA Plugin backup already exists: ' + PluginBackupPath;
      Exit;
    end;
    if not RenameFile(PluginPath, PluginBackupPath) then
    begin
      Result := 'The existing IDA Plugin could not be backed up. Close IDA and retry.';
      Exit;
    end;
    PluginBackedUp := True;
    Log('Backed up pre-existing IDA Plugin to ' + PluginBackupPath);
  end;
end;

function PrepareToInstall(var NeedsRestart: Boolean): String;
begin
  Result := '';
  if FileExists(ExpandConstant('{app}\ida-agent-gateway.exe')) or
     FileExists(ExpandConstant('{app}\ida-mcp-gateway.exe')) then
  begin
    Result := 'This version requires a fresh installation. Uninstall the previous package and remove its old MCP client entries first.';
    Exit;
  end;
  Result := PrepareCurrentPlugin;
end;

function InitializeUninstall: Boolean;
var
  AppPath: String;
begin
  AppPath := ExpandConstant('{app}');
  Result := not TreeContainsReparsePoint(AppPath);
  if not Result then
    MsgBox('Uninstall stopped because the ida-agent application or skills path is a reparse point.', mbError, MB_OK);
end;

procedure CurStepChanged(CurStep: TSetupStep);
begin
  if CurStep = ssDone then
    InstallCompleted := True;
end;

procedure DeinitializeSetup;
var
  CurrentHash: String;
begin
  if PluginBackedUp and not InstallCompleted then
  begin
    if FileExists(PluginPath) and TryFileSHA256(PluginPath, CurrentHash) and
       (CompareText(CurrentHash, '{#PluginSHA256}') = 0) then
      DeleteFile(PluginPath);
    if PluginBackedUp and not FileExists(PluginPath) and FileExists(PluginBackupPath) then
      RenameFile(PluginBackupPath, PluginPath);
  end;
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
var
  CurrentHash: String;
begin
  if CurUninstallStep <> usUninstall then
    Exit;

  if FileExists(PluginPath) then
  begin
    if TryFileSHA256(PluginPath, CurrentHash) and
       (CompareText(CurrentHash, '{#PluginSHA256}') = 0) then
    begin
      if not DeleteFile(PluginPath) then
        Log('The installed IDA Plugin is in use and was preserved: ' + PluginPath);
    end
    else
      Log('The IDA Plugin was modified after installation and was preserved: ' + PluginPath);
  end;

  if FileExists(PluginBackupPath) then
  begin
    if not FileExists(PluginPath) then
    begin
      if RenameFile(PluginBackupPath, PluginPath) then
        Log('Restored pre-existing IDA Plugin from ' + PluginBackupPath)
      else
        Log('Unable to restore pre-existing IDA Plugin from ' + PluginBackupPath);
    end
    else
      Log('Pre-existing IDA Plugin backup was preserved at ' + PluginBackupPath);
  end;
end;
