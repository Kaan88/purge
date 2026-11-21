; Inno Setup 6 script for Purge (install\README.md, "Inno installer").
;
; Build it with install\inno\build-installer.ps1, which passes every payload path and the version as
; /D defines; the defaults below are the repository layout, so `ISCC purge.iss` works from a checkout
; whose target\release and target\ui-publish are already built.
;
; What the setup does that install\install.ps1 does not do itself: it copies the payload (Inno's own
; file copy), creates the shortcuts and the uninstall (ARP) entry. The protected trees are still the
; script's: the post-install step runs install.ps1 -ProtectOnly -DataRootOnly -SkipBuild, and the
; script's -Check then verifies the whole layout and fails the setup when anything is off.

#define AppName "Purge"

#ifndef AppVersion
  #define AppVersion "0.1.0"
#endif

; The repository root: the working directory of the sources below.
#ifndef RepoRoot
  #define RepoRoot "..\.."
#endif
#ifndef EngineExe
  #define EngineExe "target\release\purge-engine.exe"
#endif
#ifndef BrokerExe
  #define BrokerExe "target\release\purge-broker.exe"
#endif
#ifndef UiPublishDir
  #define UiPublishDir "target\ui-publish"
#endif
#ifndef KbDir
  #define KbDir "kb"
#endif
#ifndef InstallPs1
  #define InstallPs1 "install\install.ps1"
#endif
#ifndef OutDir
  #define OutDir "..\..\target\installer"
#endif

[Setup]
; A fixed AppId: every build of this script upgrades the same ARP entry ("Installed apps" and
; Settings > Apps show one Purge).
AppId={{7C1B9E64-2D58-4F1A-9B03-6E4C5A8D7F21}
AppName={#AppName}
AppVersion={#AppVersion}
AppVerName={#AppName} {#AppVersion}
AppPublisher=Purge
DefaultDirName={autopf}\Purge
DefaultGroupName={#AppName}
; The broker's start check refuses a directory that a non-administrator can write (start.rs), so the
; install directory is fixed: no directory page, no previous-directory reuse.
DisableDirPage=yes
UsePreviousAppDir=no
DisableProgramGroupPage=yes
; Program Files, the data root and the event-log source need elevation.
PrivilegesRequired=admin
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
; Purge.App targets Windows 10 2004 (10.0.19041) and the Windows App SDK.
MinVersion=10.0.19041
OutputDir={#OutDir}
OutputBaseFilename=Purge-Setup-{#AppVersion}
SetupIconFile={#RepoRoot}\ui\Purge.App\Assets\Purge.ico
Compression=lzma2/ultra64
SolidCompression=yes
WizardStyle=modern
UninstallDisplayName={#AppName}
UninstallDisplayIcon={app}\Purge.exe
; A running Purge.exe holds the files the setup replaces; Restart Manager offers to close it.
CloseApplications=yes
RestartApplications=no
VersionInfoVersion={#AppVersion}
VersionInfoCompany=Purge
VersionInfoDescription={#AppName} Setup
VersionInfoProductName={#AppName}
VersionInfoProductVersion={#AppVersion}
VersionInfoCopyright=Purge

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "Create a &desktop shortcut"; GroupDescription: "Additional shortcuts:"; Flags: unchecked

[Files]
; purge-engine.exe: the release engine, built on its own (install\README.md, "Release build").
Source: "{#EngineExe}"; DestDir: "{app}"; Flags: ignoreversion
; purge-broker.exe: the only binary that links the executor; Purge.exe starts it elevated.
Source: "{#BrokerExe}"; DestDir: "{app}"; Flags: ignoreversion
; The Native AOT publish of ui\Purge.App: Purge.exe, its Windows App SDK DLLs and Assets\.
Source: "{#UiPublishDir}\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs
; The knowledge base below <install dir>\kb, which is where the broker and the engine read it.
Source: "{#KbDir}\*"; DestDir: "{app}\kb"; Flags: ignoreversion recursesubdirs createallsubdirs
; The deploy script, for the post-install step below and for -Check / -Uninstall by hand.
Source: "{#InstallPs1}"; DestDir: "{app}\setup"; Flags: ignoreversion

[Icons]
; The same all-users Start-menu shortcut install.ps1 makes (Purge.lnk in the common Programs folder),
; so install.ps1 -Check finds the target it expects.
Name: "{commonprograms}\Purge"; Filename: "{app}\Purge.exe"; WorkingDir: "{app}"; IconFilename: "{app}\Purge.exe"; Comment: "Purge: remove programs and their leftovers"
Name: "{commondesktop}\Purge"; Filename: "{app}\Purge.exe"; WorkingDir: "{app}"; IconFilename: "{app}\Purge.exe"; Tasks: desktopicon

[Run]
Filename: "{app}\Purge.exe"; Description: "Launch {#AppName}"; Flags: nowait postinstall skipifsilent runasoriginaluser

[UninstallDelete]
; Inno removes the files it installed; this also removes anything Purge left in its own directory and
; the setup\ folder with install.ps1.
Type: filesandordirs; Name: "{app}"

[Code]
const
  CrLf = #13#10;
  EventLogKey = 'SYSTEM\CurrentControlSet\Services\EventLog\Application\Purge';
  DataRootName = 'Purge';

var
  ScriptLog: String;

function InitializeSetup: Boolean;
begin
  ScriptLog := ExpandConstant('{tmp}\purge-setup-install.log');
  Result := True;
end;

function InstallScriptPath: String;
begin
  Result := ExpandConstant('{app}\setup\install.ps1');
end;

{ Runs install.ps1 with the setup's own PowerShell and returns its exit code. cmd /C is there only to
  append the script's console output to ScriptLog: Inno Setup's Exec cannot redirect, and a failed
  check must be able to show what failed. }
function RunInstallScript(const Params: String; var ExitCode: Integer): Boolean;
var
  Command: String;
begin
  Command := '/C ""' + ExpandConstant('{sys}\WindowsPowerShell\v1.0\powershell.exe') +
    '" -NoProfile -ExecutionPolicy Bypass -File "' + InstallScriptPath + '" ' + Params +
    ' >> "' + ScriptLog + '" 2>&1"';
  Result := Exec(ExpandConstant('{cmd}'), Command, ExpandConstant('{app}'),
    SW_HIDE, ewWaitUntilTerminated, ExitCode);
end;

procedure FailSetup(const What: String; ExitCode: Integer);
var
  Raw: AnsiString;
  Tail: String;
begin
  Tail := '';
  if FileExists(ScriptLog) then
  begin
    Raw := '';
    if LoadStringFromFile(ScriptLog, Raw) then
      Tail := Raw;
  end;
  if Length(Tail) > 1200 then
    Tail := '...' + Copy(Tail, Length(Tail) - 1200, 1200);
  SuppressibleMsgBox(What + CrLf + CrLf +
    'install.ps1 exited with code ' + IntToStr(ExitCode) + '. The end of its log (' + ScriptLog + '):' +
    CrLf + CrLf + Tail,
    mbCriticalError, MB_OK, IDOK);
  { Abort in ssPostInstall rolls the setup back: the files the setup copied are removed again and
    nothing half-installed is left registered in "Installed apps". }
  Abort;
end;

procedure CurStepChanged(CurStep: TSetupStep);
var
  Code: Integer;
begin
  if CurStep = ssPostInstall then
  begin
    ScriptLog := ExpandConstant('{tmp}\purge-setup-install.log');
    DeleteFile(ScriptLog);

    { The setup copied the payload into the app directory; this step does what the .iss cannot:
      - -ProtectOnly gives the tree the layout's own descriptor (owner Administrators, protected
        DACL, Users read and execute). Inno's file copy inherits the Program Files DACL, which grants
        Users no write but is not the constant -Check compares against.
      - -DataRootOnly creates %ProgramData%\Purge (sessions, Quarantine, fp, kb,
        sessions\index.json) with each object's protected descriptor and registers the "Purge"
        event-log source, reusing install.ps1's native layer instead of duplicating it.
      No build, no payload copy, no shortcut: the setup did those. }
    if (not RunInstallScript('-ProtectOnly -DataRootOnly -SkipBuild', Code)) or (Code <> 0) then
    begin
      FailSetup('Purge Setup could not prepare its data folder or protect the installed files.', Code);
      Exit;
    end;

    { The script's own verification: both trees against their descriptors, every deployed file
      against the broker's per-object rule, the Start-menu shortcut and the event-log source. }
    if (not RunInstallScript('-Check', Code)) or (Code <> 0) then
      FailSetup('The installed files do not pass Purge''s own installation check.', Code);
  end;
end;

procedure StopPurgeImage(const ImageName: String);
var
  Code: Integer;
begin
  { taskkill exit code 128 means "not running", which is the normal case; the exit code is logged,
    not treated as an error. }
  if Exec(ExpandConstant('{sys}\taskkill.exe'), '/F /T /IM "' + ImageName + '"',
      '', SW_HIDE, ewWaitUntilTerminated, Code) then
    Log('taskkill ' + ImageName + ': exit code ' + IntToStr(Code))
  else
    Log('taskkill ' + ImageName + ' could not be started');
end;

procedure RemoveEventLogSource;
begin
  if not RegKeyExists(HKLM, EventLogKey) then
  begin
    Log('The event-log source is not registered');
    Exit;
  end;
  if RegDeleteKeyIncludingSubkeys(HKLM, EventLogKey) then
    Log('Removed HKLM\' + EventLogKey)
  else
    SuppressibleMsgBox('The "Purge" event-log source could not be removed:' + CrLf + CrLf +
      'HKLM\' + EventLogKey, mbError, MB_OK, IDOK);
end;

{ usUninstall runs before the uninstaller deletes any file: stop what holds the binaries, remove the
  registry key the install added, and ask about the data root while its contents still exist. }
procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
var
  DataRoot: String;
begin
  if CurUninstallStep = usUninstall then
  begin
    { The UI, the elevated broker it starts and the engine it hosts. Force: an uninstall does not wait
      for a purge operation that is still running, and an open file would fail the file removal. }
    StopPurgeImage('Purge.exe');
    StopPurgeImage('purge-broker.exe');
    StopPurgeImage('purge-engine.exe');

    RemoveEventLogSource;

    DataRoot := ExpandConstant('{commonappdata}\' + DataRootName);
    if DirExists(DataRoot) then
    begin
      { Default No (MB_DEFBUTTON2): the quarantine holds files that were removed from this PC and can
        still be restored, so deleting it is the user's explicit choice. Silent uninstalls keep it. }
      if SuppressibleMsgBox(
          'Also delete Purge''s data folder?' + CrLf + CrLf +
          DataRoot + CrLf + CrLf +
          'It holds the quarantine, the history and the fingerprint cache. Files in the quarantine ' +
          'were removed from this PC and can still be restored from there; deleting the folder makes ' +
          'them unrecoverable.' + CrLf + CrLf +
          'Choose No to keep the data folder; installing Purge again will find it.',
          mbConfirmation, MB_YESNO or MB_DEFBUTTON2, IDNO) = IDYES then
      begin
        if DelTree(DataRoot, True, True, True) then
          Log('Removed ' + DataRoot)
        else
          SuppressibleMsgBox('The data folder could not be deleted completely:' + CrLf + CrLf +
            DataRoot, mbError, MB_OK, IDOK);
      end
      else
        Log('Kept ' + DataRoot);
    end;
  end;
end;
