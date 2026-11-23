; Inno Setup 6 script for Purge (install\README.md, "Inno installer").
;
; Build it with install\inno\build-installer.ps1, which passes every payload path and the version as
; /D defines; the payload defaults below are the repository layout. The version has no default here:
; the one version of Purge is [workspace.package] version in the root Cargo.toml, and the script passes
; it as /DAppVersion. The preprocessor then refuses to compile a setup whose purge-engine.exe,
; purge-broker.exe or Purge.exe carries another version (their version resources come from the same
; Cargo.toml: bins\versioninfo.rs, ui\Directory.Build.props).
;
; Hub (Kaan88/mdhub, docs/COMPLIANCE.md sections 1 and 4) installs and updates Purge by running this
; setup elevated with /VERYSILENT /SUPPRESSMSGBOXES /NORESTART and reading its exit code (0 = done). So:
; the AppId and DefaultDirName never change, a silent run shows nothing and asks nothing, and the setup
; itself stops Purge (PrepareToInstall), because the broker and the engine have no window Hub could
; ask to close and Hub never ends a process.
;
; What the setup does that install\install.ps1 does not do itself: it copies the payload (Inno's own
; file copy), creates the shortcuts and the uninstall (ARP) entry. The protected trees are still the
; script's: the post-install step runs install.ps1 -ProtectOnly -DataRootOnly -SkipBuild, and the
; script's -Check then verifies the whole layout and fails the setup when anything is off.

#define AppName "Purge"

#ifndef AppVersion
  #error Pass /DAppVersion=<the [workspace.package] version of Cargo.toml> (install\inno\build-installer.ps1 does)
#endif

; The repository root, relative to this script's folder unless given absolute.
#ifndef RepoRoot
  #define RepoRoot "..\.."
#endif
#ifndef EngineExe
  #define EngineExe RepoRoot + "\target\release\purge-engine.exe"
#endif
#ifndef BrokerExe
  #define BrokerExe RepoRoot + "\target\release\purge-broker.exe"
#endif
#ifndef UiPublishDir
  #define UiPublishDir RepoRoot + "\target\ui-publish"
#endif
#ifndef KbDir
  #define KbDir RepoRoot + "\kb"
#endif
#ifndef InstallPs1
  #define InstallPs1 RepoRoot + "\install\install.ps1"
#endif
#ifndef OutDir
  #define OutDir RepoRoot + "\target\installer"
#endif

; X.Y.Z of X.Y.Z[-pre]: the numeric version Windows' version resources hold.
#if Pos("-", AppVersion) > 0
  #define AppVersionNumeric Copy(AppVersion, 1, Pos("-", AppVersion) - 1)
#else
  #define AppVersionNumeric AppVersion
#endif

; Every shipped exe must carry AppVersion: ProductVersion (the string) = AppVersion, and the fixed
; FILEVERSION = AppVersionNumeric.0, which is what Hub reads from Purge.exe (COMPLIANCE.md section 5).
#sub CheckExeVersion
  #define Path PayloadExe
  #if !FileExists(Path)
    #pragma error "The payload is missing: " + Path
  #endif
  #define GotProduct GetStringFileInfo(Path, "ProductVersion")
  #define GotFixed GetVersionNumbersString(Path)
  #if GotProduct != AppVersion
    #pragma error "Version mismatch: " + Path + " says ProductVersion '" + GotProduct + "', the setup is " + AppVersion
  #endif
  #if GotFixed != AppVersionNumeric + ".0"
    #pragma error "Version mismatch: " + Path + " has FILEVERSION " + GotFixed + ", the setup is " + AppVersionNumeric + ".0"
  #endif
#endsub
#define PayloadExe EngineExe
#expr CheckExeVersion
#define PayloadExe BrokerExe
#expr CheckExeVersion
#define PayloadExe UiPublishDir + "\Purge.exe"
#expr CheckExeVersion

[Setup]
; A fixed AppId: every build of this script upgrades the same ARP entry ("Installed apps" and
; Settings > Apps show one Purge). Never change it, nor DefaultDirName: Hub's catalog names the
; uninstall key {7C1B9E64-2D58-4F1A-9B03-6E4C5A8D7F21}_is1 and finds Purge.exe through its
; InstallLocation and DisplayVersion (= AppVersion, rewritten by every install and update).
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
; A running Purge.exe holds the files the setup replaces. PrepareToInstall (below) stops every process
; that runs from {app} first, window or not; Restart Manager stays as the fallback for anything else
; that holds a file (a silent setup lets it close those without asking).
CloseApplications=yes
RestartApplications=no
VersionInfoVersion={#AppVersionNumeric}
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

type
  TPidList = array of Integer;

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
  { A silent setup (Hub's update) shows nothing even without /SUPPRESSMSGBOXES: the setup log gets the
    text and the exit code tells the caller the setup failed. }
  if WizardSilent then
    Log(What + ' install.ps1 exited with code ' + IntToStr(ExitCode) + '. The end of its log (' +
      ScriptLog + '):' + CrLf + Tail)
  else
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

{ The processes whose executable is inside AppDir (Purge.exe, purge-broker.exe, purge-engine.exe, and
  anything else started from the install folder), found by their path through WMI, so that a
  purge-engine.exe of a development build elsewhere is not touched. Purge.exe comes first: it hosts
  the engine and started the broker. The setup is elevated, so it reads the elevated broker's path. }
function FindAppProcesses(const AppDir: String; var Pids: TPidList; var Names: String): Integer;
var
  Locator, Services, Found, Item: Variant;
  I, Pid, Pass: Integer;
  ExePath, Name, Prefix: String;
begin
  Result := 0;
  Names := '';
  SetArrayLength(Pids, 0);
  Prefix := AddBackslash(AppDir);
  Locator := CreateOleObject('WbemScripting.SWbemLocator');
  Services := Locator.ConnectServer('.', 'root\CIMV2');
  Found := Services.ExecQuery('SELECT ProcessId, Name, ExecutablePath FROM Win32_Process');
  for Pass := 0 to 1 do
    for I := 0 to Found.Count - 1 do
    begin
      Item := Found.ItemIndex(I);
      if VarIsNull(Item.ExecutablePath) or VarIsNull(Item.Name) then
        Continue;
      ExePath := Item.ExecutablePath;
      Name := Item.Name;
      if CompareText(Copy(ExePath, 1, Length(Prefix)), Prefix) <> 0 then
        Continue;
      if (CompareText(Name, 'Purge.exe') = 0) <> (Pass = 0) then
        Continue;
      Pid := Item.ProcessId;
      SetArrayLength(Pids, Result + 1);
      Pids[Result] := Pid;
      Result := Result + 1;
      if Names <> '' then
        Names := Names + ', ';
      Names := Names + Name + ' (' + IntToStr(Pid) + ')';
    end;
end;

{ Stops every process that runs from AppDir and waits until they are gone. True when none is left.
  taskkill /F per process id, without /T: a child the broker started (another program's uninstaller)
  is not Purge's and is left alone. }
function StopAppProcesses(const AppDir: String): Boolean;
var
  Pids: TPidList;
  Names: String;
  I, Count, Code, Waited: Integer;
begin
  Count := FindAppProcesses(AppDir, Pids, Names);
  Result := Count = 0;
  if Result then
    Exit;
  Log('Stopping Purge before the files are replaced: ' + Names);
  for I := 0 to Count - 1 do
    if Exec(ExpandConstant('{sys}\taskkill.exe'), '/F /PID ' + IntToStr(Pids[I]), '', SW_HIDE,
        ewWaitUntilTerminated, Code) then
      Log('taskkill /F /PID ' + IntToStr(Pids[I]) + ': exit code ' + IntToStr(Code))
    else
      Log('taskkill could not be started for process ' + IntToStr(Pids[I]));
  Waited := 0;
  repeat
    Sleep(250);
    Waited := Waited + 250;
    Count := FindAppProcesses(AppDir, Pids, Names);
  until (Count = 0) or (Waited >= 10000);
  Result := Count = 0;
  if not Result then
    Log('Still running after ' + IntToStr(Waited) + ' ms: ' + Names);
end;

{ Hub (COMPLIANCE.md section 4) asks Purge's window to close and never ends a process; the broker and
  the engine have no window. So the setup stops whatever still runs from the install folder before it
  replaces a file, in a silent run without asking. Interactive, it asks first (OK is the default when
  message boxes are suppressed). A non-empty result stops the setup on the Preparing page; a silent
  setup then exits with code 7 and changes nothing. }
function PrepareToInstall(var NeedsRestart: Boolean): String;
var
  AppDir, Names: String;
  Pids: TPidList;
  Count: Integer;
begin
  Result := '';
  AppDir := ExpandConstant('{app}');
  if not DirExists(AppDir) then
    Exit;
  try
    Count := FindAppProcesses(AppDir, Pids, Names);
    if Count = 0 then
      Exit;
    if not WizardSilent then
      if SuppressibleMsgBox('Purge is running: ' + Names + '.' + CrLf + CrLf +
          'Setup closes it before it replaces the files. A cleanup that is still running stops where it ' +
          'is; Purge offers to resume or roll it back the next time it starts.' + CrLf + CrLf +
          'Choose Cancel to close Purge yourself first.',
          mbConfirmation, MB_OKCANCEL, IDOK) <> IDOK then
      begin
        Result := 'Purge is still running. Close Purge, then run Setup again.';
        Exit;
      end;
    if not StopAppProcesses(AppDir) then
      Result := 'Purge could not be closed. Close Purge, then run Setup again.';
  except
    { No WMI: stop the three images by name, as the uninstaller does. }
    Log('Finding Purge''s processes failed (' + GetExceptionMessage + '); stopping them by name');
    StopPurgeImage('Purge.exe');
    StopPurgeImage('purge-broker.exe');
    StopPurgeImage('purge-engine.exe');
  end;
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
  else if UninstallSilent then
    Log('The "Purge" event-log source could not be removed: HKLM\' + EventLogKey)
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
        still be restored, so deleting it is the user's explicit choice. Silent uninstalls keep it
        without asking, also without /SUPPRESSMSGBOXES. }
      if UninstallSilent then
        Log('Silent uninstall: kept ' + DataRoot)
      else if SuppressibleMsgBox(
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
