; Inno Setup 6 script for Purge (install\README.md, "Inno installer").
;
; Build it with install\inno\build-installer.ps1, which passes every payload path and the version as
; /D defines; the payload defaults below are the repository layout. The version has no default here:
; the one version of Purge is [workspace.package] version in the root Cargo.toml, and the script passes
; it as /DAppVersion. The preprocessor then refuses to compile a setup whose purge-engine.exe,
; purge-broker.exe or Purge.exe carries another version (their version resources come from the same
; Cargo.toml through bins\versioninfo.rs; Purge.exe is the Rust UI, bins\purge-ui).
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
; Purge.exe: the release build of bins\purge-ui (cargo build --release -p purge-ui), one file.
#ifndef UiExe
  #define UiExe RepoRoot + "\target\release\Purge.exe"
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

; X.Y.Z of X.Y.Z[-pre].
#if Pos("-", AppVersion) > 0
  #define AppVersionNumeric Copy(AppVersion, 1, Pos("-", AppVersion) - 1)
#else
  #define AppVersionNumeric AppVersion
#endif

; The four-number FILEVERSION of AppVersion (check-version.ps1 -FileVersion: X.Y.Z -> X.Y.Z.0,
; X.Y.Z-alpha.N -> X.Y.Z.N, -beta.N -> 1000+N, -rc.N -> 2000+N; bins\versioninfo.rs has the same rule).
; build-installer.ps1 passes it; without it only a final X.Y.Z compiles (X.Y.Z.0).
#ifndef AppFileVersion
  #if Pos("-", AppVersion) > 0
    #error Pass /DAppFileVersion=<check-version.ps1 -FileVersion> for a pre-release version (install\inno\build-installer.ps1 does)
  #endif
  #define AppFileVersion AppVersionNumeric + ".0"
#endif
#if Copy(AppFileVersion, 1, Len(AppVersionNumeric) + 1) != AppVersionNumeric + "."
  #error AppFileVersion does not start with the X.Y.Z of AppVersion
#endif

; Every shipped exe must carry AppVersion: ProductVersion (the string) = AppVersion, and the fixed
; FILEVERSION = AppFileVersion, which is what Hub reads from Purge.exe (COMPLIANCE.md section 5).
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
  #if GotFixed != AppFileVersion
    #pragma error "Version mismatch: " + Path + " has FILEVERSION " + GotFixed + ", the setup is " + AppFileVersion
  #endif
#endsub
#define PayloadExe EngineExe
#expr CheckExeVersion
#define PayloadExe BrokerExe
#expr CheckExeVersion
#define PayloadExe UiExe
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
; Windows 10 2004 (10.0.19041), the floor of the earlier WinUI app, kept for the Rust UI.
MinVersion=10.0.19041
OutputDir={#OutDir}
OutputBaseFilename=Purge-Setup-{#AppVersion}
SetupIconFile={#RepoRoot}\install\inno\Purge.ico
Compression=lzma2/ultra64
SolidCompression=yes
WizardStyle=modern
UninstallDisplayName={#AppName}
UninstallDisplayIcon={app}\Purge.exe
; A running Purge.exe holds the files the setup replaces. PrepareToInstall (below) first stops Purge's
; own executables in {app} (Purge.exe, purge-broker.exe, purge-engine.exe, and RestartAgent.exe of an
; earlier WinUI install), window or
; not, and refuses any install folder but {autopf}\Purge; Restart Manager stays as the fallback for
; anything else that holds a file (a silent setup lets it close those without asking).
CloseApplications=yes
RestartApplications=no
; Always write %TEMP%\Setup Log <date> #<n>.txt (Hub's arguments have no /LOG): a silent run reports a
; failed post-install step only there and through its exit code.
SetupLogging=yes
VersionInfoVersion={#AppFileVersion}
VersionInfoCompany=Purge
VersionInfoDescription={#AppName} Setup
VersionInfoProductName={#AppName}
; The binary versions are four numbers (AppFileVersion); the strings carry AppVersion, so the setup's
; ProductVersion string is AppVersion also for a pre-release (check-version.ps1 -Setup reads it).
VersionInfoTextVersion={#AppVersion}
VersionInfoProductVersion={#AppFileVersion}
VersionInfoProductTextVersion={#AppVersion}
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
; Purge.exe: the Rust UI (bins\purge-ui), a single file with no DLLs or resource folders. The broker
; serves only <install dir>\Purge.exe (start.rs), so the name never changes.
Source: "{#UiExe}"; DestDir: "{app}"; DestName: "Purge.exe"; Flags: ignoreversion
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
; Not offered after a failed post-install step: the tree did not pass its own check.
Filename: "{app}\Purge.exe"; Description: "Launch {#AppName}"; Flags: nowait postinstall skipifsilent runasoriginaluser; Check: PostInstallSucceeded

[InstallDelete]
; An update over 0.1.x (the WinUI app) first removes that app's Windows App SDK payload: its DLLs,
; .winmd/.pri files, PDBs, RestartAgent.exe and its folders (Assets, Microsoft.UI.Xaml; the language
; folders go in RemoveWinUiLanguageDirs below). {app} is always {autopf}\Purge (PrepareToInstall), and
; nothing Purge ships today has these names.
Type: files; Name: "{app}\*.dll"
Type: files; Name: "{app}\*.winmd"
Type: files; Name: "{app}\*.pri"
Type: files; Name: "{app}\*.pdb"
Type: files; Name: "{app}\RestartAgent.exe"
Type: filesandordirs; Name: "{app}\Assets"
Type: filesandordirs; Name: "{app}\Microsoft.UI.Xaml"

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
  { Set by FailSetup. The post-install step runs after Inno has copied the files and written the
    uninstall entry, and Inno cannot undo that from ssPostInstall (an exception there is logged and
    swallowed, and the setup still ends with exit code 0), so a failure is reported through the exit
    code instead: GetCustomSetupExitCode below. }
  PostInstallFailed: Boolean;

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
  { No rollback: the new files and the uninstall entry (with the new DisplayVersion) stay. The setup
    exits with code 9 instead of 0 (GetCustomSetupExitCode), so Hub and any other caller see a failed
    install, and the Finished page says so. Running the setup again repeats the step. }
  PostInstallFailed := True;
end;

function PostInstallSucceeded: Boolean;
begin
  Result := not PostInstallFailed;
end;

{ Inno's own exit codes are 0 to 8; it calls this only when the setup would otherwise exit with 0. }
function GetCustomSetupExitCode: Integer;
begin
  if PostInstallFailed then
    Result := 9
  else
    Result := 0;
end;

procedure CurPageChanged(CurPageID: Integer);
begin
  if (CurPageID = wpFinished) and PostInstallFailed then
  begin
    WizardForm.FinishedLabel.Caption :=
      'Setup copied Purge''s files, but its post-install step failed, so Purge is not ready to use. ' +
      'Run Setup again; if it fails again, the setup log (%TEMP%\Setup Log*.txt) says why.';
    WizardForm.AdjustLabelHeight(WizardForm.FinishedLabel);
  end;
end;

{ The language folders of the earlier WinUI app's publish (en-us, de-DE, sr-Cyrl-RS, ...): every
  folder directly in AppDir whose name has a '-' and no '.'. Purge's own folders are kb and setup. }
procedure RemoveWinUiLanguageDirs(const AppDir: String);
var
  F: TFindRec;
  Dirs: TArrayOfString;
  I: Integer;
begin
  SetArrayLength(Dirs, 0);
  if FindFirst(AppDir + '\*', F) then
  try
    repeat
      if ((F.Attributes and FILE_ATTRIBUTE_DIRECTORY) <> 0) and (Pos('-', F.Name) > 0) and
        (Pos('.', F.Name) = 0) then
      begin
        SetArrayLength(Dirs, GetArrayLength(Dirs) + 1);
        Dirs[GetArrayLength(Dirs) - 1] := F.Name;
      end;
    until not FindNext(F);
  finally
    FindClose(F);
  end;
  for I := 0 to GetArrayLength(Dirs) - 1 do
  begin
    Log('Removing the WinUI language folder ' + AppDir + '\' + Dirs[I]);
    if not DelTree(AppDir + '\' + Dirs[I], True, True, True) then
      Log('Could not remove ' + AppDir + '\' + Dirs[I]);
  end;
end;

procedure CurStepChanged(CurStep: TSetupStep);
var
  Code: Integer;
begin
  { ssInstall runs after PrepareToInstall stopped Purge and before Inno copies the files. }
  if CurStep = ssInstall then
    RemoveWinUiLanguageDirs(RemoveBackslashUnlessRoot(ExpandConstant('{app}')));
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

{ The executables of Purge in its install folder: the UI, the broker and the engine, and
  RestartAgent.exe, which the earlier WinUI app's Windows App SDK publish put next to Purge.exe (an
  update over such an install may still find it; it runs only for AppInstance.Restart, which Purge
  never called). The setup stops nothing else, so a /DIR that
  points at a folder of other programs could not make it end those (PrepareToInstall refuses such a
  folder anyway). }
function IsAppImage(const Name: String): Boolean;
begin
  Result := (CompareText(Name, 'Purge.exe') = 0) or (CompareText(Name, 'purge-broker.exe') = 0) or
    (CompareText(Name, 'purge-engine.exe') = 0) or (CompareText(Name, 'RestartAgent.exe') = 0);
end;

{ By image name, without /T: a program's uninstaller the broker started is not Purge's and is left
  alone. taskkill exit code 128 means "not running", which is the normal case; the exit code is
  logged, not treated as an error. Used by the uninstaller, and by the setup only when WMI cannot
  list the processes; never for RestartAgent.exe, which every Windows App SDK app ships. }
procedure StopPurgeImage(const ImageName: String);
var
  Code: Integer;
begin
  if Exec(ExpandConstant('{sys}\taskkill.exe'), '/F /IM "' + ImageName + '"',
      '', SW_HIDE, ewWaitUntilTerminated, Code) then
    Log('taskkill /F /IM ' + ImageName + ': exit code ' + IntToStr(Code))
  else
    Log('taskkill ' + ImageName + ' could not be started');
end;

{ True when the file is held by a running process: an exe that runs cannot be opened for writing
  (its image section refuses it). The setup is elevated and Administrators may write the install
  tree, so a refusal here means "in use". Opening changes nothing in the file. }
function ImageInUse(const Path: String): Boolean;
var
  Stream: TFileStream;
begin
  Result := False;
  if not FileExists(Path) then
    Exit;
  try
    Stream := TFileStream.Create(Path, fmOpenReadWrite or fmShareDenyNone);
    Stream.Free;
  except
    Result := True;
  end;
end;

{ The app's executables in AppDir that are in use, as a list for the log and the question. }
function ImagesInUse(const AppDir: String; var Names: String): Boolean;
begin
  Names := '';
  if ImageInUse(AppDir + '\Purge.exe') then
    Names := Names + ', Purge.exe';
  if ImageInUse(AppDir + '\purge-broker.exe') then
    Names := Names + ', purge-broker.exe';
  if ImageInUse(AppDir + '\purge-engine.exe') then
    Names := Names + ', purge-engine.exe';
  if ImageInUse(AppDir + '\RestartAgent.exe') then
    Names := Names + ', RestartAgent.exe';
  Result := Names <> '';
  if Result then
    Names := Copy(Names, 3, Length(Names) - 2);
end;

{ Waits up to 10 s until no executable of the app in AppDir is in use. True when none is. }
function WaitImagesFree(const AppDir: String): Boolean;
var
  Names: String;
  Waited: Integer;
begin
  Waited := 0;
  while ImagesInUse(AppDir, Names) and (Waited < 10000) do
  begin
    Sleep(250);
    Waited := Waited + 250;
  end;
  Result := not ImagesInUse(AppDir, Names);
  if not Result then
    Log('Still in use after ' + IntToStr(Waited) + ' ms: ' + Names);
end;

{ The processes whose executable is AppDir\<one of the app's images> (IsAppImage), found by their
  path through WMI, so that a purge-engine.exe of a development build elsewhere is not touched.
  Purge.exe comes first: it hosts the engine and started the broker. The setup is elevated, so it
  reads the elevated broker's path. Raises an exception when WMI cannot be used. }
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
      if not IsAppImage(Name) then
        Continue;
      if CompareText(ExePath, Prefix + Name) <> 0 then
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

{ Stops the processes FindAppProcesses found (taskkill /F per process id, without /T: a child the
  broker started, another program's uninstaller, is not Purge's and is left alone) and waits up to
  10 s until they are gone, then until their files are free. True when nothing of the app is left. }
function StopAppProcesses(const AppDir: String; const Pids: TPidList): Boolean;
var
  Left: TPidList;
  Names: String;
  I, Count, Code, Waited: Integer;
begin
  for I := 0 to GetArrayLength(Pids) - 1 do
    if Exec(ExpandConstant('{sys}\taskkill.exe'), '/F /PID ' + IntToStr(Pids[I]), '', SW_HIDE,
        ewWaitUntilTerminated, Code) then
      Log('taskkill /F /PID ' + IntToStr(Pids[I]) + ': exit code ' + IntToStr(Code))
    else
      Log('taskkill could not be started for process ' + IntToStr(Pids[I]));
  Waited := 0;
  try
    repeat
      Sleep(250);
      Waited := Waited + 250;
      Count := FindAppProcesses(AppDir, Left, Names);
    until (Count = 0) or (Waited >= 10000);
    Result := Count = 0;
    if not Result then
      Log('Still running after ' + IntToStr(Waited) + ' ms: ' + Names);
  except
    { The kills went out and only the second look failed: the files tell whether they worked. }
    Log('Listing the processes again failed (' + GetExceptionMessage + '); checking the files instead');
    Result := True;
  end;
  if Result then
    Result := WaitImagesFree(AppDir);
end;

{ Interactive runs ask before Purge is stopped; a silent run (Hub's update) does not ask. OK is the
  default when message boxes are suppressed. }
function MayStop(const Names: String): Boolean;
begin
  Result := WizardSilent or (SuppressibleMsgBox('Purge is running: ' + Names + '.' + CrLf + CrLf +
    'Setup closes it before it replaces the files. A cleanup that is still running stops where it ' +
    'is; Purge offers to resume or roll it back the next time it starts.' + CrLf + CrLf +
    'Choose Cancel to close Purge yourself first.',
    mbConfirmation, MB_OKCANCEL, IDOK) = IDOK);
end;

{ Hub (COMPLIANCE.md section 4) asks Purge's window to close and never ends a process; the broker and
  the engine have no window. So the setup stops Purge itself before it replaces a file. A non-empty
  result stops the setup on the Preparing page, before any change; a silent setup then exits with
  code 7. With /VERYSILENT alone Inno first shows the message in a suppressible box; Hub's arguments
  include /SUPPRESSMSGBOXES, so its run shows nothing.
  - The install folder is fixed (Program Files\Purge; the broker refuses a folder a non-administrator
    could write). DisableDirPage does not stop a /DIR on the command line, so a setup run for another
    folder is refused here, before it copies, re-protects or stops anything.
  - Normally: the app's processes in the install folder, by path (WMI), killed by process id.
  - Without WMI: the three Purge images whose installed file is in use, by name, then a wait until
    the files are free.
  Either way the result says "could not be closed" when a file of the app is still in use. }
function PrepareToInstall(var NeedsRestart: Boolean): String;
var
  AppDir, Expected, Names: String;
  Pids: TPidList;
  Count: Integer;
  Listed: Boolean;
begin
  Result := '';
  AppDir := RemoveBackslashUnlessRoot(ExpandConstant('{app}'));
  Expected := ExpandConstant('{autopf}\Purge');
  if CompareText(AppDir, Expected) <> 0 then
  begin
    Log('Refused the install folder ' + AppDir + ': Purge installs only to ' + Expected);
    Result := 'Purge can only be installed to ' + Expected + '. Run Setup again without /DIR.';
    Exit;
  end;
  if not DirExists(AppDir) then
    Exit;

  Listed := True;
  Count := 0;
  try
    Count := FindAppProcesses(AppDir, Pids, Names);
  except
    Listed := False;
    Log('Finding Purge''s processes failed (' + GetExceptionMessage + '); checking its files instead');
  end;

  if Listed then
  begin
    if Count = 0 then
    begin
      { Nothing of the app in the process list; a file still in use is waited for all the same. }
      if not WaitImagesFree(AppDir) then
        Result := 'Purge could not be closed. Close Purge, then run Setup again.';
      Exit;
    end;
    if not MayStop(Names) then
    begin
      Result := 'Purge is still running. Close Purge, then run Setup again.';
      Exit;
    end;
    Log('Stopping Purge before the files are replaced: ' + Names);
    if not StopAppProcesses(AppDir, Pids) then
      Result := 'Purge could not be closed. Close Purge, then run Setup again.';
    Exit;
  end;

  { No WMI: by image name, only for an image whose installed file is in use. }
  if not ImagesInUse(AppDir, Names) then
    Exit;
  if not MayStop(Names) then
  begin
    Result := 'Purge is still running. Close Purge, then run Setup again.';
    Exit;
  end;
  Log('Stopping Purge by image name before the files are replaced: ' + Names);
  if ImageInUse(AppDir + '\Purge.exe') then
    StopPurgeImage('Purge.exe');
  if ImageInUse(AppDir + '\purge-broker.exe') then
    StopPurgeImage('purge-broker.exe');
  if ImageInUse(AppDir + '\purge-engine.exe') then
    StopPurgeImage('purge-engine.exe');
  if not WaitImagesFree(AppDir) then
    Result := 'Purge could not be closed. Close Purge, then run Setup again.';
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
