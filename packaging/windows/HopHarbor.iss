; Compile with official Inno Setup 7.1.0. Payloads are built and reviewed first.
#ifndef PackageRoot
  #error Supply /DPackageRoot=the-reviewed-package-directory
#endif
#ifndef OutputDir
  #error Supply /DOutputDir=the-private-output-directory
#endif
#ifndef AppVersion
  #define AppVersion "1.3.0"
#endif
#ifndef AppBuild
  #define AppBuild "10"
#endif
#ifndef TargetArch
  #error Supply /DTargetArch=arm64 or x64
#endif
#if (TargetArch != "arm64") && (TargetArch != "x64")
  #error TargetArch must be arm64 or x64
#endif

[Setup]
AppId={{B4759D18-CA80-4BE1-9083-CAD022482AE7}
AppName=HopHarbor
AppVersion={#AppVersion}
AppVerName=HopHarbor {#AppVersion}
VersionInfoVersion={#AppVersion}.{#AppBuild}
AppPublisher=HopHarbor
AppPublisherURL=https://github.com/kiyanibehzad/HopHarbor
AppSupportURL=https://github.com/kiyanibehzad/HopHarbor/issues
AppUpdatesURL=https://github.com/kiyanibehzad/HopHarbor/releases
DefaultDirName={localappdata}\Programs\HopHarbor
DisableDirPage=yes
UsePreviousAppDir=no
DefaultGroupName=HopHarbor
DisableProgramGroupPage=yes
PrivilegesRequired=lowest
SetupArchitecture=x64
#if TargetArch == "arm64"
ArchitecturesAllowed=arm64
MinVersion=10.0.22000
#else
ArchitecturesAllowed=x64compatible and not arm64
MinVersion=10.0.19045
#endif
ArchitecturesInstallIn64BitMode=win64
OutputDir={#OutputDir}
OutputBaseFilename=HopHarbor-{#AppVersion}-windows-{#TargetArch}-setup
SetupIconFile={#PackageRoot}\assets\HopHarbor.ico
UninstallDisplayIcon={app}\ui\HopHarbor.exe
WizardStyle=modern dynamic
Compression=lzma2/normal
SolidCompression=yes
CloseApplications=no
RestartApplications=no
RestartIfNeededByRun=no
AlwaysRestart=no
Uninstallable=yes
UninstallFilesDir={app}\uninstall
ChangesEnvironment=no
ChangesAssociations=no

[Tasks]
Name: "autostart"; Description: "Start HopHarbor when I sign in"; GroupDescription: "Background connections:"; Flags: checkedonce
Name: "desktopicon"; Description: "Create a desktop shortcut"; GroupDescription: "Shortcuts:"; Flags: unchecked

[Files]
Source: "{#PackageRoot}\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{userprograms}\HopHarbor"; Filename: "{app}\ui\HopHarbor.exe"; WorkingDir: "{app}"; AppUserModelID: "io.github.kiyanibehzad.HopHarbor"
Name: "{userdesktop}\HopHarbor"; Filename: "{app}\ui\HopHarbor.exe"; WorkingDir: "{app}"; AppUserModelID: "io.github.kiyanibehzad.HopHarbor"; Tasks: desktopicon

[Run]
Filename: "{app}\ui\HopHarbor.exe"; Description: "Open HopHarbor"; WorkingDir: "{app}"; Flags: postinstall nowait skipifsilent

[Code]
function PrivateDataDir: String;
begin
  Result := ExpandConstant('{localappdata}\HopHarbor');
end;

function AppArguments: String;
begin
  Result := ' --app-dir ' + AddQuotes(ExpandConstant('{app}')) + ' --data-dir ' + AddQuotes(PrivateDataDir);
end;

function RunChecked(const FileName, Parameters: String): Boolean;
var
  ExitCode: Integer;
begin
  Result := Exec(FileName, Parameters, ExpandConstant('{app}'), SW_HIDE, ewWaitUntilTerminated, ExitCode);
  if Result then Result := ExitCode = 0;
end;

function CloseMatchingPanel: Boolean;
begin
  Result := RunChecked(ExpandConstant('{app}\ui\HopHarbor.exe'), '--quit-panel --data-dir ' + AddQuotes(PrivateDataDir));
  { The matching UI observes its private per-user event on the next timer tick. }
  if Result then Sleep(1000);
end;

function PrepareToInstall(var NeedsRestart: Boolean): String;
begin
  Result := '';
  { A fixed private root is part of the native ACL preparation contract. }
  if CompareText(RemoveBackslashUnlessRoot(ExpandConstant('{app}')), ExpandConstant('{localappdata}\Programs\HopHarbor')) <> 0 then begin
    Result := 'HopHarbor must be installed in its private per-user Programs folder. Remove a custom /DIR option and run Setup again.';
    exit;
  end;
  if not FileExists(ExpandConstant('{win}\System32\OpenSSH\ssh.exe')) then begin
    Result := 'Install OpenSSH Client from Windows Settings > System > Optional features, then run Setup again. HopHarbor uses the Windows SSH client; SSH Server is not needed.';
    exit;
  end;
  if FileExists(ExpandConstant('{app}\hopharbor-package.json')) then begin
    if not RunChecked(ExpandConstant('{app}\runtime\pythonw.exe'), AddQuotes(ExpandConstant('{app}\install_windows.py')) + ' --stop' + AppArguments) then begin
      Result := 'The matching HopHarbor background service could not stop safely. Existing application files and settings have been preserved. Open HopHarbor and try again.';
      exit;
    end;
    if not CloseMatchingPanel then
      Result := 'The matching HopHarbor panel could not close. Close it using Quit Panel in the system tray and try again.';
  end else if DirExists(ExpandConstant('{app}')) then begin
    Result := 'An unrecognized HopHarbor folder already exists at the installation location. Setup did not change it. Move that folder aside before installing.';
  end;
end;

procedure CurStepChanged(CurStep: TSetupStep);
var
  Parameters: String;
begin
  if CurStep = ssPostInstall then begin
    if not RunChecked(ExpandConstant('{app}\bin\HopHarborHelper.exe'), 'prepare-package --app-dir ' + AddQuotes(ExpandConstant('{app}'))) then
      RaiseException('The private application permissions could not be prepared. Setup has not started any connections.');
    if not RunChecked(ExpandConstant('{app}\bin\HopHarborHelper.exe'), 'prepare --data-dir ' + AddQuotes(PrivateDataDir)) then
      RaiseException('The private settings folder could not be prepared. Setup has not started any connections.');
    Parameters := AddQuotes(ExpandConstant('{app}\install_windows.py')) + ' --register' + AppArguments;
    if not WizardIsTaskSelected('autostart') then Parameters := Parameters + ' --no-autostart';
    if not RunChecked(ExpandConstant('{app}\runtime\pythonw.exe'), Parameters) then
      RaiseException('This installation could not register its private background launcher. No existing configuration was replaced.');
  end;
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
begin
  if CurUninstallStep = usUninstall then begin
    if not CloseMatchingPanel then
      RaiseException('The matching panel could not close. Use Quit Panel in the system tray and try uninstalling again.');
    if not RunChecked(ExpandConstant('{app}\runtime\pythonw.exe'), AddQuotes(ExpandConstant('{app}\install_windows.py')) + ' --uninstall' + AppArguments) then
      RaiseException('The matching background service could not stop safely. Application files, settings and credentials were preserved.');
    { Only files recorded by this installer are removed. AppData settings and
      Windows Credential Manager entries are deliberately preserved. }
  end;
end;
