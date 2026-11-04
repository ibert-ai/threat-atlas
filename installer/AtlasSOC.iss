; AtlasSOC Desktop installer. Version, build and paths come from scripts/build-windows-soc-installer.ps1.
; Never change AppId: it links upgrades, repair and uninstall across versions.
#define AppGuid "1F031F19-B5CA-46F3-AE2B-4FD1EB9DA99D"
#define UninstallKey "Software\Microsoft\Windows\CurrentVersion\Uninstall\{" + AppGuid + "}_is1"

[Setup]
AppId={{#AppGuid}
AppName=AtlasSOC
AppVersion={#AppVersion}
AppVerName=AtlasSOC {#AppVersion} (build {#AppBuild})
AppPublisher=Ibert Consulting
VersionInfoVersion={#AppVersion}.{#AppBuild}
VersionInfoProductName=AtlasSOC
VersionInfoCompany=Ibert Consulting
; {autopf} is Program Files for everyone and %LocalAppData%\Programs for one user.
DefaultDirName={autopf}\AtlasSOC
DisableDirPage=yes
DisableProgramGroupPage=yes
AlwaysShowDirOnReadyPage=yes
DefaultGroupName=AtlasSOC
; Just me is the default; the dialog offers Everyone, which asks for elevation.
PrivilegesRequired=lowest
PrivilegesRequiredOverridesAllowed=dialog
UsePreviousPrivileges=yes
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
MinVersion=10.0
OutputDir={#OutputDirectory}
OutputBaseFilename=AtlasSOC-Setup-{#AppVersion}-build{#AppBuild}
SetupIconFile={#SourceRoot}\assets\atlassoc\sentinel\AtlasSOC.ico
UninstallDisplayIcon={app}\AtlasSOC.exe
UninstallDisplayName=AtlasSOC
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
CloseApplications=yes
RestartApplications=no
ChangesAssociations=no
ChangesEnvironment=no

[Tasks]
Name: desktopicon; Description: "Add a desktop shortcut"; Flags: unchecked
Name: startmenu; Description: "Add a Start menu shortcut"

[Files]
Source: "{#PackageDirectory}\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs

[Icons]
Name: "{autodesktop}\AtlasSOC"; Filename: "{app}\AtlasSOC.exe"; Tasks: desktopicon
Name: "{autoprograms}\AtlasSOC"; Filename: "{app}\AtlasSOC.exe"; Tasks: startmenu

[Run]
; The app always runs unelevated, as the person who started the installer.
Filename: "{app}\AtlasSOC.exe"; Description: "Open AtlasSOC"; Flags: postinstall nowait unchecked skipifsilent runasoriginaluser

[Code]
function OtherScopeInstalled(): Boolean;
var
  Root: Integer;
begin
  if IsAdminInstallMode() then
    Root := HKCU
  else
    Root := HKLM64;
  Result := RegKeyExists(Root, ExpandConstant('{#UninstallKey}'));
end;

function InitializeSetup(): Boolean;
begin
  Result := True;
  // Installer scopes do not upgrade each other, so moving scope must be an explicit uninstall first.
  if OtherScopeInstalled() then begin
    SuppressibleMsgBox('AtlasSOC is already installed for a different scope. Uninstall it from Settings > Apps, then run this installer again. Your settings are kept.', mbError, MB_OK, IDOK);
    Result := False;
  end;
end;

function UpdateReadyMemo(Space, NewLine, MemoUserInfoInfo, MemoDirInfo, MemoTypeInfo, MemoComponentsInfo, MemoGroupInfo, MemoTasksInfo: String): String;
var
  Scope: String;
begin
  if IsAdminInstallMode() then
    Scope := 'Everyone using this computer'
  else
    Scope := 'Just me';
  Result := 'Install for:' + NewLine + Space + Scope + NewLine + NewLine + MemoDirInfo + NewLine + NewLine + MemoTasksInfo;
end;
