#define MyAppName "报文检查"
#define MyAppVersion "1.0.8"
#define MyAppPublisher "PcapCheck"
#define PortableDir AddBackslash(SourcePath) + "output\PcapCheck_Portable_1.0.8"

[Languages]
Name: "chinesesimp"; MessagesFile: "languages\ChineseSimplified.isl"

[Setup]
AppId={{E7A4D8BD-9A78-45D3-8B6C-7D8B5B5B7C4A}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
SetupIconFile=pcapcheck.ico
DefaultDirName={localappdata}\PcapCheck
DefaultGroupName={#MyAppName}
DisableProgramGroupPage=yes
PrivilegesRequired=lowest
ArchitecturesInstallIn64BitMode=x64compatible
OutputDir=output
OutputBaseFilename=PcapCheck_Setup_1.0.8
Compression=lzma2/max
SolidCompression=yes
WizardStyle=modern
UninstallDisplayName={#MyAppName}

[Files]
Source: "{#PortableDir}\*"; DestDir: "{app}"; Excludes: "data\*"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "{#PortableDir}\data\settings.json"; DestDir: "{app}\data"; Flags: onlyifdoesntexist uninsneveruninstall

[InstallDelete]
Type: files; Name: "{app}\PcapDoctor.exe"
Type: files; Name: "{app}\backend\PcapDoctorBackend.exe"
Type: files; Name: "{autoprograms}\PcapDoctor.lnk"
Type: files; Name: "{autodesktop}\PcapDoctor.lnk"

[Icons]
Name: "{autoprograms}\{#MyAppName}"; Filename: "{app}\PcapCheck.exe"
Name: "{autodesktop}\{#MyAppName}"; Filename: "{app}\PcapCheck.exe"

[Run]
Filename: "{app}\PcapCheck.exe"; Description: "启动 {#MyAppName}"; Flags: nowait postinstall skipifsilent
