; NSIS port of CoreStationAppInstaller.iss, for building the Windows installer
; from a Linux CI runner (makensis, apt package "nsis") where Inno Setup's
; ISCC compiler isn't available. Keep functional parity with the .iss when
; editing either file.
;
; Build:
;   makensis -DAPP_VERSION=20.26.8.1_rc1 -DAPP_VERSION_SHORT=20.26.8.1 CoreStationAppInstaller.nsi
;
; Expects (relative to this script):
;   installer/CoreStationHXAgent.exe
;   installer/install.ps1
;   installer/remove.ps1
;   logo.ico

!ifndef APP_VERSION
  !define APP_VERSION "0.0.0.0_dev"
!endif
!ifndef APP_VERSION_SHORT
  !define APP_VERSION_SHORT "0.0.0.0"
!endif

!define APP_NAME "CoreStation HX Agent"
!define APP_PUBLISHER "Amulet Hotkey LTD"
!define APP_URL "https://www.amulethotkey.com/"
!define APP_EXE "CoreStationHXAgent.exe"
!define SVC_INSTALL_SCRIPT "install.ps1"
!define SVC_UNINSTALL_SCRIPT "remove.ps1"
!define APP_REGKEY "Software\CoreStation_Management_Service"

!include "MUI2.nsh"

Name "${APP_NAME}"
OutFile "CoreStation_HX_Agent_Installer_${APP_VERSION}.exe"
InstallDir "$PROGRAMFILES32\CoreStation HX Agent"
InstallDirRegKey HKLM "${APP_REGKEY}" "InstallDir"
RequestExecutionLevel admin
SetCompressor /SOLID lzma
Icon "logo.ico"
UninstallIcon "logo.ico"

VIProductVersion "${APP_VERSION_SHORT}"
VIAddVersionKey "ProductName" "${APP_NAME} Installer"
VIAddVersionKey "CompanyName" "Amulet Hotkey"
VIAddVersionKey "FileDescription" "CoreStation HX Agent installer"
VIAddVersionKey "ProductVersion" "${APP_VERSION_SHORT}"
VIAddVersionKey "FileVersion" "${APP_VERSION_SHORT}"
VIAddVersionKey "LegalCopyright" "(C) Amulet Hotkey 2026"

!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_PAGE_FINISH

!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES

!insertmacro MUI_LANGUAGE "English"

Section "Install" SEC_INSTALL
  SetOutPath "$INSTDIR"

  ; Diagnostic: confirm install reached (mirrors the [Run] diagnostic step in the .iss)
  ExecWait 'cmd.exe /c echo [Install] reached > "$WINDIR\Temp\CoreStation_run.log"'

  ; Extract remove.ps1 and run it before install to clean up any previous
  ; install (mirrors [Code] CurStepChanged(ssInstall) in the .iss).
  File "/oname=$PLUGINSDIR\${SVC_UNINSTALL_SCRIPT}" "installer/${SVC_UNINSTALL_SCRIPT}"
  ExecWait 'powershell.exe -ExecutionPolicy Bypass -NoProfile -File "$PLUGINSDIR\${SVC_UNINSTALL_SCRIPT}"'

  File "installer/${SVC_INSTALL_SCRIPT}"
  File "installer/${APP_EXE}"
  File "installer/${SVC_UNINSTALL_SCRIPT}"
  File "logo.ico"

  DetailPrint "Installing CoreStation HX Agent..."
  ExecWait 'powershell.exe -ExecutionPolicy Bypass -NoProfile -File "$INSTDIR\${SVC_INSTALL_SCRIPT}"'

  WriteRegStr HKLM "${APP_REGKEY}" "InstallDir" "$INSTDIR"
  WriteUninstaller "$INSTDIR\Uninstall.exe"

  CreateDirectory "$SMPROGRAMS\Amulet Hotkey"
  CreateShortcut "$SMPROGRAMS\Amulet Hotkey\Uninstall ${APP_NAME}.lnk" "$INSTDIR\Uninstall.exe" "" "$INSTDIR\logo.ico"

  ; AlwaysRestart=yes in the .iss
  SetRebootFlag true
SectionEnd

Section "Uninstall"
  DetailPrint "Uninstalling CoreStation HX Agent..."
  ExecWait 'powershell.exe -ExecutionPolicy Bypass -NoProfile -File "$INSTDIR\${SVC_UNINSTALL_SCRIPT}"'

  Delete "$SMPROGRAMS\Amulet Hotkey\Uninstall ${APP_NAME}.lnk"
  RMDir "$SMPROGRAMS\Amulet Hotkey"
  DeleteRegKey HKLM "${APP_REGKEY}"

  ; [UninstallDelete] Type: filesandordirs; Name: "{app}"
  RMDir /r "$INSTDIR"
SectionEnd
