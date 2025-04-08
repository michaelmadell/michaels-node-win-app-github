# README #


This project was developed on a Win 11 Pro CoreStation Node


# To build
- Run build.bat from windows cmd shell. This will populate the installer dir that can then be passed to a third party
- As admin from PowerShell script run installer/install.ps1 to setup as windows service
- Can be removed with remove.ps1


# Build machine setup #
- Install VSCode: [download](https://code.visualstudio.com/download) and pin to task bar
- Install Cmake [4.0.0 Windows x64 Installer](https://cmake.org/download/) add to PATH
- INstall MSVC Microsoft Studio Compiler [Build Tools](https://visualstudio.microsoft.com/visual-cpp-build-tools/) Select Desktop development with C++ and ensure the following are checked:
  - MSVC v143 - VS 2022 C++ x64/x86 build tools
  - Windows 11 SDK (10.0.xxxxx.x)
  - C++ CMake tools for Windows 
- Create a `build` directory
- Open VScode
- `Ctrl+Shift+P`
- `CMake: Scan for Kits`
- `CMake: Select a Kit`
- `CMake: Configure`
- Install [clang-tidy](https://github.com/openblack/openblack/wiki/Getting-clang%E2%80%90tidy-working-on-Windows-with-VSCode) C++ linter
  - See https://llvm.org/ for documentation
  - Download & install as admin latest [LLVM-20.x.x-win64.exe](https://github.com/llvm/llvm-project/releases) **NOTE**: You might need to go back a version to find the windows installer Asset as they update every couple of weeks
  - Windows will moan about an unsigned app, accept and install
  - Add LLVM to system path for all users
  - Will be installed to `C:\Program Files\LLVM`
  - Reboot dev machine (to sort out paths etc)
  - Check it works via `clang-tidy --version`

To allow cl.exe and dumpbin to work from the command line, `C:\Users\labtest\AppData\Roaming\Code\User\settings.json` should read as follows


    {
      "git.confirmSync": false,
      "terminal.integrated.profiles.windows": {
      "Developer Command Prompt": {
          "path": "C:\\Windows\\System32\\cmd.exe",
          "args": [
              "/k",
              "C:\\Program Files (x86)\\Microsoft Visual Studio\\2022\\BuildTools\\VC\\Auxiliary\\Build\\vcvars64.bat"
          ]
      },   

          "PowerShell": {
              "source": "PowerShell",
              "icon": "terminal-powershell"
          },
          "Command Prompt": {
              "path": [
                  "${env:windir}\\Sysnative\\cmd.exe",
                  "${env:windir}\\System32\\cmd.exe"
              ],
              "args": [],
              "icon": "terminal-cmd"
          },
          "Git Bash": {
              "source": "Git Bash"
          }
      },
      "terminal.integrated.defaultProfile.windows": "Developer Command Prompt"        
    }
  


# Day to Day use
- Build `Ctrl+Shift+P` > `CMake: Build` or `F7`
- Clang current file `Ctrl+Shift+P` > `Tasks: Run Task` > `Run Clang Tidy (Current File)`, Issues will be listed in PROBLEMS tab at bottom and 
- To transfer exe to another machine from Win11 console
  ```
  cd  C:\Users\labtest\repos\node-win-app\build
  scp *.exe user@node-jm:~
  ```

  Build for release via
    ```
    cl.exe /O2 /DNDEBUG /EHsc /MT /nologo /FeC:\Users\labtest\repos\node-win-app\main_release.exe C:\Users\labtest\repos\node-win-app\main.cpp /link user32.lib gdi32.lib shell32.lib advapi32.lib comctl32.lib winmm.lib Wtsapi32.lib
  main.cpp
    ```


# Working with services
- Run `services.msc` from windows search bar
- To register a window service (one-time) open an admin cmd window
` sc.exe create CoreStationService  binPath= "C:\Users\labtest\repos\node-win-app\build\NodeWinApp.exe" start= demand  displayname= "CoreStation Service AHK`
  ```
  PS C:\Users\labtest> sc.exe create CoreStationService  binPath= "C:\Users\labtest\repos\node-win-app\build\NodeWinApp.exe" start= demand  displayname= "AHK CoreStation Service"
  [SC] CreateService SUCCESS
  ```
- Start can be `auto` or `demand`
- Can change with `sc.exe config CoreStationService start= auto`
- `start.ps1` and `stop.ps1` helper scripts will open a admin shell and start or stop the service
- `ps.bat` will open a admin powershell window and attempt to run the start.ps1 script. Window will remain open 
- Start sevice `sc.exe start CoreStationService`
  ```
  PS C:\Users\labtest> sc.exe start CoreStationService

  SERVICE_NAME: CoreStationService
        TYPE               : 10  WIN32_OWN_PROCESS
        STATE              : 4  RUNNING
                                (STOPPABLE, NOT_PAUSABLE, IGNORES_SHUTDOWN)
        WIN32_EXIT_CODE    : 0  (0x0)
        SERVICE_EXIT_CODE  : 0  (0x0)
        CHECKPOINT         : 0x0
        WAIT_HINT          : 0x0
        PID                : 6640
        FLAGS              :
  ```

  - You can check current status with  `sc.exe query CoreStationService`


# PowerShell Execution policies
 PowerShell has several execution policy levels 
 You can find the current level via `Get-ExecutionPolicy -List` and change it for current session (if admin) via `Set-ExecutionPolicy Bypass -Scope Process`

 Policy	          Description
  Restricted	    ❌ Default on Windows: No scripts can run. Only interactive commands allowed.
  AllSigned	      ✅ Only scripts signed by a trusted publisher can run (including local ones).
  RemoteSigned	  ✅ Local scripts can run freely, but downloaded ones must be signed.
  Unrestricted	  ⚠️ All scripts can run. Warns before running downloaded scripts.
  Bypass	        🟢 No restrictions, no warnings. Used for automation or temporary installs.
  Undefined	      🚫 No policy set at that scope. Inherits from higher scope or defaults to Restricted.
  
# Lint-ing
Research with chatGPT concluded that [*clang_tidy*](https://learn.microsoft.com/en-us/cpp/code-quality/clang-tidy?view=msvc-170) was best lint-er for this kind of project 

How to set up clang-tidy with CMake (MSVC or Clang toolchain):
- Configure your CMake project with compile commands:
`cmake -B build -DCMAKE_EXPORT_COMPILE_COMMANDS=ON`
which generates compile_commands.json, which clang-tidy uses to understand how each file is compiled.

- Run clang-tidy manually:
`clang-tidy src/main.cpp -- -Iinclude`
- Or use the helper script to run clang-tidy on all source files:
`run-clang-tidy.py -p build/`
- VSCode Integration: Install the extension: *C++ Advanced Lint* or just configure clang-tidy via c_cpp_properties.json.

To enable pre-commit checks I created this file 
  ```
  #!/bin/bash

  echo "🔍 Running clang-tidy on main.cpp..."

  SRC="main.cpp"
  CLANG_FLAGS="-std=c++17 -Iinclude"

  if [ -f "$SRC" ]; then
    clang-tidy "$SRC" -- $CLANG_FLAGS
    if [ $? -ne 0 ]; then
      echo "❌ clang-tidy failed. Commit aborted."
      exit 1
    else
      echo "✅ clang-tidy passed."
    fi
  else
    echo "⚠️ File '$SRC' not found. Skipping."
  fi
  ```



# Future development 

The first release is a windows service that can't have a GUI / tray icon etc. If this is required later, we
will need to create a seperate Tray helper app that starts after a user logs in, shows a tray icon that can 
be interacted with. Communciation between the two could be via Named Pies, Shared memroy, local sockets and/or
Windows Messages via services hidden windows handle.

The first development version of this (See tag 2025.4.1-adhoc1) was a pure tray app




# Session state defines
Session state are defined in WinUser.h `C:\Program Files (x86)\Windows Kits\10\Include\10.0.22621.0\um`
  ```
              APP_STARTING                       0
      #define WTS_CONSOLE_CONNECT                1
      #define WTS_CONSOLE_DISCONNECT             2
      #define WTS_REMOTE_CONNECT                 3
      #define WTS_REMOTE_DISCONNECT              4
      #define WTS_SESSION_LOGON                  5
      #define WTS_SESSION_LOGOFF                 6
      #define WTS_SESSION_LOCK                   7
      #define WTS_SESSION_UNLOCK                 8
      #define WTS_SESSION_REMOTE_CONTROL         9
      #define WTS_SESSION_CREATE                 10
      #define WTS_SESSION_TERMINATE              11   
  ```

# Serial output

## System power up 
If user previously powered down from a session, both network cables connected
  ```
  appVersion, 2025.4.1_adhoc2
  winVersion, 10.0.26100 Build 26100
  sessionState, 0
  Ethernet, up, fe80::1451:e373:4c26:e165, 192.168.203.52, dhcp, 74:fe:48:a3:fe:8d
  Ethernet 2, up, fe80::98d7:656:a39:8ad3, 192.168.203.51, dhcp, 00:17:fd:60:02:e1
  username, labtest
  hostname, NODE-30042-0023
  ```

## Log in
  ```
  sessionState, 5
  username, labtest
  ```

## Lock windows session
  ```
  sessionState, 7
  ```    

## Unlock session
  ```
  sessionState, 8
  ```

## Power down from log in screen
The network changes come several seconds later just before power off, note static ip
  ```
  sessionState, 11
  username, none
  Ethernet, up, fe80::1451:e373:4c26:e165, 192.168.203.52, static, 74:fe:48:a3:fe:8d
  Ethernet 2, up, fe80::98d7:656:a39:8ad3, 192.168.203.51, static, 00:17:fd:60:02:e1
  ```  