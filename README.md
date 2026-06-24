# README #

## Files ##
```
michaels-node-win-app
│   .gitignore                  - files and folders that GitHub should not commit
│   app.rc                      - resource definitions for things like Icons
│   architecture-graph.html     - interactive HTML graph of the codebase structure (open in a browser)
│   app.res                     - compiled resource file
│   build.bat                   - Windows Build script (CMake + MSVC)
│   build-g++.bat               - Windows Build script (CMake + MSYS2 MinGW G++)
│   build.sh                    - Linux Build script (cross-compiles Windows .exe via MinGW)
│   build-linux.sh              - Linux Build script (CMake + native GCC/G++)
│   CMakeLists.txt              - CMake configuration
│   CoreStationHXAgent.service  - Service file for installation in Linux
│   logo.ico                    - Application Icon
│   README.md                   - This File
│   release-notes.txt           - Application release notes
│   sign.bat                    - used to sign exe, not currently used
├── debian
│    ├─ changelog               - Debian build changelog for .deb file
│    ├─ clean                   - files to remove when cleaning
│    ├─ compat                  - debuild compat file
│    ├─ control                 - debuild control file
│    ├─ copyright               - debuild copyright contents
│    ├─ dh-cmake.compat         - dhmake compat file for cmake
│    ├─ files                   - files to build
│    ├─ postinst                - commands to run post install
│    ├─ postrm                  - commands to run post removal
│    ├─ prerm                   - commands to run pre removal
│    ├─ rules                   - make rules
│    └─ source
│        └─ format              - debuild cmake format
├── installer
│    ├─ install.ps1             - service installation script
│    ├─ release-notes.txt       - clone of release notes in root dir
│    └─ remove.ps1              - service removal script
└── src
     ├─ main.cpp                - main entry point
     ├─ version.h               - Application versioning header
     ├─ core
     │   ├─ Platform.h          - Platform spec
     │   └─ SystemState.h       - System state specs
     ├─ modules
     │   ├─ 3kcheck
     │   │   ├─ 3kcheck.cpp     - CPU detection logic for HX2K vs HX3K
     │   │   └─ 3kcheck.h       - Header for CPU detection
     │   ├─ metrics
     │   │   ├─ MetricCache.h   - header for Caching metrics
     │   │   ├─ MetricsCollector.cpp    - Functions for collecting system metrics
     │   │   └─ MetricsCollector.h      - Headers for metrics collector
     │   ├─ regedits
     │   │   ├─ Regedit.cpp     - Functions for performing Registry edits
     │   │   └─ Regedit.h       - Headers for registry edits
     │   ├─ serial
     │   │   ├─ SerialManager.cpp       - Functions for serial operations
     │   │   └─ SerialManager.h         - Header for serial operations
     │   ├─ session
     │   │   ├─ SessionMonitor.cpp      - Functions for handling session states
     │   │   └─ SessionMonitor.h        - Header for session handler
     │   ├─ serialpipe
     │   │   ├─ SerialBridgePipe.cpp    - Authenticated named-pipe to serial bridge
     │   │   └─ SerialBridgePipe.h      - Header for serial bridge pipe
     │   └─ tray
     │       ├─ TrayApp.cpp             - Tray application functions
     │       └─ TrayApp.h               - Tray Application header
     └─ platform
         ├─ LinuxPlatform.cpp           - Linux specific functions
         ├─ WindowsPlatform.cpp         - Windows specific functions
         ├─ WindowsPlatform.h           - Header for windows specific functions
         └─ WinHandles.h                - RAII wrappers for Windows handles
tools/
   └─ serial_bridge_client.py       - Test client for the serial bridge pipe (see Serial bridge pipe section)
```

## Architecture ##
- Open `architecture-graph.html` in a browser for an interactive graph of the codebase: every module/class is a clickable node showing what it does in plain English, the file it lives in, and arrows showing what it depends on / what depends on it.
- No build step or server needed — it's a single self-contained HTML file (inline CSS/SVG/JS, no external dependencies), so it works offline straight from the file system.
- Quick summary of the shape of the app:
    - `main.cpp` is the entry point — it picks service/console/tray-helper mode, builds the platform object, and owns the `SerialManager` (talks to the BMC over serial) and `MetricsCollector` (gathers CPU/RAM/GPU/network stats)
    - `Platform` (in `core/`) is the interface that hides OS differences; `WindowsPlatform` and `LinuxPlatform` are its two implementations
    - `WindowsPlatform` additionally owns the Windows-only helper modules: `TrayApp` (tray icon/tooltip), `SessionMonitor` (WTS session change notifications), `Regedit` (optional registry access), `MetricCache` (TTL cache for slow lookups) and `WinHandles` (RAII wrappers for Win32 handles/COM)

## Linux Build ##
Developed on Ubuntu 24.04.5 LTS due to better compatibility with the Meteor Lake Processor

### User Guide ###

- Ensure the Serial Port that links to the MEC is set to `/dev/ttyUSB0`
    - Can be checked by monitoring serial output and sending data to the port:  
    ```bash
    echo "TESTING" > /dev/ttyUSB0
    ```
- Clone the repo
- cd into the directory
- Install Dependencies  
`sudo apt install build-essential cmake devscripts debhelper dh-cmake libdbus-1-dev network-manager`
    - build-essential and cmake are build dependencies
    - debhelper, dh-cmake and devscripts are dependencies for building the .deb package
    - libdbus-1-dev and network-manager are required for pulling system info
 - Update Information in relevant files:
     - `src/version.h`
     - `debian/control` - Not 100% necessary to be updated
     - `debian/copyright`
     - `debian/changelog` - *100% Necessary to change this*
 - ***NOTE***: If debuild complains about no new lines at end of files, run `echo "" >> <file>` to add a new line to the end
 - in the project root, run:
    ```bash
    debuild -us -uc -S -I
    ```
    to build the source files
 - then run:
   ```bash
   debuild -us -uc -b
   ```
    to build the .deb file, but this will be unsigned
- I think at this point, it could be signed with the existing method for windows executables but I am not sure

### To Install ###
```bash
sudo apt install ./corestationhxagent_20.26.5.1-1_amd64.deb
```
following that, the status of the service can be viewed with
```bash
sudo systemctl status CoreStationHXAgent
```
this will show something like:
```
● CoreStationHXAgent.service - CoreStation HX Agent
     Loaded: loaded (/usr/lib/systemd/system/CoreStationHXAgent.service; enabled; preset: enabled)
     Active: active (running) since Wed 2025-09-24 15:14:08 BST; 18h ago
   Main PID: 57599 (CoreStationHXAg)
      Tasks: 3 (limit: 13993)
     Memory: 15.5M ()
     CGroup: /system.slice/CoreStationHXAgent.service
             └─57599 /usr/sbin/CoreStationHXAgent
```

## Windows Build ##
This project was developed on a Win 11 Pro CoreStation Node


### User guide

- **COM port is selected automatically** at runtime based on CPU model — no manual configuration required:
  - **HX2K** (Core Ultra 165H, 165U, 285H) → **COM3** (Congatec/AAEON COM port)
  - **HX3K** (all other CPUs) → **COM1**
- The `Intel(R) Active Management Technology SOL` (AMT/vPRO) port can conflict on COM3. The app detects this at startup and will reassign it to COM4 automatically ([Jira Ticket](https://ahkeng.atlassian.net/browse/CSHD-1200))
- The `./build.bat` script will (not currently) push RC and GA to [ahkengbuild](http://ahkengbuild/versions)
- Run `install.ps1` from an Administrator PowerShell terminal. This script will remove any previous version, install and then run the service
- The service will appear as `CoreStation Management Service` in the Windows Service Manager
- Use `remove.ps1` to remove the service



### Debug output
RC builds write all log output to `C:\ProgramData\ahk\node-win-app.log` via `LogMessage(<string>);`. GA builds only write messages tagged `ERROR`, `WARNING`, or `FATAL` to the same file -- routine/verbose messages are suppressed.

### Tray helper (interactive mode)
- When the app runs interactively (StartServiceCtrlDispatcher fails), a tray icon is created using the Windows notification area.
- The tray tooltip is fed by a named pipe at `\\.\pipe\corestation_tray`.
- Send plain text lines containing `hostname=`, `ip=` (or `ipaddress=`), and `uptime=`. Example payload:
  ```text
  hostname=NODE-01
  ip=192.168.1.10
  uptime=2d 04h 13m 09s
  ```
- A quick PowerShell sender for testing:
  ```powershell
  $pipe = New-Object System.IO.Pipes.NamedPipeClientStream('.', 'corestation_tray', [System.IO.Pipes.PipeDirection]::Out)
  $pipe.Connect(1000)
  $writer = New-Object System.IO.StreamWriter($pipe)
  $writer.AutoFlush = $true
  $writer.WriteLine('hostname=NODE-01')
  $writer.WriteLine('ip=192.168.1.10')
  $writer.WriteLine('uptime=2d 04h 13m 09s')
  $writer.Dispose(); $pipe.Dispose()
  ```
- Tooltip format: `Host: <hostname> | IP: <ip> | Up: <uptime>`.

### Serial bridge pipe
- A second named pipe, `\\.\pipe\corestation_serial_bridge`, lets a local application forward raw bytes straight to the serial port the agent is connected to (COM1/COM3 depending on CPU model).
- The pipe is created with a security descriptor (`D:(A;;GA;;;BA)`) restricting connection to **BUILTIN\Administrators** -- any other caller's `CreateFile` fails with access denied before a single byte is exchanged. There is no app-level secret/token.
- Whatever bytes are written to the pipe are forwarded **as-is** (no framing, no newline added) to the live `SerialManager` connection used by the main serial worker thread -- not a separate/unopened connection.
- Started/stopped alongside the session monitor in both interactive and service mode. Controlled by the `BUILD_SERIAL_BRIDGE_PIPE` CMake option (default `ON`, Windows only).
- Test client: `tools/serial_bridge_client.py` (stdlib only, run from an elevated prompt):
  ```powershell
  python tools\serial_bridge_client.py "hello world"
  python tools\serial_bridge_client.py --hex 41420D0A
  python tools\serial_bridge_client.py --interactive
  ```


### To build
- Update `version.h` with the desired release details and commit to git
- Run `build.bat` from windows **cmd shell**. This will populate the installer dir that can then be passed to a third party
- As admin from **PowerShell shell** run `installer/install.ps1` to setup as windows service. This will automatically stop and remove any previous versions before instalation 
- `remove.ps1` can be used to remove the service

#### Alternative: build with MSYS2 MinGW G++
- Run `build-g++.bat` instead of `build.bat` to build with the MSYS2 MinGW64/UCRT64 G++ toolchain via CMake (`-G "MinGW Makefiles"`) instead of MSVC
- Auto-detects the MSYS2 toolchain (checks `PATH`, then `C:\msys64\<mingw64|ucrt64|clang64>\bin`) and CMake (checks `PATH`, then the copy bundled with Visual Studio)
- Requires `mingw-w64-x86_64-gcc` (or the `ucrt64`/`clang64` equivalent) installed via `pacman` in MSYS2
- Output goes to `build-mingw\bin\CoreStationHXAgent.exe` (kept separate from the MSVC `build\` dir)


### Build machine setup #
- Install VSCode: [download](https://code.visualstudio.com/download) and pin to task bar
- Install Cmake [4.0.0 Windows x64 Installer](https://cmake.org/download/) add to PATH
- Install MSVC Microsoft Studio Compiler [Build Tools](https://visualstudio.microsoft.com/visual-cpp-build-tools/) Select Desktop development with C++ and ensure the following are checked:
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
```json
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
```


### Day to Day use
- To build open main.cpp and press `F7` (or `Ctrl+Shift+P` > `CMake: Build`)
- Clang current file `Ctrl+Shift+P` > `Tasks: Run Task` > `Run Clang Tidy (Current File)`, Issues will be listed in PROBLEMS tab at bottom and 
- To transfer exe to another machine from Win11 console
  ```bat
  cd  C:\Users\labtest\repos\node-win-app\build
  scp *.exe user@node-jm:~
  ```

  Build for release via
    ```bat
    cl.exe /O2 /DNDEBUG /EHsc /MT /nologo /FeC:\Users\labtest\repos\node-win-app\main_release.exe C:\Users\labtest\repos\node-win-app\main.cpp /link user32.lib gdi32.lib shell32.lib advapi32.lib comctl32.lib winmm.lib Wtsapi32.lib
  main.cpp
    ```


### How to sign and exe
- Need 
   - A Extended Validation (EV) Code Signing Certificate (Cloud, USB dongle or Hardware Security Module)
   - AHK purhased a [Code Signing EV + Keylocker](https://docs.digicert.com/en/digicert-keylocker.html) annual subscription from digicert.com Apr 25 for £804
   - signtool from Windows SDK / MSVC tools above
DigiCert offer EV on USB Token £708 /year or Cloud based KeyLocker for £804
- Sign into digiCert [account](https://accounts.digicert.com/) (DaveG/MattA/IT are admins)
- [General Signer guide](https://docs.digicert.com/en/digicert-keylocker/get-started/signer-guide.html)
- [Code Signing guide](https://docs.digicert.com/en/digicert-keylocker/code-signing/sign-with-digicert-signing-tools.html)

 

### Working with services
- Run `services.msc` from windows search bar
- To register a window service (one-time) open an admin cmd window
` sc.exe create CoreStationService  binPath= "C:\Users\labtest\repos\node-win-app\build\NodeWinApp.exe" start= demand  displayname= "CoreStation Service AHK`
  ```powershell
  PS C:\Users\labtest> sc.exe create CoreStationService  binPath= "C:\Users\labtest\repos\node-win-app\build\NodeWinApp.exe" start= demand  displayname= "AHK CoreStation Service"
  [SC] CreateService SUCCESS
  ```
- Start can be `auto` or `demand`
- Can change with `sc.exe config CoreStationService start= auto`
- `start.ps1` and `stop.ps1` helper scripts will open a admin shell and start or stop the service
- `ps.bat` will open a admin powershell window and attempt to run the start.ps1 script. Window will remain open 
- Start sevice `sc.exe start CoreStationService`
  ```powershell
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



### PowerShell Execution policies
 PowerShell has several execution policy levels 
 You can find the current level via `Get-ExecutionPolicy -List` and change it for current session (if admin) via `Set-ExecutionPolicy Bypass -Scope Process`
 
| Policy       | Description                                                                          |
|--------------|--------------------------------------------------------------------------------------|
| Restricted   | ❌ Default on Windows: No scripts can run. Only interactive commands allowed.         |
| AllSigned    | ✅ Only scripts signed by a trusted publisher can run (including local ones).         |
| RemoteSigned | ✅ Local scripts can run freely, but downloaded ones must be signed.                  |
| Unrestricted | ⚠️ All scripts can run. Warns before running downloaded scripts.                      |
| Bypass       | 🟢 No restrictions, no warnings. Used for automation or temporary installs.           |
| Undefined    | 🚫 No policy set at that scope. Inherits from higher scope or defaults to Restricted. |

### Lint-ing
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
  ```bash
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



### Future development

The tray helper app (`TrayApp.cpp/h`) is implemented and communicates with the service via a named pipe (`\\.\pipe\corestation_tray`). See the **Tray helper** section above for usage details.

The serial bridge pipe (`SerialBridgePipe.cpp/h`) lets another local admin-elevated app forward raw bytes to the serial port via `\\.\pipe\corestation_serial_bridge`. See the **Serial bridge pipe** section above for usage details.

The first development version (tag `2025.4.1-adhoc1`) was a pure tray app before it was converted to a Windows service.




### Session state defines
Session state are defined in WinUser.h `C:\Program Files (x86)\Windows Kits\10\Include\10.0.22621.0\um`
  ```c
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

### Serial output

#### System power up 
If user previously powered down from a session, both network cables connected
  ```raw
  appVersion, 2025.4.2.rc2
  winVersion, 10.0.26100 Build 26100
  sessionState, 0
  network, 74:fe:48:a3:fe:8d, up, 192.168.203.86, fe80::1451:e373:4c26:e165, dhcp, Ethernet
  network, 00:17:fd:60:02:e1, up, 192.168.203.82, fe80::98d7:656:a39:8ad3, dhcp, Ethernet 2
  username, labtest
  hostname, NODE-30042-0023
  ```

#### Log in
  ```raw
  sessionState, 5
  username, labtest
  ```

#### Lock windows session
  ```raw
  sessionState, 7
  ```    

#### Unlock session
  ```raw
  sessionState, 8
  ```

#### Power down from log in screen
The network changes come several seconds later just before power off, note static ip
  ```raw
  sessionState, 11
  username, none
  network, 74:fe:48:a3:fe:8d, up, 192.168.203.52, fe80::1451:e373:4c26:e165, static, Ethernet
  network, 00:17:fd:60:02:e1, up, 192.168.203.51, fe80::98d7:656:a39:8ad3,  static,  Ethernet 2
  ```  
