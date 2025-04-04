# README #


This project was developed on a Win 11 Pro CoreStation Node

# Build machine setup #
- VSCode: [download](https://code.visualstudio.com/download) and pin to task bar
- Cmake [4.0.0 Windows x64 Installer](https://cmake.org/download/) add to PATH
- MSVC Microsoft Studio Compiler [Build Tools](https://visualstudio.microsoft.com/visual-cpp-build-tools/) Select Desktop development with C++ and ensure the following are checked:
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


  ```
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


# Day to Day use
- Build `Ctrl+Shift+P` > `CMake: Build` or `F7`
- Clang current file `Ctrl+Shift+P` > `Tasks: Run Task` > `Run Clang Tidy (Current File)`, Issues will be listed in PROBLEMS tab at bottom and 
- To transfer exe to another machine from Win11 console
  ```
  cd  C:\Users\labtest\repos\node-win-app\build
  scp *.exe user@node-jm:~
  ```


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