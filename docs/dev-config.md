# Build Profiles (local dev config)

Which modules get compiled is decided by CMake options (`BUILD_METRICS`,
`BUILD_SERIAL_BRIDGE_PIPE`, `BUILD_C2A`, ...). A **build profile** is a named
set of those options so you don't have to pass five `-D` flags every time.

Profiles are build-time only: the binary has no idea which profile built it,
and there is no runtime config.

## Quick start

```bat
build.bat --profile dev-full          :: Windows, MSVC  -> build-dev-full\
build-g++.bat --profile dev-full      :: Windows, MinGW -> build-mingw-dev-full\
```

```bash
./build.sh --profile dev-full                    # native Linux -> build-linux-dev-full/
./build.sh --target windows --profile dev-full   # cross-compile the .exe -> build-win-dev-full/
```

Or with CMake directly:

```bash
cmake -S . -B build-dev-full -DDEVELOPMENT_PROFILE=dev-full
cmake --build build-dev-full
```

## Profiles

| Option                     | `dev-full` | `dev-minimal` | `dev-ci` | `production` | *(none)* |
|----------------------------|:----------:|:-------------:|:--------:|:------------:|:--------:|
| `BUILD_SESSION_MONITOR`    | ON  | OFF | ON  | ON  | ON  |
| `BUILD_TRAY_APP` ¹         | ON  | OFF | ON  | OFF | ON  |
| `BUILD_METRICS`            | ON  | OFF | ON  | OFF | OFF |
| `BUILD_SERIAL_BRIDGE_PIPE` | ON  | OFF | ON  | OFF | OFF |
| `BUILD_C2A`                | ON  | OFF | ON  | OFF | OFF |
| `IPC_AUTH_DEV_DISABLE` ²   | ON  | ON  | OFF | OFF | OFF |
| `ENABLE_TESTING`           | ON  | ON  | ON  | OFF | OFF |

- **dev-full** — everything, plus tests; IPC client auth compiled out so
  unsigned dev clients can talk to the serial bridge.
- **dev-minimal** — core + serial only, plus tests. Fastest build.
- **dev-ci** — everything, plus tests, with real IPC auth. Reproduces a
  thorough CI build locally.
- **production** — the shipping feature set (the flags `build-production.bat`
  has always used).
- **(none)** — no profile: the `option()` defaults in `CMakeLists.txt`. This
  is what plain `cmake`, IDEs and CI get, and what `build.bat` with no
  arguments builds (unchanged from before profiles existed).

¹ Windows only — ignored (with a status note) elsewhere.
² Never ship a build with this ON. CMake refuses to configure the
`production` profile with it ON.

## What the scripts do

| | `build.bat` | `build-g++.bat` | `build.sh` |
|---|---|---|---|
| Toolchain | MSVC + Ninja | MSYS2 MinGW + MinGW Makefiles | native GCC, or `--target windows` = mingw-w64 cross |
| Build dir | `build` / `build-<profile>` | `build-mingw` / `build-mingw-<profile>` | `build-linux[-<profile>]` / `build-win[-<profile>]` |
| Unit tests | built and run when the profile enables them | same | same (native only; cross-compiled tests can't run) |
| `installer/` | copy + signing prompt, **no profile or `production` only** | never | copy, **no profile or `production` only** |

dev-* builds deliberately never touch `installer/`: `dev-full` has IPC auth
compiled out and must not end up in an installer.

Options common to all three:

```
--profile NAME     cmake/profiles/NAME.cmake
--config CONFIG    Release (default), Debug, RelWithDebInfo, MinSizeRel
--help             usage + list of profiles
anything else      passed to the CMake configure step
```

On Windows, **quote** pass-through flags — `cmd.exe` splits unquoted
arguments at `=`:

```bat
build.bat --profile dev-full "-DCORESTATION_LOG_MIN_LEVEL=Debug"
```

The old entry points still work: `build-production.bat` is now
`build.bat --profile production`; `build-linux.sh` / `build-linux.bash` are
`build.sh --target linux`. All accept the same arguments.

## Personal overrides: `cmake/profiles/local.cmake`

```bash
cp cmake/profiles/local.cmake.example cmake/profiles/local.cmake
```

`local.cmake` is git-ignored and is applied **after** the selected profile,
so it can change anything. Use `FORCE`, as the profiles do:

```cmake
set(BUILD_METRICS OFF CACHE BOOL "" FORCE)
set(CORESTATION_LOG_MIN_LEVEL "Debug" CACHE STRING "" FORCE)
```

It is only read when a profile is selected; re-run the configure step after
editing it. The configure output says `(+ local.cmake overrides)` when it
was applied.

## How it works

- `cmake/load-profile.cmake` defines `load_profile(name)`: it includes
  `cmake/profiles/<name>.cmake`, then `local.cmake` if present, and prints
  which modules are enabled and disabled.
- `CMakeLists.txt` calls it right after the `option()` declarations, but
  only when `DEVELOPMENT_PROFILE` is non-empty.
- Profiles `FORCE` their cache values, so selecting a profile wins over
  whatever an existing build directory had cached, **and over `-D` flags for
  the same options**. Use `local.cmake` (or no profile) to override a
  profile's choice. The scripts always pass `DEVELOPMENT_PROFILE` (empty for
  none) so a build dir never silently keeps an old profile.
- The configure summary shows `Profile: <name>` (or `(none ...)`).

### Compatibility checks (with or without a profile)

| Condition | Result |
|---|---|
| `BUILD_TRAY_APP` on a non-Windows platform | status note; the tray sources are Windows-only anyway |
| `ENABLE_TESTING` with a compiler other than MSVC/GCC/Clang | warning |
| `production` profile with `IPC_AUTH_DEV_DISABLE=ON` | configure error |
| Unknown profile name | configure error listing the available profiles |

`BUILD_C2A` and `BUILD_SERIAL_BRIDGE_PIPE` are independent (C2A is the BMC
serial command handler; the bridge is the local IPC pipe/socket), so there is
no check tying them together.

## CI

CI (`bitbucket-pipelines.yml`, `.github/workflows/ci-build.yml`) builds the
shipping artifacts (exe, installer, .deb) without a profile - exactly the
`option()` defaults - and runs the unit-test jobs with
`-DDEVELOPMENT_PROFILE=dev-ci`. See README "Running tests".

## Adding a profile

Create `cmake/profiles/<name>.cmake` setting every option in
`CORESTATION_PROFILE_OPTIONS` (see `cmake/load-profile.cmake`) with
`CACHE BOOL "" FORCE`. The scripts and `--help` pick it up automatically.
