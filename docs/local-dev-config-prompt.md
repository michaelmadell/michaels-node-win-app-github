# Local Dev Config: Compile-Time Module Selection

> **Status: implemented (2026-10-21).** This document was originally the task
> prompt; it has been updated to describe what was actually built, including
> the decisions taken where the original prompt conflicted with the codebase.
> User-facing documentation is [dev-config.md](dev-config.md). See
> [Decisions and deviations](#decisions-and-deviations).

## Context

CoreStationHXAgent chooses modules with CMake options. Before this work,
local development meant passing several `-D` flags per build, there was no
named "minimal" or "full" configuration, and each build script hard-coded its
own configuration.

The real option defaults (the prompt originally listed different ones) are:

```cmake
option(BUILD_METRICS            ... OFF)
option(BUILD_SESSION_MONITOR    ... ON)
option(BUILD_TRAY_APP           ... ON)   # Windows only
option(BUILD_SERIAL_BRIDGE_PIPE ... OFF)
option(BUILD_C2A                ... OFF)
option(IPC_AUTH_DEV_DISABLE     ... OFF)
option(ENABLE_TESTING           ... OFF)
```

The real build scripts before this work:

| Script | What it actually did |
|---|---|
| `build.bat` | MSVC + Ninja, option defaults, `build\`, copied the exe to `installer\` with a signing prompt |
| `build-production.bat` | Same as `build.bat`, but with Tray/C2A/Bridge/Metrics OFF and Session ON, in `build-production\` |
| `build-g++.bat` | MSYS2 MinGW + MinGW Makefiles, option defaults, `build-mingw\` |
| `build.sh` | **Not a Linux build**: a direct `x86_64-w64-mingw32-g++` cross-compile of the Windows exe without CMake, already broken (no `-std=c++23`, missing sources and libraries, `src/Platform/` paths) |
| `build-linux.sh` / `build-linux.bash` | Native Linux CMake builds (two near-duplicates) |

## What was built

### Profiles — `cmake/profiles/*.cmake`

Each profile `FORCE`-sets every module option:

| Option                     | `dev-full` | `dev-minimal` | `dev-ci` | `production` |
|----------------------------|:---:|:---:|:---:|:---:|
| `BUILD_SESSION_MONITOR`    | ON  | OFF | ON  | ON  |
| `BUILD_TRAY_APP`           | ON  | OFF | ON  | OFF |
| `BUILD_METRICS`            | ON  | OFF | ON  | OFF |
| `BUILD_SERIAL_BRIDGE_PIPE` | ON  | OFF | ON  | OFF |
| `BUILD_C2A`                | ON  | OFF | ON  | OFF |
| `IPC_AUTH_DEV_DISABLE`     | ON  | ON  | OFF | OFF |
| `ENABLE_TESTING`           | ON  | ON  | ON  | OFF |

`production` reproduces exactly the flags `build-production.bat` always
passed. `cmake/profiles/local.cmake.example` is tracked;
`cmake/profiles/local.cmake` is git-ignored.

### Loader — `cmake/load-profile.cmake`

- `load_profile(name)` includes `cmake/profiles/<name>.cmake`, then
  `local.cmake` if it exists, and prints the enabled and disabled modules
  (noting when `local.cmake` was applied). An unknown name, or `local`, fails
  with the list of available profiles.
- `list_profiles(out_var)` lists the available profile names.

### `CMakeLists.txt`

- Right after the `option()` declarations, it includes the loader and
  declares `DEVELOPMENT_PROFILE` (a cache string, empty by default). It calls
  `load_profile()` **only when `DEVELOPMENT_PROFILE` is non-empty**, so plain
  `cmake`, IDEs and CI behave exactly as before.
- Compatibility checks, applied with or without a profile:
  - `BUILD_TRAY_APP` on a non-Windows platform → `STATUS` note (the tray
    sources were already Windows-gated).
  - `ENABLE_TESTING` with a compiler other than MSVC/GCC/Clang → `WARNING`.
  - `production` profile with `IPC_AUTH_DEV_DISABLE=ON` (e.g. set in
    `local.cmake`) → `FATAL_ERROR`.
- The configure summary includes a `Profile:` line.

### Scripts

All accept `--profile NAME`, `--config CONFIG` and `--help`, and pass any
other arguments to the CMake configure step. Each profile gets its own build
folder. Unit tests are built and run when the profile enables them. Each
script always passes `DEVELOPMENT_PROFILE` (empty for none), so a build
folder never keeps an old profile.

| Script | Behaviour |
|---|---|
| `build.bat` | MSVC + Ninja. No profile → `build\`, otherwise `build-<profile>\`. Copies to `installer\` and offers signing **only with no profile or `production`**. |
| `build-production.bat` | Thin wrapper: `build.bat --profile production %*` (same `build-production\` folder and installer copy as before). |
| `build-g++.bat` | MSYS2 MinGW, now with profile support. `build-mingw[-<profile>]\`. Never copies to `installer\`, as before. |
| `build.sh` | Rewritten as a unified CMake script: native Linux by default (`build-linux[-<profile>]/`); `--target windows` cross-compiles the exe with `mingw-w64-toolchain.cmake` (`build-win[-<profile>]/`), as CI does. Copies to `installer/` only with no profile or `production`. Installs missing apt packages only when run from a terminal; otherwise it exits with the install command. |
| `build-linux.sh`, `build-linux.bash` | Thin wrappers: `build.sh --target linux "$@"`. |

### Other

- `.gitignore`: `cmake/profiles/local.cmake`.
- `.gitattributes`: `*.bash text eol=lf`, so `build-linux.bash` doesn't check
  out with CRLF and break under bash.
- `docs/dev-config.md`: user documentation. `README.md`: file list and build
  steps updated.

## Decisions and deviations

1. **No profile means today's build** *(user decision)*. The prompt said that
   with no `--profile` the scripts should default to `dev-minimal`
   (`production` on CI). `build.bat` is the documented release build in the
   README, and `dev-minimal` drops the session monitor and tray, so anyone
   building an installer would silently have lost them. With no profile, the
   scripts build the `option()` defaults exactly as before.
2. **`build.sh` builds native Linux and cross-compiles Windows** *(user
   decision)*. The prompt took `build.sh` to be a Linux build. It was really a
   broken direct-g++ cross-compile of the Windows exe. It is now a CMake script
   that builds native Linux by default and cross-compiles with
   `--target windows`.
3. **Dev profiles never touch `installer/`**. `dev-full` and `dev-minimal`
   compile out IPC client authentication, so only no-profile and `production`
   builds are copied there or offered signing.
4. **No "`BUILD_C2A` requires `BUILD_SERIAL_BRIDGE_PIPE`" check**. The claim
   is false: C2A (the BMC serial command handler) and the bridge (the local
   IPC pipe/socket) are independent. C2A ON with the bridge OFF builds on
   Windows and Linux, and enforcing the check would have broken valid builds.
5. **Tray on non-Windows is a status note, not a forced-OFF warning**.
   `BUILD_TRAY_APP` defaults to ON, so the prompt's version would print a
   WARNING on every plain Linux configure. The tray sources were already
   Windows-gated.
6. **The profile is not defaulted inside CMake**. The prompt suggested a
   `DEVELOPMENT_PROFILE` that defaults from the `CI` environment variable.
   Defaults live only in the scripts, so every non-script CMake run
   (CI, VS Code CMake Tools, plain `cmake`) is unchanged.
7. **Per-profile build folders** (`build-<profile>`), rather than one shared
   `build\`, so switching profiles doesn't rebuild everything.
   `build-production\` keeps its old name.
8. **Profiles override `-D` flags** for the options they set (the `FORCE`
   behaviour the prompt asked for). Per-developer overrides go in
   `local.cmake`, which runs after the profile.
9. **Pass-through flags must be quoted on Windows**: `cmd.exe` splits
   unquoted arguments at `=`, so `"-DVAR=VALUE"`.
10. **CI unchanged** (Task 8). It configures with explicit flags and no
    profile, which still works. Adding `-DDEVELOPMENT_PROFILE=dev-ci` is
    optional; `docs/testing-ci-prompt.md` is the place for that.

## Acceptance Criteria

- [x] `cmake/profiles/` exists with dev-full, dev-minimal, dev-ci, production
- [x] `cmake -DDEVELOPMENT_PROFILE=dev-full ...` loads the profile — *verified
      for all four; an unknown name lists the valid ones*
- [x] Profile summary printed during configure (plus a `Profile:` line in the
      configure summary)
- [x] `local.cmake` override works and is git-ignored — *verified that an
      override is applied and shown as `(+ local.cmake overrides)`*
- [x] Incompatible combinations produce warnings or errors — *the production +
      auth-disabled error was verified*
- [x] Build scripts accept `--profile` — *verified:*
  - *`build.bat --profile dev-minimal`: build plus 13/13 tests, `installer\`
    untouched*
  - *`build-production.bat`: production flags, exe copied to `installer\`*
  - *`build-g++.bat --profile dev-minimal`: 13/13 tests*
  - *`build.sh --profile dev-minimal` (WSL): 13/13 tests*
  - *`build.sh` with no profile: binary copied to `installer/`*
- [x] Existing CI pipelines work unchanged (they don't set
      `DEVELOPMENT_PROFILE`)
- [x] No runtime config files introduced
- [ ] `build.bat --profile dev-full` builds all modules — *the same module set
      builds and passes 19/19 tests via CMake on MSVC and MinGW. The
      `build.bat` script path was exercised with `dev-minimal` and
      `production`, not `dev-full`*
- [ ] `build.sh --target windows` — *not run: no mingw-w64 cross toolchain
      on the test machine. It uses the same toolchain-file configure as CI;
      the missing-toolchain path fails fast with the install command*
