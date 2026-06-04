# Graph Report - .  (2026-06-04)

## Corpus Check
- Corpus is ~15,846 words - fits in a single context window. You may not need a graph.

## Summary
- 218 nodes · 285 edges · 17 communities (13 shown, 4 thin omitted)
- Extraction: 95% EXTRACTED · 5% INFERRED · 0% AMBIGUOUS · INFERRED: 13 edges (avg confidence: 0.9)
- Token cost: 0 input · 0 output

## Community Hubs (Navigation)
- [[_COMMUNITY_STL & Standard Headers|STL & Standard Headers]]
- [[_COMMUNITY_Windows Service Lifecycle|Windows Service Lifecycle]]
- [[_COMMUNITY_Windows Platform Types|Windows Platform Types]]
- [[_COMMUNITY_Platform Interface & Factory|Platform Interface & Factory]]
- [[_COMMUNITY_Deployment & Packaging|Deployment & Packaging]]
- [[_COMMUNITY_Linux Platform Implementation|Linux Platform Implementation]]
- [[_COMMUNITY_Application Core|Application Core]]
- [[_COMMUNITY_VS Code CMake Settings|VS Code CMake Settings]]
- [[_COMMUNITY_VS Code Build Tasks|VS Code Build Tasks]]
- [[_COMMUNITY_VS Code C++ Config|VS Code C++ Config]]
- [[_COMMUNITY_CMake Configuration|CMake Configuration]]
- [[_COMMUNITY_Power State Callback|Power State Callback]]
- [[_COMMUNITY_Void Callback Type|Void Callback Type]]

## God Nodes (most connected - your core abstractions)
1. `files.associations` - 72 edges
2. `WindowsPlatform` - 38 edges
3. `LinuxPlatform` - 22 edges
4. `string` - 8 edges
5. `ServiceMain()` - 8 edges
6. `sendLineToBmc()` - 8 edges
7. `logMessage()` - 7 edges
8. `Platform()` - 7 edges
9. `string` - 7 edges
10. `run()` - 7 edges

## Surprising Connections (you probably didn't know these)
- `sendLineToBmc()` --implements--> `BMC Serial Protocol (key=value CSV messages over serial port to management controller)`  [INFERRED]
  src/main.cpp → README.md
- `CMakeSettings.json (x64-Debug Ninja config)` --conceptually_related_to--> `CMakeLists.txt (build configuration)`  [INFERRED]
  CMakeSettings.json → CMakeLists.txt
- `tasks.json (VSCode build + clang-tidy tasks)` --conceptually_related_to--> `CMakeLists.txt (build configuration)`  [INFERRED]
  .vscode/tasks.json → CMakeLists.txt
- `CMakeLists.txt (build configuration)` --references--> `LinuxPlatform`  [EXTRACTED]
  CMakeLists.txt → src/LinuxPlatform.cpp
- `CMakeLists.txt (build configuration)` --references--> `WindowsPlatform`  [EXTRACTED]
  CMakeLists.txt → src/WindowsPlatform.cpp

## Import Cycles
- None detected.

## Hyperedges (group relationships)
- **Platform Abstract Interface + Implementations (Windows and Linux)** — src_platform_platform, src_windowsplatform_windowsplatform, src_linuxplatform_linuxplatform [EXTRACTED 1.00]
- **Windows Service Lifecycle (install, start, stop, remove)** — installer_install_install_ps1, installer_remove_remove_ps1, root_start_start_ps1, root_stop_stop_ps1, src_windowsplatform_servicemain, src_windowsplatform_servicectrlhandler [INFERRED 0.95]
- **Linux systemd Service Lifecycle (install .deb, postinst, prerm, postrm)** — debian_postinst_postinst, debian_prerm_prerm, debian_postrm_postrm, root_cmakelists_cmakelists [INFERRED 0.95]

## Communities (17 total, 4 thin omitted)

### Community 0 - "STL & Standard Headers"
Cohesion: 0.03
Nodes (72): files.associations, algorithm, array, atomic, bit, cctype, charconv, chrono (+64 more)

### Community 1 - "Windows Service Lifecycle"
Cohesion: 0.07
Nodes (31): SERVICE_STATUS, SERVICE_STATUS_HANDLE, PowerStateCallback, SessionStateCallback, VoidCallback, run(), startService(), stopService() (+23 more)

### Community 2 - "Windows Platform Types"
Cohesion: 0.16
Nodes (20): DWORD, HANDLE, LPTSTR, NetworkInterface, string, vector, getHostname(), getLoggedInUser() (+12 more)

### Community 3 - "Platform Interface & Factory"
Cohesion: 0.11
Nodes (19): Platform, unique_ptr, createPlatform(), dbusThread(), LinuxPlatform, closeSerialPort, getHostname, getLoggedInUser (+11 more)

### Community 4 - "Deployment & Packaging"
Cohesion: 0.12
Nodes (18): BMC Serial Protocol (key=value CSV messages over serial port to management controller), CoreStationHXAgent Service (system monitoring agent for Amulet Hotkey CoreStation hardware), postinst (Debian post-install: enable+start systemd service), postrm (Debian post-removal: disable+purge systemd service), prerm (Debian pre-removal: stop systemd service), install.ps1 (Windows service installer), installer/release-notes.txt, remove.ps1 (Windows service remover) (+10 more)

### Community 5 - "Linux Platform Implementation"
Cohesion: 0.19
Nodes (16): NetworkInterface, PowerStateCallback, SessionStateCallback, string, vector, VoidCallback, getDhcpStatus(), getHostname() (+8 more)

### Community 6 - "Application Core"
Cohesion: 0.22
Nodes (12): class, Cross-Platform Service Pattern (same logic runs as Windows Service or Linux systemd daemon), checkSystemState(), string, createPlatform() declaration (main.cpp), heartbeatThread(), main(), sendLineToBmc() (+4 more)

### Community 7 - "VS Code CMake Settings"
Cohesion: 0.50
Nodes (3): cmake.buildDirectory, cmake.configureOnOpen, cmake.generator

### Community 8 - "VS Code Build Tasks"
Cohesion: 0.50
Nodes (3): problemMatcher, tasks, version

## Knowledge Gaps
- **131 isolated node(s):** `configurations`, `version`, `cmake.generator`, `cmake.buildDirectory`, `cmake.configureOnOpen` (+126 more)
  These have ≤1 connection - possible missing edges or undocumented components.
- **4 thin communities (<3 nodes) omitted from report** — run `graphify query` to explore isolated nodes.

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **Why does `WindowsPlatform` connect `Windows Service Lifecycle` to `Windows Platform Types`, `Platform Interface & Factory`, `Deployment & Packaging`, `Application Core`?**
  _High betweenness centrality (0.183) - this node is a cross-community bridge._
- **Why does `LinuxPlatform` connect `Platform Interface & Factory` to `Windows Service Lifecycle`, `Deployment & Packaging`, `Linux Platform Implementation`, `Application Core`?**
  _High betweenness centrality (0.121) - this node is a cross-community bridge._
- **Why does `files.associations` connect `STL & Standard Headers` to `VS Code CMake Settings`?**
  _High betweenness centrality (0.118) - this node is a cross-community bridge._
- **Are the 2 inferred relationships involving `WindowsPlatform` (e.g. with `Cross-Platform Service Pattern (same logic runs as Windows Service or Linux systemd daemon)` and `LinuxPlatform`) actually correct?**
  _`WindowsPlatform` has 2 INFERRED edges - model-reasoned connections that need verification._
- **Are the 2 inferred relationships involving `LinuxPlatform` (e.g. with `Cross-Platform Service Pattern (same logic runs as Windows Service or Linux systemd daemon)` and `WindowsPlatform`) actually correct?**
  _`LinuxPlatform` has 2 INFERRED edges - model-reasoned connections that need verification._
- **What connects `configurations`, `version`, `cmake.generator` to the rest of the system?**
  _131 weakly-connected nodes found - possible documentation gaps or missing edges._
- **Should `STL & Standard Headers` be split into smaller, more focused modules?**
  _Cohesion score 0.027777777777777776 - nodes in this community are weakly interconnected._