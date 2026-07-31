# Graph Report - .  (2026-06-05)

## Corpus Check
- Corpus is ~21,896 words - fits in a single context window. You may not need a graph.

## Summary
- 355 nodes · 581 edges · 31 communities (19 shown, 12 thin omitted)
- Extraction: 98% EXTRACTED · 2% INFERRED · 0% AMBIGUOUS · INFERRED: 13 edges (avg confidence: 0.84)
- Token cost: 0 input · 0 output

## Community Hubs (Navigation)
- [[_COMMUNITY_Windows Platform Core|Windows Platform Core]]
- [[_COMMUNITY_Linux Platform Interface|Linux Platform Interface]]
- [[_COMMUNITY_Linux Platform Implementation|Linux Platform Implementation]]
- [[_COMMUNITY_Windows Service Manager|Windows Service Manager]]
- [[_COMMUNITY_BMC Protocol and Concepts|BMC Protocol and Concepts]]
- [[_COMMUNITY_Main Application Logic|Main Application Logic]]
- [[_COMMUNITY_CPU Detection (3kcheck)|CPU Detection (3kcheck)]]
- [[_COMMUNITY_Metrics Collection|Metrics Collection]]
- [[_COMMUNITY_Core Abstractions and Cache|Core Abstractions and Cache]]
- [[_COMMUNITY_Session Monitoring|Session Monitoring]]
- [[_COMMUNITY_Serial Manager|Serial Manager]]
- [[_COMMUNITY_Tray and Session UI|Tray and Session UI]]
- [[_COMMUNITY_Registry Editor|Registry Editor]]
- [[_COMMUNITY_Claude Code Config|Claude Code Config]]
- [[_COMMUNITY_Platform Factory|Platform Factory]]
- [[_COMMUNITY_Module Group 15|Module Group 15]]
- [[_COMMUNITY_Module Group 16|Module Group 16]]
- [[_COMMUNITY_Module Group 17|Module Group 17]]
- [[_COMMUNITY_Module Group 18|Module Group 18]]
- [[_COMMUNITY_Module Group 19|Module Group 19]]
- [[_COMMUNITY_Module Group 20|Module Group 20]]
- [[_COMMUNITY_Module Group 22|Module Group 22]]
- [[_COMMUNITY_Module Group 24|Module Group 24]]
- [[_COMMUNITY_Module Group 27|Module Group 27]]
- [[_COMMUNITY_Module Group 28|Module Group 28]]
- [[_COMMUNITY_Module Group 29|Module Group 29]]

## God Nodes (most connected - your core abstractions)
1. `LinuxPlatform` - 35 edges
2. `string` - 24 edges
3. `string` - 18 edges
4. `logMessage()` - 14 edges
5. `run()` - 12 edges
6. `string` - 10 edges
7. `LogError()` - 10 edges
8. `WndProc()` - 10 edges
9. `Platform()` - 9 edges
10. `OpenServiceHandle()` - 9 edges

## Surprising Connections (you probably didn't know these)
- `Named Pipe Tray IPC` --rationale_for--> `TrayApp()`  [EXTRACTED]
  README.md → src/modules/tray/TrayApp.cpp
- `BMC Serial Protocol` --rationale_for--> `SerialManager`  [INFERRED]
  README.md → src/modules/serial/SerialManager.h
- `Version Info (20.26.5.1-rc7)` --references--> `CMakeLists Build Config`  [INFERRED]
  src/version.h → CMakeLists.txt
- `SerialManager` --semantically_similar_to--> `Platform()`  [INFERRED] [semantically similar]
  src/modules/serial/SerialManager.h → src/core/Platform.h
- `AMT SOL COM Port Conflict Resolution` --rationale_for--> `reassignComPort`  [EXTRACTED]
  README.md → src/main.cpp

## Import Cycles
- None detected.

## Hyperedges (group relationships)
- **Linux Systemd Service Lifecycle** — debian_postinst, debian_prerm, debian_postrm, build_sh [EXTRACTED 0.95]
- **AMT COM Port Detection and Reassignment** — main_getamtcomport, main_reassigncomport, regedits_regedit_regedit [INFERRED 0.85]
- **Platform Interface Implementations** — core_platform_platform, platform_windowsplatform_windowsplatform, platform_linuxplatform_linuxplatform [EXTRACTED 1.00]
- **Windows Session and Tray Management** — session_sessionmonitor_sessionmonitor, tray_trayapp_trayapp, service_servicemanager_servicemanager, platform_windowsplatform_windowsplatform [INFERRED 0.85]

## Communities (31 total, 12 thin omitted)

### Community 0 - "Windows Platform Core"
Cohesion: 0.06
Nodes (73): FILETIME, Windows_Addon, closeSerialPort(), FileTimeToInt64(), getCpuUsagePercent(), getCpuUsagePercentImpl(), getCurrentSessionState(), getDiskQueueLength() (+65 more)

### Community 1 - "Linux Platform Interface"
Cohesion: 0.11
Nodes (30): Platform, createPlatform(), executeCommand(), getCpuTimes(), getCpuUsagePercent(), getCurrentSessionState(), getDhcpStatus(), getFreeDiskSpaceGB() (+22 more)

### Community 2 - "Linux Platform Implementation"
Cohesion: 0.06
Nodes (31): LinuxPlatform, closeSerialPort, getCpuUsagePercent, getCurrentSessionState, getDiskQueueLength, getFreeDiskSpaceGB, getGpuDriverInfo, getGpuUsagePercent (+23 more)

### Community 3 - "Windows Service Manager"
Cohesion: 0.14
Nodes (28): SC_HANDLE, GetLastErrorString(), GetStopEvent(), Install(), IsInstalled(), IsRunning(), LogError(), OpenServiceHandle() (+20 more)

### Community 4 - "BMC Protocol and Concepts"
Cohesion: 0.11
Nodes (26): AMT SOL COM Port Conflict Resolution, BMC Serial Protocol, Named Pipe Tray IPC, GetAMTComPort, main, reassignComPort, CoreStation HX Agent Project Documentation, Regedit (+18 more)

### Community 5 - "Main Application Logic"
Cohesion: 0.24
Nodes (18): AMTPortInfo, comPort, instanceId, checkSystemState(), string, wstring, disableAMTComPort(), enableAMTComPort() (+10 more)

### Community 6 - "CPU Detection (3kcheck)"
Cohesion: 0.16
Nodes (17): GetCpuInfo(), IsHX2KCPU, IsHX2KCPU(), trim(), Platform(), NetworkInterface, SystemState, CPUInfo (+9 more)

### Community 7 - "Metrics Collection"
Cohesion: 0.15
Nodes (14): GpuMetrics, CheckUpdates(), CollectAll(), CollectGpu(), CollectPerformance(), CollectProcesses(), GetFormattedMetrics(), PerformanceMetrics (+6 more)

### Community 8 - "Core Abstractions and Cache"
Cohesion: 0.12
Nodes (9): CacheDurations(), get(), namespace, ComInitializer(), class, MetricsCollector(), class, std (+1 more)

### Community 9 - "Session Monitoring"
Cohesion: 0.15
Nodes (16): GetCurrentSessionState(), HandleSessionChange(), Start(), Stop(), ThreadProc(), WndProc(), DWORD, HWND (+8 more)

### Community 10 - "Serial Manager"
Cohesion: 0.26
Nodes (10): MessageCallback, closeSerialPort(), Close(), Open(), ProcessIncomingData(), Read(), TryReconnect(), Write() (+2 more)

### Community 11 - "Tray and Session UI"
Cohesion: 0.17
Nodes (10): NOTIFYICONDATAW, run(), class, SessionMonitor(), PowerStateCallback, SessionStateCallback, StringCallback, VoidCallback (+2 more)

### Community 12 - "Registry Editor"
Cohesion: 0.39
Nodes (8): Create(), Delete(), Read(), Write(), DWORD, Regedit(), string, WindowsPlatform

### Community 14 - "Platform Factory"
Cohesion: 0.67
Nodes (3): createPlatform(), Platform, unique_ptr

## Knowledge Gaps
- **108 isolated node(s):** `allow`, `build.sh script`, `class`, `comPort`, `instanceId` (+103 more)
  These have ≤1 connection - possible missing edges or undocumented components.
- **12 thin communities (<3 nodes) omitted from report** — run `graphify query` to explore isolated nodes.

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **Why does `thread` connect `Tray and Session UI` to `Windows Platform Core`, `Linux Platform Interface`, `Linux Platform Implementation`, `Main Application Logic`, `Core Abstractions and Cache`?**
  _High betweenness centrality (0.235) - this node is a cross-community bridge._
- **Why does `LinuxPlatform` connect `Linux Platform Implementation` to `Linux Platform Interface`, `Tray and Session UI`, `CPU Detection (3kcheck)`?**
  _High betweenness centrality (0.157) - this node is a cross-community bridge._
- **Why does `Platform()` connect `CPU Detection (3kcheck)` to `Core Abstractions and Cache`, `Windows Platform Core`, `Linux Platform Implementation`, `BMC Protocol and Concepts`?**
  _High betweenness centrality (0.117) - this node is a cross-community bridge._
- **What connects `allow`, `build.sh script`, `class` to the rest of the system?**
  _108 weakly-connected nodes found - possible documentation gaps or missing edges._
- **Should `Windows Platform Core` be split into smaller, more focused modules?**
  _Cohesion score 0.061088485746019994 - nodes in this community are weakly interconnected._
- **Should `Linux Platform Interface` be split into smaller, more focused modules?**
  _Cohesion score 0.1126984126984127 - nodes in this community are weakly interconnected._
- **Should `Linux Platform Implementation` be split into smaller, more focused modules?**
  _Cohesion score 0.06451612903225806 - nodes in this community are weakly interconnected._