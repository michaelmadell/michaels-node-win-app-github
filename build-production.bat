@echo off
rem Kept for backward compatibility: the production feature set
rem (TrayApp=OFF C2A=OFF SerialBridgePipe=OFF SessionMonitor=ON Metrics=OFF)
rem now lives in cmake\profiles\production.cmake. Builds into build-production\
rem and copies to installer\ exactly as before. See build.bat / docs\dev-config.md.
call "%~dp0build.bat" --profile production %*
exit /b %errorlevel%
