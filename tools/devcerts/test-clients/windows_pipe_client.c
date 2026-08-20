/* Minimal named-pipe client for locally testing the authenticated serial IPC
 * bridge's Windows path (SerialBridgePipe.cpp or WindowsSerialBridgeListener.cs
 * -- same pipe name, either agent). Connects, writes one message, lingers
 * briefly so the server has time to resolve this process's Authenticode
 * signature before it exits, then disconnects.
 *
 * Build (MinGW or MSVC):
 *   gcc -O0 -o windows_pipe_client.exe windows_pipe_client.c
 *
 * Then sign it (or don't, to test the rejection path) with
 * tools/devcerts/sign-windows-client.ps1, and run it against a locally
 * running agent -- see tools/devcerts/README.md.
 */
#include <windows.h>
#include <stdio.h>
#include <string.h>

int main(int argc, char** argv) {
    const wchar_t* pipePath = L"\\\\.\\pipe\\corestation_serial_bridge";
    HANDLE h = CreateFileW(pipePath, GENERIC_READ | GENERIC_WRITE, 0, NULL,
                            OPEN_EXISTING, 0, NULL);
    if (h == INVALID_HANDLE_VALUE) {
        printf("CreateFile failed, error=%lu\n", GetLastError());
        return 1;
    }

    const char* msg = (argc > 1) ? argv[1] : "hello from windows_pipe_client\r\n";
    DWORD written = 0;
    BOOL ok = WriteFile(h, msg, (DWORD)strlen(msg), &written, NULL);
    printf("WriteFile ok=%d wrote=%lu bytes\n", ok, written);

    Sleep(2000); /* linger so the server can resolve our identity before we exit */
    CloseHandle(h);
    return ok ? 0 : 1;
}
