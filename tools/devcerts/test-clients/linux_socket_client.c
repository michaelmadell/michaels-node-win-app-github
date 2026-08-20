/* Minimal Unix-domain-socket client for locally testing the authenticated
 * serial IPC bridge's Linux path (SerialBridgeSocket.cpp or
 * LinuxSerialBridgeListener.cs -- same socket path, either agent). Connects,
 * writes one message, lingers briefly so the server has time to resolve
 * this process's /proc/<pid>/exe and detached signature before it exits
 * (see spec.md's Edge Case on short-lived clients -- exiting immediately
 * after writing risks a spurious rejection due to that race, not a real
 * signature problem), then disconnects.
 *
 * Build:
 *   gcc -O0 -o linux_socket_client linux_socket_client.c
 *
 * Then sign it (or don't, to test the rejection path) with
 * tools/devcerts/sign-linux-client.sh, and run it against a locally running
 * agent -- see tools/devcerts/README.md.
 */
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

int main(int argc, char** argv) {
    const char* path = "/run/corestation/serial_bridge.sock";
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) { perror("socket"); return 1; }

    struct sockaddr_un addr = {0};
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, path, sizeof(addr.sun_path) - 1);

    if (connect(fd, (struct sockaddr*)&addr, sizeof(addr)) != 0) {
        perror("connect");
        return 1;
    }

    const char* msg = (argc > 1) ? argv[1] : "hello from linux_socket_client\n";
    ssize_t n = write(fd, msg, strlen(msg));
    printf("wrote %zd bytes, lingering 2s before close...\n", n);
    sleep(2);
    close(fd);
    return (n >= 0) ? 0 : 1;
}
