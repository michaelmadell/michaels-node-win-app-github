// IPC bridge client authentication, end to end without mocks: the test
// process connects to itself over a real named pipe (Windows) or socketpair
// (Linux), and the production authentication code inspects that connection.
// The test binary is unsigned, so it must be rejected - unless the build has
// IPC_AUTH_DEV_DISABLE, in which case it must be let through as a dev bypass.
// Subject matching against the trusted identity is covered by
// test_ipc_client_auth.cpp / test_linux_ipc_client_auth.cpp.
//
// Not covered: SerialBridgePipe's forwarding loop (it is bound to the
// concrete WindowsPlatform) and the agent's periodic resend (main.cpp's
// thread loop).

#ifdef ENABLE_SERIAL_BRIDGE_PIPE

#include <gtest/gtest.h>

#include <string>

#ifdef _WIN32
#include <windows.h>
#include <softpub.h>
#include "modules/serialpipe/WindowsIpcClientAuth.h"
#elif defined(__linux__)
#include <sys/socket.h>
#include <unistd.h>
#include "modules/serialpipe/LinuxIpcClientAuth.h"
#endif

#ifdef _WIN32

namespace {

// Wine implements WinVerifyTrust/GetNamedPipeClientProcessId differently, so
// error *details* are only asserted on real Windows.
bool RunningUnderWine() {
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    return ntdll != nullptr && GetProcAddress(ntdll, "wine_get_version") != nullptr;
}

// A connected server/client named-pipe pair within this process.
struct PipePair {
    HANDLE server = INVALID_HANDLE_VALUE;
    HANDLE client = INVALID_HANDLE_VALUE;

    PipePair() {
        std::wstring name = L"\\\\.\\pipe\\corestation_test_" + std::to_wstring(GetCurrentProcessId()) +
                            L"_" + std::to_wstring(GetTickCount64());
        server = CreateNamedPipeW(name.c_str(), PIPE_ACCESS_DUPLEX,
                                  PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
                                  1, 1024, 1024, 0, nullptr);
        if (server == INVALID_HANDLE_VALUE) return;
        client = CreateFileW(name.c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, 0, nullptr);
        if (client == INVALID_HANDLE_VALUE) return;
        // The client already connected, so this reports ERROR_PIPE_CONNECTED.
        if (!ConnectNamedPipe(server, nullptr) && GetLastError() != ERROR_PIPE_CONNECTED) {
            CloseHandle(client);
            client = INVALID_HANDLE_VALUE;
        }
    }
    ~PipePair() {
        if (client != INVALID_HANDLE_VALUE) CloseHandle(client);
        if (server != INVALID_HANDLE_VALUE) CloseHandle(server);
    }
    bool ok() const { return server != INVALID_HANDLE_VALUE && client != INVALID_HANDLE_VALUE; }
};

} // namespace

TEST(IpcClientAuth, UnsignedClientOverARealPipe) {
    PipePair pipe;
    ASSERT_TRUE(pipe.ok()) << "could not create a connected named pipe, error " << GetLastError();

    auto client = IpcAuth::AuthenticateClient(pipe.server);
#ifdef IPC_AUTH_DEV_DISABLE
    ASSERT_TRUE(client) << core::describe(client.error());
    EXPECT_TRUE(client->devBypass);
#else
    ASSERT_FALSE(client) << "an unsigned test binary was authenticated";
    if (!RunningUnderWine()) {
        // The pipe resolved to this process; its image has no Authenticode
        // signature at all.
        EXPECT_EQ(client.error().sub_code, core::AuthError::SubCode::SignatureVerificationFailed)
            << core::describe(client.error());
        EXPECT_EQ(client.error().code, core::CoreError::Code::PermissionDenied);
        EXPECT_EQ(client.error().platform_error, static_cast<std::uint32_t>(TRUST_E_NOSIGNATURE))
            << core::describe(client.error());
    }
#endif
}

TEST(IpcClientAuth, HandleThatIsNotAPipeIsUnresolved) {
    HANDLE event = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    ASSERT_NE(event, nullptr);
    auto client = IpcAuth::AuthenticateClient(event);
    CloseHandle(event);
#ifdef IPC_AUTH_DEV_DISABLE
    EXPECT_TRUE(client);  // the dev bypass doesn't look at the handle
#else
    ASSERT_FALSE(client);
    EXPECT_EQ(client.error().sub_code, core::AuthError::SubCode::ClientUnresolved)
        << core::describe(client.error());
    EXPECT_NE(client.error().platform_error, 0u);
#endif
}

#elif defined(__linux__)

TEST(IpcClientAuth, UnsignedPeerOverASocketPair) {
    int fds[2];
    ASSERT_EQ(socketpair(AF_UNIX, SOCK_STREAM, 0, fds), 0);

    std::string logged;
    bool authenticated = IpcAuth::LinuxIsAuthenticated(fds[0], "[test] ",
                                                       [&](const std::string& m) { logged += m + "\n"; });
    close(fds[0]);
    close(fds[1]);

#ifdef IPC_AUTH_DEV_DISABLE
    EXPECT_TRUE(authenticated);
#else
    // The peer is this test binary, which has no detached .sig file.
    EXPECT_FALSE(authenticated);
    EXPECT_FALSE(logged.empty()) << "a rejection should say why";
#endif
}

TEST(IpcClientAuth, ClosedSocketIsRejected) {
    int fds[2];
    ASSERT_EQ(socketpair(AF_UNIX, SOCK_STREAM, 0, fds), 0);
    close(fds[0]);
    close(fds[1]);
    bool authenticated = IpcAuth::LinuxIsAuthenticated(fds[0], "[test] ", [](const std::string&) {});
#ifdef IPC_AUTH_DEV_DISABLE
    EXPECT_TRUE(authenticated);
#else
    EXPECT_FALSE(authenticated);
#endif
}

#endif // platform

#endif // ENABLE_SERIAL_BRIDGE_PIPE
