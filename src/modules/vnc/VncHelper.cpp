#ifdef _WIN32
#ifdef ENABLE_VNC

#include "VncHelper.h"
#include <rfb/rfb.h>
#include <rfb/keysym.h>
#include <windows.h>
#include <string>
#include <atomic>
#include <thread>

static std::atomic<bool> g_vncStop{ false };
static rfbScreenInfoPtr g_screen = nullptr;

// ── Input forwarding ────────────────────────────────────────────────────────

static void handleKey(rfbBool down, rfbKeySym key, rfbClientPtr /*client*/) {
    // Map RFB keysym to Windows virtual key via WM_CHAR / VkKeyScan path.
    // For Latin characters rfbKeySym == Unicode codepoint (XKB convention).
    WORD vk = 0;

    // Common control keys
    switch (key) {
    case XK_BackSpace:  vk = VK_BACK;    break;
    case XK_Tab:        vk = VK_TAB;     break;
    case XK_Return:     vk = VK_RETURN;  break;
    case XK_Escape:     vk = VK_ESCAPE;  break;
    case XK_Delete:     vk = VK_DELETE;  break;
    case XK_Home:       vk = VK_HOME;    break;
    case XK_End:        vk = VK_END;     break;
    case XK_Prior:      vk = VK_PRIOR;   break;  // Page Up
    case XK_Next:       vk = VK_NEXT;    break;  // Page Down
    case XK_Left:       vk = VK_LEFT;    break;
    case XK_Up:         vk = VK_UP;      break;
    case XK_Right:      vk = VK_RIGHT;   break;
    case XK_Down:       vk = VK_DOWN;    break;
    case XK_Insert:     vk = VK_INSERT;  break;
    case XK_Shift_L:
    case XK_Shift_R:    vk = VK_SHIFT;   break;
    case XK_Control_L:
    case XK_Control_R:  vk = VK_CONTROL; break;
    case XK_Alt_L:
    case XK_Alt_R:      vk = VK_MENU;    break;
    case XK_Super_L:
    case XK_Super_R:    vk = VK_LWIN;    break;
    case XK_F1:  vk = VK_F1;  break;  case XK_F2:  vk = VK_F2;  break;
    case XK_F3:  vk = VK_F3;  break;  case XK_F4:  vk = VK_F4;  break;
    case XK_F5:  vk = VK_F5;  break;  case XK_F6:  vk = VK_F6;  break;
    case XK_F7:  vk = VK_F7;  break;  case XK_F8:  vk = VK_F8;  break;
    case XK_F9:  vk = VK_F9;  break;  case XK_F10: vk = VK_F10; break;
    case XK_F11: vk = VK_F11; break;  case XK_F12: vk = VK_F12; break;
    default:
        // Latin / Unicode — VkKeyScan handles printable ASCII range
        if (key >= 0x20 && key <= 0x7E) {
            SHORT vks = VkKeyScanW((WCHAR)key);
            if (vks != -1) vk = LOBYTE(vks);
        }
        break;
    }

    if (!vk) return;

    INPUT input = {};
    input.type = INPUT_KEYBOARD;
    input.ki.wVk = vk;
    input.ki.dwFlags = down ? 0 : KEYEVENTF_KEYUP;
    SendInput(1, &input, sizeof(INPUT));
}

static void handlePtr(int buttonMask, int x, int y, rfbClientPtr /*client*/) {
    // Scale from RFB coordinates (framebuffer pixels) to screen coordinates.
    // GetSystemMetrics gives the primary monitor size; for single-monitor
    // setups this is 1:1, but we normalise to 65535 as SendInput requires.
    int sw = GetSystemMetrics(SM_CXSCREEN);
    int sh = GetSystemMetrics(SM_CYSCREEN);

    INPUT input = {};
    input.type = INPUT_MOUSE;
    input.mi.dx = (LONG)((x * 65535L) / (sw - 1));
    input.mi.dy = (LONG)((y * 65535L) / (sh - 1));
    input.mi.dwFlags = MOUSEEVENTF_MOVE | MOUSEEVENTF_ABSOLUTE;

    static int prevButtons = 0;
    int changed = buttonMask ^ prevButtons;
    prevButtons = buttonMask;

    if (changed & 0x01) input.mi.dwFlags |= (buttonMask & 0x01) ? MOUSEEVENTF_LEFTDOWN  : MOUSEEVENTF_LEFTUP;
    if (changed & 0x02) input.mi.dwFlags |= (buttonMask & 0x02) ? MOUSEEVENTF_MIDDLEDOWN : MOUSEEVENTF_MIDDLEUP;
    if (changed & 0x04) input.mi.dwFlags |= (buttonMask & 0x04) ? MOUSEEVENTF_RIGHTDOWN  : MOUSEEVENTF_RIGHTUP;

    // Buttons 4/5 are scroll wheel (RFB convention)
    if (buttonMask & 0x08) { input.mi.dwFlags |= MOUSEEVENTF_WHEEL; input.mi.mouseData = (DWORD)WHEEL_DELTA;  SendInput(1, &input, sizeof(INPUT)); input.mi.dwFlags &= ~MOUSEEVENTF_WHEEL; input.mi.mouseData = 0; }
    if (buttonMask & 0x10) { input.mi.dwFlags |= MOUSEEVENTF_WHEEL; input.mi.mouseData = (DWORD)-WHEEL_DELTA; SendInput(1, &input, sizeof(INPUT)); input.mi.dwFlags &= ~MOUSEEVENTF_WHEEL; input.mi.mouseData = 0; }

    SendInput(1, &input, sizeof(INPUT));
}

// ── Frame capture ────────────────────────────────────────────────────────────

static void captureFrame(rfbScreenInfoPtr screen) {
    int w = screen->width;
    int h = screen->height;

    HDC hdcScreen = GetDC(NULL);
    HDC hdcMem    = CreateCompatibleDC(hdcScreen);

    BITMAPINFO bmi = {};
    bmi.bmiHeader.biSize        = sizeof(BITMAPINFOHEADER);
    bmi.bmiHeader.biWidth       = w;
    bmi.bmiHeader.biHeight      = -h;  // top-down
    bmi.bmiHeader.biPlanes      = 1;
    bmi.bmiHeader.biBitCount    = 32;
    bmi.bmiHeader.biCompression = BI_RGB;

    void* bits = nullptr;
    HBITMAP hbm = CreateDIBSection(hdcScreen, &bmi, DIB_RGB_COLORS, &bits, NULL, 0);
    HBITMAP hOld = (HBITMAP)SelectObject(hdcMem, hbm);

    BitBlt(hdcMem, 0, 0, w, h, hdcScreen, 0, 0, SRCCOPY);

    // LibVNCServer framebuffer is BGRA (32bpp) — matches DIB layout
    memcpy(screen->frameBuffer, bits, (size_t)w * h * 4);
    rfbMarkRectAsModified(screen, 0, 0, w, h);

    SelectObject(hdcMem, hOld);
    DeleteObject(hbm);
    DeleteDC(hdcMem);
    ReleaseDC(NULL, hdcScreen);
}

// ── Performance Encodings─────────────────────────────────────────────────────

static enum rfbNewClientAction handleNewClient(rfbClientPtr client) {
#if defined(LIBVNCSERVER_HAVE_LIBZ) || defined(LIBVNCSERVER_HAVE_LIBPNG)
    client->tightQualityLevel = 6;
#endif
#ifdef LIBVNCSERVER_HAVE_LIBJPEG
    client->tightCompressLevel = 1;
#endif
    return RFB_CLIENT_ACCEPT;
}


// ── Auth ─────────────────────────────────────────────────────────────────────

// Static storage required: rfbCheckPasswordByList holds a pointer to this
// for the lifetime of the rfbScreen.
static char s_vncPassword[16] = {};
static char* s_passwdList[2]  = { s_vncPassword, nullptr };

// ── Entry point ──────────────────────────────────────────────────────────────

int runVncHelper(DWORD parentPid, const std::string& password) {
    int w = GetSystemMetrics(SM_CXSCREEN);
    int h = GetSystemMetrics(SM_CYSCREEN);

    // Dummy argc/argv for rfbGetScreen
    int argc = 0;
    rfbScreenInfoPtr screen = rfbGetScreen(&argc, nullptr, w, h, 8, 3, 4);
    if (!screen) return 1;

    screen->frameBuffer      = (char*)malloc((size_t)w * h * 4);
    screen->kbdAddEvent      = handleKey;
    screen->ptrAddEvent      = handlePtr;
    screen->desktopName      = "CoreStation HX Agent";
    screen->alwaysShared     = TRUE;
    screen->port             = 5900;
    screen->ipv6port         = 5900;

    // Password auth — use the password passed by the service. VNC DES auth
    // truncates to 8 chars so we cap the copy at 8 bytes.
    if (!password.empty()) {
        strncpy_s(s_vncPassword, password.c_str(), 8);
        s_vncPassword[8]       = '\0';
        screen->authPasswdData = s_passwdList;
        screen->passwordCheck  = rfbCheckPasswordByList;
    }

    // Pixel format: 32bpp BGRA (matches GDI DIB output)
    screen->serverFormat.bitsPerPixel = 32;
    screen->serverFormat.depth        = 24;
    screen->serverFormat.trueColour   = TRUE;
    screen->serverFormat.redMax       = 0xFF;
    screen->serverFormat.greenMax     = 0xFF;
    screen->serverFormat.blueMax      = 0xFF;
    screen->serverFormat.redShift     = 16;
    screen->serverFormat.greenShift   = 8;
    screen->serverFormat.blueShift    = 0;

    rfbInitServer(screen);
    g_screen = screen;

    // Open parent process handle to detect service exit
    HANDLE hParent = (parentPid != 0)
        ? OpenProcess(SYNCHRONIZE, FALSE, parentPid)
        : NULL;

    // Frame loop: capture + process VNC events at ~30fps
    const DWORD frameMs = 33;
    while (!g_vncStop.load()) {
        captureFrame(screen);
        rfbProcessEvents(screen, frameMs * 1000); // microseconds

        // Exit if parent service has gone
        if (hParent && WaitForSingleObject(hParent, 0) == WAIT_OBJECT_0) break;
    }

    if (hParent) CloseHandle(hParent);

    rfbShutdownServer(screen, TRUE);
    free(screen->frameBuffer);
    rfbScreenCleanup(screen);
    return 0;
}

#endif // ENABLE_VNC
#endif // _WIN32
