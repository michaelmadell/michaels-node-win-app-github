#ifdef _WIN32
#ifdef ENABLE_VNC

#include "VncHelper.h"
#include <rfb/rfb.h>
#include <rfb/keysym.h>
#include <windows.h>
#include <winuser.h>

#ifndef DESKTOP_ALL_ACCESS
#define DESKTOP_ALL_ACCESS (STANDARD_RIGHTS_REQUIRED | 0x01FF)
#endif
#include <string>
#include <atomic>
#include <thread>
#include <chrono>
#include <vector>

static std::atomic<bool> g_vncStop{ false };
static rfbScreenInfoPtr g_screen = nullptr;

// ── Desktop attachment ───────────────────────────────────────────────────────
//
// LibVNCServer creates one OS thread per connected client. Those threads do
// NOT automatically inherit the interactive desktop, so SendInput from them
// silently fails. Call this once per thread (thread_local flag) to attach.

// Attach the calling thread to the currently active input desktop so that
// SendInput reaches the right place. Called on every input event so it
// follows desktop switches (e.g. UAC Secure Desktop) automatically.
// SetThreadDesktop is cheap when the desktop hasn't changed.
static void attachToInputDesktop() {
    HDESK hInput = OpenInputDesktop(0, FALSE, DESKTOP_ALL_ACCESS);
    if (!hInput) return;
    SetThreadDesktop(hInput);
    CloseDesktop(hInput); // safe to close after SetThreadDesktop
}

// ── Input forwarding ────────────────────────────────────────────────────────

static void handleKey(rfbBool down, rfbKeySym key, rfbClientPtr /*client*/) {
    attachToInputDesktop();
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
    attachToInputDesktop();
    // Use virtual desktop metrics so coordinates work across all monitors.
    // MOUSEEVENTF_VIRTUALDESK maps (0,0)-(65535,65535) to the full virtual
    // desktop rather than just the primary monitor.
    int sw = GetSystemMetrics(SM_CXVIRTUALSCREEN);
    int sh = GetSystemMetrics(SM_CYVIRTUALSCREEN);
    if (sw < 1) sw = 1;
    if (sh < 1) sh = 1;

    INPUT input = {};
    input.type = INPUT_MOUSE;
    input.mi.dx = (LONG)((x * 65535L) / (sw - 1));
    input.mi.dy = (LONG)((y * 65535L) / (sh - 1));
    input.mi.dwFlags = MOUSEEVENTF_MOVE | MOUSEEVENTF_ABSOLUTE | MOUSEEVENTF_VIRTUALDESK;

    static thread_local int prevButtons = 0;
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

// ── Cursor shape ─────────────────────────────────────────────────────────────
//
// Captures the current Windows cursor and forwards it to connected VNC clients
// via LibVNCServer's RichCursor encoding. Clients render the cursor locally so
// it matches the real Windows cursor (arrow, I-beam, hand, resize, etc.).

static HCURSOR s_lastHCursor = NULL;

static void updateCursorShape(rfbScreenInfoPtr screen) {
    CURSORINFO ci = { sizeof(ci) };
    if (!GetCursorInfo(&ci) || !ci.hCursor) return;
    if (ci.hCursor == s_lastHCursor) return; // unchanged
    s_lastHCursor = ci.hCursor;

    ICONINFO ii = {};
    if (!GetIconInfo(ci.hCursor, &ii)) return;

    BITMAP bm = {};
    GetObject(ii.hbmMask, sizeof(bm), &bm);
    int w = bm.bmWidth;
    int h = ii.hbmColor ? bm.bmHeight : bm.bmHeight / 2;
    if (w <= 0 || h <= 0) {
        if (ii.hbmColor) DeleteObject(ii.hbmColor);
        DeleteObject(ii.hbmMask);
        return;
    }

    HDC hdc = GetDC(NULL);
    std::vector<uint8_t> rgba(w * h * 4, 0);

    if (ii.hbmColor) {
        // Colour cursor — get 32bpp colour bitmap and 1bpp alpha mask
        BITMAPINFO bmi = {};
        bmi.bmiHeader.biSize        = sizeof(BITMAPINFOHEADER);
        bmi.bmiHeader.biWidth       = w;
        bmi.bmiHeader.biHeight      = -h;
        bmi.bmiHeader.biPlanes      = 1;
        bmi.bmiHeader.biBitCount    = 32;
        bmi.bmiHeader.biCompression = BI_RGB;
        std::vector<uint8_t> colBits(w * h * 4);
        GetDIBits(hdc, ii.hbmColor, 0, h, colBits.data(), &bmi, DIB_RGB_COLORS);

        BITMAPINFO mbmi = bmi;
        mbmi.bmiHeader.biBitCount = 1;
        int mStride = ((w + 31) / 32) * 4;
        std::vector<uint8_t> maskBits(mStride * h);
        GetDIBits(hdc, ii.hbmMask, 0, h, maskBits.data(), &mbmi, DIB_RGB_COLORS);

        for (int y = 0; y < h; y++) {
            for (int x = 0; x < w; x++) {
                int pi = (y * w + x) * 4;
                rgba[pi + 0] = colBits[pi + 2]; // R (DIB = BGRA)
                rgba[pi + 1] = colBits[pi + 1]; // G
                rgba[pi + 2] = colBits[pi + 0]; // B
                int mb = y * mStride + x / 8;
                bool transp = (maskBits[mb] >> (7 - x % 8)) & 1;
                rgba[pi + 3] = transp ? 0 : 255;
            }
        }
    } else {
        // Monochrome cursor — mask bitmap is double-height:
        // top half = AND mask, bottom half = XOR mask
        BITMAPINFO mbmi = {};
        mbmi.bmiHeader.biSize        = sizeof(BITMAPINFOHEADER);
        mbmi.bmiHeader.biWidth       = w;
        mbmi.bmiHeader.biHeight      = -(h * 2);
        mbmi.bmiHeader.biPlanes      = 1;
        mbmi.bmiHeader.biBitCount    = 1;
        mbmi.bmiHeader.biCompression = BI_RGB;
        int mStride = ((w + 31) / 32) * 4;
        std::vector<uint8_t> maskBits(mStride * h * 2);
        GetDIBits(hdc, ii.hbmMask, 0, h * 2, maskBits.data(), &mbmi, DIB_RGB_COLORS);

        for (int y = 0; y < h; y++) {
            for (int x = 0; x < w; x++) {
                int bit = 7 - (x % 8);
                bool andBit = (maskBits[y * mStride + x / 8] >> bit) & 1;
                bool xorBit = (maskBits[(y + h) * mStride + x / 8] >> bit) & 1;
                int pi = (y * w + x) * 4;
                // Windows cursor pixel modes:
                //   AND=0, XOR=0 → black
                //   AND=0, XOR=1 → white
                //   AND=1, XOR=0 → transparent
                //   AND=1, XOR=1 → screen inversion (XOR) — VNC has no equivalent,
                //                   render as black so cursors like the I-beam appear
                if (!andBit) {
                    uint8_t c = xorBit ? 255 : 0;
                    rgba[pi+0] = rgba[pi+1] = rgba[pi+2] = c;
                    rgba[pi+3] = 255;
                } else if (andBit && xorBit) {
                    // Inverted region — Windows XOR-inverts the screen here so the
                    // cursor is visible on any background. VNC has no equivalent, so
                    // render white: gives the classic white I-beam body with the
                    // AND=0/XOR=0 black pixels forming a visible dark outline.
                    rgba[pi+0] = rgba[pi+1] = rgba[pi+2] = 255;
                    rgba[pi+3] = 255;
                }
                // AND=1, XOR=0 → transparent (alpha stays 0)
            }
        }
    }

    ReleaseDC(NULL, hdc);
    if (ii.hbmColor) DeleteObject(ii.hbmColor);
    DeleteObject(ii.hbmMask);

    // Build LibVNCServer cursor. Set both richSource (RGBA, for modern clients)
    // and monochrome source+mask (fallback for older clients).
    int monoStride = ((w + 7) / 8);
    rfbCursorPtr cur = (rfbCursorPtr)calloc(1, sizeof(rfbCursor));
    if (!cur) return;

    cur->cleanup = TRUE; // rfbSetCursor will free the struct when replacing
    cur->width   = (unsigned short)w;
    cur->height  = (unsigned short)h;
    cur->xhot    = (unsigned short)ii.xHotspot;
    cur->yhot    = (unsigned short)ii.yHotspot;

    // richSource — preferred path
    cur->richSource = (unsigned char*)malloc(w * h * 4);
    if (cur->richSource) {
        memcpy(cur->richSource, rgba.data(), w * h * 4);
        cur->cleanupRichSource = TRUE;
    }

    // Monochrome fallback: derive from RGBA alpha
    cur->source = (unsigned char*)calloc(monoStride * h, 1);
    cur->mask   = (unsigned char*)calloc(monoStride * h, 1);
    if (cur->source && cur->mask) {
        for (int y = 0; y < h; y++) {
            for (int x = 0; x < w; x++) {
                bool opaque = rgba[(y * w + x) * 4 + 3] > 127;
                bool bright = rgba[(y * w + x) * 4 + 0] > 127;
                if (opaque) {
                    int byte = y * monoStride + x / 8, bit = 7 - x % 8;
                    if (bright) cur->source[byte] |= (1 << bit); // XOR white
                    cur->mask[byte] |= (1 << bit);                // opaque
                }
            }
        }
        cur->cleanupSource = TRUE;
        cur->cleanupMask   = TRUE;
    }

    rfbSetCursor(screen, cur);
}

// ── Frame capture ────────────────────────────────────────────────────────────
//
// GDI resources are allocated once and reused across frames. Recreating a
// DIB section every frame (~30fps) exhausts GDI handles within minutes and
// causes the session to crash.

static HDC    s_hdcScreen = NULL;
static HDC    s_hdcMem    = NULL;
static HBITMAP s_hbm      = NULL;
static void*  s_bits      = nullptr;
static int    s_capW = 0, s_capH = 0;

static bool ensureCapture(int w, int h) {
    if (s_hdcScreen && s_hbm && s_capW == w && s_capH == h)
        return true;

    // Release any stale resources before reallocating
    if (s_hdcMem)    { DeleteDC(s_hdcMem);            s_hdcMem    = NULL; }
    if (s_hbm)       { DeleteObject(s_hbm);            s_hbm       = NULL; }
    if (s_hdcScreen) { ReleaseDC(NULL, s_hdcScreen);   s_hdcScreen = NULL; }
    s_bits = nullptr;

    s_hdcScreen = GetDC(NULL);
    if (!s_hdcScreen) return false;

    s_hdcMem = CreateCompatibleDC(s_hdcScreen);
    if (!s_hdcMem) {
        ReleaseDC(NULL, s_hdcScreen); s_hdcScreen = NULL;
        return false;
    }

    BITMAPINFO bmi = {};
    bmi.bmiHeader.biSize        = sizeof(BITMAPINFOHEADER);
    bmi.bmiHeader.biWidth       = w;
    bmi.bmiHeader.biHeight      = -h;  // top-down
    bmi.bmiHeader.biPlanes      = 1;
    bmi.bmiHeader.biBitCount    = 32;
    bmi.bmiHeader.biCompression = BI_RGB;

    s_hbm = CreateDIBSection(s_hdcScreen, &bmi, DIB_RGB_COLORS, &s_bits, NULL, 0);
    if (!s_hbm || !s_bits) {
        DeleteDC(s_hdcMem);           s_hdcMem    = NULL;
        ReleaseDC(NULL, s_hdcScreen); s_hdcScreen = NULL;
        return false;
    }

    SelectObject(s_hdcMem, s_hbm);
    s_capW = w;
    s_capH = h;
    return true;
}

// Track which desktop the capture thread is currently attached to so we
// can detect switches (Default ↔ Winlogon/secure desktop) and reinitialise
// the GDI resources on the new desktop.
static wchar_t s_currentDesktop[256] = {};

static void captureFrame(rfbScreenInfoPtr screen) {
    int w = screen->width;
    int h = screen->height;

    // Open whatever desktop Windows has made active for input. Running as
    // SYSTEM we can open both winsta0\Default and winsta0\Winlogon (UAC).
    HDESK hInput = OpenInputDesktop(0, FALSE, DESKTOP_ALL_ACCESS);
    if (!hInput) return;

    wchar_t desktopName[256] = {};
    DWORD needed = 0;
    GetUserObjectInformationW(hInput, UOI_NAME, desktopName, sizeof(desktopName), &needed);

    if (_wcsicmp(desktopName, s_currentDesktop) != 0) {
        // Desktop switched — reattach the thread and drop stale GDI objects
        // so ensureCapture() recreates them on the new desktop.
        SetThreadDesktop(hInput);
        if (s_hdcMem)    { DeleteDC(s_hdcMem);           s_hdcMem    = NULL; }
        if (s_hbm)       { DeleteObject(s_hbm);           s_hbm       = NULL; }
        if (s_hdcScreen) { ReleaseDC(NULL, s_hdcScreen);  s_hdcScreen = NULL; }
        s_bits = nullptr; s_capW = 0; s_capH = 0;
        wcscpy_s(s_currentDesktop, desktopName);
    }

    CloseDesktop(hInput);

    if (!ensureCapture(w, h)) return;

    if (BitBlt(s_hdcMem, 0, 0, w, h, s_hdcScreen, 0, 0, SRCCOPY)) {
        memcpy(screen->frameBuffer, s_bits, (size_t)w * h * 4);
        rfbMarkRectAsModified(screen, 0, 0, w, h);
    }
}

// ── Performance Encodings─────────────────────────────────────────────────────

static enum rfbNewClientAction handleNewClient(rfbClientPtr client) {
    // Cursor shape updates let the VNC client render the cursor locally so
    // pointer movement appears instant without waiting for a framebuffer update.
    client->enableCursorShapeUpdates = TRUE;
    client->cursorWasChanged         = TRUE;
#if defined(LIBVNCSERVER_HAVE_LIBZ) || defined(LIBVNCSERVER_HAVE_LIBPNG)
    client->tightQualityLevel = 9;
#endif
#ifdef LIBVNCSERVER_HAVE_LIBJPEG
    client->tightCompressLevel = 9;
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
    // Explicitly attach the main thread to the interactive desktop.
    // CreateProcessAsUser sets lpDesktop on the process, but explicitly
    // calling SetThreadDesktop here ensures the window station is fully
    // accessible before rfbInitServer creates any client threads.
    HWINSTA hWinSta = OpenWindowStationW(L"winsta0", FALSE, WINSTA_ALL_ACCESS);
    if (hWinSta) SetProcessWindowStation(hWinSta);
    HDESK hDesk = OpenDesktopW(L"default", 0, FALSE, DESKTOP_ALL_ACCESS);
    if (hDesk) SetThreadDesktop(hDesk);

    int w = GetSystemMetrics(SM_CXSCREEN);
    int h = GetSystemMetrics(SM_CYSCREEN);

    // Dummy argc/argv for rfbGetScreen
    int argc = 0;
    rfbScreenInfoPtr screen = rfbGetScreen(&argc, nullptr, w, h, 8, 3, 4);
    if (!screen) return 1;

    screen->frameBuffer      = (char*)malloc((size_t)w * h * 4);
    screen->kbdAddEvent      = handleKey;
    screen->ptrAddEvent      = handlePtr;
    screen->newClientHook    = handleNewClient;
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

    // Decouple network I/O from frame capture:
    //   rfbProcessEvents runs every 5ms so buffered data (including the result
    //   of mouse/keyboard events) flushes to clients quickly.
    //   Frame captures are rate-limited to ~30fps independently.
    using clock = std::chrono::steady_clock;
    auto nextCapture = clock::now();
    const auto framePeriod = std::chrono::milliseconds(33);

    while (!g_vncStop.load()) {
        auto now = clock::now();
        if (now >= nextCapture) {
            updateCursorShape(screen);
            captureFrame(screen);
            nextCapture = now + framePeriod;
        }

        rfbProcessEvents(screen, 5000); // 5ms — flush data to clients quickly

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
