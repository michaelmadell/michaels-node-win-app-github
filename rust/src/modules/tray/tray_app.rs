#[cfg(target_os = "windows")]
use std::sync::{Arc, Condvar, Mutex};
#[cfg(target_os = "windows")]
use std::sync::atomic::{AtomicBool, Ordering};
#[cfg(target_os = "windows")]
use std::thread::{self, JoinHandle};
#[cfg(target_os = "windows")]
use std::os::windows::ffi::OsStrExt;
#[cfg(target_os = "windows")]
use windows::core::{w, PCWSTR};
#[cfg(target_os = "windows")]
use windows::Win32::Foundation::{
    CloseHandle, GetLastError, HWND, LPARAM, LRESULT, WPARAM, POINT,
};
#[cfg(target_os = "windows")]
use windows::Win32::System::LibraryLoader::GetModuleHandleW;
#[cfg(target_os = "windows")]
use windows::Win32::System::Threading::{CreateEventA, ResetEvent, SetEvent};
#[cfg(target_os = "windows")]
use windows::Win32::UI::Shell::{
    Shell_NotifyIconW, NIF_ICON, NIF_MESSAGE, NIF_SHOWTIP, NIF_TIP, NIM_ADD, NIM_DELETE,
    NIM_MODIFY, NIM_SETVERSION, NOTIFYICONDATAW, NOTIFYICON_VERSION_4,
};
#[cfg(target_os = "windows")]
use windows::Win32::UI::WindowsAndMessaging::{
    AppendMenuW, CreatePopupMenu, CreateWindowExW, DefWindowProcW, DestroyMenu,
    DestroyWindow, DispatchMessageW, GetCursorPos, GetMessageW, KillTimer, LoadCursorW, LoadIconW,
    PostMessageW, PostQuitMessage, RegisterClassExW, RegisterWindowMessageW, SetForegroundWindow,
    SetTimer, SetWindowLongPtrW, GetWindowLongPtrW, TrackPopupMenu, TranslateMessage,
    CREATESTRUCTW, CS_HREDRAW, CS_VREDRAW, CW_USEDEFAULT, GWLP_USERDATA, HMENU,
    HWND_MESSAGE, IDC_ARROW, IDI_APPLICATION, MF_GRAYED, MF_SEPARATOR, MF_STRING, MSG,
    TPM_BOTTOMALIGN, TPM_LEFTALIGN, TPM_RIGHTBUTTON, WM_APP, WM_CLOSE, WM_COMMAND,
    WM_CREATE, WM_DESTROY, WM_LBUTTONUP, WM_NULL, WM_RBUTTONUP, WM_TIMER, WNDCLASSEXW,
    WS_OVERLAPPED,
};
#[cfg(target_os = "windows")]
use windows::Win32::Graphics::Gdi::COLOR_WINDOW;

#[cfg(target_os = "windows")]
const TRAY_ICON_RESOURCE_ID: u16 = 101; //[cite: 30]
#[cfg(target_os = "windows")]
const WM_TRAY_UPDATE: u32 = WM_APP + 1; //[cite: 29]
#[cfg(target_os = "windows")]
const WM_TRAY_CALLBACK: u32 = WM_APP + 2; //[cite: 29]

#[cfg(target_os = "windows")]
pub type LogCallback = Box<dyn Fn(&str) + Send + Sync>;

#[cfg(target_os = "windows")]
#[derive(Default, Clone)]
pub struct TrayInfo {
    pub hostname: String,
    pub win_version: String,
    pub ips: Vec<String>,
}

#[cfg(target_os = "windows")]
pub type RefreshCallback = Box<dyn Fn() -> TrayInfo + Send + Sync>;

#[cfg(target_os = "windows")]
struct TrayAppState {
    log_callback: Arc<LogCallback>,
    refresh_callback: Arc<RefreshCallback>,
    info: Mutex<TrayInfo>,
    hwnd: Mutex<isize>,
    wm_taskbar_created: Mutex<u32>,
}

#[cfg(target_os = "windows")]
pub struct TrayApp {
    state: Arc<TrayAppState>,
    stop_event: windows::Win32::Foundation::HANDLE,
    stop_flag: Arc<AtomicBool>,
    ui_thread: Option<JoinHandle<()>>,
    hwnd_ready_cv: Arc<(Mutex<bool>, Condvar)>,
}

#[cfg(target_os = "windows")]
impl TrayApp {
    pub fn new(log_callback: LogCallback, refresh_callback: RefreshCallback) -> Self {
        let stop_event = unsafe { CreateEventA(None, true, false, None).unwrap_or_default() }; //[cite: 30]
        let log_arc = Arc::new(log_callback);

        if stop_event.is_invalid() {
            (log_arc)("Failed to create stop event"); //[cite: 30]
        }

        Self {
            state: Arc::new(TrayAppState {
                log_callback: log_arc,
                refresh_callback: Arc::new(refresh_callback),
                info: Mutex::new(TrayInfo {
                    hostname: "Waiting...".to_string(), //[cite: 29]
                    win_version: "Waiting...".to_string(), //[cite: 29]
                    ips: vec![],
                }),
                hwnd: Mutex::new(HWND::default()),
                wm_taskbar_created: Mutex::new(0),
            }),
            stop_event,
            stop_flag: Arc::new(AtomicBool::new(false)),
            ui_thread: None,
            hwnd_ready_cv: Arc::new((Mutex::new(false), Condvar::new())),
        }
    }

    pub fn start(&mut self) -> bool {
        self.stop_flag.store(false, Ordering::SeqCst); //[cite: 30]

        if !self.stop_event.is_invalid() {
            unsafe {
                let _ = ResetEvent(self.stop_event); //[cite: 30]
            }
        }

        let state_clone = Arc::clone(&self.state);
        let stop_clone = Arc::clone(&self.stop_flag);
        let cv_clone = Arc::clone(&self.hwnd_ready_cv);

        self.ui_thread = Some(thread::spawn(move || {
            Self::ui_thread_proc(state_clone, stop_clone, cv_clone); //[cite: 30]
        }));

        let (lock, cvar) = &*self.hwnd_ready_cv;
        let mut ready = lock.lock().unwrap();
        while !*ready && !self.stop_flag.load(Ordering::SeqCst) {
            let result = cvar.wait_timeout(ready, std::time::Duration::from_secs(5)).unwrap(); //[cite: 30]
            ready = result.0;
            if result.1.timed_out() {
                break;
            }
        }

        true
    }

    pub fn stop(&mut self) {
        if self.stop_flag.swap(true, Ordering::SeqCst) {
            return; //[cite: 30]
        }

        if !self.stop_event.is_invalid() {
            unsafe {
                let _ = SetEvent(self.stop_event); //[cite: 30]
            }
        }

        let hwnd = HWND(*self.state.hwnd.lock().unwrap() as *mut std::ffi::c_void);
        if hwnd.0 != 0 {
            unsafe {
                let _ = PostMessageW(Some(hwnd), WM_CLOSE, WPARAM(0), LPARAM(0)); //[cite: 30]
            }
        }

        if let Some(handle) = self.ui_thread.take() {
            let _ = handle.join(); //[cite: 30]
        }
    }

    fn ui_thread_proc(
        state: Arc<TrayAppState>,
        stop_flag: Arc<AtomicBool>,
        ready_cv: Arc<(Mutex<bool>, Condvar)>,
    ) {
        unsafe {
            let h_instance = GetModuleHandleW(PCWSTR::null()).unwrap_or_default(); //[cite: 30]
            let class_name = w!("NodeWinTrayWindow"); //[cite: 29]

            let mut h_icon = LoadIconW(h_instance, PCWSTR(TRAY_ICON_RESOURCE_ID as usize as *const u16)).unwrap_or_default(); //[cite: 30]
            if h_icon.is_invalid() {
                h_icon = LoadIconW(None, IDI_APPLICATION).unwrap_or_default(); //[cite: 30]
            }

            let wcex = WNDCLASSEXW {
                cbSize: std::mem::size_of::<WNDCLASSEXW>() as u32,
                style: CS_HREDRAW | CS_VREDRAW, //[cite: 30]
                lpfnWndProc: Some(Self::wnd_proc),
                hInstance: h_instance.into(),
                hIcon: h_icon,
                hCursor: LoadCursorW(None, IDC_ARROW).unwrap_or_default(), //[cite: 30]
                hbrBackground: windows::Win32::Graphics::Gdi::HBRUSH((COLOR_WINDOW.0 as usize + 1) as *mut _),hbrBackground: windows::Win32::Graphics::Gdi::HBRUSH((COLOR_WINDOW.0 as usize + 1) as *mut _),
                lpszClassName: class_name,
                hIconSm: h_icon,
                ..Default::default()
            };

            *state.wm_taskbar_created.lock().unwrap() = RegisterWindowMessageW(w!("TaskbarCreated")); //[cite: 30]
            let _ = RegisterClassExW(&wcex); //[cite: 30]

            let state_ptr = Arc::into_raw(state.clone());

            let hwnd = CreateWindowExW(
                Default::default(), class_name, w!("NodeWinTrayWindow"), WS_OVERLAPPED,
                CW_USEDEFAULT, CW_USEDEFAULT, CW_USEDEFAULT, CW_USEDEFAULT,
                Some(HWND_MESSAGE), None, Some(h_instance.into()), Some(state_ptr as *const std::ffi::c_void),
            ).unwrap_or_default();

            {
                *state.hwnd.lock().unwrap() = hwnd.0 as isize;
                let (lock, cvar) = &*ready_cv;
                *lock.lock().unwrap() = true;
                cvar.notify_all(); //[cite: 30]
            }

            if hwnd.0 == 0 {
                let _ = Arc::from_raw(state_ptr);
                (state.log_callback)("Failed to create tray window"); //[cite: 30]
                return;
            }

            Self::add_tray_icon(hwnd, h_icon, &state); //[cite: 30]

            let mut msg = MSG::default();
            while GetMessageW(&mut msg, Some(HWND::default()), 0, 0).into() { //[cite: 30]
                let _ = TranslateMessage(&msg); //[cite: 30]
                DispatchMessageW(&msg); //[cite: 30]
            }
            
            let _ = Arc::from_raw(state_ptr); // Clean up Arc allocation
        }
    }

    unsafe fn add_tray_icon(hwnd: HWND, h_icon: windows::Win32::UI::WindowsAndMessaging::HICON, state: &TrayAppState) {
        let mut nid = NOTIFYICONDATAW::default();
        nid.cbSize = std::mem::size_of::<NOTIFYICONDATAW>() as u32; //[cite: 30]
        nid.hWnd = hwnd; //[cite: 30]
        nid.uID = 1; //[cite: 30]
        nid.uFlags = NIF_ICON | NIF_TIP | NIF_MESSAGE | NIF_SHOWTIP; //[cite: 30]
        nid.uCallbackMessage = WM_TRAY_CALLBACK; //[cite: 30]
        nid.hIcon = h_icon; //[cite: 30]

        let tooltip = "CoreStation HX Agent".encode_utf16().collect::<Vec<u16>>();
        let copy_len = std::cmp::min(tooltip.len(), nid.szTip.len() - 1);
        nid.szTip[..copy_len].copy_from_slice(&tooltip[..copy_len]); //[cite: 30]

        if Shell_NotifyIconW(NIM_ADD, &nid).as_bool() == false {
            let err = GetLastError(); //[cite: 30]
            (state.log_callback)(&format!("Shell_NotifyIconW(NIM_ADD) failed (error={:?}), retrying in 5s", err)); //[cite: 30]
            let _ = SetTimer(Some(hwnd), 2, 5000, None); //[cite: 30]
            return;
        }

        let _ = KillTimer(Some(hwnd), 2); //[cite: 30]
        nid.Anonymous.uVersion = NOTIFYICON_VERSION_4;
        let _ = Shell_NotifyIconW(NIM_SETVERSION, &nid); //[cite: 30]
        let _ = SetTimer(Some(hwnd), 1, 30000, None); //[cite: 30]
        
        Self::refresh_from_platform(hwnd, state); //[cite: 30]
    }

    unsafe fn refresh_from_platform(hwnd: HWND, state: &TrayAppState) {
        let new_info = (state.refresh_callback)(); //[cite: 29]
        *state.info.lock().unwrap() = new_info;
        let _ = PostMessageW(Some(hwnd), WM_TRAY_UPDATE, WPARAM(0), LPARAM(0)); //[cite: 30]
    }

    unsafe fn apply_tooltip(hwnd: HWND, state: &TrayAppState) {
        let info = state.info.lock().unwrap().clone();
        
        let ip_list = if info.ips.is_empty() {
            "None".to_string() //[cite: 30]
        } else {
            info.ips.join(", ") //[cite: 30]
        };

        let tooltip_str = format!("CoreStation HX Agent\n{}  |  {}\n{}", info.hostname, ip_list, info.win_version); //[cite: 30]
        
        let mut nid = NOTIFYICONDATAW::default();
        nid.cbSize = std::mem::size_of::<NOTIFYICONDATAW>() as u32;
        nid.hWnd = hwnd;
        nid.uID = 1;

        let tooltip_utf16 = tooltip_str.encode_utf16().collect::<Vec<u16>>();
        let copy_len = std::cmp::min(tooltip_utf16.len(), nid.szTip.len() - 1); //[cite: 30]
        nid.szTip[..copy_len].copy_from_slice(&tooltip_utf16[..copy_len]); //[cite: 30]
        
        nid.uFlags = NIF_TIP | NIF_SHOWTIP; //[cite: 30]
        let _ = Shell_NotifyIconW(NIM_MODIFY, &nid); //[cite: 30]
    }

    unsafe fn show_context_menu(hwnd: HWND, x: i32, y: i32, state: &TrayAppState) {
        let h_menu = CreatePopupMenu().unwrap_or_default(); //[cite: 30]
        if h_menu.is_invalid() { return; }

        let _ = AppendMenuW(h_menu, MF_STRING | MF_GRAYED, 0, w!("CoreStation HX Agent")); //[cite: 30]
        let _ = AppendMenuW(h_menu, MF_SEPARATOR, 0, PCWSTR::null()); //[cite: 30]

        let info = state.info.lock().unwrap().clone();
        let host_item = format!("Host:  {}", info.hostname).encode_utf16().chain(std::iter::once(0)).collect::<Vec<u16>>(); //[cite: 30]
        let os_item = format!("OS:    {}", info.win_version).encode_utf16().chain(std::iter::once(0)).collect::<Vec<u16>>(); //[cite: 30]
        
        let _ = AppendMenuW(h_menu, MF_STRING | MF_GRAYED, 0, PCWSTR(host_item.as_ptr())); //[cite: 30]
        let _ = AppendMenuW(h_menu, MF_STRING | MF_GRAYED, 0, PCWSTR(os_item.as_ptr())); //[cite: 30]
        
        if info.ips.is_empty() {
            let _ = AppendMenuW(h_menu, MF_STRING | MF_GRAYED, 0, w!("IP:    None")); //[cite: 30]
        } else {
            for ip in info.ips {
                let ip_item = format!("IP:    {}", ip).encode_utf16().chain(std::iter::once(0)).collect::<Vec<u16>>(); //[cite: 30]
                let _ = AppendMenuW(h_menu, MF_STRING | MF_GRAYED, 0, PCWSTR(ip_item.as_ptr())); //[cite: 30]
            }
        }

        let _ = AppendMenuW(h_menu, MF_SEPARATOR, 0, PCWSTR::null()); //[cite: 30]
        let _ = AppendMenuW(h_menu, MF_STRING, 1001, w!("Refresh")); //[cite: 30]

        let _ = SetForegroundWindow(hwnd); //[cite: 30]
        let _ = TrackPopupMenu(h_menu, TPM_RIGHTBUTTON | TPM_BOTTOMALIGN | TPM_LEFTALIGN, x, y, Some(0), hwnd, None); //[cite: 30]
        let _ = PostMessageW(Some(hwnd), WM_NULL, WPARAM(0), LPARAM(0)); //[cite: 30]
        let _ = DestroyMenu(h_menu); //[cite: 30]
    }

    unsafe extern "system" fn wnd_proc(hwnd: HWND, msg: u32, wparam: WPARAM, lparam: LPARAM) -> LRESULT {
        if msg == WM_CREATE {
            let create_struct = lparam.0 as *const CREATESTRUCTW; //[cite: 30]
            let state_ptr = (*create_struct).lpCreateParams as *const TrayAppState; //[cite: 30]
            SetWindowLongPtrW(hwnd, GWLP_USERDATA, state_ptr as isize); //[cite: 30]
        }

        let state_ptr = GetWindowLongPtrW(hwnd, GWLP_USERDATA) as *const TrayAppState; //[cite: 30]
        
        if !state_ptr.is_null() {
            let state = &*state_ptr;
            let wm_taskbar_created = *state.wm_taskbar_created.lock().unwrap();
            
            if wm_taskbar_created != 0 && msg == wm_taskbar_created { //[cite: 30]
                Self::add_tray_icon(hwnd, LoadIconW(None, IDI_APPLICATION).unwrap_or_default(), state); //[cite: 30]
                return LRESULT(0);
            }

            match msg {
                WM_TRAY_UPDATE => {
                    Self::apply_tooltip(hwnd, state); //[cite: 30]
                    return LRESULT(0);
                }
                WM_TRAY_CALLBACK => {
                    let event = (lparam.0 & 0xFFFF) as u32; 
                    if event == WM_RBUTTONUP || event == WM_LBUTTONUP { //[cite: 30]
                        let mut pt = POINT::default();
                        let _ = GetCursorPos(&mut pt);
                        Self::show_context_menu(hwnd, pt.x, pt.y, state); //[cite: 30]
                    }
                    return LRESULT(0);
                }
                WM_TIMER => {
                    if wparam.0 == 1 {
                        Self::refresh_from_platform(hwnd, state); //[cite: 30]
                    } else if wparam.0 == 2 {
                        Self::add_tray_icon(hwnd, LoadIconW(None, IDI_APPLICATION).unwrap_or_default(), state); //[cite: 30]
                    }
                    return LRESULT(0);
                }
                WM_COMMAND => {
                    if (wparam.0 & 0xFFFF) == 1001 { //[cite: 30]
                        Self::refresh_from_platform(hwnd, state); //[cite: 30]
                    }
                    return LRESULT(0);
                }
                WM_DESTROY => {
                    let _ = KillTimer(Some(hwnd), 1); //[cite: 30]
                    let _ = KillTimer(Some(hwnd), 2); //[cite: 30]
                    
                    let mut nid = NOTIFYICONDATAW::default();
                    nid.cbSize = std::mem::size_of::<NOTIFYICONDATAW>() as u32;
                    nid.hWnd = hwnd;
                    nid.uID = 1;
                    let _ = Shell_NotifyIconW(NIM_DELETE, &nid); //[cite: 30]
                    
                    PostQuitMessage(0); //[cite: 30]
                    return LRESULT(0);
                }
                _ => {}
            }
        }

        DefWindowProcW(hwnd, msg, wparam, lparam) //[cite: 30]
    }
}

#[cfg(target_os = "windows")]
impl Drop for TrayApp {
    fn drop(&mut self) {
        self.stop(); //[cite: 30]
        if !self.stop_event.is_invalid() {
            unsafe {
                let _ = CloseHandle(self.stop_event); //[cite: 30]
            }
        }
    }
}