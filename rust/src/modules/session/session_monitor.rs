#[cfg(target_os = "windows")]
use std::sync::{Arc, Condvar, Mutex};
#[cfg(target_os = "windows")]
use std::thread::{self, JoinHandle};
#[cfg(target_os = "windows")]
use windows::core::{PCWSTR, w};
#[cfg(target_os = "windows")]
use windows::Win32::Foundation::{
    GetLastError, HWND, LPARAM, LRESULT, WPARAM,
};
#[cfg(target_os = "windows")]
use windows::Win32::System::LibraryLoader::GetModuleHandleW;
#[cfg(target_os = "windows")]
use windows::Win32::System::StationsAndDesktops::{
    CloseDesktop, GetUserObjectInformationW, OpenInputDesktop, UOI_NAME,
};
#[cfg(target_os = "windows")]
use windows::Win32::System::RemoteDesktop::{
    WTSFreeMemory, WTSGetActiveConsoleSessionId, WTSQuerySessionInformationW,
    WTSRegisterSessionNotification, WTSUnRegisterSessionNotification,
    WTSConnectState, WTS_CONNECTSTATE_CLASS, WTS_CURRENT_SERVER_HANDLE,
    NOTIFY_FOR_ALL_SESSIONS, WTSActive, WTSConnected, WTSDisconnected, WTSIdle,
};
#[cfg(target_os = "windows")]
use windows::Win32::UI::WindowsAndMessaging::{
    CreateWindowExW, DefWindowProcW, DestroyWindow, DispatchMessageW, GetMessageW,
    GetSystemMetrics, GetWindowLongPtrW, PostMessageW, PostQuitMessage, RegisterClassExW,
    SetWindowLongPtrW, TranslateMessage, CREATESTRUCTW, CW_USEDEFAULT, GWLP_USERDATA,
    HWND_MESSAGE, MSG, SM_REMOTESESSION, WNDCLASSEXW, WM_CLOSE, WM_CREATE, WM_DESTROY,
    WM_WTSSESSION_CHANGE,
};

#[cfg(target_os = "windows")]
pub type SessionStateCallback = Box<dyn Fn(&str) + Send + Sync>;
#[cfg(target_os = "windows")]
pub type LogCallback = Box<dyn Fn(&str) + Send + Sync>;

#[cfg(target_os = "windows")]
struct SessionMonitorState {
    log_callback: Arc<LogCallback>,
    session_callback: Arc<SessionStateCallback>,
}

#[cfg(target_os = "windows")]
impl SessionMonitorState {
    fn handle_session_change(&self, session_change_type: u32, session_id: u32) {
        let (event_name, state_value) = match session_change_type {
            1 /* WTS_CONSOLE_CONNECT */ => ("Console Connect", "1"),
            2 /* WTS_CONSOLE_DISCONNECT */ => ("Console Disconnect", "2"),
            3 /* WTS_REMOTE_CONNECT */ => ("Remote Connect (RDP)", "3"),
            4 /* WTS_REMOTE_DISCONNECT */ => ("Remote Disconnect (RDP)", "4"),
            5 /* WTS_SESSION_LOGON */ => ("Session Logon", "5"),
            6 /* WTS_SESSION_LOGOFF */ => ("Session Logoff", "6"),
            7 /* WTS_SESSION_LOCK */ => ("Session Lock", "7"),
            8 /* WTS_SESSION_UNLOCK */ => ("Session Unlock", "8"),
            9 /* WTS_SESSION_REMOTE_CONTROL */ => ("Remote Control", "9"),
            10 /* WTS_SESSION_CREATE */ => ("Session Create", "10"),
            11 /* WTS_SESSION_TERMINATE */ => ("Session Terminate", "11"),
            15 => ("Session Reconnect", "15"),
            _ => ("Unknown", ""),
        };

        let state_str = if state_value.is_empty() {
            session_change_type.to_string()
        } else {
            state_value.to_string()
        };

        (self.log_callback)(&format!(
            "Session State Change: {} (Type: {}, Session ID: {})",
            event_name, state_str, session_id
        ));

        (self.session_callback)(&state_str);
    }
}

#[cfg(target_os = "windows")]
pub struct SessionMonitor {
    log_callback: Arc<LogCallback>,
    state: Arc<SessionMonitorState>,
    active: Arc<Mutex<bool>>,
    window: Arc<Mutex<isize>>,
    window_ready: Arc<(Mutex<bool>, Condvar)>,
    thread_handle: Option<JoinHandle<()>>,
}

#[cfg(target_os = "windows")]
impl SessionMonitor {
    /// Construct a new SessionMonitor object
    pub fn new(log_callback: LogCallback, session_callback: SessionStateCallback) -> Self {
        let log_arc = Arc::new(log_callback);
        Self {
            state: Arc::new(SessionMonitorState {
                log_callback: Arc::clone(&log_arc),
                session_callback: Arc::new(session_callback),
            }),
            log_callback: log_arc,
            active: Arc::new(Mutex::new(false)),
            window: Arc::new(Mutex::new(0)),
            window_ready: Arc::new((Mutex::new(false), Condvar::new())),
            thread_handle: None,
        }
    }

    /// Start the session monitor thread
    pub fn start(&mut self) {
        *self.active.lock().unwrap() = true;
        
        let (lock, cvar) = &*self.window_ready;
        *lock.lock().unwrap() = false;

        let thread_state = Arc::clone(&self.state);
        let thread_active = Arc::clone(&self.active);
        let thread_window = Arc::clone(&self.window);
        let thread_ready = Arc::clone(&self.window_ready);

        self.thread_handle = Some(thread::spawn(move || {
            Self::thread_proc(thread_state, thread_active, thread_window, thread_ready);
        }));

        // Wait up to 5 seconds for the window to be created
        let mut ready = lock.lock().unwrap();
        while !*ready {
            let result = cvar.wait_timeout(ready, std::time::Duration::from_secs(5)).unwrap();
            ready = result.0;
            if result.1.timed_out() {
                break;
            }
        }

        (self.log_callback)("Session state monitor started");
    }

    /// Stop the session monitor and wait for thread to finish
    pub fn stop(&mut self) {
        *self.active.lock().unwrap() = false;

        let hwnd = HWND(*self.window.lock().unwrap() as *mut std::ffi::c_void);
        if hwnd.0 != std::ptr::null_mut() {
            unsafe {
                let _ = PostMessageW(Some(hwnd), WM_CLOSE, WPARAM(0), LPARAM(0));
            }
        }

        if let Some(handle) = self.thread_handle.take() {
            let _ = handle.join();
        }

        (self.log_callback)("Session state monitor stopped");
    }

    pub fn get_current_session_state(&self) -> String {
        unsafe {
            let session_id = WTSGetActiveConsoleSessionId();
            if session_id == 0xFFFFFFFF {
                (self.log_callback)("No active console session detected");
                return "0".to_string();
            }

            let h_desk = OpenInputDesktop(
                windows::Win32::System::StationsAndDesktops::DESKTOP_CONTROL_FLAGS(0), 
                false, 
                windows::Win32::System::StationsAndDesktops::DESKTOP_READOBJECTS
            ).unwrap_or_default();
            
            if h_desk.is_invalid() {
                return "7".to_string();
            }

            let mut desktop_name = [0u16; 256];
            let mut needed = 0;
            if GetUserObjectInformationW(
                windows::Win32::Foundation::HANDLE(h_desk.0),
                UOI_NAME,
                Some(desktop_name.as_mut_ptr() as *mut std::ffi::c_void),
                (desktop_name.len() * 2) as u32,
                Some(&mut needed),
            ).is_ok() {
                let desk_name = String::from_utf16_lossy(&desktop_name[..(needed / 2) as usize - 1]);
                (self.log_callback)(&format!("Current Desktop: {}", desk_name));

                if desk_name.contains("Winlogon") {
                    let _ = CloseDesktop(h_desk);
                    (self.log_callback)("Desktop is Winlogon - workstation is locked");
                    return "7".to_string();
                }
            }
            let _ = CloseDesktop(h_desk);

            if GetSystemMetrics(SM_REMOTESESSION) != 0 {
                (self.log_callback)("Running in RDP Session");
                return "3".to_string();
            }

            let mut p_buffer = windows::core::PWSTR::null();
            let mut bytes_returned = 0;

            if WTSQuerySessionInformationW(
                Some(WTS_CURRENT_SERVER_HANDLE),
                session_id,
                WTSConnectState,
                &mut p_buffer,
                &mut bytes_returned,
            ).is_ok() {
                let state_enum = *(p_buffer.0 as *const i32);
                WTSFreeMemory(p_buffer.0 as *mut std::ffi::c_void);

                match WTS_CONNECTSTATE_CLASS(state_enum) {
                    WTSActive => {
                        (self.log_callback)("Session is active and connected");
                        return "5".to_string();
                    }
                    WTSConnected => {
                        (self.log_callback)("Session is connected");
                        return "1".to_string();
                    }
                    WTSDisconnected => {
                        (self.log_callback)("Session is Disconnected");
                        return "2".to_string();
                    }
                    WTSIdle => {
                        (self.log_callback)("Session is Idle");
                        return "5".to_string();
                    }
                    _ => {
                        (self.log_callback)(&format!("Session state: {}", state_enum));
                        return "6".to_string();
                    }
                }
            }
        }
        
        "5".to_string()
    }

    fn thread_proc(
        state: Arc<SessionMonitorState>,
        active: Arc<Mutex<bool>>,
        window_ref: Arc<Mutex<isize>>,
        ready_cond: Arc<(Mutex<bool>, Condvar)>,
    ) {
        unsafe {
            let h_instance = GetModuleHandleW(PCWSTR::null()).unwrap_or_default();
            let class_name = w!("SessionMonitorWindow");

            let wcex = WNDCLASSEXW {
                cbSize: std::mem::size_of::<WNDCLASSEXW>() as u32,
                lpfnWndProc: Some(Self::wnd_proc),
                hInstance: h_instance.into(),
                lpszClassName: class_name,
                ..Default::default()
            };

            let _ = RegisterClassExW(&wcex);

            // Pass the state Arc raw pointer into lParam so the WndProc can access it
            let state_ptr = Arc::into_raw(state);

            let hwnd = CreateWindowExW(
                Default::default(),
                class_name,
                w!("Session Monitor"),
                Default::default(),
                CW_USEDEFAULT, CW_USEDEFAULT, CW_USEDEFAULT, CW_USEDEFAULT,
                Some(HWND_MESSAGE), // Message-only window
                None,
                Some(h_instance.into()),
                Some(state_ptr as *const std::ffi::c_void),
            ).unwrap_or_default();

            {
                let mut w = window_ref.lock().unwrap();
                *w = hwnd.0 as isize;
            }

            {
                let (lock, cvar) = &*ready_cond;
                *lock.lock().unwrap() = true;
                cvar.notify_all();
            }

            if hwnd.0 == std::ptr::null_mut() {
                // Recover Arc to prevent memory leak
                let state_arc = Arc::from_raw(state_ptr);
                (state_arc.log_callback)("ERROR: Failed to create session monitor window");
                return;
            }

            let state_arc = Arc::from_raw(state_ptr); // Safe to recover now

            if WTSRegisterSessionNotification(hwnd, NOTIFY_FOR_ALL_SESSIONS).is_err() {
                let err = GetLastError();
                (state_arc.log_callback)(&format!("ERROR: WTSRegisterSessionNotification failed, error: {:?}", err));
                let _ = DestroyWindow(hwnd);
                *window_ref.lock().unwrap() = 0;
                return;
            }

            (state_arc.log_callback)("Session monitor registered successfully");

            let mut msg = MSG::default();
            while GetMessageW(&mut msg, Some(hwnd), 0, 0).into() {
                if !*active.lock().unwrap() {
                    break;
                }
                let _ = TranslateMessage(&msg);
                DispatchMessageW(&msg);
            }

            let _ = WTSUnRegisterSessionNotification(hwnd);
            let _ = DestroyWindow(hwnd);
            *window_ref.lock().unwrap() = hwnd.0 as isize;
        }
    }

    unsafe extern "system" fn wnd_proc(hwnd: HWND, msg: u32, wparam: WPARAM, lparam: LPARAM) -> LRESULT {
        if msg == WM_CREATE {
            let create_struct = lparam.0 as *const CREATESTRUCTW;
            let state_ptr = (*create_struct).lpCreateParams as *const SessionMonitorState;
            SetWindowLongPtrW(hwnd, GWLP_USERDATA, state_ptr as isize);
        }

        let state_ptr = GetWindowLongPtrW(hwnd, GWLP_USERDATA) as *const SessionMonitorState;

        match msg {
            WM_WTSSESSION_CHANGE => {
                if !state_ptr.is_null() {
                    (*state_ptr).handle_session_change(wparam.0 as u32, lparam.0 as u32);
                }
                LRESULT(0)
            }
            WM_CLOSE | WM_DESTROY => {
                PostQuitMessage(0);
                LRESULT(0)
            }
            _ => DefWindowProcW(hwnd, msg, wparam, lparam),
        }
    }
}

#[cfg(target_os = "windows")]
impl Drop for SessionMonitor {
    fn drop(&mut self) {
        self.stop();
    }
}