#[cfg(target_os = "windows")]
use std::sync::atomic::{AtomicBool, Ordering};
#[cfg(target_os = "windows")]
use std::sync::Arc;
#[cfg(target_os = "windows")]
use std::thread::{self, JoinHandle};
#[cfg(target_os = "windows")]
use windows::core::{s, PCSTR};
#[cfg(target_os = "windows")]
use windows::Win32::Foundation::{
    CloseHandle, GetLastError, ERROR_IO_PENDING, ERROR_PIPE_CONNECTED, HANDLE,
    INVALID_HANDLE_VALUE, WAIT_OBJECT_0, LocalFree, HLOCAL,
};
#[cfg(target_os = "windows")]
use windows::Win32::Security::Authorization::{ConvertStringSecurityDescriptorToSecurityDescriptorA, SDDL_REVISION_1};
#[cfg(target_os = "windows")]
use windows::Win32::Security::{PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES};
#[cfg(target_os = "windows")]
use windows::Win32::Storage::FileSystem::{ReadFile, FILE_FLAG_OVERLAPPED, PIPE_ACCESS_DUPLEX};
#[cfg(target_os = "windows")]
use windows::Win32::System::IO::{CancelIoEx, GetOverlappedResult, OVERLAPPED};
#[cfg(target_os = "windows")]
use windows::Win32::System::Pipes::{
    ConnectNamedPipe, CreateNamedPipeA, DisconnectNamedPipe,
    PIPE_READMODE_MESSAGE, PIPE_TYPE_MESSAGE, PIPE_WAIT,
};
#[cfg(target_os = "windows")]
use windows::Win32::System::Threading::{
    CreateEventA, ResetEvent, SetEvent, WaitForMultipleObjects, INFINITE,
};

#[cfg(target_os = "windows")]
pub type LogCallback = Box<dyn Fn(&str) + Send + Sync>;
#[cfg(target_os = "windows")]
pub type ForwardCallback = Box<dyn Fn(&str) -> bool + Send + Sync>;

#[cfg(target_os = "windows")]
pub struct SerialBridgePipe {
    log_callback: Arc<LogCallback>,
    forward_callback: Arc<ForwardCallback>,
    stop_event: isize,
    stop_flag: Arc<AtomicBool>,
    pipe_thread: Option<JoinHandle<()>>,
}

impl SerialBridgePipe {
    const PIPE_NAME: PCSTR = s!("\\\\.\\pipe\\corestation_serial_bridge");

    pub fn new(log_callback: LogCallback, forward_callback: ForwardCallback) -> Self {
        let stop_event = unsafe { CreateEventA(None, true, false, None).unwrap_or_default() };
        let log_arc = Arc::new(log_callback);

        Self {
            log_callback: log_arc,
            forward_callback: Arc::new(forward_callback),
            stop_event: stop_event.0 as isize,
            stop_flag: Arc::new(AtomicBool::new(false)),
            pipe_thread: None,
        }
    }

    pub fn start(&mut self) -> bool {
        let stop_event_handle = HANDLE(self.stop_event as *mut std::ffi::c_void);
        if stop_event_handle.is_invalid() {
            return false;
        }

        self.stop_flag.store(false, Ordering::SeqCst);
        unsafe { let _ = ResetEvent(stop_event_handle); }

        let stop_flag_clone = Arc::clone(&self.stop_flag);
        let log_clone = Arc::clone(&self.log_callback);
        let forward_clone = Arc::clone(&self.forward_callback);
        let stop_event_isize = self.stop_event;

        self.pipe_thread = Some(thread::spawn(move || {
            Self::pipe_thread_proc(stop_flag_clone, stop_event_isize, log_clone, forward_clone);
        }));

        true
    }

    pub fn stop(&mut self) {
        if self.stop_flag.swap(true, Ordering::SeqCst) { return; }
        
        let stop_event_handle = HANDLE(self.stop_event as *mut std::ffi::c_void);

        if self.stop_event != 0 {
            unsafe { let _ = SetEvent(stop_event_handle); }
        }

        if let Some(handle) = self.pipe_thread.take() {
            let _ = handle.join();
        }
    }

    fn pipe_thread_proc(
        stop_flag: Arc<AtomicBool>,
        stop_event_isize: isize,
        log_callback: Arc<LogCallback>,
        forward_callback: Arc<ForwardCallback>,
    ) {
        unsafe {
            let stop_event = HANDLE(stop_event_isize as *mut std::ffi::c_void);
            let mut sd: PSECURITY_DESCRIPTOR = PSECURITY_DESCRIPTOR::default();
            if ConvertStringSecurityDescriptorToSecurityDescriptorA(
                s!("D:(A;;GA;;;BA)"), SDDL_REVISION_1, &mut sd, None,
            ).is_err() { return; }

            let mut sa = SECURITY_ATTRIBUTES {
                nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
                lpSecurityDescriptor: sd.0,
                bInheritHandle: false.into(),
            };

            while !stop_flag.load(Ordering::SeqCst) {
                let h_pipe = CreateNamedPipeA(
                    Self::PIPE_NAME,
                    PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED,
                    PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
                    1, 1024, 1024, 0, Some(&mut sa),
                ).unwrap_or_default();

                if h_pipe.is_invalid() {
                    thread::sleep(std::time::Duration::from_secs(1));
                    continue;
                }

                let mut ov_connect = OVERLAPPED::default();
                ov_connect.hEvent = CreateEventA(None, true, false, None).unwrap_or_default();
                
                let mut connected = ConnectNamedPipe(h_pipe, Some(&mut ov_connect as *mut _)).is_ok();
                let err = GetLastError();

                if !connected && err == ERROR_IO_PENDING {
                    let handles = [ov_connect.hEvent, stop_event];
                    let wait = WaitForMultipleObjects(&handles[..], false, INFINITE);
                    if wait.0 == windows::Win32::Foundation::WAIT_OBJECT_0.0 + 1 {
                        let _ = CancelIoEx(h_pipe, Some(&ov_connect as *const _));
                    } else {
                        connected = true;
                    }
                } else if !connected && err == ERROR_PIPE_CONNECTED {
                    connected = true;
                }

                if connected && !stop_flag.load(Ordering::SeqCst) {
                    loop {
                        let mut buffer = [0u8; 1024];
                        let mut bytes_read = 0;
                        let mut ov_read = OVERLAPPED::default();
                        ov_read.hEvent = CreateEventA(None, true, false, None).unwrap_or_default();

                        let read_ok = ReadFile(h_pipe, Some(&mut buffer), None, Some(&mut ov_read as *mut _)).is_ok();

                        if !read_ok {
                            let read_err = GetLastError();
                            if read_err == ERROR_IO_PENDING {
                                let handles = [ov_read.hEvent, stop_event];
                                let wait = WaitForMultipleObjects(&handles[..], false, INFINITE);
                                if wait.0 == windows::Win32::Foundation::WAIT_OBJECT_0.0 + 1 {
                                    let _ = CancelIoEx(h_pipe, Some(&ov_read as *const _));
                                    let _ = CloseHandle(ov_read.hEvent);
                                    break;
                                }
                                let _ = GetOverlappedResult(h_pipe, &ov_read, &mut bytes_read, false);
                            } else {
                                let _ = CloseHandle(ov_read.hEvent);
                                break;
                            }
                        } else {
                            let _ = GetOverlappedResult(h_pipe, &ov_read, &mut bytes_read, true);
                        }

                        let _ = CloseHandle(ov_read.hEvent);
                        if bytes_read == 0 { break; }

                        let payload = String::from_utf8_lossy(&buffer[..bytes_read as usize]).to_string();
                        let _ = (forward_callback)(&payload);
                    }
                }
                if !ov_connect.hEvent.is_invalid() { let _ = CloseHandle(ov_connect.hEvent); }
                let _ = DisconnectNamedPipe(h_pipe);
                let _ = CloseHandle(h_pipe);
            }
            let _ = LocalFree(Some(HLOCAL(sd.0)));
        }
    }
}

#[cfg(target_os = "windows")]
impl Drop for SerialBridgePipe {
    fn drop(&mut self) {
        self.stop();
        // Check if the isize is non-zero instead of calling .is_invalid()
        if self.stop_event != 0 {
            unsafe {
                // Cast the isize back to a HANDLE before closing
                let _ = CloseHandle(HANDLE(self.stop_event as *mut std::ffi::c_void)); 
            }
        }
    }
}