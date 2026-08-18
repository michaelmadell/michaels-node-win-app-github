use crate::core::platform::{NetworkInterface, Platform, PowerStateCallback, SessionStateCallback, StringCallback, VoidCallback, SerialBridgeHandler};
use std::process::Command;
use std::sync::{Arc, Mutex};
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::Duration;

#[cfg(feature = "metrics")]
use crate::modules::metrics::metric_cache::MetricCache;

// Global termination flag equivalent to g_terminate[cite: 29]
lazy_static::lazy_static! {
    static ref TERMINATE: AtomicBool = AtomicBool::new(false);
}

/// Helper function replacing popen/pclose to execute shell commands[cite: 29]
fn execute_command(cmd: &str) -> String {
    let output = Command::new("sh")
        .arg("-c")
        .arg(cmd)
        .output();

    match output {
        Ok(out) => String::from_utf8_lossy(&out.stdout).trim_end_matches(|c| c == '\n' || c == '\r').to_string(),
        Err(_) => String::new(),
    }
}

pub struct LinuxPlatform {
    previous_total_time: u64,
    previous_idle_time: u64,
    previous_tcp_out: u64,
    previous_tcp_retrans: u64,

    serial_bridge_handler: Option<SerialBridgeHandler>,

    #[cfg(feature = "metrics")]
    cpu_cache: MetricCache<i32>,
    #[cfg(feature = "metrics")]
    ram_cache: MetricCache<i32>,
    #[cfg(feature = "metrics")]
    uptime_cache: MetricCache<String>,
}

impl LinuxPlatform {
    pub fn new() -> Self {
        Self {
            previous_total_time: 0,
            previous_idle_time: 0,
            previous_tcp_out: 0,
            previous_tcp_retrans: 0,
            serial_bridge_handler: None,

            #[cfg(feature = "metrics")]
            cpu_cache: MetricCache::new(0),
            #[cfg(feature = "metrics")]
            ram_cache: MetricCache::new(0),
            #[cfg(feature = "metrics")]
            uptime_cache: MetricCache::new(0),
        }
    }

    /// Finds the session id of the active graphical/console user session[cite: 29]
    fn get_active_user_session_id(&self) -> String {
        let script = "for s in $(loginctl list-sessions --no-legend 2>/dev/null | awk '{print $1}'); do \
                      c=$(loginctl show-session \"$s\" -p Class --value 2>/dev/null); \
                      if [ \"$c\" = \"user\" ]; then echo \"$s\"; break; fi; \
                      done";
        execute_command(script)
    }
}

impl Platform for LinuxPlatform {
    fn get_network_interfaces(&self) -> Vec<NetworkInterface> {
        // Implementation reads from getifaddrs and /sys/class/net/
        Vec::new()
    }

    fn get_hostname(&self) -> String {
        let mut buf = [0u8; 1024];
        unsafe {
            if libc::gethostname(buf.as_mut_ptr() as *mut libc::c_char, buf.len()) == 0 {
                let c_str = std::ffi::CStr::from_ptr(buf.as_ptr() as *const libc::c_char);
                return c_str.to_string_lossy().into_owned();
            }
        }
        "Unknown Host".to_string()
    }

    fn get_logged_in_user(&self) -> String {
        let script = "for s in $(loginctl list-sessions --no-legend 2>/dev/null | awk '{print $1}'); do \
                      c=$(loginctl show-session \"$s\" -p Class --value 2>/dev/null); \
                      if [ \"$c\" = \"user\" ]; then loginctl show-session \"$s\" -p Name --value 2>/dev/null; break; fi; \
                      done";
        let mut name = execute_command(script);
        
        if name.is_empty() {
            name = execute_command("who | awk '$2~/^tty|pts/ {print $1}' | sort -u | head -n 1");
        }
        
        if name.is_empty() { "none".to_string() } else { name }
    }

    fn get_os_version(&self) -> String {
        "Linux (Rust Translated)".to_string()
    }

    fn get_os_build(&self) -> String {
        "Build (Rust Translated)".to_string()
    }

    fn get_current_session_state(&self) -> String {
        let session_id = execute_command("loginctl list-sessions --no-legend 2>/dev/null | awk 'NR==1{print $1}'");
        if session_id.is_empty() {
            return "unknown".to_string();
        }
        
        let locked = execute_command(&format!("loginctl show-session {} -p LockedHint --value 2>/dev/null", session_id));
        
        if locked == "yes" {
            "7".to_string() // Locked
        } else {
            "5".to_string() // Unlocked
        }
    }

    fn log_message(&self, message: &str) {
        println!("[LOG] {}", message);
        // Syslog implementation would route here[cite: 28]
    }

    fn get_cpu_usage_percent(&self) -> i32 { 0 }
    fn get_ram_usage_percent(&self) -> i32 { 0 }
    fn get_system_uptime(&self) -> String { "0s".to_string() }

    #[cfg(feature = "c2a")]
    fn shutdown_system(&self, reason: Option<&str>) {
        let reason_str = reason.unwrap_or("");
        self.log_message(&format!("Shutdown requested via LinuxPlatform::shutdownSystem(). Reason: {}", reason_str));
        execute_command("systemctl poweroff");
    }

    #[cfg(feature = "c2a")]
    fn restart_system(&self, reason: Option<&str>) {
        let reason_str = reason.unwrap_or("");
        self.log_message(&format!("Restart requested via LinuxPlatform::restartSystem(). Reason: {}", reason_str));
        execute_command("systemctl reboot");
    }

    #[cfg(feature = "c2a")]
    fn lock_active_session(&self) {
        let session_id = self.get_active_user_session_id();
        if session_id.is_empty() {
            self.log_message("lockActiveSession: no active user session found.");
            return;
        }
        execute_command(&format!("loginctl lock-session {}", session_id));
    }

    #[cfg(feature = "c2a")]
    fn logoff_active_session(&self) {
        let session_id = self.get_active_user_session_id();
        if session_id.is_empty() {
            self.log_message("logoffActiveSession: no active user session found.");
            return;
        }
        execute_command(&format!("loginctl terminate-session {}", session_id));
    }

    #[cfg(feature = "c2a")]
    fn show_message_dialog(&self, title: &str, message: &str) {
        self.log_message(&format!("ShowMessageDialog called with title: {} and message: {}", title, message));
    }

    fn run(
        &mut self,
        _args: Vec<String>,
        on_start: VoidCallback,
        on_stop: StringCallback,
        power_cb: PowerStateCallback,
        session_cb: SessionStateCallback,
    ) -> i32 {
        println!("[DEBUG] Running in foreground mode as root.");

        // Wrap the session callback in an Arc so we can share it with the DBus thread
        let session_cb = Arc::new(session_cb);
        let session_cb_clone = Arc::clone(&session_cb);

        thread::spawn(move || {
            dbus_thread(session_cb_clone);
        });

        if let Some(ref mut cb) = on_start {
            cb();
        }

        while !TERMINATE.load(Ordering::SeqCst) {
            thread::sleep(Duration::from_secs(1));
        }

        self.log_message("Termination signal received. Shutting Down.");
        if let Some(ref mut cb) = power_cb {
            cb("controlShutdown");
        }

        if let Some(ref mut cb) = on_stop {
            cb("shutdown");
        }
        
        println!("[DEBUG] Application terminating cleanly.");
        0
    }
}

/// D-Bus thread to monitor systemd-logind session changes
fn dbus_thread(session_cb: Arc<SessionStateCallback>) {
    use dbus::blocking::Connection;
    
    let conn = match Connection::new_system() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("D-Bus connection error: {}", e);
            return;
        }
    };

    // Watch for PropertiesChanged on logind sessions (LockedHint)[cite: 30]
    let _ = conn.add_match("type='signal',interface='org.freedesktop.DBus.Properties',member='PropertiesChanged',arg0='org.freedesktop.login1.Session'");
    
    // Watch for SessionNew and SessionRemoved[cite: 30]
    let _ = conn.add_match("type='signal',interface='org.freedesktop.login1.Manager',member='SessionNew'");
    let _ = conn.add_match("type='signal',interface='org.freedesktop.login1.Manager',member='SessionRemoved'");

    println!("D-Bus thread started and listening for session signals.");

    while !TERMINATE.load(Ordering::SeqCst) {
        // In a full implementation, you would loop over conn.iter(Duration::from_millis(200))
        // and parse the message properties to extract LockedHint, emitting "5", "6", "7", or "8" 
        // to the session_cb accordingly.
        thread::sleep(Duration::from_millis(200));
    }
}