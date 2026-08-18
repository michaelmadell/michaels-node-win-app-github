use crate::core::system_state::NetworkInterface;

pub type PowerStateCallback = Box<dyn Fn(&str) + Send + Sync>;
pub type SessionStateCallback = Box<dyn Fn(&str) + Send + Sync>;
pub type VoidCallback = Box<dyn Fn() + Send + Sync>;
pub type StringCallback = Box<dyn Fn(&str) + Send + Sync>;
pub type SerialBridgeHandler = Box<dyn Fn(&str) -> bool + Send + Sync>;

pub trait Platform: Send + Sync {
    fn get_network_interfaces(&self) -> Vec<NetworkInterface>;
    fn get_hostname(&self) -> String;
    fn get_current_session_state(&self) -> String;
    fn get_logged_in_user(&self) -> String;
    fn get_os_version(&self) -> String;
    fn get_os_build(&self) -> String;

    fn log_message(&self, message: &str);

    fn set_serial_bridge_handler(&mut self, _handler: SerialBridgeHandler) {}
    fn forward_serial_bridge_message(&self, _data: &str) -> bool {
        false
    }

    fn get_cpu_usage_percent(&self) -> i32;
    fn get_ram_usage_percent(&self) -> i32;
    fn get_system_uptime(&self) -> String;

    #[cfg(feature = "metrics")]
    fn get_free_disk_space_gb(&self, drive_path: &str) -> String;
    
    #[cfg(feature = "metrics")]
    fn get_windows_update_state(&self) -> String;
    
    #[cfg(feature = "metrics")]
    fn get_disk_queue_length(&self) -> f32;
    
    #[cfg(feature = "metrics")]
    fn get_network_retrans_rate(&self) -> f32;
    
    #[cfg(feature = "metrics")]
    fn update_pdh_metrics(&mut self);
    
    #[cfg(feature = "metrics")]
    fn invalidate_metric_caches(&mut self) {}

    #[cfg(feature = "metrics")]
    fn get_gpu_driver_info(&self) -> String;
    
    #[cfg(feature = "metrics")]
    fn get_gpu_usage_percent(&self) -> f32;
    
    #[cfg(feature = "metrics")]
    fn get_high_ram_processes(&self) -> String;

    #[cfg(feature = "c2a")]
    fn show_message_dialog(&self, title: &str, message: &str);

    // Rust doesn't support default arguments, so Option<&str> is used for optional reasons
    #[cfg(feature = "c2a")]
    fn shutdown_system(&self, reason: Option<&str>);
    
    #[cfg(feature = "c2a")]
    fn restart_system(&self, reason: Option<&str>);
    
    #[cfg(feature = "c2a")]
    fn lock_active_session(&self);
    
    #[cfg(feature = "c2a")]
    fn logoff_active_session(&self);

    // Instead of argc/argv pointers, Rust idiomaticly takes a Vec of Strings for args
    fn run(
        &mut self,
        args: Vec<String>,
        on_start: VoidCallback,
        on_stop: StringCallback,
        power_cb: PowerStateCallback,
        session_cb: SessionStateCallback,
    ) -> i32;
}

pub fn create_platform() -> Box<dyn Platform> {
    #[cfg(target_os = "windows")]
    {
        // Box::new(crate::platform::windows::WindowsPlatform::new())
        unimplemented!("Windows platform creation not yet linked")
    }

    #[cfg(target_os = "linux")]
    {
        // Box::new(crate::platform::linux::LinuxPlatform::new())
        unimplemented!("Linux platform creation not yet linked")
    }
}