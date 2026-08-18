#[derive(Debug, Clone, PartialEq)]
pub struct NetworkInterface {
    pub name: String,
    pub ipv4: String,
    pub ipv6: String,
    pub dhcp: String,
    pub link_status: String,
    pub mac_address: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct SystemState {
    pub network_interfaces: Vec<NetworkInterface>,
    pub hostname: String,
    pub power_state: String,
    pub session_state: String,
    pub username: String,

    #[cfg(feature = "metrics")]
    pub cpu_usage_percent: i32,
    #[cfg(feature = "metrics")]
    pub ram_usage_percent: i32,
    #[cfg(feature = "metrics")]
    pub free_disk_space_gb: String,
    #[cfg(feature = "metrics")]
    pub windows_update_state: String,
    #[cfg(feature = "metrics")]
    pub disk_queue_length: f32,
    #[cfg(feature = "metrics")]
    pub network_retrans_rate: f32,
    #[cfg(feature = "metrics")]
    pub system_uptime: String,
    #[cfg(feature = "metrics")]
    pub gpu_driver_info: String,
    #[cfg(feature = "metrics")]
    pub gpu_usage_percent: f32,
    #[cfg(feature = "metrics")]
    pub high_ram_processes: String,
}

impl Default for SystemState {
    fn default() -> Self {
        Self {
            network_interfaces: Vec::new(),
            hostname: String::new(),
            power_state: String::new(),
            session_state: String::new(),
            username: String::new(),

            #[cfg(feature = "metrics")]
            cpu_usage_percent: 0,
            #[cfg(feature = "metrics")]
            ram_usage_percent: 0,
            #[cfg(feature = "metrics")]
            free_disk_space_gb: String::new(),
            #[cfg(feature = "metrics")]
            windows_update_state: String::from("Unknown"),
            #[cfg(feature = "metrics")]
            disk_queue_length: 0.0,
            #[cfg(feature = "metrics")]
            network_retrans_rate: 0.0,
            #[cfg(feature = "metrics")]
            system_uptime: String::new(),
            #[cfg(feature = "metrics")]
            gpu_driver_info: String::from("Unknown"),
            #[cfg(feature = "metrics")]
            gpu_usage_percent: 0.0,
            #[cfg(feature = "metrics")]
            high_ram_processes: String::from("none"),
        }
    }
}