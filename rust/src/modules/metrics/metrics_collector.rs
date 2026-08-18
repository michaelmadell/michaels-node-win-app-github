use crate::core::platform::Platform;
use std::sync::{Arc, Mutex};

#[derive(Debug, Clone, Default)]
pub struct PerformanceMetrics {
    pub cpu_usage: i32,
    pub ram_usage: i32,
    pub disk_queue: f32,
    pub net_retrans: f32,
    pub uptime: String,
    pub free_disk_space: String,
}

#[derive(Debug, Clone, Default)]
pub struct GpuMetrics {
    pub driver_info: String,
    pub usage: f32,
}

#[derive(Debug, Clone, Default)]
pub struct ProcessMetrics {
    pub high_ram_processes: String,
}

#[derive(Debug, Clone, Default)]
pub struct UpdateStatus {
    pub state: String,
}

#[derive(Debug, Clone, Default)]
pub struct SystemMetrics {
    pub performance: PerformanceMetrics,
    pub gpu: GpuMetrics,
    pub processes: ProcessMetrics,
    pub updates: UpdateStatus,
}

pub struct MetricsCollector {
    platform: Arc<Mutex<Box<dyn Platform>>>,
    caching_enabled: Mutex<bool>,
}

impl MetricsCollector {
    pub fn new(platform: Arc<Mutex<Box<dyn Platform>>>) -> Self {
        Self {
            platform,
            caching_enabled: Mutex::new(true),
        }
    }

    pub fn update_counters(&self) {
        let mut p = self.platform.lock().unwrap();
        p.update_pdh_metrics();
    }

    pub fn collect_all(&self) -> SystemMetrics {
        SystemMetrics {
            performance: self.collect_performance(),
            gpu: self.collect_gpu(),
            processes: self.collect_processes(),
            updates: self.check_updates(),
        }
    }

    pub fn collect_performance(&self) -> PerformanceMetrics {
        let mut p = self.platform.lock().unwrap();

        if !*self.caching_enabled.lock().unwrap() {
            p.invalidate_metric_caches();
        }

        let free_disk_space = if cfg!(target_os = "windows") {
            p.get_free_disk_space_gb("C:")
        } else {
            p.get_free_disk_space_gb("/")
        };

        PerformanceMetrics {
            cpu_usage: p.get_cpu_usage_percent(),
            ram_usage: p.get_ram_usage_percent(),
            disk_queue: p.get_disk_queue_length(),
            net_retrans: p.get_network_retrans_rate(),
            uptime: p.get_system_uptime(),
            free_disk_space,
        }
    }

    pub fn collect_gpu(&self) -> GpuMetrics {
        let mut p = self.platform.lock().unwrap();

        if !*self.caching_enabled.lock().unwrap() {
            p.invalidate_metric_caches();
        }

        GpuMetrics {
            driver_info: p.get_gpu_driver_info(),
            usage: p.get_gpu_usage_percent(),
        }
    }

    pub fn collect_processes(&self) -> ProcessMetrics {
        let mut p = self.platform.lock().unwrap();

        if !*self.caching_enabled.lock().unwrap() {
            p.invalidate_metric_caches();
        }

        ProcessMetrics {
            high_ram_processes: p.get_high_ram_processes(),
        }
    }

    pub fn check_updates(&self) -> UpdateStatus {
        let mut p = self.platform.lock().unwrap();

        if !*self.caching_enabled.lock().unwrap() {
            p.invalidate_metric_caches();
        }

        UpdateStatus {
            state: p.get_windows_update_state(),
        }
    }

    pub fn invalidate_cache(&self) {
        let mut p = self.platform.lock().unwrap();
        p.invalidate_metric_caches();
    }

    pub fn set_caching_enabled(&self, enabled: bool) {
        let mut caching = self.caching_enabled.lock().unwrap();
        *caching = enabled;
    }

    pub fn get_formatted_metrics(&self) -> String {
        let metrics = self.collect_all();

        format!(
            "=== System Metrics ===\n\
            CPU Usage: {}%\n\
            RAM Usage: {}%\n\
            Disk Queue Length: {:.2}\n\
            Network Retransmission Rate: {:.2}\n\
            System Uptime: {}\n\
            Free Disk Space: {} GB\n\
            === GPU Metrics ===\n\
            GPU Driver Info: {}\n\
            GPU Usage: {:.2}%\n\
            === System Status ===\n\
            Update State: {}\n\
            High RAM Processes: {}\n",
            metrics.performance.cpu_usage,
            metrics.performance.ram_usage,
            metrics.performance.disk_queue,
            metrics.performance.net_retrans,
            metrics.performance.uptime,
            metrics.performance.free_disk_space,
            metrics.gpu.driver_info,
            metrics.gpu.usage,
            metrics.updates.state,
            metrics.processes.high_ram_processes
        )
    }
}