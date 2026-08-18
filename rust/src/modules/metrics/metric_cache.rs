use std::sync::Mutex;
use std::time::{Duration, Instant};

struct CacheState<T> {
    cached_value: Option<T>,
    last_update: Instant,
    is_valid: bool,
}

pub struct MetricCache<T> {
    state: Mutex<CacheState<T>>,
    ttl: Mutex<Duration>,
}

impl<T: Clone> MetricCache<T> {
    pub fn new(ttl_seconds: u64) -> Self {
        Self {
            state: Mutex::new(CacheState {
                cached_value: None,
                last_update: Instant::now().checked_sub(Duration::from_secs(ttl_seconds + 1)).unwrap(),
                is_valid: false,
            }),
            ttl: Mutex::new(Duration::from_secs(ttl_seconds)),
        }
    }

    pub fn get<F>(&self, compute_func: F) -> T 
    where 
        F: FnOnce() -> T,
    {
        let mut state = self.state.lock().unwrap();
        let ttl = *self.ttl.lock().unwrap();
        let now = Instant::now();

        if !state.is_valid || state.last_update.elapsed() >= ttl {
            state.cached_value = Some(compute_func());
            state.last_update = now;
            state.is_valid = true;
        }

        state.cached_value.clone().unwrap()
    }

    pub fn invalidate(&self) {
        let mut state = self.state.lock().unwrap();
        state.is_valid = false;
    }

    pub fn is_valid(&self) -> bool {
        let state = self.state.lock().unwrap();
        let ttl = *self.ttl.lock().unwrap();
        state.is_valid && state.last_update.elapsed() < ttl
    }

    pub fn get_ttl_seconds(&self) -> u64 {
        self.ttl.lock().unwrap().as_secs()
    }

    pub fn set_ttl(&self, ttl_seconds: u64) {
        let mut ttl = self.ttl.lock().unwrap();
        *ttl = Duration::from_secs(ttl_seconds);
    }
}

pub mod cache_durations {
    pub const CPU_USAGE: u64 = 0;
    pub const RAM_USAGE: u64 = 0;
    pub const DISK_QUEUE: u64 = 0;
    pub const NET_RETRANS: u64 = 0;
    pub const SYSTEM_UPTIME: u64 = 0;
    pub const GPU_USAGE: u64 = 5;

    pub const FREE_DISK_SPACE: u64 = 60;
    pub const HIGH_RAM_PROCS: u64 = 30;

    pub const WINDOWS_UPDATE: u64 = 300;
    pub const GPU_DRIVER_INFO: u64 = 3600;
}