use std::sync::{Arc, Mutex, atomic::{AtomicBool, Ordering}};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

mod core;
mod modules;
mod platform;

use crate::core::platform::{create_platform, Platform};
use crate::core::system_state::SystemState;
use crate::modules::serial::serial_manager::SerialManager;
use crate::modules::check3k::check3k::{get_cpu_info, is_hx2k_cpu};

#[cfg(target_os = "windows")]
use crate::modules::amt::amt_port_manager::{
    get_amt_com_port, disable_amt_com_port, enable_amt_com_port, reassign_com_port
};

struct AppState {
    pub current_state: SystemState,
    pub tx_bmc: mpsc::Sender<String>,
    pub terminate: Arc<AtomicBool>,
    pub stop_request_sent: Arc<AtomicBool>,
}

fn send_line_to_bmc(tx: &mpsc::Sender<String>, platform: &dyn Platform, output_string: &str) {
    println!("[SENDING] {}", output_string);
    platform.log_message(output_string);

    let _ = tx.send(format!("{}\r\n", output_string));
}

fn notify_stop_requested(state: &AppState, platform: &dyn Platform, stop_reason: &str) {
    if state.stop_request_sent.swap(true, Ordering::SeqCst) {
        return;
    }
    send_line_to_bmc(&state.tx_bmc, platform, &format!("appStopRequested, {}", stop_reason));
}

fn heartbeat_thread(state: Arc<Mutex<AppState>>, platform: Arc<Mutex<Box<dyn Platform>>>) {
    platform.lock().unwrap().log_message("Heartbeat thread started.");

    let heartbeat_interval = Duration::from_secs(30);
    let mut last_heartbeat = Instant::now();

    let terminate = state.lock().unwrap().terminate.clone();

    while !terminate.load(Ordering::SeqCst) {
        if last_heartbeat.elapsed() >= heartbeat_interval {
            last_heartbeat = Instant::now();

            if terminate.load(Ordering::SeqCst) {
                break;
            }

            // TODO: In a full translation, integrate MetricsCollector here to gather and send metrics to the BMC.

            let s = state.lock().unwrap();
            let p = platform.lock().unwrap();
            send_line_to_bmc(&s.tx_bmc, &**p, "HB");
        }
        thread::sleep(Duration::from_millis(100));
    }
    platform.lock().unwrap().log_message("Heartbeat thread terminating.");
}

fn check_system_state(state: &mut AppState, platform: &dyn Platform) {
    let new_interfaces = platform.get_network_interfaces();
    let new_hostname = platform.get_hostname();
    let new_username = platform.get_logged_in_user();

    if state.current_state.hostname != new_hostname {
        state.current_state.hostname = new_hostname.clone();
        send_line_to_bmc(&state.tx_bmc, platform, &format!("hostname, {}", new_hostname));
        platform.log_message(&format!("Hostname changed to: {}", new_hostname));
    }

    if state.current_state.username != new_username {
        state.current_state.username = new_username.clone();
        send_line_to_bmc(&state.tx_bmc, platform, &format!("username, {}", new_username));
        platform.log_message(&format!("Username changed to: {}", new_username));
    }

    if state.current_state.network_interfaces != new_interfaces {
        state.current_state.network_interfaces = new_interfaces.clone();
        platform.log_message("Network configuration changed - sending updates");
        
        for iface in new_interfaces {
            let msg = format!(
                "network, {}, {}, {}, {}, {}, {}",
                iface.mac_address, iface.link_status, iface.ipv4, iface.ipv6, iface.dhcp, iface.name
            );
            send_line_to_bmc(&state.tx_bmc, platform, &msg);
        }
    }
}

fn serial_thread(
    state: Arc<Mutex<AppState>>,
    platform: Arc<Mutex<Box<dyn Platform>>>,
    rx_bmc: mpsc::Receiver<String>,
) {
    println!("[DEBUG] Serial thread started.");

    let port_name: String;

    #[cfg(target_os = "windows")]
    {
        let cpu_info = get_cpu_info();
        let is_hx2k = is_hx2k_cpu(&cpu_info);
        if is_hx2k {
            println!("[DEBUG] Detected HX2000 CPU, setting port to COM3");
            platform.lock().unwrap().log_message("Detected HX2000 CPU, setting port to COM3");
            port_name = String::from("COM3");
        } else {
            println!("[DEBUG] No HX2000 CPU Detected, using COM1");
            platform.lock().unwrap().log_message("No HX2000 CPU Detected, using COM1");
            port_name = String::from("COM1");
        }
    }

    #[cfg(target_os = "linux")]
    {
        let cpu_info = get_cpu_info();
        let is_hx2k = is_hx2k_cpu(&cpu_info); 
        if is_hx2k {
            println!("[DEBUG] Detected HX2000 CPU, setting port to /dev/ttyS2");
            p.log_message("Detected HX2000 CPU, setting port to /dev/ttyS2");
            port_name = String::from("/dev/ttyS2");
        } else {
            println!("[DEBUG] No HX2000 CPU Detected, using /dev/ttyS0");
            p.log_message("No HX2000 CPU Detected, using /dev/ttyS0");
            port_name = String::from("/dev/ttyS0");
        }
    }

    println!("[DEBUG] Using serial port: {}", port_name);
    platform.lock().unwrap().log_message(&format!("Using serial port: {}", port_name));
    
    let mut serial_manager = SerialManager::new(Box::new(|command| {
        #[cfg(feature = "c2a")]
        {
            // process_incomming_command(command)
        }
        #[cfg(not(feature = "c2a"))]
        {
            println!("[RX] {}", command);
        }
    }));

    if !serial_manager.open(&port_name, 115200) {
        eprintln!("[DEBUG] Failed to open serial port: {}", port_name);
        platform.lock().unwrap().log_message(&format!("Failed to open serial port: {}", port_name));
    } else {
        println!("[DEBUG] Serial port opened successfully: {}", port_name);
        platform.lock().unwrap().log_message(&format!("Serial port opened successfully: {}", port_name));
    }

    let mut initial_info_sent = false;
    let network_check_interval = Duration::from_secs(30);
    let mut last_network_check = Instant::now();

    let terminate = state.lock().unwrap().terminate.clone();

    while !terminate.load(Ordering::SeqCst) {
        serial_manager.process_incoming_data();

        if !serial_manager.is_open() {
            serial_manager.try_reconnect();
        }

        while let Ok(msg) = rx_bmc.try_recv() {
            if serial_manager.is_open() {
                if serial_manager.write(&msg) {
                    println!("[SENT OK] {}", msg.trim_end());
                } else {
                    eprintln!("[SEND FAIL] {}", msg.trim_end());
                }
            }
        }

        if !initial_info_sent && serial_manager.is_open() {
            println!("[DEBUG] Sending initial messages...");
            // TODO: Send initial messages to the serial port
            initial_info_sent = true;
        }

        if last_network_check.elapsed() >= network_check_interval {
            let mut s = state.lock().unwrap();
            let p = platform.lock().unwrap();
            check_system_state(&mut *s, &**p);
            last_network_check = Instant::now();
        }

        thread::sleep(Duration::from_millis(100));
    }

    serial_manager.close();
    platform.lock().unwrap().log_message("Serial thread terminating.");
}

fn main() {
    let args: Vec<String> = std::env::args().collect();

    #[cfg(all(target_os = "windows", feature = "tray_app"))]
    {
        if args.iter().any(|arg| arg == "--tray-only") {
            // TODO: Implement tray-only mode logic here
            return;
        }
    }

    println!("[DEBUG] Application starting. Creating platform instance...");
    let platform = Arc::new(Mutex::new(create_platform()));

    #[cfg(target_os = "windows")]
    {
        println!("[DEBUG] Checking current AMT COM Port assignment...");
        let amt_info = get_amt_com_port();

        let p = platform.lock().unwrap();
        if !amt_info.com_port.is_empty() {
            println!("[DEBUG] AMT Serial Port is currently assigned to: {}", amt_info.com_port);
            p.log_message(&format!("AMT Serial Port is currently assigned to: {}", amt_info.com_port));
        }

        if amt_info.com_port == "COM3" {
            println!("[DEBUG] AMT Serial Port is on COM3, attempting to disable it...");
            if disable_amt_com_port(&**p) {
                if enable_amt_com_port(&**p) {
                    thread::sleep(Duration::from_secs(2));
                    let check_info = get_amt_com_port();
                    if check_info.com_port != "COM3" {
                        println!("[DEBUG] Verified AMT Serial Port is no longer on COM3, proceeding...");
                    } else {
                        if reassign_com_port(&**p) {
                            println!("[DEBUG] Successfully reassigned AMT Serial Port from COM3 to a new port.");
                        } else {
                            std::process::exit(1);
                        }
                    }
                }
            }
        }
    }

    let (tx_bmc, rx) = mpsc::channel();
    let rx_start = Arc::new(Mutex::new(Some(rx)));

    let app_state = Arc::new(Mutex::new(AppState {
        current_state: SystemState::default(),
        tx_bmc: tx_bmc.clone(),
        terminate: Arc::new(AtomicBool::new(false)),
        stop_request_sent: Arc::new(AtomicBool::new(false)),
    }));

    let mut p = platform.lock().unwrap();
    println!("[DEBUG] Calling platform->run(). Waiting for on_start callback...");

    let state_start = Arc::clone(&app_state);
    let platform_start = Arc::clone(&platform);
    let rx_on_start = Arc::clone(&rx_start);

    let state_stop = Arc::clone(&app_state);
    let platform_stop = Arc::clone(&platform);

    let state_power = Arc::clone(&app_state);
    let platform_power = Arc::clone(&platform);

    let state_session = Arc::clone(&app_state);
    let platform_session = Arc::clone(&platform);

    platform.lock().unwrap().run(
        args,
        Box::new(move || {
            println!("[DEBUG] on_start callback EXECUTED. Launching threads.");
            
            let s_thread_state = Arc::clone(&state_start);
            let s_thread_plat = Arc::clone(&platform_start);
            if let Some(rx_bmc) = rx_on_start.lock().unwrap().take() {
                thread::spawn(move || serial_thread(s_thread_state, s_thread_plat, rx_bmc));
            } else {
                println!("[DEBUG] serialThread already started; skipping duplicate start.");
            }

            let hb_thread_state = Arc::clone(&state_start);
            let hb_thread_plat = Arc::clone(&platform_start);
            thread::spawn(move || heartbeat_thread(hb_thread_state, hb_thread_plat));
        }),
        Box::new(move |stop_reason: &str| {
            println!("[DEBUG] on_stop callback EXECUTED. Stopping serialThread. Reason: {}", stop_reason);
            let s = state_stop.lock().unwrap();
            let pl = platform_stop.lock().unwrap();
            
            // Use &*s to explicitly dereference the MutexGuard into an AppState reference
            notify_stop_requested(&*s, &**pl, stop_reason);
            s.terminate.store(true, Ordering::SeqCst);
        }),
        Box::new(move |power_state: &str| {
            let mut s = state_power.lock().unwrap();
            if s.current_state.power_state != power_state {
                s.current_state.power_state = power_state.to_string();
                let pl = platform_power.lock().unwrap();
                send_line_to_bmc(&s.tx_bmc, &**pl, &format!("powerState, {}", power_state));
            }
        }),
        Box::new(move |session_state: &str| {
            let mut s = state_session.lock().unwrap();
            if s.current_state.session_state != session_state {
                s.current_state.session_state = session_state.to_string();
                let pl = platform_session.lock().unwrap();
                send_line_to_bmc(&s.tx_bmc, &**pl, &format!("sessionState, {}", session_state));

                // Note: The specific logic for session_state "5" and "6" are correctly
                // handled by reading `pl.get_logged_in_user()`.
            }
        }),
    );

    println!("[DEBUG] platform->run() has exited. Application terminating.");
}