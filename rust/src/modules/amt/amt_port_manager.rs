use crate::core::platform::Platform;

#[derive(Debug, Clone, Default)]
pub struct AmtPortInfo {
    pub com_port: String,
    pub instance_id: String,
}

#[cfg(target_os = "windows")]
const AMT_DEVICE_HWIDS: &[&str] = &[
    "VEN_8087&DEV_7773&SUBSYS_72708086&REV_00",
    "VEN_8087&DEV_7E73&SUBSYS_72708086&REV_20",
];

#[cfg(target_os = "windows")]
fn get_amt_instance_id() -> String {
    use winreg::enums::*;
    use winreg::RegKey;

    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);

    for hwid in AMT_DEVICE_HWIDS {
        let dev_key_path = format!("SYSTEM\\CurrentControlSet\\Enum\\PCI\\{}", hwid);

        if let Ok(dev_key) = hklm.open_subkey_with_flags(&dev_key_path, KEY_READ) {
            if let Some(Ok(instance_name)) = dev_key.enum_keys().next() {
                return format!("PCI\\{}\\{}", hwid, instance_name);
            }
        }
    }
    String::new()
}

#[cfg(target_os = "windows")]
fn escape_powershell_single_quoted(input: &str) -> String {
    input.replace('\'', "''")
}

#[cfg(target_os = "windows")]
fn run_powershell_command(script: &str) -> bool {
    use std::process::Command;
    use std::os::windows::process::CommandExt;

    const CREATE_NO_WINDOW: u32 = 0x08000000;

    let status = Command::new("powershell.exe")
        .args(["-NoProfile", "-NonInteractive", "-Command", script])
        .creation_flags(CREATE_NO_WINDOW)
        .status();

    match status {
        Ok(exit_status) => exit_status.success(),
        Err(_e) => false,
    }
}

pub fn get_amt_com_port() -> AmtPortInfo {
    #[cfg(target_os = "windows")]
    {
        use winreg::enums::*;
        use winreg::RegKey;

        let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);

        for hwid in AMT_DEVICE_HWIDS {
            let dev_key_path = format!("SYSTEM\\CurrentControlSet\\Enum\\PCI\\{}", hwid);
            if let Ok(dev_key) = hklm.open_subkey_with_flags(&dev_key_path, KEY_READ) {
                for instance_name_result in dev_key.enum_keys() {
                    if let Ok(instance_name) = instance_name_result {
                        let param_path = format!("{}\\{}\\Device Parameters", dev_key_path, instance_name);
                        
                        if let Ok(param_key) = hklm.open_subkey_with_flags(&param_path, KEY_READ) {
                            // Read the PortName[cite: 7]
                            if let Ok(port_name) = param_key.get_value::<String, _>("PortName") {
                                return AmtPortInfo {
                                    com_port: port_name,
                                    instance_id: format!("PCI\\{}\\{}", hwid, instance_name),
                                };
                            }
                        }
                    }
                }
            }
        }
    }

    AmtPortInfo::default()
}

pub fn disable_amt_com_port(platform: &dyn Platform) -> bool {
    #[cfg(target_os = "windows")]
    {
        let instance_id = get_amt_instance_id();
        if instance_id.is_empty() {
            platform.log_message("AMT instance ID not found. Cannot disable AMT COM port.");
            return false;
        }

        let script = format!(
            "Disable-PnpDevice -InstanceId '{}' -Confirm:0",
            escape_powershell_single_quoted(&instance_id)
        );
        if !run_powershell_command(&script) {
            eprintln!("Failed to disable AMT COM port with instance ID: {}", instance_id);
            platform.log_message(&format!("Failed to disable AMT COM port with instance ID: {}", instance_id));
            return false;
        }

        return true;
    }

    #[cfg(not(target_os = "windows"))]
    false
}

pub fn enable_amt_com_port(platform: &dyn Platform) -> bool {
    #[cfg(target_os = "windows")]
    {
        let instance_id = get_amt_instance_id();
        if instance_id.is_empty() {
            platform.log_message("AMT instance ID not found. Cannot enable AMT COM port.");
            return false;
        }

        let script = format!(
            "Enable-PnpDevice -InstanceId '{}' -Confirm:0",
            escape_powershell_single_quoted(&instance_id)
        );

        if !run_powershell_command(&script) {
            eprintln!("Failed to enable AMT COM port with instance ID: {}", instance_id);
            platform.log_message(&format!("Failed to enable AMT COM port with instance ID: {}", instance_id));
            return false;
        }

        return true;
    }

    #[cfg(not(target_os = "windows"))]
    false
}

pub fn reassign_com_port(platform:&dyn Platform) -> bool {
    #[cfg(target_os = "windows")]
    {
        use std::thread;
        use std::time::Duration;
        use winreg::enums::*;
        use winreg::RegKey;

        platform.log_message("Reassigning AMT COM port...");

        let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);

        let arb_path = "SYSTEM\\CurrentControlSet\\Control\\COM Name Arbiter";
        if let Ok(arbiter_key) = hklm.open_subkey_with_flags(arb_path, KEY_READ | KEY_WRITE) {
            if let Ok(mut com_db) = arbiter_key.get_raw_value("ComDB") {
                if !com_db.bytes.is_empty() && (com_db.bytes[0] & 0x08) == 0 {
                    let mut bytes = com_db.bytes.into_owned();
                    bytes[0] |= 0x08;
                    com_db.bytes = bytes.into();
                    let _ = arbiter_key.set_raw_value("ComDB", &com_db);
                    platform.log_message("COM Name Arbiter updated to allow COM port reassignment.");
                } else {
                    platform.log_message("COM Name Arbiter already allows COM port reassignment.");
                }
            }
        } else {
            platform.log_message("WARNING: Could not open COM Name Arbiter registry key. COM port reassignment may fail.");
        }

        let target_port = "COM4";
        let friendly_name = "Intel(R) Active Management Technology - SOL (COM4)";
        let mut any_device_found = false;

        for hwid in AMT_DEVICE_HWIDS {
            let dev_key_path = format!("SYSTEM\\CurrentControlSet\\Enum\\PCI\\{}", hwid);
            if let Ok(dev_key) = hklm.open_subkey_with_flags(&dev_key_path, KEY_READ) {
                for instance_name_result in dev_key.enum_keys() {
                    if let Ok(instance_name) = instance_name_result {
                        any_device_found = true;
                        let instance_path = format!("{}\\{}", dev_key_path, instance_name);

                        if let Ok(instance_key) = hklm.open_subkey_with_flags(&instance_path, KEY_SET_VALUE) {
                            let _ = instance_key.set_value("FriendlyName", &friendly_name);
                        }

                        let param_path = format!("{}\\{}\\Device Parameters", dev_key_path, instance_name);
                        let (param_key, _) = hklm.create_subkey_with_flags(&param_path, KEY_SET_VALUE).unwrap_or_else(|_| panic!("Failed to create subkey"));

                        if param_key.set_value("PortName", &target_port).is_ok() {
                            platform.log_message(&format!("Set PortName=COM4 for: {}", instance_path));
                        } else {
                            platform.log_message(&format!("Failed to set PortName for: {}", instance_path));
                        }
                    }
                }
            } else {
                platform.log_message(&format!("No devices found for HWID: {}", hwid));
            }
        }

        if !any_device_found {
            platform.log_message("No AMT devices found to reassign COM port.");
            return false;
        }

        if !disable_amt_com_port(platform) {
            platform.log_message("Failed to disable AMT COM port. Reassignment may not take effect.");
            return false;
        }

        if !enable_amt_com_port(platform) {
            platform.log_message("Failed to enable AMT COM port. Reassignment may not take effect.");
            return false;
        }

        thread::sleep(Duration::from_secs(3));

        let new_info = get_amt_com_port();
        if new_info.com_port.is_empty() {
            platform.log_message("Failed to retrieve new AMT COM port after reassignment.");
            return false;
        }
        if new_info.com_port == "COM3" {
            platform.log_message("AMT COM port reassignment failed. Still on COM3.");
            return false;
        }

        platform.log_message(&format!("AMT COM port reassigned successfully to: {}", new_info.com_port));
        return true;
    }

    #[cfg(not(target_os = "windows"))]
    false
}