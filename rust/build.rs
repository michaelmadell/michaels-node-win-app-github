#[cfg(target_os = "windows")]
fn main() {
    use std::env;
    use winres::WindowsResource;

    // Grab the version number from your Cargo.toml package version
    let version = env::var("CARGO_PKG_VERSION").unwrap_or_else(|_| "1.0.0".to_string());
    
    // Convert "1.0.0" to "1,0,0,0" for Windows file version formatting
    let mut version_parts: Vec<&str> = version.split('.').collect();
    while version_parts.len() < 4 {
        version_parts.push("0");
    }
    let win_version = version_parts.join(",");

    let mut res = WindowsResource::new();
    
    // 1. Set the application icon (Replaces IDI_ICON1 in app.rc)
    res.set_icon("res/app.ico");
    
    // 2. Set the metadata properties (Replaces version.h values)
    res.set("ProductName", "CoreStation HX Agent");
    res.set("FileDescription", "CoreStation HX Agent Service & Tray");
    res.set("FileVersion", &version);
    res.set("ProductVersion", &version);
    
    // The version strings expected by Windows resources use commas
    res.set_version_info(winres::VersionInfo::FILEVERSION, 
        std::primitive::u64::from_str_radix(&win_version.replace(',', ""), 16).unwrap_or(0x0001000000000000)
    );
    res.set_version_info(winres::VersionInfo::PRODUCTVERSION, 
        std::primitive::u64::from_str_radix(&win_version.replace(',', ""), 16).unwrap_or(0x0001000000000000)
    );

    // Compile the resource into the Windows executable
    if let Err(e) = res.compile() {
        eprintln!("Failed to compile Windows resources: {}", e);
    }
}

#[cfg(not(target_os = "windows"))]
fn main() {
    // Linux doesn't embed metadata/icons into the binary in the same way,
    // so the build script does nothing on non-Windows platforms.
}