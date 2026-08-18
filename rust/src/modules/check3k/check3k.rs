#[derive(Debug, Default, Clone)]
pub struct CpuInfo {
    pub manufacturer: String,
    pub model: String,
    pub clockspeed: String,
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
pub fn get_cpu_info() -> CpuInfo {
    #[cfg(target_arch = "x86")]
    use std::arch::x86::__cpuid;
    #[cfg(target_arch = "x86_64")]
    use std::arch::x86_64::__cpuid;

    let mut info = CpuInfo::default();

    let leaf_0 = unsafe { __cpuid(0) };

    let mut vendor_bytes = Vec::new();
    vendor_bytes.extend_from_slice(&leaf_0.ebx.to_le_bytes());
    vendor_bytes.extend_from_slice(&leaf_0.edx.to_le_bytes());
    vendor_bytes.extend_from_slice(&leaf_0.ecx.to_le_bytes());

    info.manufacturer = String::from_utf8_lossy(&vendor_bytes).trim().to_string();

    let ext_leaf_0 = unsafe { __cpuid(0x8000_0000) };

    if ext_leaf_0.eax >= 0x8000_0004 {
        let mut brand_bytes = Vec::new();

        for leaf in 0x8000_0002..=0x8000_0004 {
            let res = unsafe { __cpuid(leaf) };
            brand_bytes.extend_from_slice(&res.eax.to_le_bytes());
            brand_bytes.extend_from_slice(&res.ebx.to_le_bytes());
            brand_bytes.extend_from_slice(&res.ecx.to_le_bytes());
            brand_bytes.extend_from_slice(&res.edx.to_le_bytes());
        }

        if let Some(null_pos) = brand_bytes.iter().position(|&b| b == 0) {
            brand_bytes.truncate(null_pos);
        }

        let full_brand = String::from_utf8_lossy(&brand_bytes).trim().to_string();

        if let Some((model, clock)) = full_brand.split_once('@') {
            info.model = model.trim().to_string();
            info.clockspeed = clock.trim().to_string();
        } else {
            info.model = full_brand;
        }
    }

    info
}

#[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
pub fn get_cpu_info() -> CpuInfo {
    CpuInfo::default()
}

pub fn is_hx2k_cpu(info: &CpuInfo) -> bool {
    const HX2K_CPUS: &[&str] = &[
        "Intel(R) Core(TM) Ultra 7 165H",
        "Intel(R) Core(TM) Ultra 7 165U",
        "Intel(R) Core(TM) Ultra 9 285H",
    ];

    HX2K_CPUS.iter().any(|hx2k_cpu| info.model.contains(hx2k_cpu))
}