use libmwemu::arch::{Arch, OperatingSystem};

/// Target OS + list of architectures to try at every offset.
#[derive(Debug, Clone)]
pub struct Target {
    pub os: OperatingSystem,
    pub archs: Vec<Arch>,
}

/// Default target: the system the detector is running on.
pub fn host_target() -> Target {
    let os = match std::env::consts::OS {
        "windows" => OperatingSystem::Windows,
        "macos" => OperatingSystem::MacOS,
        _ => OperatingSystem::Linux,
    };
    let archs = match (os, std::env::consts::ARCH) {
        (OperatingSystem::Windows, "x86_64") => vec![Arch::X86_64, Arch::X86], // WoW64
        (OperatingSystem::MacOS, "aarch64") => vec![Arch::Aarch64, Arch::X86_64], // Rosetta
        (OperatingSystem::Linux, "x86_64") => vec![Arch::X86_64, Arch::X86],
        (_, "aarch64") => vec![Arch::Aarch64],
        (_, "x86_64") => vec![Arch::X86_64],
        _ => vec![Arch::X86],
    };
    Target { os, archs }
}

pub fn parse_os(s: &str) -> Result<Option<OperatingSystem>, String> {
    match s.to_lowercase().as_str() {
        "host" => Ok(None),
        "windows" | "win" => Ok(Some(OperatingSystem::Windows)),
        "linux" => Ok(Some(OperatingSystem::Linux)),
        "macos" | "mac" | "osx" => Ok(Some(OperatingSystem::MacOS)),
        _ => Err(format!("unknown os '{s}' (host|windows|linux|macos)")),
    }
}

pub fn parse_archs(s: &str) -> Result<Vec<Arch>, String> {
    s.split(',')
        .map(|a| match a.trim().to_lowercase().as_str() {
            "x86" | "x32" | "i386" => Ok(Arch::X86),
            "x64" | "x86_64" | "amd64" => Ok(Arch::X86_64),
            "arm64" | "aarch64" => Ok(Arch::Aarch64),
            other => Err(format!("unknown arch '{other}' (x86|x64|arm64)")),
        })
        .collect()
}

pub fn arch_name(a: Arch) -> &'static str {
    match a {
        Arch::X86 => "x86",
        Arch::X86_64 => "x64",
        Arch::Aarch64 => "arm64",
    }
}

pub fn os_name(o: OperatingSystem) -> &'static str {
    match o {
        OperatingSystem::Windows => "windows",
        OperatingSystem::Linux => "linux",
        OperatingSystem::MacOS => "macos",
    }
}
