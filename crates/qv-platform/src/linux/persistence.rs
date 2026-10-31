// SPDX-License-Identifier: AGPL-3.0-or-later

//! Conservative, bounded configuration reporting; never infer locked key custody.
use crate::{Evidence, ProtectionStatus};
use std::io::Read;
const MAX_CONFIG: u64 = 64 * 1024;
fn read(path: &str) -> Option<String> {
    let file = std::fs::File::open(path).ok()?;
    let mut data = String::new();
    file.take(MAX_CONFIG + 1).read_to_string(&mut data).ok()?;
    (data.len() as u64 <= MAX_CONFIG).then_some(data)
}
/// Report configuration without reading swap contents or changing OS policy.
/// Even encrypted device names do not establish locked-state key unavailability.
pub fn detect_persistence() -> ProtectionStatus {
    parse(
        read("/proc/swaps").as_deref(),
        read("/sys/power/state").as_deref(),
        read("/sys/power/resume").as_deref(),
    )
}
fn parse(swaps: Option<&str>, power: Option<&str>, resume: Option<&str>) -> ProtectionStatus {
    let swap = swaps
        .filter(|s| s.len() as u64 <= MAX_CONFIG)
        .map(|s| {
            let mut lines = s.lines();
            if lines
                .next()
                .map(|h| h.split_whitespace().collect::<Vec<_>>())
                != Some(vec!["Filename", "Type", "Size", "Used", "Priority"])
            {
                return Evidence::Unknown;
            }
            let mut active = false;
            for line in lines {
                let row: Vec<_> = line.split_whitespace().collect();
                if row.len() != 5
                    || !matches!(row[1], "file" | "partition")
                    || row[2].parse::<u64>().is_err()
                    || row[3].parse::<u64>().is_err()
                    || row[4].parse::<i32>().is_err()
                {
                    return Evidence::Unknown;
                }
                active = true;
            }
            if active {
                Evidence::Unknown
            } else {
                Evidence::Verified
            }
        })
        .unwrap_or(Evidence::Unknown);
    let hibernation = match power.filter(|s| !s.trim().is_empty() && s.len() as u64 <= MAX_CONFIG) {
        Some(s)
            if s.split_whitespace()
                .all(|s| matches!(s, "freeze" | "standby" | "mem")) =>
        {
            Evidence::Verified
        }
        Some(s) if s.split_whitespace().any(|s| s == "disk") => {
            // A configured resume device can contain an image; naming it says
            // nothing about encryption or custody of its keys while locked.
            let _ = resume;
            Evidence::Unknown
        }
        _ => Evidence::Unknown,
    };
    ProtectionStatus {
        storage: Evidence::Unknown,
        swap,
        hibernation,
        lifecycle: false,
        clipboard: false,
        quick_unlock: false,
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    // 0012 §1: Swap/hibernation leaks
    #[test]
    fn persistence_unknown_encryption_never_becomes_verified_protection() {
        let header = "Filename\tType\tSize\tUsed\tPriority\n";
        let s = parse(Some(header), Some("freeze mem\n"), Some("0:0"));
        assert_eq!(s.swap, Evidence::Verified);
        assert_eq!(s.hibernation, Evidence::Verified);
        assert!(s.is_reduced());
        for device in ["/dev/sda2", "/dev/mapper/cryptswap", "/swapfile"] {
            let swaps = format!("{header}{device} partition 1024 0 -2\n");
            let s = parse(Some(&swaps), Some("freeze mem disk"), Some("8:2"));
            assert_eq!(s.swap, Evidence::Unknown);
            assert_eq!(s.hibernation, Evidence::Unknown);
            assert!(!s.quick_unlock);
        }
        for bad in [
            "",
            "bad",
            "Filename Type Size Used Priority\nx file NaN 0 -2",
            &"x".repeat(MAX_CONFIG as usize + 1),
        ] {
            assert_eq!(parse(Some(bad), None, None).swap, Evidence::Unknown);
        }
        assert_eq!(
            parse(None, Some("surprise"), None).hibernation,
            Evidence::Unknown
        );
    }
}
