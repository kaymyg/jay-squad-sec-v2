//! Real userspace sensors: Linux (/proc) and Windows (tasklist/netstat/reg/
//! PowerShell). Polling-based, no admin rights, no kernel components.
//!
//! Both implementations compile on every platform (they only shell out or
//! read files), and the right one is chosen at runtime — this lets the
//! Windows parsing logic be unit-tested from any OS.
//!
//! Honest coverage note: userspace polling sees process starts/exits,
//! network peers, signature status, suspicious paths, deleted binaries and
//! autorun changes. It cannot see RWX allocations, thread injection or
//! credential reads — those need the kernel adapters (eBPF/ETW), a later phase.

use std::collections::HashMap;
use std::process::Command;

#[derive(Clone, Debug)]
pub struct ProcInfo {
    pub pid: u32,
    pub name: String,
    /// Executable path if known, else empty.
    pub exe: String,
}

pub trait Sensor {
    /// Current process list (pid + name; exe filled where cheap).
    fn processes(&mut self) -> Vec<ProcInfo>;
    /// Executable paths for specific pids (used only for NEW processes).
    fn exe_paths(&mut self, pids: &[u32]) -> HashMap<u32, String>;
    /// Established non-loopback TCP peers for the given pids: (pid, remote).
    fn connections(&mut self, pids: &[u32]) -> Vec<(u32, String)>;
    /// Current autorun/persistence entries (names only, for diffing).
    fn autoruns(&mut self) -> Vec<String>;
    /// Signature status for paths: true = UNSIGNED/invalid. Empty on Linux.
    fn check_unsigned(&mut self, paths: &[String]) -> Vec<(String, bool)>;
}

pub fn platform_sensor() -> Box<dyn Sensor> {
    if cfg!(windows) {
        Box::new(WindowsSensor)
    } else {
        Box::new(LinuxSensor)
    }
}

/// Path-based suspicion, shared across platforms.
/// Returns a reason string if the executable location is a classic
/// malware staging area.
pub fn suspicious_path(path: &str) -> Option<&'static str> {
    let p = path.to_ascii_lowercase().replace('\\', "/");
    const NEEDLES: [(&str, &str); 6] = [
        ("/tmp/", "running from /tmp"),
        ("/dev/shm/", "running from shared memory"),
        ("/var/tmp/", "running from /var/tmp"),
        ("/appdata/local/temp/", "running from %TEMP%"),
        ("/windows/temp/", "running from Windows temp"),
        ("/downloads/", "running from Downloads"),
    ];
    for (needle, reason) in NEEDLES {
        if p.contains(needle) {
            return Some(reason);
        }
    }
    None
}

// ---------------------------------------------------------------- Linux ---

pub struct LinuxSensor;

impl Sensor for LinuxSensor {
    fn processes(&mut self) -> Vec<ProcInfo> {
        let mut out = Vec::new();
        let Ok(dir) = std::fs::read_dir("/proc") else { return out };
        for entry in dir.flatten() {
            let fname = entry.file_name();
            let Some(pid) = fname.to_str().and_then(|s| s.parse::<u32>().ok()) else {
                continue;
            };
            let name = std::fs::read_to_string(format!("/proc/{pid}/comm"))
                .map(|s| s.trim().to_string())
                .unwrap_or_default();
            if name.is_empty() {
                continue; // vanished mid-scan
            }
            let exe = std::fs::read_link(format!("/proc/{pid}/exe"))
                .map(|p| p.to_string_lossy().into_owned())
                .unwrap_or_default();
            out.push(ProcInfo { pid, name, exe });
        }
        out
    }

    fn exe_paths(&mut self, pids: &[u32]) -> HashMap<u32, String> {
        pids.iter()
            .filter_map(|&pid| {
                std::fs::read_link(format!("/proc/{pid}/exe"))
                    .ok()
                    .map(|p| (pid, p.to_string_lossy().into_owned()))
            })
            .collect()
    }

    fn connections(&mut self, pids: &[u32]) -> Vec<(u32, String)> {
        // inode -> remote addr, from /proc/net/tcp{,6}
        let mut inode_remote: HashMap<u64, String> = HashMap::new();
        for table in ["/proc/net/tcp", "/proc/net/tcp6"] {
            if let Ok(text) = std::fs::read_to_string(table) {
                for (inode, remote) in parse_proc_net_tcp(&text) {
                    inode_remote.insert(inode, remote);
                }
            }
        }
        // pid -> socket inodes, via /proc/<pid>/fd (only for pids of interest)
        let mut out = Vec::new();
        for &pid in pids {
            let Ok(fds) = std::fs::read_dir(format!("/proc/{pid}/fd")) else { continue };
            for fd in fds.flatten() {
                if let Ok(target) = std::fs::read_link(fd.path()) {
                    let t = target.to_string_lossy();
                    if let Some(inode) = t
                        .strip_prefix("socket:[")
                        .and_then(|s| s.strip_suffix(']'))
                        .and_then(|s| s.parse::<u64>().ok())
                    {
                        if let Some(remote) = inode_remote.get(&inode) {
                            out.push((pid, remote.clone()));
                        }
                    }
                }
            }
        }
        out
    }

    fn autoruns(&mut self) -> Vec<String> {
        let mut out = Vec::new();
        let home = std::env::var("HOME").unwrap_or_default();
        for dir in [
            format!("{home}/.config/autostart"),
            "/etc/cron.d".to_string(),
            "/etc/systemd/system".to_string(),
        ] {
            if let Ok(rd) = std::fs::read_dir(&dir) {
                for e in rd.flatten() {
                    out.push(format!("{}/{}", dir, e.file_name().to_string_lossy()));
                }
            }
        }
        out.sort();
        out
    }

    fn check_unsigned(&mut self, _paths: &[String]) -> Vec<(String, bool)> {
        Vec::new() // no Authenticode equivalent in scope for v0.1
    }
}

/// Parse /proc/net/tcp format. Returns (inode, "ip:port") for ESTABLISHED
/// rows with non-loopback remotes.
pub fn parse_proc_net_tcp(text: &str) -> Vec<(u64, String)> {
    let mut out = Vec::new();
    for line in text.lines().skip(1) {
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() < 10 || f[3] != "01" {
            continue; // not ESTABLISHED
        }
        let Some((rip, rport)) = f[2].split_once(':') else { continue };
        let Ok(port) = u16::from_str_radix(rport, 16) else { continue };
        let Ok(inode) = f[9].parse::<u64>() else { continue };
        let remote = if rip.len() == 8 {
            // IPv4, hex little-endian
            let Ok(v) = u32::from_str_radix(rip, 16) else { continue };
            let b = v.to_le_bytes();
            if b[0] == 127 {
                continue; // loopback
            }
            format!("{}.{}.{}.{}:{}", b[0], b[1], b[2], b[3], port)
        } else {
            // IPv6: skip loopback (::1), keep the rest opaque
            if rip.ends_with("01000000") && rip.starts_with("0000000000000000") {
                continue;
            }
            format!("[v6]:{port}")
        };
        out.push((inode, remote));
    }
    out
}

// -------------------------------------------------------------- Windows ---

pub struct WindowsSensor;

impl Sensor for WindowsSensor {
    fn processes(&mut self) -> Vec<ProcInfo> {
        let Ok(o) = Command::new("tasklist").args(["/fo", "csv", "/nh"]).output() else {
            return Vec::new();
        };
        parse_tasklist_csv(&String::from_utf8_lossy(&o.stdout))
    }

    fn exe_paths(&mut self, pids: &[u32]) -> HashMap<u32, String> {
        if pids.is_empty() {
            return HashMap::new();
        }
        let list = pids.iter().map(|p| p.to_string()).collect::<Vec<_>>().join(",");
        let script = format!(
            "Get-Process -Id {list} -ErrorAction SilentlyContinue | ForEach-Object {{ \"$($_.Id)|$($_.Path)\" }}"
        );
        let Ok(o) = powershell(&script) else { return HashMap::new() };
        String::from_utf8_lossy(&o.stdout)
            .lines()
            .filter_map(|l| {
                let (pid, path) = l.split_once('|')?;
                let pid = pid.trim().parse::<u32>().ok()?;
                let path = path.trim();
                (!path.is_empty()).then(|| (pid, path.to_string()))
            })
            .collect()
    }

    fn connections(&mut self, pids: &[u32]) -> Vec<(u32, String)> {
        let Ok(o) = Command::new("netstat").args(["-ano", "-p", "TCP"]).output() else {
            return Vec::new();
        };
        parse_netstat(&String::from_utf8_lossy(&o.stdout))
            .into_iter()
            .filter(|(pid, _)| pids.contains(pid))
            .collect()
    }

    fn autoruns(&mut self) -> Vec<String> {
        let mut out = Vec::new();
        for hive in [
            r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
            r"HKLM\Software\Microsoft\Windows\CurrentVersion\Run",
        ] {
            if let Ok(o) = Command::new("reg").args(["query", hive]).output() {
                for name in parse_reg_query(&String::from_utf8_lossy(&o.stdout)) {
                    out.push(format!("{hive}\\{name}"));
                }
            }
        }
        out.sort();
        out
    }

    fn check_unsigned(&mut self, paths: &[String]) -> Vec<(String, bool)> {
        if paths.is_empty() {
            return Vec::new();
        }
        let quoted: Vec<String> = paths
            .iter()
            .map(|p| format!("'{}'", p.replace('\'', "''")))
            .collect();
        let script = format!(
            "foreach($p in @({})){{ $s = Get-AuthenticodeSignature -LiteralPath $p -ErrorAction SilentlyContinue; Write-Output \"$p|$($s.Status)\" }}",
            quoted.join(",")
        );
        let Ok(o) = powershell(&script) else { return Vec::new() };
        String::from_utf8_lossy(&o.stdout)
            .lines()
            .filter_map(|l| {
                let (path, status) = l.rsplit_once('|')?;
                Some((path.trim().to_string(), status.trim() != "Valid"))
            })
            .collect()
    }
}

fn powershell(script: &str) -> std::io::Result<std::process::Output> {
    Command::new("powershell")
        .args(["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script])
        .output()
}

/// Parse `tasklist /fo csv /nh` output: "name","pid","session","#","mem".
pub fn parse_tasklist_csv(text: &str) -> Vec<ProcInfo> {
    let mut out = Vec::new();
    for line in text.lines() {
        let fields: Vec<String> = line
            .split("\",\"")
            .map(|f| f.trim_matches(|c| c == '"' || c == '\r').to_string())
            .collect();
        if fields.len() < 2 {
            continue;
        }
        if let Ok(pid) = fields[1].parse::<u32>() {
            out.push(ProcInfo { pid, name: fields[0].clone(), exe: String::new() });
        }
    }
    out
}

/// Parse `netstat -ano -p TCP`: keep ESTABLISHED, non-loopback remotes.
pub fn parse_netstat(text: &str) -> Vec<(u32, String)> {
    let mut out = Vec::new();
    for line in text.lines() {
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() < 5 || f[0] != "TCP" || f[3] != "ESTABLISHED" {
            continue;
        }
        let remote = f[2];
        if remote.starts_with("127.") || remote.starts_with("[::1]") {
            continue;
        }
        if let Ok(pid) = f[4].parse::<u32>() {
            out.push((pid, remote.to_string()));
        }
    }
    out
}

/// Parse `reg query ...\Run` output: value names of REG_SZ/REG_EXPAND_SZ rows.
pub fn parse_reg_query(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    for line in text.lines() {
        let t = line.trim();
        if let Some(idx) = t.find("REG_") {
            let name = t[..idx].trim();
            if !name.is_empty() {
                out.push(name.to_string());
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tasklist_csv_parses() {
        let text = "\"chrome.exe\",\"1234\",\"Console\",\"1\",\"180,000 K\"\r\n\"weird,name.exe\",\"77\",\"Console\",\"1\",\"5,000 K\"\r\n";
        let p = parse_tasklist_csv(text);
        assert_eq!(p.len(), 2);
        assert_eq!(p[0].pid, 1234);
        assert_eq!(p[1].name, "weird,name.exe");
    }

    #[test]
    fn netstat_keeps_established_non_loopback() {
        let text = "\n  Proto  Local Address          Foreign Address        State           PID\n  TCP    10.0.0.5:52034         140.82.113.4:443       ESTABLISHED     1234\n  TCP    127.0.0.1:8080         127.0.0.1:52035        ESTABLISHED     99\n  TCP    10.0.0.5:52036         1.2.3.4:80             TIME_WAIT       55\n";
        let c = parse_netstat(text);
        assert_eq!(c, vec![(1234, "140.82.113.4:443".to_string())]);
    }

    #[test]
    fn reg_query_extracts_value_names() {
        let text = "\r\nHKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\r\n    OneDrive    REG_SZ    \"C:\\Users\\x\\OneDrive.exe\" /background\r\n    Evil Updater    REG_EXPAND_SZ    %TEMP%\\evil.exe\r\n";
        let names = parse_reg_query(text);
        assert_eq!(names, vec!["OneDrive".to_string(), "Evil Updater".to_string()]);
    }

    #[test]
    fn proc_net_tcp_parses_established_ipv4() {
        // remote 8.8.8.8:443 established, inode 12345; loopback row skipped
        let text = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n\
   0: 0100007F:1F90 08080808:01BB 01 00000000:00000000 00:00000000 00000000  1000        0 12345 1 0000000000000000 20 4 30 10 -1\n\
   1: 0100007F:1F90 0100007F:CCCC 01 00000000:00000000 00:00000000 00000000  1000        0 999 1 0000000000000000 20 4 30 10 -1\n";
        let rows = parse_proc_net_tcp(text);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0], (12345, "8.8.8.8:443".to_string()));
    }

    #[test]
    fn suspicious_paths_flagged_cross_platform() {
        assert!(suspicious_path("/tmp/x/payload").is_some());
        assert!(suspicious_path(r"C:\Users\p\AppData\Local\Temp\a.exe").is_some());
        assert!(suspicious_path(r"C:\Users\p\Downloads\setup.exe").is_some());
        assert!(suspicious_path("/usr/bin/firefox").is_none());
        assert!(suspicious_path(r"C:\Program Files\App\app.exe").is_none());
    }
}
