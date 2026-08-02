use std::net::TcpStream;

#[cfg(target_os = "linux")]
use std::fs;
#[cfg(target_os = "macos")]
use std::process::{Command, Stdio};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProcessIdentity {
    pub pid: u32,
    pub ppid: u32,
    pub started_at: String,
    pub executable: String,
    pub command: String,
}

pub fn inspect_process_tree(pid: u32, limit: usize) -> Result<Vec<ProcessIdentity>, String> {
    if pid == 0 {
        return Err("Invalid process ID".into());
    }
    let mut result = Vec::new();
    let mut visited = std::collections::HashSet::new();
    let mut current = pid;
    while current > 0 && result.len() < limit && visited.insert(current) {
        let Some(identity) = inspect_process(current)? else {
            break;
        };
        let parent = identity.ppid;
        result.push(identity);
        if parent == 0 || parent == current {
            break;
        }
        current = parent;
    }
    Ok(result)
}

pub fn same_process(left: &ProcessIdentity, right: &ProcessIdentity) -> bool {
    left.pid == right.pid
        && left.started_at == right.started_at
        && left.executable == right.executable
}

pub fn is_launchd_process(process: &ProcessIdentity) -> bool {
    let executable = process
        .executable
        .replace('\\', "/")
        .rsplit('/')
        .next()
        .unwrap_or_default()
        .to_ascii_lowercase();
    let invoked = process
        .command
        .trim()
        .replace('\\', "/")
        .split_whitespace()
        .next()
        .unwrap_or_default()
        .rsplit('/')
        .next()
        .unwrap_or_default()
        .to_ascii_lowercase();
    executable == "launchd" || invoked == "launchd"
}

pub fn process_is_alive(process: &ProcessIdentity) -> bool {
    inspect_process(process.pid)
        .ok()
        .flatten()
        .is_some_and(|current| same_process(&current, process))
}

pub fn omit_secretd_client_processes(tree: &[ProcessIdentity]) -> Vec<ProcessIdentity> {
    tree.iter()
        .skip_while(|process| is_secretd_client_process(process))
        .cloned()
        .collect()
}

pub fn is_secretd_client_process(process: &ProcessIdentity) -> bool {
    let command = process
        .command
        .trim()
        .replace('\\', "/")
        .to_ascii_lowercase();
    let executable = process
        .executable
        .replace('\\', "/")
        .rsplit('/')
        .next()
        .unwrap_or_default()
        .to_ascii_lowercase();
    let invoked = command
        .split_whitespace()
        .next()
        .unwrap_or_default()
        .rsplit('/')
        .next()
        .unwrap_or_default();
    if executable == "secretd" || invoked == "secretd" {
        return true;
    }
    executable == "deno"
        && (command.contains("deno task cli") || command.contains("src/cli/main.ts"))
}

pub fn verify_connection_owner(pid: u32, connection: &TcpStream) -> bool {
    let Ok(local) = connection.local_addr() else {
        return false;
    };
    let Ok(peer) = connection.peer_addr() else {
        return false;
    };
    verify_connection_tuple(pid, peer.port(), local.port())
}

#[cfg(target_os = "macos")]
fn inspect_process(pid: u32) -> Result<Option<ProcessIdentity>, String> {
    let Some(ppid) = ps(pid, "ppid=")? else {
        return Ok(None);
    };
    let Some(started_at) = ps(pid, "lstart=")? else {
        return Ok(None);
    };
    let Some(executable) = ps(pid, "comm=")? else {
        return Ok(None);
    };
    let Some(command) = ps(pid, "command=")? else {
        return Ok(None);
    };
    let Ok(ppid) = ppid.trim().parse::<u32>() else {
        return Ok(None);
    };
    Ok(Some(ProcessIdentity {
        pid,
        ppid,
        started_at: started_at.trim().into(),
        executable: executable.trim().into(),
        command: command.trim().into(),
    }))
}

#[cfg(target_os = "macos")]
fn ps(pid: u32, field: &str) -> Result<Option<String>, String> {
    let output = Command::new("/bin/ps")
        .args(["-p", &pid.to_string(), "-o", field])
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .map_err(|error| error.to_string())?;
    if !output.status.success() {
        return Ok(None);
    }
    Ok(Some(String::from_utf8_lossy(&output.stdout).into_owned()))
}

#[cfg(target_os = "macos")]
fn verify_connection_tuple(pid: u32, client_port: u16, server_port: u16) -> bool {
    let Ok(output) = Command::new("/usr/sbin/lsof")
        .args([
            "-nP",
            "-a",
            "-p",
            &pid.to_string(),
            "-iTCP",
            "-sTCP:ESTABLISHED",
            "-Fn",
        ])
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
    else {
        return false;
    };
    if !output.status.success() {
        return false;
    }
    let expected = format!("127.0.0.1:{client_port}->127.0.0.1:{server_port}");
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .any(|line| line.starts_with('n') && line.contains(&expected))
}

#[cfg(target_os = "linux")]
fn inspect_process(pid: u32) -> Result<Option<ProcessIdentity>, String> {
    let stat = match fs::read_to_string(format!("/proc/{pid}/stat")) {
        Ok(value) => value,
        Err(error)
            if matches!(
                error.kind(),
                std::io::ErrorKind::NotFound | std::io::ErrorKind::PermissionDenied
            ) =>
        {
            return Ok(None);
        }
        Err(error) => return Err(error.to_string()),
    };
    let Some(closing) = stat.rfind(')') else {
        return Ok(None);
    };
    let fields: Vec<_> = stat[closing + 1..].split_whitespace().collect();
    let (Some(ppid), Some(started_at)) = (fields.get(1), fields.get(19)) else {
        return Ok(None);
    };
    let Ok(ppid) = ppid.parse::<u32>() else {
        return Ok(None);
    };
    let executable = match fs::read_link(format!("/proc/{pid}/exe")) {
        Ok(path) => path.to_string_lossy().into_owned(),
        Err(_) => return Ok(None),
    };
    let command = fs::read(format!("/proc/{pid}/cmdline"))
        .map(|bytes| {
            String::from_utf8_lossy(&bytes)
                .replace('\0', " ")
                .trim()
                .to_string()
        })
        .unwrap_or_else(|_| executable.clone());
    Ok(Some(ProcessIdentity {
        pid,
        ppid,
        started_at: (*started_at).into(),
        executable,
        command,
    }))
}

#[cfg(target_os = "linux")]
fn verify_connection_tuple(pid: u32, client_port: u16, server_port: u16) -> bool {
    let Ok(table) = fs::read_to_string("/proc/net/tcp") else {
        return false;
    };
    let expected_local = format!("0100007F:{client_port:04X}");
    let expected_remote = format!("0100007F:{server_port:04X}");
    let inode = table.lines().skip(1).find_map(|line| {
        let fields: Vec<_> = line.split_whitespace().collect();
        (fields.len() >= 10
            && fields[1] == expected_local
            && fields[2] == expected_remote
            && fields[3] == "01")
            .then(|| fields[9].to_string())
    });
    let Some(inode) = inode else {
        return false;
    };
    let Ok(entries) = fs::read_dir(format!("/proc/{pid}/fd")) else {
        return false;
    };
    entries.flatten().any(|entry| {
        fs::read_link(entry.path())
            .is_ok_and(|target| target.to_string_lossy() == format!("socket:[{inode}]"))
    })
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn inspect_process(_pid: u32) -> Result<Option<ProcessIdentity>, String> {
    Ok(None)
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn verify_connection_tuple(_pid: u32, _client_port: u16, _server_port: u16) -> bool {
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    fn process(pid: u32, executable: &str, command: &str) -> ProcessIdentity {
        ProcessIdentity {
            pid,
            ppid: pid.saturating_sub(1),
            started_at: pid.to_string(),
            executable: executable.into(),
            command: command.into(),
        }
    }

    #[test]
    fn removes_compiled_and_development_clients() {
        let cli = process(30, "/usr/local/bin/secretd", "secretd get service/token");
        let deno = process(20, "/opt/bin/deno", "deno task cli get service/token");
        let shell = process(10, "/bin/zsh", "zsh");
        assert_eq!(
            omit_secretd_client_processes(&[cli, deno, shell.clone()]),
            [shell]
        );
    }

    #[test]
    fn checks_the_full_identity_of_a_live_process() {
        let current = inspect_process_tree(std::process::id(), 1)
            .unwrap()
            .into_iter()
            .next()
            .unwrap();
        assert!(process_is_alive(&current));

        let mut reused_pid = current;
        reused_pid.started_at.push_str("-different");
        assert!(!process_is_alive(&reused_pid));
    }

    #[test]
    fn identifies_launchd_by_pid_or_executable() {
        assert!(is_launchd_process(&process(
            1,
            "/sbin/launchd",
            "/sbin/launchd"
        )));
        assert!(is_launchd_process(&process(
            99,
            "/sbin/launchd",
            "/sbin/launchd"
        )));
        assert!(!is_launchd_process(&process(20, "/bin/zsh", "-zsh")));
        assert!(!is_launchd_process(&process(1, "/sbin/init", "/sbin/init")));
    }
}
