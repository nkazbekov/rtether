//! Which app owns a socket.
//!
//! The kernel's PCB lists (`net.inet.{tcp,udp}.pcblist_n`) are sequences of
//! self-describing records: each sub-structure starts with its length and a
//! kind, padded to 8 bytes. Walking by length rather than fixed record sizes
//! keeps this working when Apple grows a structure (they did in Darwin 22).
//! Offsets inside the structures were verified on macOS 26 (Darwin 25).

use std::collections::HashMap;
use std::ffi::CString;
use std::net::Ipv4Addr;
use std::path::Path;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

const XSO_SOCKET: u32 = 0x001;
const XSO_INPCB: u32 = 0x010;

// xinpcb_n
const INP_LPORT: usize = 18; // big-endian
const INP_VFLAG: usize = 44; // 0x1 = IPv4
const INP_LADDR4: usize = 76;
// xsocket_n
const SO_LAST_PID: usize = 68;
const SO_E_PID: usize = 72; // the app a daemon acts for (delegated sockets)

#[derive(Clone)]
pub struct Owner {
    /// Stable identity: the app bundle path, or the executable path.
    pub id: Arc<str>,
    pub name: Arc<str>,
}

fn sysctl(name: &str) -> Option<Vec<u8>> {
    let c = CString::new(name).ok()?;
    let mut len = 0usize;
    unsafe {
        if libc::sysctlbyname(c.as_ptr(), std::ptr::null_mut(), &mut len, std::ptr::null_mut(), 0) != 0 {
            return None;
        }
        let mut buf = vec![0u8; len + 64 * 1024]; // the list can grow between the two calls
        len = buf.len();
        if libc::sysctlbyname(c.as_ptr(), buf.as_mut_ptr().cast(), &mut len, std::ptr::null_mut(), 0) != 0 {
            return None;
        }
        buf.truncate(len);
        Some(buf)
    }
}

fn u32_at(b: &[u8], off: usize) -> u32 {
    u32::from_le_bytes(b[off..off + 4].try_into().unwrap())
}

fn pid_path(pid: i32) -> Option<String> {
    let mut buf = vec![0u8; 4096];
    let n = unsafe { libc::proc_pidpath(pid, buf.as_mut_ptr().cast(), buf.len() as u32) };
    if n <= 0 {
        return None;
    }
    buf.truncate(n as usize);
    String::from_utf8(buf).ok()
}

/// Map an executable to the app a user would recognise: the outermost
/// `.app` bundle (so Chrome's helper processes count as Chrome).
fn owner_from_path(path: &str) -> Owner {
    if path.contains("com.apple.WebKit.Networking") {
        return Owner { id: "com.apple.WebKit.Networking".into(), name: "Safari & WebKit apps".into() };
    }
    if let Some(i) = path.find(".app/") {
        let bundle = &path[..i + 4];
        let name = Path::new(bundle).file_stem().and_then(|s| s.to_str()).unwrap_or(bundle);
        return Owner { id: bundle.into(), name: name.into() };
    }
    let name = Path::new(path).file_name().and_then(|s| s.to_str()).unwrap_or(path);
    Owner { id: path.into(), name: name.into() }
}

fn owner_of_pid(pid: i32) -> Option<Owner> {
    static CACHE: OnceLock<Mutex<HashMap<i32, (Owner, Instant)>>> = OnceLock::new();
    let cache = CACHE.get_or_init(Default::default);
    // PIDs get reused, so cache only briefly.
    if let Some((o, t)) = cache.lock().unwrap().get(&pid) {
        if t.elapsed() < Duration::from_secs(10) {
            return Some(o.clone());
        }
    }
    let owner = owner_from_path(&pid_path(pid)?);
    let mut c = cache.lock().unwrap();
    if c.len() > 4096 {
        c.clear();
    }
    c.insert(pid, (owner.clone(), Instant::now()));
    Some(owner)
}

/// Snapshot of one PCB list: (local address, local port) -> pid.
struct Snapshot {
    taken: Instant,
    owners: HashMap<(Ipv4Addr, u16), i32>,
}

fn snapshot(buf: &[u8]) -> HashMap<(Ipv4Addr, u16), i32> {
    let mut owners = HashMap::new();
    if buf.len() < 4 {
        return owners;
    }
    let mut off = u32_at(buf, 0) as usize;
    let mut current: Option<(Ipv4Addr, u16)> = None;
    while off + 8 <= buf.len() {
        let (len, kind) = (u32_at(buf, off) as usize, u32_at(buf, off + 4));
        if len == 0 || off + len > buf.len() {
            break;
        }
        match kind {
            XSO_INPCB if len >= INP_LADDR4 + 4 => {
                let port = u16::from_be_bytes([buf[off + INP_LPORT], buf[off + INP_LPORT + 1]]);
                let a = &buf[off + INP_LADDR4..off + INP_LADDR4 + 4];
                current = (buf[off + INP_VFLAG] & 0x1 != 0).then(|| (Ipv4Addr::new(a[0], a[1], a[2], a[3]), port));
            }
            XSO_SOCKET if len >= SO_E_PID + 4 => {
                if let Some(k) = current.take() {
                    let e = u32_at(buf, off + SO_E_PID) as i32;
                    owners.entry(k).or_insert(if e > 0 { e } else { u32_at(buf, off + SO_LAST_PID) as i32 });
                }
            }
            _ => {}
        }
        off += (len + 7) & !7;
    }
    owners
}

/// The app that owns the local socket `laddr:lport` for TCP (6) or UDP (17).
///
/// `seen` is when the packet that revealed the socket was read; the socket
/// existed by then. Called for every new flow on the packet path, so it
/// reads the kernel's socket table only when it must:
/// - a snapshot taken after `seen` is authoritative, hit or miss (a burst of
///   new connections is answered by one read);
/// - an older snapshot's hit is trusted for 1 s (a port reused by another
///   app within that second is the accepted risk);
/// - anything else re-reads.
pub fn find(proto: u8, laddr: Ipv4Addr, lport: u16, seen: Instant) -> Option<Owner> {
    static SNAPS: OnceLock<Mutex<[Option<Snapshot>; 2]>> = OnceLock::new();
    let (slot, list) = match proto {
        6 => (0, "net.inet.tcp.pcblist_n"),
        17 => (1, "net.inet.udp.pcblist_n"),
        _ => return None,
    };
    let lookup = |m: &HashMap<(Ipv4Addr, u16), i32>| {
        m.get(&(laddr, lport)).or_else(|| m.get(&(Ipv4Addr::UNSPECIFIED, lport))).copied()
    };
    let snaps = SNAPS.get_or_init(Default::default);
    let mut s = snaps.lock().unwrap();
    let cached = match &s[slot] {
        Some(snap) if snap.taken >= seen => Some(lookup(&snap.owners)),
        Some(snap) if snap.taken.elapsed() < Duration::from_secs(1) => lookup(&snap.owners).map(Some),
        _ => None,
    };
    let pid = match cached {
        Some(answer) => answer,
        None => {
            let owners = snapshot(&sysctl(list)?);
            let pid = lookup(&owners);
            s[slot] = Some(Snapshot { taken: Instant::now(), owners });
            pid
        }
    }?;
    drop(s);
    owner_of_pid(pid)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{TcpListener, TcpStream, UdpSocket};

    #[test]
    fn finds_own_tcp_socket() {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let c = TcpStream::connect(l.local_addr().unwrap()).unwrap();
        let port = c.local_addr().unwrap().port();
        let o = find(6, Ipv4Addr::LOCALHOST, port, Instant::now()).expect("owner of our TCP socket");
        let me = std::env::current_exe().unwrap();
        assert_eq!(&*o.id, me.to_str().unwrap());
    }

    #[test]
    fn finds_own_wildcard_udp_socket() {
        let u = UdpSocket::bind("0.0.0.0:0").unwrap();
        let port = u.local_addr().unwrap().port();
        let o = find(17, Ipv4Addr::new(10, 9, 8, 7), port, Instant::now()).expect("owner of our UDP socket");
        assert!(o.name.starts_with("rtether"), "{}", o.name);
    }

    #[test]
    fn helper_processes_count_as_their_app() {
        let o = owner_from_path(
            "/Applications/Google Chrome.app/Contents/Frameworks/Google Chrome Framework.framework/Helpers/Google Chrome Helper.app/Contents/MacOS/Google Chrome Helper",
        );
        assert_eq!(&*o.id, "/Applications/Google Chrome.app");
        assert_eq!(&*o.name, "Google Chrome");
    }
}
