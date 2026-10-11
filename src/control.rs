//! Local control socket for the menu bar app: one JSON request per line, one
//! JSON reply per line. Only root and members of the `admin` group may
//! connect; the check uses the peer's credentials, not file permissions.

use std::io::{self, BufRead, BufReader, Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::bond::{self, AppStatus, Bonder};
use crate::log;
use crate::state::{self, global, Mode, PhoneInfo, WifiInfo};

pub const SOCKET: &str = "/var/run/rtether.sock";
const ADMIN_GID: libc::gid_t = 80;
const MAX_REQUEST: u64 = 64 * 1024;
const MAX_APP_ID: usize = 1024;
const MAX_CONFIGURED_APPS: usize = 256;

static CURRENT: Mutex<Option<Arc<Bonder>>> = Mutex::new(None);

/// The bonder of the live phone session, if any.
pub fn set_current(b: Option<Arc<Bonder>>) {
    *CURRENT.lock().unwrap() = b;
}

#[derive(Deserialize)]
#[serde(tag = "cmd", rename_all = "snake_case")]
enum Request {
    Status,
    SetMode { app: String, mode: Mode },
}

#[derive(Serialize)]
struct Status {
    phone: Option<PhoneInfo>,
    wifi: WifiInfo,
    usb_rx: u64,
    usb_tx: u64,
    wifi_rx: u64,
    wifi_tx: u64,
    apps: Vec<AppStatus>,
}

fn status() -> Status {
    use std::sync::atomic::Ordering::Relaxed;
    let g = global();
    let apps = match CURRENT.lock().unwrap().clone() {
        Some(b) => b.app_status(),
        None => {
            let cfg = g.config.read().unwrap();
            cfg.apps.iter().map(|(id, m)| bond::configured_only(id, *m)).collect()
        }
    };
    Status {
        phone: g.phone.lock().unwrap().clone(),
        wifi: g.wifi.lock().unwrap().clone(),
        usb_rx: g.usb_rx.load(Relaxed),
        usb_tx: g.usb_tx.load(Relaxed),
        wifi_rx: g.wifi_rx.load(Relaxed),
        wifi_tx: g.wifi_tx.load(Relaxed),
        apps,
    }
}

fn is_admin(uid: libc::uid_t) -> bool {
    if uid == 0 {
        return true;
    }
    unsafe {
        let pw = libc::getpwuid(uid);
        if pw.is_null() {
            return false;
        }
        let mut groups = [0 as libc::c_int; 64];
        let mut n = groups.len() as libc::c_int;
        libc::getgrouplist((*pw).pw_name, (*pw).pw_gid as libc::c_int, groups.as_mut_ptr(), &mut n);
        // On overflow n reports the size needed, not what was filled.
        let filled = (n.max(0) as usize).min(groups.len());
        groups[..filled].contains(&(ADMIN_GID as libc::c_int))
    }
}

fn peer_allowed(s: &UnixStream) -> bool {
    let (mut uid, mut gid) = (0, 0);
    let r = unsafe { libc::getpeereid(s.as_raw_fd(), &mut uid, &mut gid) };
    r == 0 && is_admin(uid)
}

fn error_reply(msg: &str) -> io::Result<String> {
    Ok(format!("{{\"error\":{}}}", serde_json::to_string(msg)?))
}

fn set_mode(app: String, mode: Mode) -> io::Result<String> {
    if app.is_empty() || app.len() > MAX_APP_ID || app.chars().any(char::is_control) {
        return error_reply("invalid app id");
    }
    // Change under the lock, write to disk after releasing it: the packet
    // path reads this config for every new connection.
    let snapshot = {
        let mut cfg = global().config.write().unwrap();
        if mode == Mode::Off {
            cfg.apps.remove(&app);
        } else {
            if !cfg.apps.contains_key(&app) && cfg.apps.len() >= MAX_CONFIGURED_APPS {
                return error_reply("too many configured apps");
            }
            cfg.apps.insert(app.clone(), mode);
        }
        state::Config { apps: cfg.apps.clone() }
    };
    match snapshot.save() {
        Ok(()) => {
            log!("bonding for {app}: {mode:?}");
            Ok(serde_json::to_string(&status())?)
        }
        Err(e) => error_reply(&e.to_string()),
    }
}

fn handle(mut s: UnixStream) -> io::Result<()> {
    // Bounded in time and size: a stuck or hostile client must not wedge
    // the (single) control thread or grow root's memory.
    s.set_read_timeout(Some(Duration::from_secs(2)))?;
    s.set_write_timeout(Some(Duration::from_secs(2)))?;
    if !peer_allowed(&s) {
        return s.write_all(b"{\"error\":\"not allowed\"}\n");
    }
    let mut line = String::new();
    BufReader::new((&s).take(MAX_REQUEST)).read_line(&mut line)?;
    let reply = match serde_json::from_str::<Request>(&line) {
        Ok(Request::Status) => serde_json::to_string(&status())?,
        Ok(Request::SetMode { app, mode }) => set_mode(app, mode)?,
        Err(e) => error_reply(&e.to_string())?,
    };
    s.write_all(reply.as_bytes())?;
    s.write_all(b"\n")
}

pub fn serve() -> io::Result<()> {
    let _ = std::fs::remove_file(SOCKET);
    let listener = UnixListener::bind(SOCKET)?;
    // Anyone may connect; handle() decides who gets an answer.
    std::fs::set_permissions(SOCKET, std::fs::Permissions::from_mode(0o666))?;
    std::thread::Builder::new().name("rtether-control".into()).spawn(move || {
        for s in listener.incoming().flatten() {
            let _ = handle(s);
        }
    })?;
    Ok(())
}
