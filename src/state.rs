//! Settings and process-wide status, shared by the phone session, the
//! bonder and the control socket.

use std::collections::BTreeMap;
use std::io;
use std::sync::atomic::{AtomicU64, Ordering::Relaxed};
use std::sync::{Mutex, OnceLock, RwLock};

use serde::{Deserialize, Serialize};

const CONFIG_DIR: &str = "/Library/Application Support/rtether";
const CONFIG_PATH: &str = "/Library/Application Support/rtether/config.json";

/// How an app's connections are spread over USB and Wi-Fi.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Mode {
    /// Everything over USB, like any other app.
    #[default]
    Off,
    /// Each server sticks to one link; different servers use different links.
    /// Safe for logins, still faster for apps that talk to many servers.
    PerServer,
    /// Every new connection picks the less busy link. Fastest, but one site
    /// can see the Mac arrive from two different IP addresses.
    PerConnection,
}

#[derive(Default, Serialize, Deserialize)]
pub struct Config {
    /// App id (bundle path or executable path) -> mode. Absent means Off.
    #[serde(default)]
    pub apps: BTreeMap<String, Mode>,
}

impl Config {
    pub fn load() -> Config {
        std::fs::read(CONFIG_PATH)
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or_default()
    }

    pub fn save(&self) -> io::Result<()> {
        std::fs::create_dir_all(CONFIG_DIR)?;
        let tmp = format!("{CONFIG_PATH}.tmp");
        std::fs::write(&tmp, serde_json::to_vec_pretty(self)?)?;
        std::fs::rename(tmp, CONFIG_PATH)
    }

    pub fn mode(&self, app: &str) -> Mode {
        self.apps.get(app).copied().unwrap_or_default()
    }

}

#[derive(Clone, Serialize)]
pub struct PhoneInfo {
    pub ip: String,
    pub router: String,
    pub ifname: String,
}

#[derive(Clone, Default, Serialize)]
pub struct WifiInfo {
    pub ifname: String,
    #[serde(skip)]
    pub index: u32,
    pub up: bool,
}

pub struct Global {
    pub config: RwLock<Config>,
    pub phone: Mutex<Option<PhoneInfo>>,
    pub wifi: Mutex<WifiInfo>,
    pub usb_rx: AtomicU64,
    pub usb_tx: AtomicU64,
    pub wifi_rx: AtomicU64,
    pub wifi_tx: AtomicU64,
}

pub fn global() -> &'static Global {
    static G: OnceLock<Global> = OnceLock::new();
    G.get_or_init(|| Global {
        config: RwLock::new(Config::load()),
        phone: Mutex::new(None),
        wifi: Mutex::new(WifiInfo::default()),
        usb_rx: AtomicU64::new(0),
        usb_tx: AtomicU64::new(0),
        wifi_rx: AtomicU64::new(0),
        wifi_tx: AtomicU64::new(0),
    })
}

pub fn add(counter: &AtomicU64, n: usize) {
    counter.fetch_add(n as u64, Relaxed);
}

/// The Wi-Fi interface (from `networksetup`) and whether it has an IPv4
/// address right now. Polled; cheap enough to run every couple of seconds.
pub fn refresh_wifi() {
    let g = global();
    let mut ifname = g.wifi.lock().unwrap().ifname.clone();
    if ifname.is_empty() {
        ifname = wifi_device().unwrap_or_else(|| "en0".into());
    }
    let index = std::ffi::CString::new(ifname.as_str())
        .map(|c| unsafe { libc::if_nametoindex(c.as_ptr()) })
        .unwrap_or(0);
    let up = index != 0 && has_ipv4(&ifname);
    *g.wifi.lock().unwrap() = WifiInfo { ifname, index, up };
}

fn wifi_device() -> Option<String> {
    let out = std::process::Command::new("/usr/sbin/networksetup")
        .arg("-listallhardwareports")
        .output()
        .ok()?;
    let text = String::from_utf8_lossy(&out.stdout);
    let mut lines = text.lines();
    while let Some(l) = lines.next() {
        if l.trim() == "Hardware Port: Wi-Fi" {
            return lines.next()?.strip_prefix("Device: ").map(|d| d.trim().to_string());
        }
    }
    None
}

fn has_ipv4(ifname: &str) -> bool {
    let mut found = false;
    unsafe {
        let mut ifap: *mut libc::ifaddrs = std::ptr::null_mut();
        if libc::getifaddrs(&mut ifap) != 0 {
            return false;
        }
        let mut p = ifap;
        while !p.is_null() {
            let ifa = &*p;
            let running = (libc::IFF_UP | libc::IFF_RUNNING) as u32;
            if !ifa.ifa_addr.is_null()
                && (*ifa.ifa_addr).sa_family as i32 == libc::AF_INET
                && ifa.ifa_flags & running == running
                && std::ffi::CStr::from_ptr(ifa.ifa_name).to_bytes() == ifname.as_bytes()
            {
                found = true;
                break;
            }
            p = ifa.ifa_next;
        }
        libc::freeifaddrs(ifap);
    }
    found
}
