//! Per-app link bonding: spread selected apps' connections over USB and Wi-Fi.
//!
//! Every packet the Mac sends still arrives on the tether's utun. For each new
//! flow (TCP SYN or first UDP datagram) we find the owning app; if that app is
//! bonded and Wi-Fi is up, the flow may be assigned to Wi-Fi. USB flows go to
//! the phone untouched. Wi-Fi flows are diverted into a userspace TCP/IP stack
//! (ipstack) that terminates them and re-originates them from a socket bound
//! to the Wi-Fi interface, writing the replies back into the utun. Apps that
//! are not bonded never touch any of this.

use std::collections::HashMap;
use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering::Relaxed};
use std::sync::{Arc, Mutex, Weak};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use serde::Serialize;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::sync::mpsc::{self, Receiver, Sender};

use crate::procinfo;
use crate::state::{self, global, Mode};
use crate::utun::Utun;
use crate::log;

const TCP: u8 = 6;
const UDP: u8 = 17;
/// Forget idle USB flows after this; they need no state to keep working.
const IDLE_PHONE_FLOW: Duration = Duration::from_secs(120);
/// How long a server stays on the link it was given (PerServer mode).
const STICKY_FOR: Duration = Duration::from_secs(600);
/// Apps that have gone quiet stay listed in the UI for this long.
const APP_LISTED_FOR: Duration = Duration::from_secs(1800);
/// A Wi-Fi flow the stack never picked up (no relay) is dropped after this.
const UNRELAYED_IDLE: Duration = Duration::from_secs(60);
/// Bounds on state that local processes can grow by opening flows.
const MAX_FLOWS: usize = 65_536;
const MAX_STICKY: usize = 65_536;
/// Packets waiting for the Wi-Fi stack; beyond this they are dropped (TCP
/// retransmits) rather than queued in root's memory.
const DIVERT_QUEUE: usize = 4096;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Link {
    Usb,
    Wifi,
}

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
struct FlowKey {
    proto: u8,
    local_port: u16,
    remote: Ipv4Addr,
    remote_port: u16,
}

struct Flow {
    app: Option<Arc<str>>,
    link: Link,
    bonded: bool,
    last: Instant,
    /// TCP FIN seen from the Mac / from the server (USB flows only; the
    /// Wi-Fi relay knows when its own connections end).
    fin_out: bool,
    fin_in: bool,
    /// Distinguishes this flow from a later one reusing the same 4-tuple, so
    /// a relay ending late cannot remove its successor.
    generation: u64,
    /// A Wi-Fi relay owns this flow and will remove it when it ends.
    relayed: bool,
}

#[derive(Default)]
struct AppStats {
    name: Arc<str>,
    usb_bytes: u64,
    wifi_bytes: u64,
    flows: u32,
    last_seen: Option<Instant>,
}

#[derive(Serialize)]
pub struct AppStatus {
    pub id: String,
    pub name: String,
    pub mode: Mode,
    pub flows: u32,
    pub usb_bytes: u64,
    pub wifi_bytes: u64,
    pub idle_secs: u64,
}

struct Tables {
    flows: HashMap<FlowKey, Flow>,
    sticky: HashMap<(Arc<str>, Ipv4Addr), (Link, Instant)>,
    apps: HashMap<Arc<str>, AppStats>,
    /// Live bonded flows per link, for least-busy assignment.
    bonded_usb: u32,
    bonded_wifi: u32,
    next_generation: u64,
}

pub struct Bonder {
    local_ip: Ipv4Addr,
    /// Wi-Fi interface and router of a scoped default route *we* added (none
    /// if macOS already had one, which we then leave alone).
    wifi_route: Mutex<Option<(String, String)>>,
    /// Wi-Fi can take new flows: it has a router, a scoped route, and the
    /// userspace stack is alive.
    wifi_ok: AtomicBool,
    stack_alive: AtomicBool,
    tables: Mutex<Tables>,
    divert_tx: Sender<Vec<u8>>,
    runtime: Option<tokio::runtime::Runtime>,
    toggle: AtomicU64,
}

/// Parsed IPv4 header fields the bonder cares about.
struct Pkt {
    proto: u8,
    src: Ipv4Addr,
    dst: Ipv4Addr,
    sport: u16,
    dport: u16,
    syn_only: bool,
    fin: bool,
    rst: bool,
}

fn parse(ip: &[u8]) -> Option<Pkt> {
    if ip.len() < 20 || ip[0] >> 4 != 4 {
        return None;
    }
    let ihl = (ip[0] & 0x0f) as usize * 4;
    let frag_offset = u16::from_be_bytes([ip[6], ip[7]]) & 0x1fff;
    let proto = ip[9];
    if frag_offset != 0 || (proto != TCP && proto != UDP) || ip.len() < ihl + 8 {
        return None;
    }
    let t = &ip[ihl..];
    let flags = if proto == TCP && t.len() >= 14 { t[13] } else { 0 };
    Some(Pkt {
        proto,
        src: Ipv4Addr::new(ip[12], ip[13], ip[14], ip[15]),
        dst: Ipv4Addr::new(ip[16], ip[17], ip[18], ip[19]),
        sport: u16::from_be_bytes([t[0], t[1]]),
        dport: u16::from_be_bytes([t[2], t[3]]),
        syn_only: flags & 0x12 == 0x02,
        fin: flags & 0x01 != 0,
        rst: flags & 0x04 != 0,
    })
}

impl Bonder {
    pub fn start(tun: Arc<Utun>, local_ip: Ipv4Addr) -> io::Result<Arc<Bonder>> {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .thread_name("rtether-bond")
            .enable_all()
            .build()?;
        let (divert_tx, divert_rx) = mpsc::channel(DIVERT_QUEUE);
        // Everything inside the runtime holds only Weak references, so
        // dropping the session's Arc really drops the Bonder: its runtime and
        // relays stop and its Wi-Fi route goes, before a new session starts.
        Ok(Arc::new_cyclic(|weak| {
            let device = DivertDevice { rx: divert_rx, tun, bonder: weak.clone() };
            runtime.spawn(accept_loop(device, weak.clone()));
            Bonder {
                local_ip,
                wifi_route: Mutex::new(None),
                wifi_ok: AtomicBool::new(false),
                stack_alive: AtomicBool::new(true),
                tables: Mutex::new(Tables {
                    flows: HashMap::new(),
                    sticky: HashMap::new(),
                    apps: HashMap::new(),
                    bonded_usb: 0,
                    bonded_wifi: 0,
                    next_generation: 0,
                }),
                divert_tx,
                runtime: Some(runtime),
                toggle: AtomicU64::new(0),
            }
        }))
    }

    /// Decide where an outgoing packet goes; counts it towards its app.
    /// `seen` is when the packet was read, which bounds when its socket
    /// was created (for the app lookup).
    pub fn route_outgoing(&self, ip: &[u8], seen: Instant) -> Link {
        let Some(p) = parse(ip) else { return Link::Usb };
        let key = FlowKey { proto: p.proto, local_port: p.sport, remote: p.dst, remote_port: p.dport };
        let now = Instant::now();
        {
            let mut t = self.tables.lock().unwrap();
            if let Some(f) = t.flows.get_mut(&key) {
                f.last = now;
                f.fin_out |= p.fin;
                let (link, app, done) = (f.link, f.app.clone(), p.rst || (f.fin_out && f.fin_in));
                t.count(app.as_deref(), link, ip.len(), now);
                if done && link == Link::Usb {
                    t.remove(&key);
                }
                return link;
            }
        }
        if p.proto == TCP && !p.syn_only {
            return Link::Usb; // a flow from before we started: leave it alone
        }

        // New flow: find the app (a sysctl, so outside the lock).
        let owner = procinfo::find(p.proto, self.local_ip, p.sport, seen);
        let mode = owner.as_ref().map(|o| global().config.read().unwrap().mode(&o.id)).unwrap_or_default();

        let mut t = self.tables.lock().unwrap();
        if t.flows.len() >= MAX_FLOWS {
            return Link::Usb; // full: pass through untracked rather than grow
        }
        // Only traffic to the internet is split; the phone itself (DNS!) and
        // private networks always stay on the tether.
        let bonded = mode != Mode::Off && self.wifi_ok.load(Relaxed) && is_internet(p.dst);
        let link = if !bonded {
            Link::Usb
        } else {
            match mode {
                Mode::PerServer => {
                    let id = owner.as_ref().unwrap().id.clone();
                    match t.sticky.get_mut(&(id.clone(), p.dst)) {
                        // Refresh on use, so a busy server never switches links.
                        Some((l, at)) if at.elapsed() < STICKY_FOR => {
                            *at = now;
                            *l
                        }
                        _ => {
                            let l = self.pick(&t);
                            if t.sticky.len() < MAX_STICKY {
                                t.sticky.insert((id, p.dst), (l, now));
                            }
                            l
                        }
                    }
                }
                _ => self.pick(&t),
            }
        };
        if bonded {
            match link {
                Link::Usb => t.bonded_usb += 1,
                Link::Wifi => t.bonded_wifi += 1,
            }
        }
        let app = owner.as_ref().map(|o| o.id.clone());
        if let Some(o) = &owner {
            let s = t.apps.entry(o.id.clone()).or_default();
            s.name = o.name.clone();
            s.flows += 1;
        }
        if bonded && debug() {
            log!("bond: {} -> {}:{} ({:?}) on {link:?}", owner.as_ref().unwrap().name, p.dst, p.dport, mode);
        }
        let generation = t.next_generation;
        t.next_generation += 1;
        t.flows.insert(
            key,
            Flow { app: app.clone(), link, bonded, last: now, fin_out: p.fin, fin_in: false, generation, relayed: false },
        );
        t.count(app.as_deref(), link, ip.len(), now);
        link
    }

    /// The less busy link for a bonded flow; alternates on a tie.
    fn pick(&self, t: &Tables) -> Link {
        use std::cmp::Ordering::*;
        match t.bonded_usb.cmp(&t.bonded_wifi) {
            Less => Link::Usb,
            Greater => Link::Wifi,
            Equal if self.toggle.fetch_add(1, Relaxed) % 2 == 0 => Link::Usb,
            Equal => Link::Wifi,
        }
    }

    /// Count an incoming packet (from the phone or from the Wi-Fi stack).
    pub fn account_incoming(&self, ip: &[u8]) {
        let Some(p) = parse(ip) else { return };
        if p.dst != self.local_ip {
            return;
        }
        let key = FlowKey { proto: p.proto, local_port: p.dport, remote: p.src, remote_port: p.sport };
        let now = Instant::now();
        let mut t = self.tables.lock().unwrap();
        if let Some(f) = t.flows.get_mut(&key) {
            f.last = now;
            f.fin_in |= p.fin;
            let (link, app, done) = (f.link, f.app.clone(), p.rst || (f.fin_out && f.fin_in));
            t.count(app.as_deref(), link, ip.len(), now);
            if done && link == Link::Usb {
                t.remove(&key);
            }
        }
    }

    /// Hand an outgoing packet of a Wi-Fi flow to the userspace stack.
    /// Dropped if the stack is backed up; TCP will retransmit it.
    pub fn divert(&self, ip: Vec<u8>) {
        let _ = self.divert_tx.try_send(ip);
    }

    /// Make sure sockets pinned to Wi-Fi (IP_BOUND_IF) have a way out: a
    /// default route scoped to the Wi-Fi interface. macOS does not add one
    /// while the tether is the primary route, so we add our own if none
    /// exists, remember that we did, and only ever delete our own.
    fn ensure_wifi_route(&self) {
        let w = global().wifi.lock().unwrap().clone();
        let router = w.up.then(|| wifi_router(&w.ifname)).flatten();
        let mut ours = self.wifi_route.lock().unwrap();
        if let Some((ifname, r)) = ours.clone() {
            if ifname != w.ifname || router.as_deref() != Some(r.as_str()) {
                route(&["delete", "-ifscope", &ifname, "default", &r]);
                *ours = None; // Wi-Fi changed network or went away
            }
        }
        if let Some(r) = &router {
            if !scoped_default_exists(&w.ifname) && route(&["add", "-ifscope", &w.ifname, "default", r]) {
                *ours = Some((w.ifname.clone(), r.clone()));
            }
        }
        let ok = router.is_some() && scoped_default_exists(&w.ifname) && self.stack_alive.load(Relaxed);
        self.wifi_ok.store(ok, Relaxed);
    }

    /// Drop idle USB flows, Wi-Fi flows no relay ever took, and stale sticky
    /// entries; keep the Wi-Fi route. Call every few seconds.
    pub fn sweep(&self) {
        self.ensure_wifi_route();
        let now = Instant::now();
        let mut t = self.tables.lock().unwrap();
        let idle: Vec<FlowKey> = t
            .flows
            .iter()
            .filter(|(_, f)| match f.link {
                Link::Usb => now.duration_since(f.last) > IDLE_PHONE_FLOW,
                Link::Wifi => !f.relayed && now.duration_since(f.last) > UNRELAYED_IDLE,
            })
            .map(|(k, _)| *k)
            .collect();
        for k in idle {
            t.remove(&k);
        }
        t.sticky.retain(|_, (_, at)| at.elapsed() < STICKY_FOR);
        t.apps.retain(|_, s| s.flows > 0 || s.last_seen.is_some_and(|l| l.elapsed() < APP_LISTED_FOR));
    }

    /// A relay took over this flow: returns its generation and app.
    fn claim_relay(&self, key: &FlowKey) -> (Option<u64>, Option<Arc<str>>) {
        let mut t = self.tables.lock().unwrap();
        match t.flows.get_mut(key) {
            Some(f) => {
                f.relayed = true;
                (Some(f.generation), f.app.clone())
            }
            None => (None, None),
        }
    }

    /// Remove a relayed flow, unless the 4-tuple has since been reused.
    fn release_relay(&self, key: &FlowKey, generation: Option<u64>) {
        let mut t = self.tables.lock().unwrap();
        if generation.is_some() && t.flows.get(key).map(|f| f.generation) == generation {
            t.remove(key);
        }
    }

    /// Apps seen recently, plus every app with a non-Off setting.
    pub fn app_status(&self) -> Vec<AppStatus> {
        let cfg = global().config.read().unwrap();
        let t = self.tables.lock().unwrap();
        let mut out: Vec<AppStatus> = t
            .apps
            .iter()
            .map(|(id, s)| AppStatus {
                id: id.to_string(),
                name: s.name.to_string(),
                mode: cfg.mode(id),
                flows: s.flows,
                usb_bytes: s.usb_bytes,
                wifi_bytes: s.wifi_bytes,
                idle_secs: s.last_seen.map(|l| l.elapsed().as_secs()).unwrap_or(u64::MAX),
            })
            .collect();
        for (id, mode) in &cfg.apps {
            if !t.apps.contains_key(id.as_str()) {
                out.push(configured_only(id, *mode));
            }
        }
        out
    }
}

/// Status entry for an app that is configured but has not been seen yet.
pub fn configured_only(id: &str, mode: Mode) -> AppStatus {
    let name = if id == "com.apple.WebKit.Networking" {
        "Safari & WebKit apps".to_string()
    } else {
        std::path::Path::new(id).file_stem().and_then(|s| s.to_str()).unwrap_or(id).to_string()
    };
    AppStatus { id: id.to_string(), name, mode, flows: 0, usb_bytes: 0, wifi_bytes: 0, idle_secs: u64::MAX }
}

impl Tables {
    fn count(&mut self, app: Option<&str>, link: Link, n: usize, now: Instant) {
        if let Some(s) = app.and_then(|a| self.apps.get_mut(a)) {
            match link {
                Link::Usb => s.usb_bytes += n as u64,
                Link::Wifi => s.wifi_bytes += n as u64,
            }
            s.last_seen = Some(now);
        }
    }

    fn remove(&mut self, key: &FlowKey) {
        if let Some(f) = self.flows.remove(key) {
            if f.bonded {
                match f.link {
                    Link::Usb => self.bonded_usb = self.bonded_usb.saturating_sub(1),
                    Link::Wifi => self.bonded_wifi = self.bonded_wifi.saturating_sub(1),
                }
            }
            if let Some(s) = f.app.as_deref().and_then(|a| self.apps.get_mut(a)) {
                s.flows = s.flows.saturating_sub(1);
            }
        }
    }
}

impl Drop for Bonder {
    fn drop(&mut self) {
        // Only the route we added; a scoped route macOS made stays.
        if let Some((ifname, router)) = self.wifi_route.lock().unwrap().take() {
            route(&["delete", "-ifscope", &ifname, "default", &router]);
        }
        if let Some(rt) = self.runtime.take() {
            rt.shutdown_background();
        }
    }
}

fn is_internet(a: Ipv4Addr) -> bool {
    let o = a.octets();
    !(a.is_private()
        || a.is_loopback()
        || a.is_link_local()
        || a.is_multicast()
        || a.is_broadcast()
        || a.is_unspecified()
        || (o[0] == 100 && o[1] & 0xc0 == 64)) // 100.64/10 carrier-grade NAT
}

fn route(args: &[&str]) -> bool {
    std::process::Command::new("/sbin/route")
        .args(["-q", "-n"])
        .args(args)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

/// Whether a default route scoped to `ifname` exists.
fn scoped_default_exists(ifname: &str) -> bool {
    std::process::Command::new("/sbin/route")
        .args(["-n", "get", "-ifscope", ifname, "default"])
        .output()
        .is_ok_and(|o| is_scoped_default(&String::from_utf8_lossy(&o.stdout), ifname))
}

/// `route get -ifscope IF default` exits 0 even for "not in table", and when
/// IF has only the ordinary (unscoped) default it reports that one, which
/// sockets pinned with IP_BOUND_IF cannot use. Only a route on IF carrying
/// the IFSCOPE flag counts.
fn is_scoped_default(route_get: &str, ifname: &str) -> bool {
    let on_if = route_get.lines().any(|l| l.trim() == format!("interface: {ifname}"));
    let scoped = route_get.lines().any(|l| l.trim_start().starts_with("flags:") && l.contains("IFSCOPE"));
    on_if && scoped
}

fn wifi_router(ifname: &str) -> Option<String> {
    let out = std::process::Command::new("/usr/sbin/ipconfig").args(["getoption", ifname, "router"]).output().ok()?;
    let r = String::from_utf8(out.stdout).ok()?.trim().to_string();
    r.parse::<Ipv4Addr>().is_ok().then_some(r)
}

/// Verbose bonding decisions while /var/run/rtether.debug exists. It lives
/// where only root can create it: the log names other users' destinations.
fn debug() -> bool {
    static CHECKED: Mutex<Option<(Instant, bool)>> = Mutex::new(None);
    let mut c = CHECKED.lock().unwrap();
    match *c {
        Some((at, v)) if at.elapsed() < Duration::from_secs(2) => v,
        _ => {
            let v = std::path::Path::new("/var/run/rtether.debug").exists();
            *c = Some((Instant::now(), v));
            v
        }
    }
}

// ---------------------------------------------------------------- Wi-Fi side

/// What ipstack sees as its TUN device: diverted packets in, replies out to
/// the real utun (and counted on the way).
struct DivertDevice {
    rx: Receiver<Vec<u8>>,
    tun: Arc<Utun>,
    bonder: Weak<Bonder>,
}

impl AsyncRead for DivertDevice {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        match self.rx.poll_recv(cx) {
            Poll::Ready(Some(p)) => {
                let n = p.len().min(buf.remaining());
                buf.put_slice(&p[..n]);
                Poll::Ready(Ok(()))
            }
            Poll::Ready(None) => Poll::Ready(Ok(())),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl AsyncWrite for DivertDevice {
    fn poll_write(self: Pin<&mut Self>, _cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        if let Some(b) = self.bonder.upgrade() {
            b.account_incoming(buf);
        }
        state::add(&global().wifi_rx, buf.len());
        let _ = self.tun.write_ipv4(buf);
        Poll::Ready(Ok(buf.len()))
    }
    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

async fn accept_loop(device: DivertDevice, bonder: Weak<Bonder>) {
    let mut cfg = ipstack::IpStackConfig::default();
    let _ = cfg.mtu(1500);
    cfg.udp_timeout(Duration::from_secs(60));
    // ipstack's defaults (16 KB in flight per connection) cap each relayed
    // connection at a few Mbps; give it a window fit for 100+ Mbps links.
    let mut tcp = ipstack::TcpConfig::default();
    tcp.max_unacked_bytes = 1024 * 1024;
    tcp.read_buffer_size = 256 * 1024;
    tcp.options = Some(vec![ipstack::TcpOptions::MaximumSegmentSize(1460)]);
    // Defaults would reset idle connections after 60 s (SSH, chat, push) and
    // give up on a segment after 3 retransmissions, leaving a hole that
    // stalls the stream.
    tcp.timeout = Duration::from_secs(2 * 3600);
    tcp.max_retransmit_count = 50;
    cfg.with_tcp_config(tcp);
    let mut stack = ipstack::IpStack::new(cfg, device);
    loop {
        let stream = match stack.accept().await {
            Ok(s) => s,
            Err(e) => {
                log!("bonding stack stopped: {e}; bonded apps use USB only");
                break;
            }
        };
        if bonder.strong_count() == 0 {
            return;
        }
        match stream {
            ipstack::IpStackStream::Tcp(s) => {
                tokio::spawn(relay_tcp(s, bonder.clone()));
            }
            ipstack::IpStackStream::Udp(s) => {
                tokio::spawn(relay_udp(s, bonder.clone()));
            }
            _ => {}
        }
    }
    if let Some(b) = bonder.upgrade() {
        b.stack_alive.store(false, Relaxed);
        b.wifi_ok.store(false, Relaxed);
    }
}

fn wifi_index() -> Option<u32> {
    let w = global().wifi.lock().unwrap();
    (w.up && w.index != 0).then_some(w.index)
}

/// Pin a socket to the Wi-Fi interface (scoped routing ignores our /1 routes).
fn bind_to_wifi(fd: std::os::fd::RawFd, index: u32) -> io::Result<()> {
    let r = unsafe {
        libc::setsockopt(fd, libc::IPPROTO_IP, libc::IP_BOUND_IF, (&index as *const u32).cast(), 4)
    };
    if r != 0 { Err(io::Error::last_os_error()) } else { Ok(()) }
}

fn key_for(local: SocketAddr, remote: SocketAddr, proto: u8) -> Option<FlowKey> {
    match remote {
        SocketAddr::V4(r) => Some(FlowKey { proto, local_port: local.port(), remote: *r.ip(), remote_port: r.port() }),
        SocketAddr::V6(_) => None,
    }
}

/// Errors that are normal on the internet (dead peers, resets) and not worth
/// a log line outside debug mode.
fn routine(e: &io::Error) -> bool {
    use io::ErrorKind::*;
    matches!(e.kind(), TimedOut | ConnectionRefused | ConnectionReset | ConnectionAborted | BrokenPipe | UnexpectedEof | NotConnected)
}

async fn relay_tcp(app: ipstack::IpStackTcpStream, b: Weak<Bonder>) {
    use std::os::fd::AsRawFd;
    let (local, remote) = (app.local_addr(), app.peer_addr());
    let Some(key) = key_for(local, remote, TCP) else { return };
    let (generation, owner) = b.upgrade().map(|b| b.claim_relay(&key)).unwrap_or_default();
    let result = async {
        let index = wifi_index().ok_or_else(|| io::Error::other("Wi-Fi is down"))?;
        let sock = tokio::net::TcpSocket::new_v4()?;
        bind_to_wifi(sock.as_raw_fd(), index)?;
        let net = tokio::time::timeout(Duration::from_secs(10), sock.connect(remote))
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "connect timed out"))??;
        let _ = net.set_nodelay(true);
        let (app_r, app_w) = tokio::io::split(app);
        let (net_r, net_w) = net.into_split();
        // Downstream bytes are counted per packet in DivertDevice.
        let up = pump(app_r, net_w, Some(&global().wifi_tx));
        let down = pump(net_r, app_w, None);
        // A clean EOF in one direction keeps the other open (half-close);
        // an error in either ends both, so the app sees the reset instead
        // of hanging half-open.
        tokio::try_join!(up, down)?;
        Ok::<_, io::Error>(())
    }
    .await;
    if let Err(e) = result {
        if debug() || !routine(&e) {
            let app = owner.as_deref().unwrap_or("?");
            log!("bonding: {app} -> {remote} over Wi-Fi failed: {e}");
        }
    }
    if let Some(b) = b.upgrade() {
        b.release_relay(&key, generation);
    }
}

async fn pump<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
    mut r: R,
    mut w: W,
    counter: Option<&'static AtomicU64>,
) -> io::Result<()> {
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let n = r.read(&mut buf).await?;
        if n == 0 {
            let _ = w.shutdown().await;
            return Ok(());
        }
        w.write_all(&buf[..n]).await?;
        if let Some(c) = counter {
            c.fetch_add(n as u64, Relaxed);
        }
    }
}

async fn relay_udp(mut app: ipstack::IpStackUdpStream, b: Weak<Bonder>) {
    use std::os::fd::AsRawFd;
    let (local, remote) = (app.local_addr(), app.peer_addr());
    let Some(key) = key_for(local, remote, UDP) else { return };
    let (generation, _) = b.upgrade().map(|b| b.claim_relay(&key)).unwrap_or_default();
    let result = async {
        let index = wifi_index().ok_or_else(|| io::Error::other("Wi-Fi is down"))?;
        let std_sock = std::net::UdpSocket::bind("0.0.0.0:0")?;
        bind_to_wifi(std_sock.as_raw_fd(), index)?;
        std_sock.set_nonblocking(true)?;
        let net = tokio::net::UdpSocket::from_std(std_sock)?;
        net.connect(remote).await?;
        let (mut a, mut n) = (vec![0u8; 65536], vec![0u8; 65536]);
        loop {
            tokio::select! {
                r = app.read(&mut a) => {
                    let len = r?;
                    if len == 0 { return Ok(()); } // ipstack's idle timeout
                    net.send(&a[..len]).await?;
                    state::add(&global().wifi_tx, len);
                }
                r = net.recv(&mut n) => {
                    let len = r?;
                    app.write_all(&n[..len]).await?;
                }
            }
        }
    }
    .await;
    // UDP errors (ICMP unreachable and the like) are routine; stay quiet.
    let _: io::Result<()> = result;
    if let Some(b) = b.upgrade() {
        b.release_relay(&key, generation);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_a_real_scoped_route_counts() {
        // Captured on macOS 26 with the tether as the primary route.
        let unscoped_fallback = "   route to: default\ndestination: default\n       mask: default\n    gateway: 10.1.1.1\n  interface: en0\n      flags: <UP,GATEWAY,DONE,STATIC,PRCLONING,GLOBAL>\n";
        let scoped = "   route to: default\n    gateway: 10.1.1.1\n  interface: en0\n      flags: <UP,GATEWAY,DONE,STATIC,PRCLONING,IFSCOPE,GLOBAL>\n";
        let missing = "route: writing to routing socket: not in table\n";
        assert!(!is_scoped_default(unscoped_fallback, "en0"));
        assert!(is_scoped_default(scoped, "en0"));
        assert!(!is_scoped_default(scoped, "en1"));
        assert!(!is_scoped_default(missing, "en0"));
    }

    #[test]
    fn packet_classifier_survives_garbage() {
        let mut seed = 0xd1b54a32d192ed03u64;
        for _ in 0..50_000 {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            let len = (seed % 80) as usize;
            let mut ip: Vec<u8> = (0..len).map(|i| (seed.rotate_left(i as u32 % 64)) as u8).collect();
            if len > 0 {
                ip[0] = 0x40 | (ip[0] & 0x0f);
            }
            let _ = parse(&ip);
        }
    }
}
