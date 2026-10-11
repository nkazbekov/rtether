//! One phone connection: claim the RNDIS interfaces, bring the link up, get
//! an address over DHCP, configure macOS, then pump packets until the phone
//! goes away or we are asked to stop.

use std::io;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering::Relaxed};
use std::sync::mpsc::{self, Receiver, SyncSender};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use nusb::descriptors::TransferType;
use nusb::transfer::{Buffer, Bulk, Direction, In, Out, TransferError};
use nusb::{DeviceInfo, Endpoint, MaybeFuture};

use crate::bond::{Bonder, Link};
use crate::packet::{self, Dhcp, Lease, Mac, BROADCAST, ETH_ARP, ETH_IPV4};
use crate::state::{self, global, PhoneInfo};
use crate::rndis::{self, PACKET_HEADER_LEN, RX_TRANSFER};
use crate::sysnet::NetConfig;
use crate::utun::Utun;
use crate::{control, log};

const RX_QUEUE: usize = 16;
const TX_INFLIGHT: usize = 32;
const TX_BUFFER: usize = 2048;
const MTU_MAX: usize = 1500;

fn is_rndis_control(class: u8, subclass: u8, protocol: u8) -> bool {
    // Android presents Wireless/RF/RNDIS; some ROMs use CDC ACM with vendor protocol.
    (class, subclass, protocol) == (0xE0, 0x01, 0x03) || (class, subclass, protocol) == (0x02, 0x02, 0xFF)
}

/// A connected device currently exposing an RNDIS interface pair.
pub fn find_phone() -> Option<DeviceInfo> {
    nusb::list_devices()
        .wait()
        .ok()?
        .find(|d| d.interfaces().any(|i| is_rndis_control(i.class(), i.subclass(), i.protocol())))
}

fn other<E: std::fmt::Debug>(what: &'static str) -> impl Fn(E) -> io::Error {
    move |e| io::Error::other(format!("{what}: {e:?}"))
}

fn random_u32() -> u32 {
    unsafe { libc::arc4random() }
}

struct Shared {
    stop: AtomicBool,
    dead: AtomicBool,
    gw_mac: Mutex<Mac>,
    xid: AtomicU32,
    rx_bytes: AtomicU64,
    tx_bytes: AtomicU64,
    /// Bumped by rx on every DHCP ACK for our address; carries its lease time.
    acks: AtomicU32,
    lease_secs: AtomicU32,
}

/// Marks the session dead when a pump thread exits for any reason —
/// including a panic — so the main loop tears down instead of leaving the
/// Mac routed into a half-dead link.
struct DeadOnExit<'a>(&'a Shared);

impl Drop for DeadOnExit<'_> {
    fn drop(&mut self) {
        self.0.dead.store(true, Relaxed);
    }
}

/// Stops the pump threads if the session's own thread unwinds (a panic),
/// so they do not outlive it and fight the next session over the phone.
struct StopOnUnwind(Arc<Shared>);

impl Drop for StopOnUnwind {
    fn drop(&mut self) {
        self.0.stop.store(true, Relaxed);
    }
}

pub fn run(info: DeviceInfo, quit: &AtomicBool, test: bool) -> io::Result<()> {
    let ctrl_num = info
        .interfaces()
        .find(|i| is_rndis_control(i.class(), i.subclass(), i.protocol()))
        .map(|i| i.interface_number())
        .ok_or_else(|| io::Error::other("RNDIS interface vanished"))?;
    let data_num = info
        .interfaces()
        .find(|i| i.class() == 0x0A)
        .map(|i| i.interface_number())
        .ok_or_else(|| io::Error::other("phone has no RNDIS data interface"))?;

    let dev = info.open().wait().map_err(other("open phone"))?;
    let ctrl_if = dev.claim_interface(ctrl_num).wait().map_err(other("claim control interface"))?;
    let data_if = dev.claim_interface(data_num).wait().map_err(other("claim data interface"))?;

    let mut ctrl = rndis::Control::new(ctrl_if);
    let params = ctrl.bring_up()?;
    let mac = params.mac;
    log!(
        "phone {:04x}:{:04x} link up; our MAC {}; phone accepts {} packet(s)/{} bytes per transfer",
        info.vendor_id(),
        info.product_id(),
        fmt_mac(&mac),
        params.max_packets_per_transfer,
        params.tx_max_transfer
    );
    if let Ok(false) = ctrl.media_connected() {
        log!("phone reports its side of the link as down — is USB tethering on?");
    }

    let desc = data_if.descriptor().ok_or_else(|| io::Error::other("no data interface descriptor"))?;
    let (mut in_addr, mut out_addr, mut max_packet) = (None, None, 512);
    for ep in desc.endpoints() {
        if ep.transfer_type() != TransferType::Bulk {
            continue;
        }
        match ep.direction() {
            Direction::In => in_addr = Some(ep.address()),
            Direction::Out => {
                out_addr = Some(ep.address());
                // From the device's descriptor; 0 would divide by zero later.
                max_packet = match ep.max_packet_size() {
                    0 => 512,
                    n => n,
                };
            }
        }
    }
    let (Some(in_addr), Some(out_addr)) = (in_addr, out_addr) else {
        return Err(io::Error::other("phone has no bulk endpoint pair"));
    };
    let mut ep_in = data_if.endpoint::<Bulk, In>(in_addr).map_err(other("bulk IN"))?;
    let mut ep_out = data_if.endpoint::<Bulk, Out>(out_addr).map_err(other("bulk OUT"))?;
    for _ in 0..RX_QUEUE {
        let buf = ep_in.allocate(RX_TRANSFER);
        ep_in.submit(buf);
    }

    let xid = random_u32();
    let lease = dhcp(&mut ep_in, &mut ep_out, max_packet, &mac, xid, quit)?
        .validate()
        .map_err(io::Error::other)?;
    log!(
        "address {} from phone {} (DNS {}, lease {}s)",
        lease.ip,
        lease.router,
        lease.dns.iter().map(|d| d.to_string()).collect::<Vec<_>>().join(", "),
        lease.lease_secs
    );

    let tun = Arc::new(Utun::open()?);
    let mtu = (params.max_frame as usize).clamp(576, MTU_MAX) as u32;
    let net = NetConfig::apply(&tun.name, &lease, mtu, test)?;
    if test {
        log!("test mode: only traffic bound to {} uses USB (e.g. curl --interface {})", tun.name, tun.name);
    } else {
        log!("tethering over USB on {} — Ctrl+C to stop", tun.name);
    }

    let shared = Arc::new(Shared {
        stop: AtomicBool::new(false),
        dead: AtomicBool::new(false),
        gw_mac: Mutex::new(lease.server_mac),
        xid: AtomicU32::new(xid),
        rx_bytes: AtomicU64::new(0),
        tx_bytes: AtomicU64::new(0),
        acks: AtomicU32::new(0),
        lease_secs: AtomicU32::new(lease.lease_secs),
    });
    // Bounded: a phone flooding ARP requests must not grow root's memory.
    let (frames_tx, frames_rx) = mpsc::sync_channel::<Vec<u8>>(256);

    // Per-app bonding over Wi-Fi; not in test mode, where nothing is routed.
    let bonder = if test { None } else { Some(Bonder::start(tun.clone(), lease.ip)?) };
    if let Some(b) = &bonder {
        b.sweep(); // sets up the Wi-Fi route right away
    }
    control::set_current(bonder.clone());
    *global().phone.lock().unwrap() = Some(PhoneInfo {
        ip: lease.ip.to_string(),
        router: lease.router.to_string(),
        ifname: tun.name.clone(),
    });

    let rx = {
        let (tun, sh, frames, lease, b) = (tun.clone(), shared.clone(), frames_tx.clone(), lease.clone(), bonder.clone());
        thread::spawn(move || rx_loop(ep_in, &tun, &sh, &frames, mac, &lease, b.as_deref()))
    };
    let tx = {
        let (tun, sh, b) = (tun.clone(), shared.clone(), bonder.clone());
        thread::spawn(move || tx_loop(ep_out, &tun, &sh, frames_rx, mac, max_packet, b.as_deref()))
    };

    let _stop_on_unwind = StopOnUnwind(shared.clone());
    let started = Instant::now();
    let half_lease = |secs: u32| Duration::from_secs((secs / 2).max(30) as u64);
    let mut next_sweep = started;
    let mut renew_at = started + half_lease(lease.lease_secs);
    let mut acks_seen = 0;
    while !quit.load(Relaxed) && !shared.dead.load(Relaxed) && !rx.is_finished() && !tx.is_finished() {
        thread::sleep(Duration::from_millis(250));
        let now = Instant::now();
        if let Some(b) = bonder.as_ref().filter(|_| now >= next_sweep) {
            b.sweep();
            next_sweep = now + Duration::from_secs(5);
        }
        // Renew at half the lease; until the phone ACKs, retry every minute.
        let acks = shared.acks.load(Relaxed);
        if acks != acks_seen {
            acks_seen = acks;
            renew_at = now + half_lease(shared.lease_secs.load(Relaxed));
        } else if now >= renew_at {
            let xid = random_u32();
            shared.xid.store(xid, Relaxed);
            let _ = frames_tx.try_send(packet::dhcp_renew(&mac, xid, lease.ip));
            renew_at = now + Duration::from_secs(60);
        }
    }

    shared.stop.store(true, Relaxed);
    let _ = rx.join();
    let _ = tx.join();
    control::set_current(None);
    *global().phone.lock().unwrap() = None;
    drop(bonder);
    drop(net);
    let secs = started.elapsed().as_secs().max(1);
    log!(
        "session ended after {}s: {} MB down, {} MB up",
        secs,
        shared.rx_bytes.load(Relaxed) / 1_000_000,
        shared.tx_bytes.load(Relaxed) / 1_000_000
    );
    Ok(())
}

fn fmt_mac(m: &Mac) -> String {
    m.iter().map(|b| format!("{b:02x}")).collect::<Vec<_>>().join(":")
}

/// Send one frame and wait for it to complete (only used before the pumps start).
fn send_now(ep: &mut Endpoint<Bulk, Out>, max_packet: usize, frame: &[u8]) -> io::Result<()> {
    let mut v = Vec::with_capacity(PACKET_HEADER_LEN + frame.len() + 1);
    rndis::wrap_frame(&mut v, frame);
    if v.len() % max_packet == 0 {
        v.push(0); // never a zero-length packet: it wedges Android's gadget
    }
    ep.submit(v.into());
    match ep.wait_next_complete(Duration::from_secs(2)) {
        Some(c) => c.status.map_err(other("send to phone")),
        None => Err(io::Error::new(io::ErrorKind::TimedOut, "phone is not accepting data")),
    }
}

fn dhcp(
    ep_in: &mut Endpoint<Bulk, In>,
    ep_out: &mut Endpoint<Bulk, Out>,
    max_packet: usize,
    mac: &Mac,
    mut xid: u32,
    quit: &AtomicBool,
) -> io::Result<Lease> {
    let deadline = Instant::now() + Duration::from_secs(20);
    let mut offer: Option<Lease> = None;
    let mut next_send = Instant::now();
    while Instant::now() < deadline {
        if quit.load(Relaxed) {
            return Err(io::Error::new(io::ErrorKind::Interrupted, "stopped"));
        }
        if Instant::now() >= next_send {
            let frame = match &offer {
                None => packet::dhcp_discover(mac, xid),
                Some(l) => packet::dhcp_request(mac, xid, l.ip, l.server),
            };
            send_now(ep_out, max_packet, &frame)?;
            next_send = Instant::now() + Duration::from_secs(2);
        }
        let Some(c) = ep_in.wait_next_complete(Duration::from_millis(200)) else { continue };
        if let Err(TransferError::Disconnected) = c.status {
            return Err(io::Error::other("phone disconnected"));
        }
        let mut ack = None;
        if c.status.is_ok() {
            rndis::for_each_frame(&c.buffer, |f| match packet::parse_dhcp(f, mac, xid) {
                Some(Dhcp::Offer(l)) if offer.is_none() => {
                    offer = Some(l);
                    next_send = Instant::now();
                }
                Some(Dhcp::Ack(l)) => ack = Some(l),
                Some(Dhcp::Nak) => {
                    offer = None;
                    xid = random_u32();
                    next_send = Instant::now();
                }
                _ => {}
            });
        }
        ep_in.submit(c.buffer);
        if let Some(l) = ack {
            return Ok(l);
        }
    }
    Err(io::Error::new(
        io::ErrorKind::TimedOut,
        "phone did not answer DHCP — is mobile data on?",
    ))
}

/// Phone -> Mac: unwrap RNDIS, answer ARP, hand IPv4 to the utun.
fn rx_loop(
    mut ep: Endpoint<Bulk, In>,
    tun: &Utun,
    sh: &Shared,
    frames: &SyncSender<Vec<u8>>,
    mac: Mac,
    lease: &Lease,
    bonder: Option<&Bonder>,
) {
    let _dead_on_exit = DeadOnExit(sh);
    while !sh.stop.load(Relaxed) {
        let Some(c) = ep.wait_next_complete(Duration::from_millis(500)) else { continue };
        match c.status {
            Ok(()) => {}
            Err(TransferError::Disconnected) => {
                sh.dead.store(true, Relaxed);
                return;
            }
            Err(TransferError::Stall) => {
                let _ = ep.clear_halt().wait();
            }
            Err(_) if sh.stop.load(Relaxed) => return,
            // Unplugging or switching tethering off surfaces as Cancelled or
            // an IOKit code rather than Disconnected; every queued transfer
            // fails the same way, so end the session on the first one.
            Err(e) => {
                log!("USB link lost ({e:?})");
                sh.dead.store(true, Relaxed);
                return;
            }
        }
        rndis::for_each_frame(&c.buffer, |f| {
            let dst = packet::dst_mac(f);
            if dst != mac && dst != BROADCAST {
                return;
            }
            match packet::ethertype(f) {
                ETH_ARP => {
                    if let Some(reply) = packet::arp_reply(f, &mac, lease.ip) {
                        let _ = frames.try_send(reply);
                    }
                    if let Some((m, ip)) = packet::arp_sender(f) {
                        if ip == lease.router {
                            *sh.gw_mac.lock().unwrap() = m;
                        }
                    }
                }
                ETH_IPV4 => {
                    if let Some(d) = packet::parse_dhcp(f, &mac, sh.xid.load(Relaxed)) {
                        match d {
                            Dhcp::Ack(l) if l.ip == lease.ip => {
                                sh.lease_secs.store(l.lease_secs, Relaxed);
                                sh.acks.fetch_add(1, Relaxed);
                            }
                            Dhcp::Ack(_) | Dhcp::Nak => {
                                log!("phone withdrew our address; reconnecting");
                                sh.dead.store(true, Relaxed);
                            }
                            Dhcp::Offer(_) => {}
                        }
                        return;
                    }
                    if dst != mac {
                        return;
                    }
                    if let Some(ip) = packet::ipv4_payload(f) {
                        sh.rx_bytes.fetch_add(ip.len() as u64, Relaxed);
                        state::add(&global().usb_rx, ip.len());
                        if let Some(b) = bonder {
                            b.account_incoming(ip);
                        }
                        if let Err(e) = tun.write_ipv4(ip) {
                            log!("utun write: {e}");
                        }
                    }
                }
                _ => {}
            }
        });
        if !sh.dead.load(Relaxed) {
            ep.submit(c.buffer);
        }
    }
}

/// Bulk OUT side: keeps up to TX_INFLIGHT transfers queued and recycles buffers.
struct OutQueue {
    ep: Endpoint<Bulk, Out>,
    spare: Vec<Buffer>,
    max_packet: usize,
    stalled_since: Option<Instant>,
}

impl OutQueue {
    /// Collect finished transfers. With `block`, wait until a slot is free.
    /// Returns false once the link is dead.
    fn reap(&mut self, sh: &Shared, block: bool) -> bool {
        while self.ep.pending() > 0 {
            let full = self.ep.pending() >= TX_INFLIGHT;
            let timeout = if block && full { Duration::from_millis(500) } else { Duration::ZERO };
            match self.ep.wait_next_complete(timeout) {
                Some(c) => {
                    self.stalled_since = None;
                    match c.status {
                        Ok(()) => {}
                        Err(TransferError::Stall) => {
                            let _ = self.ep.clear_halt().wait();
                        }
                        Err(_) if sh.stop.load(Relaxed) => return false,
                        // Unplug, tethering off, or a fault: either way this
                        // link is gone; let the session reconnect.
                        Err(e) => {
                            log!("USB send failed ({e:?})");
                            sh.dead.store(true, Relaxed);
                            return false;
                        }
                    }
                    self.spare.push(c.buffer);
                }
                None if !(block && full) => return true,
                None => {
                    let since = *self.stalled_since.get_or_insert_with(Instant::now);
                    if since.elapsed() > Duration::from_secs(5) {
                        log!("phone stopped accepting data for 5s; reconnecting");
                        sh.dead.store(true, Relaxed);
                        return false;
                    }
                }
            }
        }
        true
    }

    /// Queue one Ethernet frame (`eth` header + `payload`) as an RNDIS packet.
    fn send(&mut self, sh: &Shared, eth: &[u8], payload: &[u8]) -> bool {
        if !self.reap(sh, true) {
            return false;
        }
        let mut b = self.spare.pop().unwrap_or_else(|| self.ep.allocate(TX_BUFFER));
        b.clear();
        let len = (eth.len() + payload.len()) as u32;
        let mut hdr = [0u8; PACKET_HEADER_LEN];
        hdr[0..4].copy_from_slice(&1u32.to_le_bytes());
        hdr[4..8].copy_from_slice(&(PACKET_HEADER_LEN as u32 + len).to_le_bytes());
        hdr[8..12].copy_from_slice(&((PACKET_HEADER_LEN - 8) as u32).to_le_bytes());
        hdr[12..16].copy_from_slice(&len.to_le_bytes());
        b.extend_from_slice(&hdr);
        b.extend_from_slice(eth);
        b.extend_from_slice(payload);
        if b.len() % self.max_packet == 0 {
            b.extend_from_slice(&[0]); // never a zero-length packet
        }
        self.ep.submit(b);
        true
    }
}

/// Mac -> phone: read IPv4 from the utun, add Ethernet + RNDIS headers, send.
fn tx_loop(
    ep: Endpoint<Bulk, Out>,
    tun: &Utun,
    sh: &Shared,
    frames: Receiver<Vec<u8>>,
    mac: Mac,
    max_packet: usize,
    bonder: Option<&Bonder>,
) {
    let _dead_on_exit = DeadOnExit(sh);
    let mut out = OutQueue { ep, spare: Vec::new(), max_packet, stalled_since: None };
    let mut pkt = vec![0u8; 65536];

    'outer: while !sh.stop.load(Relaxed) && !sh.dead.load(Relaxed) {
        if !out.reap(sh, false) {
            break;
        }
        while let Ok(f) = frames.try_recv() {
            if !out.send(sh, &f, &[]) {
                break 'outer;
            }
        }
        if !tun.wait_readable(20) {
            continue;
        }
        let mut eth = Vec::with_capacity(14);
        packet::eth_header(&mut eth, &sh.gw_mac.lock().unwrap(), &mac, ETH_IPV4);
        for _ in 0..64 {
            match tun.read_ipv4(&mut pkt) {
                Ok(Some(ip)) if ip.len() <= MTU_MAX => {
                    // Taken after the read: the sending socket existed before this.
                    let seen = Instant::now();
                    if bonder.is_some_and(|b| b.route_outgoing(ip, seen) == Link::Wifi) {
                        bonder.unwrap().divert(ip.to_vec());
                        continue;
                    }
                    sh.tx_bytes.fetch_add(ip.len() as u64, Relaxed);
                    state::add(&global().usb_tx, ip.len());
                    if !out.send(sh, &eth, ip) {
                        break 'outer;
                    }
                }
                Ok(Some(_)) => {}
                Ok(None) => break,
                Err(e) => {
                    log!("utun read: {e}");
                    sh.dead.store(true, Relaxed);
                    break 'outer;
                }
            }
        }
    }
    if out.ep.pending() > 0 {
        out.ep.cancel_all();
    }
}
