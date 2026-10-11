//! The little bit of Ethernet, ARP, IPv4 and DHCP the link needs.
//!
//! DHCP is done by hand at layer 2 because the tethering subnet is not fixed
//! (Samsung has served 10.x and 172.31.x), and a socket-level client cannot
//! reach the phone before the interface has an address.

use std::net::Ipv4Addr;

pub type Mac = [u8; 6];
pub const BROADCAST: Mac = [0xff; 6];

pub const ETH_IPV4: u16 = 0x0800;
pub const ETH_ARP: u16 = 0x0806;

pub fn ethertype(frame: &[u8]) -> u16 {
    u16::from_be_bytes([frame[12], frame[13]])
}

pub fn dst_mac(frame: &[u8]) -> Mac {
    frame[0..6].try_into().unwrap()
}

pub fn src_mac(frame: &[u8]) -> Mac {
    frame[6..12].try_into().unwrap()
}

/// Write an Ethernet header into `out`.
pub fn eth_header(out: &mut Vec<u8>, dst: &Mac, src: &Mac, ethertype: u16) {
    out.extend_from_slice(dst);
    out.extend_from_slice(src);
    out.extend_from_slice(&ethertype.to_be_bytes());
}

fn checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = data
        .chunks(2)
        .map(|c| u16::from_be_bytes([c[0], *c.get(1).unwrap_or(&0)]) as u32)
        .sum();
    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// The IPv4 packet inside an Ethernet frame, trimmed to its own total length
/// (Ethernet pads short frames, and the pad must not reach the host stack).
pub fn ipv4_payload(frame: &[u8]) -> Option<&[u8]> {
    let ip = frame.get(14..)?;
    if ip.len() < 20 || ip[0] >> 4 != 4 {
        return None;
    }
    // Both lengths come from the wire: the header must fit inside the
    // packet, and the packet inside the frame, or callers would index past
    // the end of what we return.
    let ihl = (ip[0] & 0x0f) as usize * 4;
    let total = u16::from_be_bytes([ip[2], ip[3]]) as usize;
    if ihl < 20 || total < ihl {
        return None;
    }
    ip.get(..total)
}

// ---------------------------------------------------------------- ARP

/// If `frame` is an ARP request for `our_ip`, build the reply.
pub fn arp_reply(frame: &[u8], our_mac: &Mac, our_ip: Ipv4Addr) -> Option<Vec<u8>> {
    let a = frame.get(14..42)?;
    let op = u16::from_be_bytes([a[6], a[7]]);
    let target_ip = Ipv4Addr::new(a[24], a[25], a[26], a[27]);
    if op != 1 || target_ip != our_ip {
        return None;
    }
    let sender_mac: Mac = a[8..14].try_into().unwrap();
    let mut out = Vec::with_capacity(42);
    eth_header(&mut out, &sender_mac, our_mac, ETH_ARP);
    out.extend_from_slice(&[0, 1, 8, 0, 6, 4, 0, 2]);
    out.extend_from_slice(our_mac);
    out.extend_from_slice(&our_ip.octets());
    out.extend_from_slice(&a[8..18]); // requester's MAC and IP
    Some(out)
}

/// Sender MAC and IP of any ARP packet.
pub fn arp_sender(frame: &[u8]) -> Option<(Mac, Ipv4Addr)> {
    let a = frame.get(14..42)?;
    Some((a[8..14].try_into().unwrap(), Ipv4Addr::new(a[14], a[15], a[16], a[17])))
}

// ---------------------------------------------------------------- DHCP

#[derive(Clone, Debug)]
pub struct Lease {
    pub ip: Ipv4Addr,
    pub mask: Ipv4Addr,
    pub router: Ipv4Addr,
    pub dns: Vec<Ipv4Addr>,
    pub lease_secs: u32,
    pub server: Ipv4Addr,
    pub server_mac: Mac,
}

fn is_unicast(a: Ipv4Addr) -> bool {
    !(a.is_unspecified() || a.is_loopback() || a.is_multicast() || a.is_broadcast() || a.is_link_local())
}

impl Lease {
    /// Check what the phone handed out before it reaches ifconfig, routes and
    /// DNS. A bogus router could otherwise pull an unrelated LAN host into a
    /// /32 route on the tether. Trims the DNS list to sane entries.
    pub fn validate(mut self) -> Result<Lease, String> {
        if !is_unicast(self.ip) || !is_unicast(self.router) || self.ip == self.router {
            return Err(format!("phone offered unusable addresses ({} via {})", self.ip, self.router));
        }
        let mask = u32::from(self.mask);
        let prefix = mask.leading_ones();
        if mask.count_ones() != prefix || !(8..=30).contains(&prefix) {
            return Err(format!("phone offered an unusable netmask {}", self.mask));
        }
        if u32::from(self.ip) & mask != u32::from(self.router) & mask {
            return Err(format!("phone's router {} is outside {}/{prefix}", self.router, self.ip));
        }
        self.dns.retain(|d| is_unicast(*d));
        self.dns.truncate(3);
        if self.dns.is_empty() {
            self.dns.push(self.router);
        }
        Ok(self)
    }
}

pub enum Dhcp {
    Offer(Lease),
    Ack(Lease),
    Nak,
}

const DISCOVER: u8 = 1;
const REQUEST: u8 = 3;

pub fn dhcp_discover(mac: &Mac, xid: u32) -> Vec<u8> {
    dhcp_frame(mac, xid, DISCOVER, None, None)
}

/// REQUEST for an offered address (SELECTING state).
pub fn dhcp_request(mac: &Mac, xid: u32, ip: Ipv4Addr, server: Ipv4Addr) -> Vec<u8> {
    dhcp_frame(mac, xid, REQUEST, Some((ip, server)), None)
}

/// REQUEST extending an address we hold (RFC 2131 REBINDING form: our
/// address in ciaddr, no requested-IP or server-id options, broadcast so it
/// works without ARP state).
pub fn dhcp_renew(mac: &Mac, xid: u32, ip: Ipv4Addr) -> Vec<u8> {
    dhcp_frame(mac, xid, REQUEST, None, Some(ip))
}

fn dhcp_frame(
    mac: &Mac,
    xid: u32,
    kind: u8,
    req: Option<(Ipv4Addr, Ipv4Addr)>,
    ciaddr: Option<Ipv4Addr>,
) -> Vec<u8> {
    let mut bootp = vec![0u8; 236];
    bootp[0] = 1; // BOOTREQUEST
    bootp[1] = 1; // Ethernet
    bootp[2] = 6;
    bootp[4..8].copy_from_slice(&xid.to_be_bytes());
    bootp[10] = 0x80; // ask for broadcast replies: we have no address yet
    if let Some(ip) = ciaddr {
        bootp[12..16].copy_from_slice(&ip.octets());
    }
    bootp[28..34].copy_from_slice(mac);
    bootp.extend_from_slice(&[99, 130, 83, 99]); // magic cookie
    bootp.extend_from_slice(&[53, 1, kind]);
    bootp.extend_from_slice(&[61, 7, 1]);
    bootp.extend_from_slice(mac);
    bootp.extend_from_slice(&[55, 5, 1, 3, 6, 51, 54]);
    if let Some((ip, server)) = req {
        bootp.extend_from_slice(&[50, 4]);
        bootp.extend_from_slice(&ip.octets());
        bootp.extend_from_slice(&[54, 4]);
        bootp.extend_from_slice(&server.octets());
    }
    bootp.push(255);

    let udp_len = 8 + bootp.len();
    let ip_len = 20 + udp_len;
    let mut ip = vec![0x45, 0, 0, 0, 0, 0, 0, 0, 64, 17, 0, 0, 0, 0, 0, 0, 255, 255, 255, 255];
    ip[2..4].copy_from_slice(&(ip_len as u16).to_be_bytes());
    let c = checksum(&ip);
    ip[10..12].copy_from_slice(&c.to_be_bytes());

    let mut out = Vec::with_capacity(14 + ip_len);
    eth_header(&mut out, &BROADCAST, mac, ETH_IPV4);
    out.extend_from_slice(&ip);
    out.extend_from_slice(&68u16.to_be_bytes());
    out.extend_from_slice(&67u16.to_be_bytes());
    out.extend_from_slice(&(udp_len as u16).to_be_bytes());
    out.extend_from_slice(&[0, 0]); // UDP checksum is optional over IPv4
    out.extend_from_slice(&bootp);
    out
}

/// Parse a DHCP reply addressed to `mac` with transaction id `xid`.
pub fn parse_dhcp(frame: &[u8], mac: &Mac, xid: u32) -> Option<Dhcp> {
    if ethertype(frame) != ETH_IPV4 {
        return None;
    }
    let ip = ipv4_payload(frame)?;
    let ihl = (ip[0] & 0x0f) as usize * 4;
    if ip[9] != 17 {
        return None;
    }
    let udp = ip.get(ihl..)?;
    if udp.len() < 8 || u16::from_be_bytes([udp[2], udp[3]]) != 68 {
        return None;
    }
    let b = &udp[8..];
    if b.len() < 240 || b[0] != 2 || b[4..8] != xid.to_be_bytes() || b[28..34] != mac[..] {
        return None;
    }
    if b[236..240] != [99, 130, 83, 99] {
        return None;
    }
    let mut lease = Lease {
        ip: Ipv4Addr::new(b[16], b[17], b[18], b[19]),
        mask: Ipv4Addr::new(255, 255, 255, 0),
        router: Ipv4Addr::UNSPECIFIED,
        dns: Vec::new(),
        lease_secs: 3600,
        server: Ipv4Addr::UNSPECIFIED,
        server_mac: src_mac(frame),
    };
    let mut kind = 0;
    let mut o = &b[240..];
    while let [code, rest @ ..] = o {
        match *code {
            0 => {
                o = rest;
                continue;
            }
            255 => break,
            _ => {}
        }
        let [len, rest @ ..] = rest else { break };
        let len = *len as usize;
        let Some(v) = rest.get(..len) else { break };
        let ip4 = |v: &[u8]| Ipv4Addr::new(v[0], v[1], v[2], v[3]);
        match (*code, len) {
            (53, 1) => kind = v[0],
            (1, 4) => lease.mask = ip4(v),
            (3, l) if l >= 4 => lease.router = ip4(v),
            (6, l) if l >= 4 => lease.dns = v.chunks_exact(4).map(ip4).collect(),
            (51, 4) => lease.lease_secs = u32::from_be_bytes(v.try_into().unwrap()),
            (54, 4) => lease.server = ip4(v),
            _ => {}
        }
        o = &rest[len..];
    }
    if lease.router.is_unspecified() {
        lease.router = lease.server;
    }
    if lease.dns.is_empty() {
        lease.dns.push(lease.router);
    }
    match kind {
        2 => Some(Dhcp::Offer(lease)),
        5 => Some(Dhcp::Ack(lease)),
        6 => Some(Dhcp::Nak),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frame(ip: &[u8]) -> Vec<u8> {
        let mut f = Vec::new();
        eth_header(&mut f, &BROADCAST, &[2, 0, 0, 0, 0, 1], ETH_IPV4);
        f.extend_from_slice(ip);
        f
    }

    #[test]
    fn short_ip_total_length_is_rejected() {
        // Total length 0..19 used to yield a slice the DHCP parser indexed past.
        for total in 0u16..20 {
            let mut ip = vec![0u8; 40];
            ip[0] = 0x45;
            ip[2..4].copy_from_slice(&total.to_be_bytes());
            ip[9] = 17;
            let f = frame(&ip);
            assert!(ipv4_payload(&f).is_none());
            assert!(parse_dhcp(&f, &[0; 6], 0).is_none());
        }
        // Header length longer than the packet.
        let mut ip = vec![0u8; 40];
        ip[0] = 0x4f; // ihl 60
        ip[2..4].copy_from_slice(&40u16.to_be_bytes());
        assert!(ipv4_payload(&frame(&ip)).is_none());
    }

    #[test]
    fn parsers_survive_garbage() {
        let mut seed = 0x2545f4914f6cdd1du64;
        let mac = [2, 0, 0, 0, 0, 1];
        for _ in 0..50_000 {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            let len = (seed % 400) as usize;
            let mut f: Vec<u8> = (0..len).map(|i| (seed.rotate_left(i as u32 % 64)) as u8).collect();
            if len > 34 {
                f[12] = 0x08;
                f[13] = if seed & 1 == 0 { 0x00 } else { 0x06 };
                f[14] = 0x45;
            }
            if f.len() >= 14 {
                let _ = ipv4_payload(&f);
                let _ = parse_dhcp(&f, &mac, (seed >> 32) as u32);
                let _ = arp_reply(&f, &mac, Ipv4Addr::new(10, 0, 0, 2));
                let _ = arp_sender(&f);
            }
        }
    }

    #[test]
    fn lease_validation() {
        let good = Lease {
            ip: Ipv4Addr::new(172, 31, 213, 8),
            mask: Ipv4Addr::new(255, 255, 255, 0),
            router: Ipv4Addr::new(172, 31, 213, 75),
            dns: vec![Ipv4Addr::new(172, 31, 213, 75), Ipv4Addr::UNSPECIFIED, Ipv4Addr::new(1, 1, 1, 1),
                      Ipv4Addr::new(8, 8, 8, 8), Ipv4Addr::new(9, 9, 9, 9)],
            lease_secs: 3600,
            server: Ipv4Addr::new(172, 31, 213, 75),
            server_mac: [0; 6],
        };
        let v = good.clone().validate().unwrap();
        assert_eq!(v.dns.len(), 3);
        assert!(!v.dns.contains(&Ipv4Addr::UNSPECIFIED));
        // Router on another network (e.g. a LAN host).
        let mut bad = good.clone();
        bad.router = Ipv4Addr::new(192, 168, 1, 10);
        assert!(bad.validate().is_err());
        let mut bad = good.clone();
        bad.mask = Ipv4Addr::new(255, 0, 255, 0);
        assert!(bad.validate().is_err());
        let mut bad = good;
        bad.ip = Ipv4Addr::BROADCAST;
        assert!(bad.validate().is_err());
    }

    #[test]
    fn renew_carries_our_address() {
        let mac = [2, 0, 0, 0, 0, 1];
        let f = dhcp_renew(&mac, 9, Ipv4Addr::new(172, 31, 213, 8));
        let bootp = &f[14 + 20 + 8..];
        assert_eq!(&bootp[12..16], &[172, 31, 213, 8]);
        assert!(!bootp[240..].windows(2).any(|w| w == [50, 4]));
    }

    #[test]
    fn dhcp_roundtrip_through_our_own_builder() {
        let mac = [2, 0, 0, 0, 0, 1];
        let req = dhcp_discover(&mac, 7);
        // Our own request is not a reply (op 1) and must parse as nothing.
        assert!(parse_dhcp(&req, &mac, 7).is_none());
        assert!(ipv4_payload(&req).is_some());
    }
}
