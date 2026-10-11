//! RNDIS control channel and data framing.
//!
//! Commands travel as CDC SEND_ENCAPSULATED_COMMAND on the communications
//! interface; replies are polled with GET_ENCAPSULATED_RESPONSE. Data frames
//! ride the bulk endpoints of the data interface, each wrapped in a 44-byte
//! RNDIS_MSG_PACKET header. Offsets inside messages count from byte 8.
//!
//! Android gadget quirks honoured here (see erg-tether's docs/protocol.md and
//! Linux drivers/net/usb/rndis_host.c): never SET_INTERFACE, never HALT, and
//! nothing flows until OID_GEN_CURRENT_PACKET_FILTER is set.

use std::io;
use std::time::Duration;

use nusb::transfer::{ControlIn, ControlOut, ControlType, Recipient};
use nusb::{Interface, MaybeFuture};

const MSG_PACKET: u32 = 0x0000_0001;
const MSG_INIT: u32 = 0x0000_0002;
const MSG_INIT_C: u32 = 0x8000_0002;
const MSG_QUERY: u32 = 0x0000_0004;
const MSG_QUERY_C: u32 = 0x8000_0004;
const MSG_SET: u32 = 0x0000_0005;
const MSG_SET_C: u32 = 0x8000_0005;
const MSG_INDICATE: u32 = 0x0000_0007;
const MSG_KEEPALIVE: u32 = 0x0000_0008;
const MSG_KEEPALIVE_C: u32 = 0x8000_0008;

const OID_GEN_MAXIMUM_FRAME_SIZE: u32 = 0x0001_0106;
const OID_GEN_CURRENT_PACKET_FILTER: u32 = 0x0001_010E;
const OID_GEN_MEDIA_CONNECT_STATUS: u32 = 0x0001_0114;
const OID_802_3_PERMANENT_ADDRESS: u32 = 0x0101_0101;

// DIRECTED | MULTICAST | ALL_MULTICAST | BROADCAST
const PACKET_FILTER: u32 = 0x0001 | 0x0002 | 0x0004 | 0x0008;

pub const PACKET_HEADER_LEN: usize = 44;

/// The most the phone may send us in one bulk transfer; also our RX buffer size.
pub const RX_TRANSFER: usize = 16384;

const CTRL_TIMEOUT: Duration = Duration::from_millis(1000);

fn le32(b: &[u8], off: usize) -> u32 {
    u32::from_le_bytes(b[off..off + 4].try_into().unwrap())
}

fn msg(words: &[u32]) -> Vec<u8> {
    words.iter().flat_map(|w| w.to_le_bytes()).collect()
}

fn usb_err<E: std::fmt::Debug>(what: &str) -> impl Fn(E) -> io::Error + '_ {
    move |e| io::Error::other(format!("{what}: {e:?}"))
}

pub struct DeviceParams {
    /// Phone's limit on what we send per bulk transfer.
    pub tx_max_transfer: u32,
    pub max_packets_per_transfer: u32,
    pub mac: [u8; 6],
    pub max_frame: u32,
}

pub struct Control {
    iface: Interface,
    next_id: u32,
}

impl Control {
    pub fn new(iface: Interface) -> Self {
        Control { iface, next_id: 1 }
    }

    fn id(&mut self) -> u32 {
        self.next_id = self.next_id.wrapping_add(1);
        self.next_id
    }

    fn send(&self, m: &[u8]) -> io::Result<()> {
        self.iface
            .control_out(
                ControlOut {
                    control_type: ControlType::Class,
                    recipient: Recipient::Interface,
                    request: 0x00, // SEND_ENCAPSULATED_COMMAND
                    value: 0,
                    index: self.iface.interface_number() as u16,
                    data: m,
                },
                CTRL_TIMEOUT,
            )
            .wait()
            .map_err(usb_err("SEND_ENCAPSULATED_COMMAND"))
    }

    fn receive(&self) -> io::Result<Vec<u8>> {
        self.iface
            .control_in(
                ControlIn {
                    control_type: ControlType::Class,
                    recipient: Recipient::Interface,
                    request: 0x01, // GET_ENCAPSULATED_RESPONSE
                    value: 0,
                    index: self.iface.interface_number() as u16,
                    length: 1024,
                },
                CTRL_TIMEOUT,
            )
            .wait()
            .map_err(usb_err("GET_ENCAPSULATED_RESPONSE"))
    }

    /// One command/response round trip. Polls for the reply instead of waiting
    /// on the interrupt endpoint; Android's gadget queues it synchronously.
    fn command(&mut self, m: &[u8], expect: u32) -> io::Result<Vec<u8>> {
        let id = le32(m, 8);
        self.send(m)?;
        for _ in 0..50 {
            if let Ok(r) = self.receive() {
                if r.len() >= 12 {
                    let t = le32(&r, 0);
                    if t == expect && le32(&r, 8) == id {
                        return Ok(r);
                    }
                    if t == MSG_KEEPALIVE {
                        let reply = msg(&[MSG_KEEPALIVE_C, 16, le32(&r, 8), 0]);
                        let _ = self.send(&reply);
                    }
                    // INDICATE_STATUS (link up/down) or a stale reply: keep polling.
                    if t == MSG_INDICATE || t != expect {
                        continue;
                    }
                }
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        Err(io::Error::new(
            io::ErrorKind::TimedOut,
            format!("phone did not answer RNDIS message {expect:#010x}"),
        ))
    }

    fn query(&mut self, oid: u32) -> io::Result<Vec<u8>> {
        let id = self.id();
        let r = self.command(&msg(&[MSG_QUERY, 28, id, oid, 0, 20, 0]), MSG_QUERY_C)?;
        parse_query_reply(&r).map_err(|e| io::Error::other(format!("QUERY {oid:#010x}: {e}")))
    }

    fn set(&mut self, oid: u32, value: &[u8]) -> io::Result<()> {
        let id = self.id();
        let mut m = msg(&[MSG_SET, 28 + value.len() as u32, id, oid, value.len() as u32, 20, 0]);
        m.extend_from_slice(value);
        let r = self.command(&m, MSG_SET_C)?;
        parse_set_reply(&r).map_err(|e| io::Error::other(format!("SET {oid:#010x}: {e}")))
    }

    /// INITIALIZE, learn the MAC the phone expects us to use, open the filter.
    pub fn bring_up(&mut self) -> io::Result<DeviceParams> {
        let mut init = None;
        for attempt in 1..=3 {
            let id = self.id();
            let m = msg(&[MSG_INIT, 24, id, 1, 0, RX_TRANSFER as u32]);
            match self.command(&m, MSG_INIT_C) {
                Ok(r) => {
                    init = Some(r);
                    break;
                }
                Err(e) if attempt == 3 => return Err(e),
                Err(_) => std::thread::sleep(Duration::from_secs(1)),
            }
        }
        let r = init.unwrap();
        if r.len() < 44 || le32(&r, 12) != 0 {
            return Err(io::Error::other("RNDIS INITIALIZE rejected"));
        }
        let max_packets_per_transfer = le32(&r, 32).max(1);
        let tx_max_transfer = le32(&r, 36);

        let mac: [u8; 6] = self
            .query(OID_802_3_PERMANENT_ADDRESS)?
            .get(..6)
            .and_then(|m| m.try_into().ok())
            .ok_or_else(|| io::Error::other("phone returned no MAC address"))?;
        let max_frame = self
            .query(OID_GEN_MAXIMUM_FRAME_SIZE)
            .ok()
            .filter(|v| v.len() >= 4)
            .map(|v| le32(&v, 0))
            .unwrap_or(1500);

        self.set(OID_GEN_CURRENT_PACKET_FILTER, &PACKET_FILTER.to_le_bytes())?;

        Ok(DeviceParams { tx_max_transfer, max_packets_per_transfer, mac, max_frame })
    }

    /// True when the phone reports its side of the link as connected.
    pub fn media_connected(&mut self) -> io::Result<bool> {
        let v = self.query(OID_GEN_MEDIA_CONNECT_STATUS)?;
        Ok(v.len() >= 4 && le32(&v, 0) == 0)
    }
}

// Replies come from the device, so every length and offset is untrusted.

/// The information buffer of a QUERY_CMPLT.
fn parse_query_reply(r: &[u8]) -> io::Result<Vec<u8>> {
    if r.len() < 24 {
        return Err(io::Error::other("reply too short"));
    }
    let status = le32(r, 12);
    if status != 0 {
        return Err(io::Error::other(format!("status {status:#x}")));
    }
    let len = le32(r, 16) as usize;
    let off = le32(r, 20) as usize + 8;
    off.checked_add(len)
        .and_then(|end| r.get(off..end))
        .map(<[u8]>::to_vec)
        .ok_or_else(|| io::Error::other("malformed reply"))
}

/// Status of a SET_CMPLT.
fn parse_set_reply(r: &[u8]) -> io::Result<()> {
    if r.len() < 16 {
        return Err(io::Error::other("reply too short"));
    }
    match le32(r, 12) {
        0 => Ok(()),
        status => Err(io::Error::other(format!("status {status:#x}"))),
    }
}

/// Append one Ethernet frame to `out` as an RNDIS_MSG_PACKET.
pub fn wrap_frame(out: &mut Vec<u8>, frame: &[u8]) {
    let len = frame.len() as u32;
    out.extend_from_slice(&msg(&[
        MSG_PACKET,
        PACKET_HEADER_LEN as u32 + len,
        (PACKET_HEADER_LEN - 8) as u32,
        len,
        0, 0, 0, 0, 0, 0, 0,
    ]));
    out.extend_from_slice(frame);
}

/// Walk every RNDIS_MSG_PACKET in one bulk transfer and yield its Ethernet frame.
pub fn for_each_frame(buf: &[u8], mut f: impl FnMut(&[u8])) {
    let mut off = 0;
    while off + PACKET_HEADER_LEN <= buf.len() {
        let m = &buf[off..];
        if le32(m, 0) != MSG_PACKET {
            break;
        }
        let mlen = le32(m, 4) as usize;
        if mlen < PACKET_HEADER_LEN || mlen > m.len() {
            break;
        }
        let doff = le32(m, 8) as usize + 8;
        let dlen = le32(m, 12) as usize;
        if doff + dlen <= mlen && dlen >= 14 {
            f(&m[doff..doff + dlen]);
        }
        off += mlen;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn short_or_bogus_replies_are_errors_not_panics() {
        for len in 0..40 {
            let r = vec![0xffu8; len];
            let _ = parse_query_reply(&r);
            let _ = parse_set_reply(&r);
        }
        // Offset/length pointing far outside the reply.
        let mut r = msg(&[MSG_QUERY_C, 24, 1, 0, u32::MAX, u32::MAX]);
        assert!(parse_query_reply(&r).is_err());
        r = msg(&[MSG_QUERY_C, 30, 1, 0, 6, 16]);
        r.extend_from_slice(&[1, 2, 3, 4, 5, 6]);
        assert_eq!(parse_query_reply(&r).unwrap(), vec![1, 2, 3, 4, 5, 6]);
        assert!(parse_set_reply(&msg(&[MSG_SET_C, 16, 1, 0])).is_ok());
    }

    #[test]
    fn frame_walker_survives_garbage() {
        let mut seed = 0x9e3779b97f4a7c15u64;
        for _ in 0..20_000 {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            let len = (seed % 200) as usize;
            let mut buf: Vec<u8> = (0..len).map(|i| (seed >> (i % 56)) as u8).collect();
            if len >= 16 && seed % 3 == 0 {
                buf[0..4].copy_from_slice(&MSG_PACKET.to_le_bytes());
            }
            for_each_frame(&buf, |f| assert!(f.len() >= 14));
        }
    }
}
