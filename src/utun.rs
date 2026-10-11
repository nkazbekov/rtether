//! macOS utun interface: a layer-3 tunnel device. Every packet read or
//! written carries a 4-byte address-family prefix (AF_INET, big-endian).

use std::ffi::CStr;
use std::io;
use std::mem;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

pub struct Utun {
    fd: OwnedFd,
    pub name: String,
}

impl Utun {
    pub fn open() -> io::Result<Utun> {
        unsafe {
            let raw = libc::socket(libc::PF_SYSTEM, libc::SOCK_DGRAM, libc::SYSPROTO_CONTROL);
            if raw < 0 {
                return Err(io::Error::last_os_error());
            }
            let fd = OwnedFd::from_raw_fd(raw);

            let mut info: libc::ctl_info = mem::zeroed();
            let ctl = b"com.apple.net.utun_control";
            for (d, s) in info.ctl_name.iter_mut().zip(ctl) {
                *d = *s as libc::c_char;
            }
            if libc::ioctl(raw, libc::CTLIOCGINFO, &mut info) < 0 {
                return Err(io::Error::last_os_error());
            }

            let mut addr: libc::sockaddr_ctl = mem::zeroed();
            addr.sc_len = mem::size_of::<libc::sockaddr_ctl>() as u8;
            addr.sc_family = libc::AF_SYSTEM as u8;
            addr.ss_sysaddr = libc::AF_SYS_CONTROL as u16;
            addr.sc_id = info.ctl_id;
            addr.sc_unit = 0; // let the kernel pick the next free utunN
            if libc::connect(
                raw,
                &addr as *const _ as *const libc::sockaddr,
                mem::size_of::<libc::sockaddr_ctl>() as libc::socklen_t,
            ) < 0
            {
                return Err(io::Error::last_os_error());
            }

            let mut name = [0 as libc::c_char; libc::IFNAMSIZ];
            let mut len = name.len() as libc::socklen_t;
            if libc::getsockopt(
                raw,
                libc::SYSPROTO_CONTROL,
                libc::UTUN_OPT_IFNAME,
                name.as_mut_ptr().cast(),
                &mut len,
            ) < 0
            {
                return Err(io::Error::last_os_error());
            }
            let name = CStr::from_ptr(name.as_ptr()).to_string_lossy().into_owned();

            let flags = libc::fcntl(raw, libc::F_GETFL);
            libc::fcntl(raw, libc::F_SETFL, flags | libc::O_NONBLOCK);

            Ok(Utun { fd, name })
        }
    }

    /// Wait up to `timeout_ms` for a packet to be readable.
    pub fn wait_readable(&self, timeout_ms: i32) -> bool {
        let mut p = libc::pollfd { fd: self.fd.as_raw_fd(), events: libc::POLLIN, revents: 0 };
        unsafe { libc::poll(&mut p, 1, timeout_ms) > 0 && p.revents & libc::POLLIN != 0 }
    }

    /// Read one IPv4 packet into `buf` (after the AF prefix). Ok(None) = nothing ready.
    pub fn read_ipv4<'a>(&self, buf: &'a mut [u8]) -> io::Result<Option<&'a [u8]>> {
        loop {
            let n = unsafe { libc::read(self.fd.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len()) };
            if n < 0 {
                let e = io::Error::last_os_error();
                return match e.kind() {
                    io::ErrorKind::WouldBlock => Ok(None),
                    io::ErrorKind::Interrupted => continue,
                    _ => Err(e),
                };
            }
            let n = n as usize;
            if n > 4 && buf[3] == libc::AF_INET as u8 {
                return Ok(Some(&buf[4..n]));
            }
            // IPv6 or runt: we only carry IPv4, try the next packet.
        }
    }

    pub fn write_ipv4(&self, pkt: &[u8]) -> io::Result<()> {
        let af = (libc::AF_INET as u32).to_be_bytes();
        let iov = [
            libc::iovec { iov_base: af.as_ptr() as *mut _, iov_len: 4 },
            libc::iovec { iov_base: pkt.as_ptr() as *mut _, iov_len: pkt.len() },
        ];
        let n = unsafe { libc::writev(self.fd.as_raw_fd(), iov.as_ptr(), 2) };
        if n < 0 {
            let e = io::Error::last_os_error();
            // The kernel drops when its queue is full; that is congestion, not failure.
            if e.raw_os_error() == Some(libc::ENOBUFS) || e.kind() == io::ErrorKind::WouldBlock {
                return Ok(());
            }
            return Err(e);
        }
        Ok(())
    }

}
