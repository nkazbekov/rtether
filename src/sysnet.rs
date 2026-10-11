//! macOS network configuration for the tether, and the guarantees that it is
//! undone: on normal exit (Drop), on Ctrl+C, and — via a detached guard
//! process — even if this process is killed outright.

use std::io::{self, Write};
use std::os::unix::process::CommandExt;
use std::process::{Command, Stdio};

use crate::packet::Lease;

const SVC: &str = "State:/Network/Service/rtether";
const SPLIT_DEFAULT: [&str; 2] = ["0.0.0.0/1", "128.0.0.0/1"];

fn run(cmd: &str, args: &[&str]) -> io::Result<()> {
    let out = Command::new(cmd).args(args).stdin(Stdio::null()).output()?;
    if !out.status.success() {
        return Err(io::Error::other(format!(
            "{cmd} {}: {}",
            args.join(" "),
            String::from_utf8_lossy(&out.stderr).trim()
        )));
    }
    Ok(())
}

fn scutil(script: &str) -> io::Result<()> {
    let mut child = Command::new("/usr/sbin/scutil")
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .spawn()?;
    child.stdin.take().unwrap().write_all(script.as_bytes())?;
    child.wait()?;
    Ok(())
}

/// Drop our DNS/service registration. Safe to call when none exists.
pub fn remove_dns() {
    let _ = scutil(&format!("remove {SVC}/IPv4\nremove {SVC}/DNS\n"));
}

/// Watch this process from a detached shell and remove the DNS registration
/// once it is gone, however it died. Routes need no guard: they live on the
/// utun interface, which the kernel destroys with the process.
pub fn spawn_guard() -> io::Result<()> {
    let pid = std::process::id();
    // If a new rtether is already up by the time we notice the old one is
    // gone, the DNS entry is the new one's: leave it.
    let script = format!(
        "while kill -0 {pid} 2>/dev/null; do sleep 1; done; \
         /usr/bin/pgrep -qx rtether || \
         printf 'remove {SVC}/IPv4\\nremove {SVC}/DNS\\n' | /usr/sbin/scutil"
    );
    unsafe {
        Command::new("/bin/sh")
            .arg("-c")
            .arg(script)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .pre_exec(|| {
                libc::setsid();
                Ok(())
            })
            .spawn()?;
    }
    Ok(())
}

/// The tether's addresses, routes and DNS, removed again on drop.
pub struct NetConfig {
    ifname: String,
}

impl NetConfig {
    /// `test`: only sockets bound to the interface use it (scoped default
    /// route, no DNS change), so the rest of the Mac keeps its connection.
    pub fn apply(ifname: &str, lease: &Lease, mtu: u32, test: bool) -> io::Result<NetConfig> {
        // Constructed first so a failure part-way through still cleans up.
        let cfg = NetConfig { ifname: ifname.to_string() };
        let (ip, router) = (lease.ip.to_string(), lease.router.to_string());

        // Point-to-point to the phone: everything we send goes to it anyway.
        run(
            "/sbin/ifconfig",
            &[ifname, "inet", &ip, &router, "netmask", "255.255.255.255", "mtu", &mtu.to_string(), "up"],
        )?;
        if test {
            run("/sbin/route", &["-q", "-n", "add", "-ifscope", ifname, "default", &router])?;
            return Ok(cfg);
        }

        // Two /1 routes beat the existing default without replacing it, so
        // Wi-Fi's own route comes back untouched the moment we go away.
        for net in SPLIT_DEFAULT {
            run("/sbin/route", &["-q", "-n", "add", "-net", net, "-interface", ifname])?;
        }

        // Register with configd so DNS works (and apps see a network) even
        // with Wi-Fi off. The phone runs a DNS proxy at its own address.
        let dns = lease.dns.iter().map(|d| d.to_string()).collect::<Vec<_>>().join(" ");
        scutil(&format!(
            "d.init\n\
             d.add Addresses * {ip}\n\
             d.add DestAddresses * {router}\n\
             d.add InterfaceName {ifname}\n\
             d.add Router {router}\n\
             set {SVC}/IPv4\n\
             d.init\n\
             d.add ServerAddresses * {dns}\n\
             d.add SupplementalMatchDomains * \"\"\n\
             set {SVC}/DNS\n"
        ))?;
        Ok(cfg)
    }
}

impl Drop for NetConfig {
    fn drop(&mut self) {
        remove_dns();
        for net in SPLIT_DEFAULT {
            let _ = run("/sbin/route", &["-q", "-n", "delete", "-net", net, "-interface", &self.ifname]);
        }
    }
}
