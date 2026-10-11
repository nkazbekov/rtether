# rtether

USB tethering from a Samsung (or other RNDIS) Android phone to macOS, plus
optional per-app bonding of USB and Wi-Fi.

macOS has no driver for RNDIS, the protocol Samsung's USB tethering uses, so
the phone shows up on USB and nothing happens. rtether is a userspace driver:
it claims the phone's RNDIS interfaces through IOKit (via `nusb`), speaks
RNDIS, gets an address from the phone over DHCP, and routes the Mac's traffic
through a `utun` interface. Nothing is installed on the phone, and USB
debugging is not needed.

Measured on a Galaxy S23 Ultra over a USB 3 cable: about 1.1 Gbps phone→Mac
and 340 Mbps Mac→phone across the cable itself, so the mobile network is
always the limit.

> **Status: experimental.** Tested on one Galaxy S23 Ultra (One UI 8 /
> Android 16) and one Apple Silicon Mac on macOS 26. It runs as a root
> service and changes your Mac's routing. Read [Limitations](#limitations)
> before relying on it.

## Build and install

You need Rust (`brew install rustup && rustup default stable`, or
[rustup.rs](https://rustup.rs)) and Apple's command-line tools
(`xcode-select --install`). `./build.sh` checks for both and tells you what is
missing.

```sh
./build.sh            # builds the service and the menu bar app, runs the tests
sudo ./install.sh     # installs both; the service starts at boot
```

Builds are unsigned and made on your Mac. Nothing is downloaded at run time.

Then turn on **USB tethering** on the phone (with mobile data on). The Mac
switches to it within a few seconds, even with Wi-Fi connected. Unplug the
cable or turn tethering off and the Mac falls back to Wi-Fi.

| Command | What it does |
| --- | --- |
| `sudo rtether stop` | stop it until the next boot, restore normal networking |
| `sudo rtether start` | start the background service again |
| `sudo rtether` | run in the foreground instead (Ctrl+C to stop) |
| `sudo rtether --test` | link up, but only sockets bound to the interface use it |
| `sudo ./uninstall.sh` | remove the service, the binary and the menu bar app |

Log: `/var/log/rtether.log` (admins only, rotated at 1 MB). While
`/var/run/rtether.debug` exists (`sudo touch` it), every bonding decision is
logged too.

## Bonding: USB and Wi-Fi together, per app

With the tether up and Wi-Fi connected, chosen apps can use both links at
once. Pick them in **RtetherBar**, the menu bar app:

| Mode | What it does |
| --- | --- |
| Off | the app uses USB only (the default) |
| Per server | each server sticks to one link; different servers spread out. Safe for logins |
| Max | every new connection takes the less busy link. Fastest; a site may see two IPs |

How it works (`src/bond.rs`): each new flow is matched to its app through the
kernel's socket table (`src/procinfo.rs`). Flows of bonded apps that land on
Wi-Fi are diverted into a userspace TCP/IP stack (`ipstack`) and re-originated
from a socket pinned to Wi-Fi with `IP_BOUND_IF`. Everything else goes to the
phone untouched. Only connections to public addresses are split; the phone
itself (DNS) and private networks always stay on USB.

Speeding up one connection is impossible this way, since each link has its own
public IP. Bonding helps apps that open many connections.

Side effect: to make pinned sockets work, rtether adds a Wi-Fi default route
scoped to the Wi-Fi interface while the tether is up. Apps that pin sockets to
Wi-Fi themselves can use Wi-Fi directly too. qBittorrent (libtorrent) does this:
it opens sockets on every local address and spreads peers across them, so it
uses both links with no bonding set. That is intentional here. RtetherBar's
Wi-Fi speed counts all Wi-Fi traffic, so you see it.

Settings live in `/Library/Application Support/rtether/config.json`. RtetherBar
talks to the service over `/var/run/rtether.sock`, which answers only root and
members of the `admin` group (checked with `getpeereid`).

## How it stays safe

- The routes are two `/1` routes on the `utun` interface. They override the
  default route without replacing it, and the kernel deletes them with the
  interface, so Wi-Fi's own route is back the instant rtether stops.
- DNS is registered with `configd` (`scutil`). It is removed on normal exit, and
  a detached guard process removes it even if rtether is killed outright.
- When the phone disappears, the session ends, networking is restored, and
  rtether waits for the phone to come back.

## Limitations

- **IPv4 only.** IPv6 is not carried over the tether. Apps that prefer IPv6 use
  Wi-Fi's IPv6 if it has any.
- **One phone at a time**, on RNDIS. Phones that already use NCM (Pixels, for
  example) work on macOS without this.
- **Root service.** It parses everything the phone sends. Inputs are
  bounds-checked and fuzz-tested, and a crash ends the session without taking
  the service down, but it is still a root process talking to a USB device.
- **App detection** reads an undocumented kernel structure
  (`net.inet.*.pcblist_n`), verified on macOS 26. A future macOS could change
  it. Bonding would then stop recognising apps, and plain tethering keeps
  working.
- **Bonding cannot speed up a single connection.** See above.
- **Sleep/wake and many phone models are untested.** Reports are welcome.
- If the phone's own Wi-Fi is on, Android tethers through that Wi-Fi rather
  than mobile data. Bonding then gains nothing, because both links end at the
  same router.

## Android gadget quirks it works around

See `src/rndis.rs`. In short: never send a zero-length USB packet (pad by one
byte instead), never issue `SET_INTERFACE` or `HALT`, and set the packet
filter or nothing flows. erg-tether's `docs/protocol.md` and Linux's
`drivers/net/usb/rndis_host.c` document these.

On Samsung, keep `settings global tether_force_usb_functions` at `0`. With `1`
the phone tries NCM, names the interface `usb0` (tethering expects `ncm0`),
and switches USB tethering off again immediately.

## Acknowledgements

- [erg-tether](https://github.com/ergdevops/erg-tether) (Apache-2.0). Its
  protocol notes on Android's RNDIS gadget (zero-length packets,
  `SET_INTERFACE`, `HALT`, the packet filter) saved a lot of debugging. No
  code was copied.
- Linux's `drivers/net/usb/rndis_host.c`, the reference for RNDIS device
  quirks.
- [nusb](https://github.com/kevinmehall/nusb) for USB access and
  [ipstack](https://github.com/narrowlink/ipstack) for the userspace TCP/IP
  stack used by bonding.

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or
[MIT license](LICENSE-MIT), at your option.
