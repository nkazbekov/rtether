// RtetherBar — menu bar companion for rtether.
//
// Shows whether the phone is tethered over USB, live USB and Wi-Fi speeds,
// and the apps using the network, each with a bonding mode:
//   Off         everything over USB
//   Per server  each server sticks to one link (safe for logins)
//   Max         every connection picks the less busy link (fastest)
//
// Talks to the rtether service over /var/run/rtether.sock (admins only).

import SwiftUI

// MARK: - Wire format

struct PhoneInfo: Decodable { let ip: String; let router: String; let ifname: String }
struct WifiInfo: Decodable { let ifname: String; let up: Bool }

struct AppStatus: Decodable, Identifiable {
    let id: String
    let name: String
    let mode: String
    let flows: Int
    let usb_bytes: UInt64
    let wifi_bytes: UInt64
    let idle_secs: UInt64
}

struct Status: Decodable {
    let phone: PhoneInfo?
    let wifi: WifiInfo
    let usb_rx: UInt64
    let usb_tx: UInt64
    let wifi_rx: UInt64
    let wifi_tx: UInt64
    let apps: [AppStatus]
}

struct ErrorReply: Decodable { let error: String }

// MARK: - Control socket

enum ControlError: Error { case unavailable, refused(String), bad }

func control(_ request: [String: String]) throws -> Data {
    let fd = socket(AF_UNIX, SOCK_STREAM, 0)
    guard fd >= 0 else { throw ControlError.unavailable }
    defer { close(fd) }
    // A stuck service must not hang this thread, and a service that closes
    // early must not kill the app with SIGPIPE.
    var timeout = timeval(tv_sec: 2, tv_usec: 0)
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, socklen_t(MemoryLayout<timeval>.size))
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, socklen_t(MemoryLayout<timeval>.size))
    var one: Int32 = 1
    setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &one, socklen_t(MemoryLayout<Int32>.size))

    var addr = sockaddr_un()
    addr.sun_family = sa_family_t(AF_UNIX)
    let path = "/var/run/rtether.sock"
    withUnsafeMutableBytes(of: &addr.sun_path) { raw in
        path.utf8CString.withUnsafeBytes { src in
            raw.copyMemory(from: UnsafeRawBufferPointer(rebasing: src.prefix(raw.count - 1)))
        }
    }
    let ok = withUnsafePointer(to: &addr) {
        $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
            connect(fd, $0, socklen_t(MemoryLayout<sockaddr_un>.size))
        }
    }
    guard ok == 0 else { throw ControlError.unavailable }

    var line = try JSONSerialization.data(withJSONObject: request)
    line.append(0x0a)
    _ = line.withUnsafeBytes { write(fd, $0.baseAddress, line.count) }

    var reply = Data()
    var buf = [UInt8](repeating: 0, count: 65536)
    while true {
        let n = read(fd, &buf, buf.count)
        if n <= 0 { break }
        reply.append(contentsOf: buf[0..<n])
        if buf[n - 1] == 0x0a { break }
    }
    if let e = try? JSONDecoder().decode(ErrorReply.self, from: reply) { throw ControlError.refused(e.error) }
    return reply
}

// MARK: - Interface counters

/// Bytes in/out of a network interface (32-bit kernel counters; callers
/// take differences with wrapping arithmetic).
func interfaceBytes(_ name: String) -> (UInt32, UInt32)? {
    var ifap: UnsafeMutablePointer<ifaddrs>?
    guard getifaddrs(&ifap) == 0, let first = ifap else { return nil }
    defer { freeifaddrs(ifap) }
    for p in sequence(first: first, next: { $0.pointee.ifa_next }) {
        let ifa = p.pointee
        guard let addr = ifa.ifa_addr, addr.pointee.sa_family == UInt8(AF_LINK),
              String(cString: ifa.ifa_name) == name, let data = ifa.ifa_data else { continue }
        let d = data.assumingMemoryBound(to: if_data.self).pointee
        return (d.ifi_ibytes, d.ifi_obytes)
    }
    return nil
}

// MARK: - Model

@MainActor
final class Model: ObservableObject {
    @Published var status: Status?
    @Published var problem: String?
    // Live rates in Mbps.
    @Published var usbDown = 0.0
    @Published var usbUp = 0.0
    @Published var wifiDown = 0.0   // all Wi-Fi traffic, from the interface
    @Published var wifiUp = 0.0
    @Published var relayDown = 0.0  // the part rtether relays for bonded apps
    @Published var relayUp = 0.0
    @Published var showAll = false

    private var last: (Status, Date)?
    /// Replies can arrive out of order (timer vs. a mode change); only the
    /// newest request's reply is applied, and the timer skips while one is
    /// outstanding.
    private var requested = 0
    private var applied = 0
    private var inFlight = false
    private var lastWifi: (UInt32, UInt32, Date)?
    private var timer: Timer?

    init() {
        refresh()
        timer = Timer.scheduledTimer(withTimeInterval: 1, repeats: true) { [weak self] _ in
            Task { @MainActor in self?.refresh() }
        }
    }

    func refresh(force: Bool = false) {
        if inFlight && !force { return }
        inFlight = true
        requested += 1
        let seq = requested
        Task.detached {
            let result = Result { try JSONDecoder().decode(Status.self, from: control(["cmd": "status"])) }
            await MainActor.run { self.apply(result, seq: seq) }
        }
    }

    private func apply(_ result: Result<Status, Error>, seq: Int) {
        if seq == requested { inFlight = false }
        guard seq > applied else { return }
        applied = seq
        switch result {
        case .success(let s):
            let now = Date()
            if let (prev, at) = last {
                let dt = max(now.timeIntervalSince(at), 0.2)
                func mbps(_ a: UInt64, _ b: UInt64) -> Double { Double(a &- b) * 8 / dt / 1_000_000 }
                usbDown = s.usb_rx >= prev.usb_rx ? mbps(s.usb_rx, prev.usb_rx) : 0
                usbUp = s.usb_tx >= prev.usb_tx ? mbps(s.usb_tx, prev.usb_tx) : 0
                relayDown = s.wifi_rx >= prev.wifi_rx ? mbps(s.wifi_rx, prev.wifi_rx) : 0
                relayUp = s.wifi_tx >= prev.wifi_tx ? mbps(s.wifi_tx, prev.wifi_tx) : 0
            }
            // Wi-Fi: everything on the interface, including apps that use
            // Wi-Fi directly (e.g. torrent clients that bind every address).
            if let (rx, tx) = interfaceBytes(s.wifi.ifname) {
                if let (prx, ptx, at) = lastWifi {
                    let dt = max(now.timeIntervalSince(at), 0.2)
                    wifiDown = Double(rx &- prx) * 8 / dt / 1_000_000
                    wifiUp = Double(tx &- ptx) * 8 / dt / 1_000_000
                }
                lastWifi = (rx, tx, now)
            }
            last = (s, now)
            status = s
            problem = nil
        case .failure(ControlError.refused(let why)):
            problem = "rtether refused the connection (\(why)). Only admin users can change settings."
        case .failure:
            problem = "rtether is not running. Install it with sudo ./install.sh"
            status = nil
        }
    }

    func setMode(_ app: AppStatus, _ mode: String) {
        Task.detached {
            _ = try? control(["cmd": "set_mode", "app": app.id, "mode": mode])
            await MainActor.run { self.refresh(force: true) }
        }
    }

    var bondingActive: Bool {
        guard let s = status, s.phone != nil, s.wifi.up else { return false }
        return s.apps.contains { $0.mode != "off" }
    }

    /// Configured apps first, then recently active ones by traffic.
    var visibleApps: [AppStatus] {
        guard let apps = status?.apps else { return [] }
        let configured = apps.filter { $0.mode != "off" }.sorted { $0.name < $1.name }
        let recent = apps
            .filter { $0.mode == "off" && (showAll || $0.idle_secs < 300) }
            .sorted { $0.usb_bytes + $0.wifi_bytes > $1.usb_bytes + $1.wifi_bytes }
        return configured + recent.prefix(showAll ? 200 : 12)
    }
}

// MARK: - Views

/// "97 Mbps · 12.1 MB/s" — megabits for link speed, megabytes for downloads.
func rate(_ mbps: Double) -> String {
    let bits = mbps >= 10 ? String(format: "%.0f Mbps", mbps) : String(format: "%.1f Mbps", mbps)
    let bytes = mbps / 8
    let mbs = bytes >= 10 ? String(format: "%.0f MB/s", bytes) : String(format: "%.1f MB/s", bytes)
    return bits + " · " + mbs
}

func bytes(_ b: UInt64) -> String {
    ByteCountFormatter.string(fromByteCount: Int64(clamping: b), countStyle: .file)
}

struct LinkRow: View {
    let icon: String
    let title: String
    let detail: String
    let down: Double
    let up: Double
    let active: Bool

    var body: some View {
        HStack(spacing: 10) {
            Image(systemName: icon).frame(width: 18).foregroundStyle(active ? Color.accentColor : .secondary)
            VStack(alignment: .leading, spacing: 1) {
                Text(title).font(.system(size: 13, weight: .semibold))
                Text(detail).font(.system(size: 11)).foregroundStyle(.secondary)
            }
            Spacer()
            if active {
                VStack(alignment: .trailing, spacing: 1) {
                    Text("↓ " + rate(down)).monospacedDigit()
                    Text("↑ " + rate(up)).monospacedDigit().foregroundStyle(.secondary)
                }
                .font(.system(size: 11))
            }
        }
    }
}

/// An indented breakdown line under a link, e.g. "via rtether".
struct SplitRow: View {
    let title: String
    let down: Double
    let up: Double

    var body: some View {
        HStack {
            Text(title).foregroundStyle(.secondary)
            Spacer()
            Text("↓ " + rate(down)).monospacedDigit()
            Text("↑ " + rate(up)).monospacedDigit().foregroundStyle(.secondary)
        }
        .font(.system(size: 11))
        .padding(.leading, 28)
    }
}

struct AppRow: View {
    static let height: CGFloat = 34
    let app: AppStatus
    let onChange: (String) -> Void

    var body: some View {
        HStack(spacing: 8) {
            VStack(alignment: .leading, spacing: 1) {
                Text(app.name).font(.system(size: 12, weight: .medium)).lineLimit(1)
                Text("USB \(bytes(app.usb_bytes)) · Wi-Fi \(bytes(app.wifi_bytes))")
                    .font(.system(size: 10)).foregroundStyle(.secondary).lineLimit(1)
            }
            .help(app.id)
            Spacer(minLength: 4)
            Picker("", selection: Binding(get: { app.mode }, set: onChange)) {
                Text("Off").tag("off")
                Text("Per server").tag("per_server")
                Text("Max").tag("per_connection")
            }
            .pickerStyle(.segmented)
            .labelsHidden()
            .frame(width: 190)
        }
    }
}

struct Panel: View {
    @ObservedObject var model: Model

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            if let problem = model.problem {
                Text(problem).font(.system(size: 12)).foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
            if let s = model.status {
                LinkRow(icon: "cable.connector", title: "USB",
                        detail: s.phone.map { "Phone \($0.router) · \($0.ip)" } ?? "Turn on USB tethering on the phone",
                        down: model.usbDown, up: model.usbUp, active: s.phone != nil)
                LinkRow(icon: "wifi", title: "Wi-Fi",
                        detail: s.wifi.up ? "All Wi-Fi traffic" : "Not connected",
                        down: model.wifiDown, up: model.wifiUp, active: s.wifi.up)
                if s.wifi.up {
                    // rtether's relay counts payload and the interface counts
                    // frames, so "direct" is the remainder, never below zero.
                    SplitRow(title: "via rtether (bonded apps)", down: model.relayDown, up: model.relayUp)
                    SplitRow(title: "direct (apps' own Wi-Fi)",
                             down: max(model.wifiDown - model.relayDown, 0),
                             up: max(model.wifiUp - model.relayUp, 0))
                }

                Divider()
                HStack {
                    Text("Apps").font(.system(size: 12, weight: .semibold))
                    Spacer()
                    Toggle("Show all", isOn: $model.showAll).toggleStyle(.checkbox).font(.system(size: 11))
                }
                if s.phone == nil {
                    Text("Bonding starts when the phone is tethered.").font(.system(size: 11)).foregroundStyle(.secondary)
                }
                // A ScrollView has no natural height inside a menu bar panel,
                // so size it to its rows (up to ten) and scroll beyond that.
                let apps = model.visibleApps
                ScrollView {
                    VStack(alignment: .leading, spacing: 8) {
                        ForEach(apps) { app in
                            AppRow(app: app) { model.setMode(app, $0) }
                                .frame(height: AppRow.height)
                        }
                    }
                    .padding(.trailing, 6)
                }
                .frame(height: CGFloat(min(apps.count, 10)) * (AppRow.height + 8))
                Text("Per server keeps each website on one link, so logins stay put. Max spreads every connection.")
                    .font(.system(size: 10)).foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
            Divider()
            Button("Quit RtetherBar") { NSApplication.shared.terminate(nil) }
                .buttonStyle(.plain).font(.system(size: 12))
        }
        .padding(14)
        .frame(width: 460)
    }
}

@main
struct RtetherBar: App {
    @StateObject private var model = Model()

    var body: some Scene {
        MenuBarExtra {
            Panel(model: model)
        } label: {
            Image(systemName: model.status?.phone == nil ? "cable.connector.slash"
                  : model.bondingActive ? "bolt.horizontal.circle" : "cable.connector")
        }
        .menuBarExtraStyle(.window)
    }
}
