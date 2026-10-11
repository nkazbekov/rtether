#!/bin/sh
# Build rtether (the service) and RtetherBar (the menu bar app), run the
# tests, and say what to do next. Run as yourself, not with sudo.
#
# Usage: ./build.sh            build + test
#        ./build.sh --no-test  build only
set -e
cd "$(dirname "$0")"

if [ "$(id -u)" -eq 0 ]; then
    echo "Run ./build.sh without sudo (a root-owned build folder gets in the way later)."
    echo "Only the install step needs sudo: sudo ./install.sh"
    exit 1
fi

missing=0

# Rust: on PATH, from rustup's default location, or Homebrew's keg-only rustup.
for dir in "$HOME/.cargo/bin" /opt/homebrew/opt/rustup/bin /usr/local/opt/rustup/bin; do
    [ -x "$dir/cargo" ] && PATH="$dir:$PATH"
done
if ! command -v cargo >/dev/null 2>&1; then
    echo "Rust is not installed. Install it with one of:"
    echo "    brew install rustup && rustup default stable"
    echo "    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh"
    missing=1
elif ! cargo --version >/dev/null 2>&1; then
    echo "Rust is installed but has no toolchain yet. Run:  rustup default stable"
    missing=1
fi

# Swift compiler, for the menu bar app (Xcode or the Command Line Tools).
if ! xcrun --find swiftc >/dev/null 2>&1; then
    echo "Apple's command-line developer tools are missing. Install them with:"
    echo "    xcode-select --install"
    missing=1
fi

[ "$missing" -eq 0 ] || exit 1

echo "==> Building rtether ($(cargo --version))"
cargo build --release

if [ "$1" != "--no-test" ]; then
    echo "==> Running tests"
    cargo test --release --quiet
fi

echo "==> Building RtetherBar"
bar/build.sh

echo
echo "Done. To install the service and the menu bar app:"
echo "    sudo ./install.sh"
