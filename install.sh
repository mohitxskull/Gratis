#!/bin/sh
# Installs the gratis binary for the current architecture from the latest GitHub Release.
# Does NOT log in or set up the systemd service — that happens on first `gratis up`, which
# writes/starts the unit itself. This script only places a binary on PATH.
#
#   curl -fsSL https://raw.githubusercontent.com/mohitxskull/Gratis/main/install.sh | sh
set -eu

REPO="mohitxskull/Gratis"
INSTALL_DIR="${GRATIS_INSTALL_DIR:-$HOME/.local/bin}"

if [ "$(uname -s)" != "Linux" ]; then
    echo "gratis is Linux-only." >&2
    exit 1
fi

case "$(uname -m)" in
    x86_64) TARGET="x86_64-unknown-linux-gnu" ;;
    aarch64|arm64) TARGET="aarch64-unknown-linux-gnu" ;;
    *)
        echo "gratis has no release build for architecture $(uname -m)." >&2
        exit 1
        ;;
esac

echo "Fetching latest release info..."
LATEST_TAG=$(curl -fsSL "https://api.github.com/repos/$REPO/releases/latest" | \
    grep -m1 '"tag_name"' | sed -E 's/.*"tag_name": *"([^"]+)".*/\1/')
if [ -z "$LATEST_TAG" ]; then
    echo "Could not determine the latest release tag." >&2
    exit 1
fi

ASSET="gratis-${LATEST_TAG}-${TARGET}.tar.gz"
URL="https://github.com/$REPO/releases/download/$LATEST_TAG/$ASSET"

WORK_DIR=$(mktemp -d)
trap 'rm -rf "$WORK_DIR"' EXIT

echo "Downloading $ASSET..."
curl -fsSL "$URL" -o "$WORK_DIR/$ASSET"

tar xzf "$WORK_DIR/$ASSET" -C "$WORK_DIR"

mkdir -p "$INSTALL_DIR"
# Copy to a temp file in the same directory, then rename over the target — a plain `cp` onto
# the live path fails with "Text file busy" if the currently-installed gratis is running (its
# own service holds the file open for execution); rename doesn't have that problem since it
# never opens the destination for writing. Same trick `gratis update` already uses on itself
# (see src/update.rs's replace_running_binary), applied here too since this script hit the
# exact same failure live while gratis.service was active.
NEW_BIN=$(find "$WORK_DIR" -maxdepth 2 -type f -name gratis | head -n1)
if [ -z "$NEW_BIN" ]; then
    echo "Could not find a gratis binary in the downloaded release." >&2
    exit 1
fi
STAGED="$INSTALL_DIR/gratis.new"
cp "$NEW_BIN" "$STAGED"
chmod +x "$STAGED"
mv -f "$STAGED" "$INSTALL_DIR/gratis"

echo "Installed gratis $LATEST_TAG to $INSTALL_DIR/gratis"

case ":$PATH:" in
    *":$INSTALL_DIR:"*) ;;
    *)
        echo "Note: $INSTALL_DIR is not on your PATH. Add it, e.g.:"
        echo "  echo 'export PATH=\"$INSTALL_DIR:\$PATH\"' >> ~/.bashrc"
        ;;
esac

echo "Next: gratis login && gratis up"
