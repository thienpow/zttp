#!/bin/bash
set -e

# Configuration
# https://ziglang.org/builds/zig-x86_64-linux-0.15.0-dev.643+dc6ffc28b.tar.xz
ZIG_VERSION="0.15.0-dev.643+dc6ffc28b"
ZIG_URL="https://ziglang.org/builds/zig-x86_64-linux-${ZIG_VERSION}.tar.xz"
INSTALL_DIR="/usr/local/zig"  # Installation directory
BIN_LINK="/usr/local/bin/zig"  # Symlink location

# Color output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo -e "${YELLOW}Installing Zig ${ZIG_VERSION}...${NC}"

# Check if running as root
if [ "$(id -u)" -ne 0 ]; then
    echo -e "${RED}This script needs to be run as root!${NC}"
    echo -e "Please run with: ${YELLOW}sudo bash install_zig.sh${NC}"
    exit 1
fi

# Create temporary directory
TMP_DIR=$(mktemp -d)
cd "$TMP_DIR"

# Download Zig
echo -e "${YELLOW}Downloading Zig...${NC}"
wget "$ZIG_URL" -O "zig-x86_64-linux-${ZIG_VERSION}.tar.xz"

# Extract archive
echo -e "${YELLOW}Extracting...${NC}"
mkdir -p "$INSTALL_DIR"
tar -xf "zig-x86_64-linux-${ZIG_VERSION}.tar.xz"
cp -r "zig-x86_64-linux-${ZIG_VERSION}/"* "$INSTALL_DIR/"

# Create symlink
echo -e "${YELLOW}Creating symlink...${NC}"
if [ -L "$BIN_LINK" ]; then
    rm "$BIN_LINK"
fi
ln -s "$INSTALL_DIR/zig" "$BIN_LINK"

# Clean up
echo -e "${YELLOW}Cleaning up...${NC}"
cd
rm -rf "$TMP_DIR"

# Verify installation
if command -v zig >/dev/null 2>&1; then
    echo -e "${GREEN}Zig ${ZIG_VERSION} successfully installed!${NC}"
    echo -e "Installed version: $(zig version)"
else
    echo -e "${RED}Installation failed. 'zig' command not found.${NC}"
    exit 1
fi

echo -e "${GREEN}You can now use Zig with the 'zig' command.${NC}"
