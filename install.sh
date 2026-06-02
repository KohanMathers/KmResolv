#!/usr/bin/env bash
set -euo pipefail

REPO="kohanmathers/kmresolv"
INSTALL_DIR="/etc/kmresolv"
SERVICE_NAME="kmresolv"
BINARY_NAME="kmresolv"
JAR_NAME="kmresolv-1.0.0-SNAPSHOT.jar"
CONFIG_NAME="config.yml"
POLAR_NAME="kmresolv.polar"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
RESET='\033[0m'

info()    { echo -e "${CYAN}[*]${RESET} $*"; }
success() { echo -e "${GREEN}[✓]${RESET} $*"; }
warn()    { echo -e "${YELLOW}[!]${RESET} $*"; }
error()   { echo -e "${RED}[✗]${RESET} $*" >&2; exit 1; }

require_root() {
    if [[ $EUID -ne 0 ]]; then
        error "This script must be run as root. Try: sudo $0"
    fi
}

detect_distro() {
    if [[ -f /etc/os-release ]]; then
        # shellcheck source=/dev/null
        source /etc/os-release
        echo "${ID:-unknown}"
    else
        echo "unknown"
    fi
}

detect_arch() {
    case "$(uname -m)" in
        x86_64)  echo "amd64" ;;
        aarch64) echo "arm64" ;;
        armv7l)  echo "armv7" ;;
        *)       error "Unsupported architecture: $(uname -m)" ;;
    esac
}

fetch_latest_release_url() {
    local asset="$1"
    local api_url="https://api.github.com/repos/${REPO}/releases/latest"
    local download_url

    if command -v curl &>/dev/null; then
        download_url=$(curl -fsSL "$api_url" \
            | grep -o "\"browser_download_url\": *\"[^\"]*${asset}[^\"]*\"" \
            | head -1 \
            | sed 's/.*": *"\(.*\)"/\1/')
    elif command -v wget &>/dev/null; then
        download_url=$(wget -qO- "$api_url" \
            | grep -o "\"browser_download_url\": *\"[^\"]*${asset}[^\"]*\"" \
            | head -1 \
            | sed 's/.*": *"\(.*\)"/\1/')
    else
        error "Neither curl nor wget found. Please install one and retry."
    fi

    if [[ -z "$download_url" ]]; then
        error "Could not find asset '${asset}' in the latest release of ${REPO}."
    fi

    echo "$download_url"
}

download() {
    local url="$1"
    local dest="$2"
    info "Downloading $(basename "$dest") ..."
    if command -v curl &>/dev/null; then
        curl -fsSL -o "$dest" "$url"
    else
        wget -qO "$dest" "$url"
    fi
}

install_openjdk25() {
    local distro
    distro=$(detect_distro)

    info "Installing OpenJDK 25 for distro: ${distro}"

    case "$distro" in
        ubuntu|debian|linuxmint|pop)
            apt-get update -qq
            apt-get install -y openjdk-25-jdk
            ;;
        fedora)
            dnf install -y java-25-openjdk-devel
            ;;
        rhel|centos|rocky|almalinux)
            dnf install -y java-25-openjdk-devel || \
                yum install -y java-25-openjdk-devel
            ;;
        arch|manjaro|endeavouros)
            pacman -Sy --noconfirm jdk25-openjdk
            ;;
        opensuse*|sles)
            zypper install -y java-25-openjdk-devel
            ;;
        void)
            xbps-install -Sy openjdk25
            ;;
        alpine)
            apk add --no-cache openjdk25
            ;;
        *)
            warn "Unknown distro '${distro}'. Attempting apt-get as fallback."
            apt-get update -qq && apt-get install -y openjdk-25-jdk || \
                error "Could not install OpenJDK 25 automatically. Please install it manually."
            ;;
    esac

    success "OpenJDK 25 installed."
}

prompt_java() {
    echo
    echo -e "${BOLD}Java Installation${RESET}"
    echo "  Do you want to install OpenJDK 25 (required for the Minecraft dashboard)?"
    echo "  Disable this if you already have JDK 25+ installed or do not want to install it."
    echo
    read -rp "  Install OpenJDK 25? [y/N]: " answer </dev/tty
    case "${answer,,}" in
        y|Y|yes) return 0 ;;
        *)     return 1 ;;
    esac
}

setup_path() {
    local marker="# kmresolv PATH"
    local export_line="export PATH=\"${INSTALL_DIR}:\$PATH\""

    local profile_d="/etc/profile.d/kmresolv.sh"
    if [[ ! -f "$profile_d" ]]; then
        printf '%s\n%s\n' "$marker" "$export_line" > "$profile_d"
        chmod 644 "$profile_d"
        success "Added ${INSTALL_DIR} to PATH via ${profile_d}"
    fi

    if command -v fish &>/dev/null || [[ -d /etc/fish/conf.d ]]; then
        mkdir -p /etc/fish/conf.d
        local fish_conf="/etc/fish/conf.d/kmresolv.fish"
        if [[ ! -f "$fish_conf" ]]; then
            printf '%s\nfish_add_path "%s"\n' "$marker" "${INSTALL_DIR}" > "$fish_conf"
            success "Added ${INSTALL_DIR} to PATH via ${fish_conf}"
        fi
    fi

    local real_home=""
    if [[ -n "${SUDO_USER:-}" ]]; then
        real_home=$(getent passwd "$SUDO_USER" | cut -d: -f6)
    fi
    if [[ -z "$real_home" && -n "${HOME:-}" ]]; then
        real_home="$HOME"
    fi

    if [[ -n "$real_home" ]]; then
        for rc in "$real_home/.bashrc" "$real_home/.zshrc"; do
            if [[ -f "$rc" ]] && ! grep -qF "$marker" "$rc"; then
                printf '\n%s\n%s\n' "$marker" "$export_line" >> "$rc"
                success "Added ${INSTALL_DIR} to PATH in ${rc}"
            fi
        done

        local fish_user_conf="$real_home/.config/fish/conf.d/kmresolv.fish"
        if [[ -d "$real_home/.config/fish" ]] && [[ ! -f "$fish_user_conf" ]]; then
            mkdir -p "$real_home/.config/fish/conf.d"
            printf '%s\nfish_add_path "%s"\n' "$marker" "${INSTALL_DIR}" > "$fish_user_conf"
            success "Added ${INSTALL_DIR} to PATH in ${fish_user_conf}"
        fi
    fi
}

check_port_53() {
    local occupied
    occupied=$(ss -tulpn 2>/dev/null | grep -E '\s:53\s' || true)
    if [[ -n "$occupied" ]]; then
        local proc
        proc=$(echo "$occupied" | grep -oP '"[^"]+"' | head -1 | tr -d '"')
        [[ -z "$proc" ]] && proc="another process"
        error "Port 53 is already in use by ${proc}.\n  Stop it before starting kmresolv. If using systemd-resolved:\n    sudo systemctl disable --now systemd-resolved\n    echo 'nameserver 127.0.0.1' | sudo tee /etc/resolv.conf"
    fi
}

write_service() {
    local binary="$1"
    local dest="${2:-/etc/systemd/system/${SERVICE_NAME}.service}"
    cat > "$dest" <<EOF
[Unit]
Description=kmresolv DNS resolver and dashboard
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=${binary} serve --config ${INSTALL_DIR}/config.yml
WorkingDirectory=${INSTALL_DIR}
Restart=on-failure
RestartSec=5
StandardOutput=journal
StandardError=journal
SyslogIdentifier=kmresolv

User=root

[Install]
WantedBy=multi-user.target
EOF
    if [[ "$dest" == "/etc/systemd/system/${SERVICE_NAME}.service" ]]; then
        success "systemd service written to $dest"
    fi
}

merge_config() {
    local existing="$1"
    local new_template="$2"

    if ! command -v python3 &>/dev/null; then
        warn "python3 not found — cannot check for new config options."
        warn "Compare ${existing} with the latest config.yml manually."
        return
    fi

    if ! python3 -c "import yaml" 2>/dev/null; then
        warn "PyYAML not available — cannot check for new config options."
        warn "Install it with: pip3 install pyyaml"
        return
    fi

    local added
    added=$(python3 - "$existing" "$new_template" <<'PYEOF'
import sys, yaml

with open(sys.argv[1]) as f:
    existing = yaml.safe_load(f) or {}
with open(sys.argv[2]) as f:
    template = yaml.safe_load(f) or {}

missing = {k: v for k, v in template.items() if k not in existing}
if not missing:
    sys.exit(0)

with open(sys.argv[1], 'a') as f:
    f.write('\n# Options added by kmresolv update — review and adjust as needed\n')
    yaml.dump(missing, f, default_flow_style=False, allow_unicode=True)

print(' '.join(missing.keys()))
PYEOF
    )

    if [[ -n "$added" ]]; then
        success "Added new config option(s): ${added}"
        warn "New options appended to ${existing} — review and adjust as needed."
    else
        success "Config is up to date — no new options to add."
    fi
}

merge_service() {
    local existing="$1"
    local new_template="$2"
    local output="$3"

    if [[ ! -f "$existing" ]]; then
        cp "$new_template" "$output"
        return
    fi

    if ! command -v python3 &>/dev/null; then
        cp "$new_template" "$output"
        warn "python3 not found — service file replaced with new template; your customisations may be lost."
        warn "Backup at ${existing}.bak if you need to recover them."
        cp "$existing" "${existing}.bak" 2>/dev/null || true
        return
    fi

    python3 - "$existing" "$new_template" "$output" <<'PYEOF'
import sys, configparser

def parse_unit(path):
    cp = configparser.RawConfigParser()
    cp.optionxform = str
    with open(path) as f:
        cp.read_file(f)
    return cp

existing_path, new_path, output_path = sys.argv[1], sys.argv[2], sys.argv[3]
existing = parse_unit(existing_path)
new      = parse_unit(new_path)

merged = configparser.RawConfigParser()
merged.optionxform = str

for section in new.sections():
    merged.add_section(section)
    for key, val in new.items(section):
        merged.set(section, key, val)

for section in existing.sections():
    if not merged.has_section(section):
        merged.add_section(section)
    for key, val in existing.items(section):
        merged.set(section, key, val)

lines = []
for section in merged.sections():
    lines.append(f'[{section}]')
    for key, val in merged.items(section):
        lines.append(f'{key}={val}')
    lines.append('')

with open(output_path, 'w') as f:
    f.write('\n'.join(lines).rstrip() + '\n')
PYEOF

    success "Service file merged — your customisations preserved."
}

do_fresh_install() {
    INSTALL_JAVA=false
    if prompt_java; then
        INSTALL_JAVA=true
    fi

    local arch
    arch=$(detect_arch)

    info "Fetching latest release asset URLs from GitHub..."
    local binary_url jar_url config_url polar_url
    binary_url=$(fetch_latest_release_url "${BINARY_NAME}-linux-${arch}")
    jar_url=$(fetch_latest_release_url "${JAR_NAME}")
    config_url=$(fetch_latest_release_url "${CONFIG_NAME}")
    polar_url=$(fetch_latest_release_url "${POLAR_NAME}")

    info "Creating install directory ${INSTALL_DIR} ..."
    mkdir -p "${INSTALL_DIR}"

    local tmp
    tmp=$(mktemp -d)
    trap 'rm -rf "$tmp"' EXIT

    download "$binary_url"  "${tmp}/${BINARY_NAME}"
    download "$jar_url"     "${tmp}/${JAR_NAME}"
    download "$config_url"  "${tmp}/${CONFIG_NAME}"
    download "$polar_url"   "${tmp}/${POLAR_NAME}"

    chmod +x "${tmp}/${BINARY_NAME}"

    if [[ ! -f "${INSTALL_DIR}/${CONFIG_NAME}" ]]; then
        cp "${tmp}/${CONFIG_NAME}" "${INSTALL_DIR}/${CONFIG_NAME}"
        success "Installed default ${CONFIG_NAME}"
    else
        warn "${INSTALL_DIR}/${CONFIG_NAME} already exists — skipping to preserve your configuration."
    fi

    cp "${tmp}/${BINARY_NAME}"  "${INSTALL_DIR}/${BINARY_NAME}"
    cp "${tmp}/${JAR_NAME}"     "${INSTALL_DIR}/${JAR_NAME}"
    cp "${tmp}/${POLAR_NAME}"   "${INSTALL_DIR}/${POLAR_NAME}"

    success "Files installed to ${INSTALL_DIR}"

    setup_path

    if [[ "$INSTALL_JAVA" == true ]]; then
        install_openjdk25
    fi

    write_service "${INSTALL_DIR}/${BINARY_NAME}"

    info "Reloading systemd daemon..."
    systemctl daemon-reload

    info "Enabling ${SERVICE_NAME} service..."
    systemctl enable "${SERVICE_NAME}"

    check_port_53

    info "Starting ${SERVICE_NAME} service..."
    systemctl start "${SERVICE_NAME}"

    echo
    success "kmresolv is installed and running."
    echo
    echo -e "  ${BOLD}Useful commands:${RESET}"
    echo "    systemctl status ${SERVICE_NAME}"
    echo "    journalctl -u ${SERVICE_NAME} -f"
    echo "    nano ${INSTALL_DIR}/${CONFIG_NAME}"
    echo
    echo -e "  ${YELLOW}Reload your shell or open a new terminal for PATH changes to take effect.${RESET}"
    echo "    source ~/.bashrc   (bash)"
    echo "    source ~/.zshrc    (zsh)"
    echo
}

do_update() {
    local current_version
    current_version=$("${INSTALL_DIR}/${BINARY_NAME}" version 2>/dev/null || echo "unknown")

    echo -e "  Current version : ${current_version}"
    echo

    local arch
    arch=$(detect_arch)

    info "Fetching latest release asset URLs from GitHub..."
    local binary_url jar_url config_url polar_url
    binary_url=$(fetch_latest_release_url "${BINARY_NAME}-linux-${arch}")
    jar_url=$(fetch_latest_release_url "${JAR_NAME}")
    config_url=$(fetch_latest_release_url "${CONFIG_NAME}")
    polar_url=$(fetch_latest_release_url "${POLAR_NAME}")

    local tmp
    tmp=$(mktemp -d)
    trap 'rm -rf "$tmp"' EXIT

    download "$binary_url"  "${tmp}/${BINARY_NAME}"
    download "$jar_url"     "${tmp}/${JAR_NAME}"
    download "$config_url"  "${tmp}/${CONFIG_NAME}"
    download "$polar_url"   "${tmp}/${POLAR_NAME}"

    chmod +x "${tmp}/${BINARY_NAME}"

    info "Checking configuration for new options..."
    merge_config "${INSTALL_DIR}/${CONFIG_NAME}" "${tmp}/${CONFIG_NAME}"

    info "Stopping ${SERVICE_NAME} service..."
    systemctl stop "${SERVICE_NAME}"

    info "Updating service file..."
    write_service "${INSTALL_DIR}/${BINARY_NAME}" "${tmp}/${SERVICE_NAME}.service"
    merge_service \
        "/etc/systemd/system/${SERVICE_NAME}.service" \
        "${tmp}/${SERVICE_NAME}.service" \
        "/etc/systemd/system/${SERVICE_NAME}.service"

    cp "${tmp}/${BINARY_NAME}"  "${INSTALL_DIR}/${BINARY_NAME}"
    cp "${tmp}/${JAR_NAME}"     "${INSTALL_DIR}/${JAR_NAME}"
    cp "${tmp}/${POLAR_NAME}"   "${INSTALL_DIR}/${POLAR_NAME}"

    success "Updated files installed to ${INSTALL_DIR}"

    info "Reloading systemd daemon..."
    systemctl daemon-reload

    info "Restarting ${SERVICE_NAME} service..."
    systemctl restart "${SERVICE_NAME}"

    local new_version
    new_version=$("${INSTALL_DIR}/${BINARY_NAME}" version 2>/dev/null || echo "unknown")

    echo
    success "kmresolv updated and restarted."
    echo "  ${current_version} → ${new_version}"
    echo
    echo -e "  ${BOLD}Useful commands:${RESET}"
    echo "    systemctl status ${SERVICE_NAME}"
    echo "    journalctl -u ${SERVICE_NAME} -f"
    echo
}

main() {
    require_root

    echo
    echo -e "${BOLD}kmresolv installer${RESET}"
    echo "  Repository : https://github.com/${REPO}"
    echo "  Install dir: ${INSTALL_DIR}"
    echo

    if [[ -f "${INSTALL_DIR}/${BINARY_NAME}" ]]; then
        info "Detected existing installation — running update."
        do_update
    else
        info "No existing installation detected — running fresh install."
        do_fresh_install
    fi
}

main "$@"
