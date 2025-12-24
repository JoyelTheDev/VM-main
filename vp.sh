#!/bin/bash

# ============================================
# Enhanced Multi-VM Manager Script
# Version: 2.0
# Author: QEMU/KVM VM Manager
# Description: Comprehensive VM management with cloud-init support
# ============================================

# Color definitions
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
NC='\033[0m' # No Color

# Configuration
VM_DIR="$HOME/vms"
LOG_FILE="$VM_DIR/vm_manager.log"
CONFIG_DIR="$VM_DIR/configs"
IMAGE_DIR="$VM_DIR/images"
SEED_DIR="$VM_DIR/seeds"
TEMP_DIR="/tmp/vm_manager"

# Operating System Definitions
declare -A OS_INFO=(
    ["ubuntu2204"]="Ubuntu 22.04 Jammy Jellyfish"
    ["ubuntu2404"]="Ubuntu 24.04 Noble Numbat"
    ["debian11"]="Debian 11 Bullseye"
    ["debian12"]="Debian 12 Bookworm"
    ["fedora40"]="Fedora 40"
    ["centos9"]="CentOS Stream 9"
    ["alma9"]="AlmaLinux 9"
    ["rocky9"]="Rocky Linux 9"
)

declare -A OS_URLS=(
    ["ubuntu2204"]="https://cloud-images.ubuntu.com/releases/22.04/release/ubuntu-22.04-server-cloudimg-amd64.img"
    ["ubuntu2404"]="https://cloud-images.ubuntu.com/releases/24.04/release/ubuntu-24.04-server-cloudimg-amd64.img"
    ["debian11"]="https://cloud.debian.org/images/cloud/bullseye/latest/debian-11-genericcloud-amd64.qcow2"
    ["debian12"]="https://cloud.debian.org/images/cloud/bookworm/latest/debian-12-genericcloud-amd64.qcow2"
    ["fedora40"]="https://download.fedoraproject.org/pub/fedora/linux/releases/40/Cloud/x86_64/images/Fedora-Cloud-Base-40-1.14.x86_64.qcow2"
    ["centos9"]="https://cloud.centos.org/centos/9-stream/x86_64/images/CentOS-Stream-GenericCloud-9-latest.x86_64.qcow2"
    ["alma9"]="https://repo.almalinux.org/almalinux/9/cloud/x86_64/images/AlmaLinux-9-GenericCloud-latest.x86_64.qcow2"
    ["rocky9"]="https://download.rockylinux.org/pub/rocky/9/images/x86_64/Rocky-9-GenericCloud.latest.x86_64.qcow2"
)

declare -A OS_DEFAULT_USER=(
    ["ubuntu2204"]="ubuntu"
    ["ubuntu2404"]="ubuntu"
    ["debian11"]="debian"
    ["debian12"]="debian"
    ["fedora40"]="fedora"
    ["centos9"]="cloud-user"
    ["alma9"]="cloud-user"
    ["rocky9"]="cloud-user"
)

# Default configurations
DEFAULT_CPUS=2
DEFAULT_MEMORY="2G"
DEFAULT_DISK="20G"
DEFAULT_SSH_PORT=2222
MIN_MEMORY="512M"
MAX_MEMORY="16G"
MIN_DISK="5G"
MAX_DISK="100G"

# ============================================
# Utility Functions
# ============================================

log_message() {
    local level=$1
    local message=$2
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    
    case $level in
        "INFO") echo -e "${GREEN}[INFO]${NC} $message" ;;
        "WARN") echo -e "${YELLOW}[WARN]${NC} $message" ;;
        "ERROR") echo -e "${RED}[ERROR]${NC} $message" ;;
        "DEBUG") echo -e "${BLUE}[DEBUG]${NC} $message" ;;
    esac
    
    echo "[$timestamp] [$level] $message" >> "$LOG_FILE"
}

print_header() {
    clear
    echo -e "${CYAN}"
    echo "╔══════════════════════════════════════════════════════════╗"
    echo "║          Enhanced Multi-VM Manager v2.0                 ║"
    echo "║          QEMU/KVM Virtual Machine Management            ║"
    echo "╚══════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

print_footer() {
    echo -e "${CYAN}"
    echo "╔══════════════════════════════════════════════════════════╗"
    echo "║           Press Enter to return to main menu            ║"
    echo "╚══════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
    read -p ""
}

show_spinner() {
    local pid=$1
    local delay=0.1
    local spinstr='|/-\'
    while [ "$(ps a | awk '{print $1}' | grep $pid)" ]; do
        local temp=${spinstr#?}
        printf " [%c]  " "$spinstr"
        local spinstr=$temp${spinstr%"$temp"}
        sleep $delay
        printf "\b\b\b\b\b\b"
    done
    printf "    \b\b\b\b"
}

validate_number() {
    local num=$1
    local min=${2:-0}
    local max=${3:-999999}
    
    if [[ $num =~ ^[0-9]+$ ]] && [ $num -ge $min ] && [ $num -le $max ]; then
        return 0
    else
        return 1
    fi
}

validate_port() {
    local port=$1
    if validate_number "$port" 23 65535 && ! ss -tuln | grep -q ":$port "; then
        return 0
    else
        return 1
    fi
}

validate_vm_name() {
    local name=$1
    if [[ $name =~ ^[a-zA-Z][a-zA-Z0-9_-]{1,31}$ ]] && [ ! -f "$CONFIG_DIR/$name.conf" ]; then
        return 0
    else
        return 1
    fi
}

validate_username() {
    local username=$1
    if [[ $username =~ ^[a-z_][a-z0-9_-]{0,31}$ ]]; then
        return 0
    else
        return 1
    fi
}

validate_size() {
    local size=$1
    if [[ $size =~ ^[0-9]+[MG]$ ]] || [[ $size =~ ^[0-9]+G$ ]]; then
        return 0
    else
        return 1
    fi
}

check_dependencies() {
    local missing_deps=()
    
    # Check for required commands
    for cmd in qemu-system-x86_64 wget cloud-localds qemu-img; do
        if ! command -v $cmd &> /dev/null; then
            missing_deps+=("$cmd")
        fi
    done
    
    if [ ${#missing_deps[@]} -gt 0 ]; then
        log_message "ERROR" "Missing dependencies: ${missing_deps[*]}"
        echo -e "${YELLOW}Install missing packages:${NC}"
        echo "Ubuntu/Debian: sudo apt install qemu-system cloud-image-utils wget"
        echo "Fedora/CentOS: sudo dnf install qemu-kvm cloud-utils wget"
        return 1
    fi
    
    # Check KVM support
    if ! grep -q -E "vmx|svm" /proc/cpuinfo; then
        log_message "WARN" "CPU doesn't support virtualization extensions"
    fi
    
    if [ ! -e /dev/kvm ]; then
        log_message "WARN" "/dev/kvm not found - running in software mode"
    fi
    
    return 0
}

initialize_directories() {
    mkdir -p "$VM_DIR" "$CONFIG_DIR" "$IMAGE_DIR" "$SEED_DIR" "$TEMP_DIR"
    chmod 755 "$VM_DIR"
}

cleanup_temp() {
    rm -rf "$TEMP_DIR"/*
}

# ============================================
# Core VM Functions
# ============================================

list_vms() {
    local count=0
    
    echo -e "${CYAN}╔══════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║                    Virtual Machines                      ║${NC}"
    echo -e "${CYAN}╚══════════════════════════════════════════════════════════╝${NC}"
    echo ""
    
    if [ ! -d "$CONFIG_DIR" ] || [ -z "$(ls -A $CONFIG_DIR)" ]; then
        echo -e "${YELLOW}No virtual machines found.${NC}"
        return
    fi
    
    printf "%-25s %-15s %-10s %-12s %-15s\n" "NAME" "STATUS" "CPUS" "MEMORY" "DISK"
    echo "----------------------------------------------------------------------"
    
    for config in "$CONFIG_DIR"/*.conf; do
        [ -e "$config" ] || continue
        
        local vm_name=$(basename "$config" .conf)
        source "$config"
        
        # Check if VM is running
        local status="${RED}Stopped${NC}"
        if ps aux | grep -q "[q]emu-system.*$vm_name"; then
            status="${GREEN}Running${NC}"
        fi
        
        printf "%-25s %b %-10s %-12s %-15s\n" \
            "$vm_name" "$status" "$VM_CPUS" "$VM_MEMORY" "$VM_DISK_SIZE"
        
        ((count++))
    done
    
    echo ""
    echo -e "${GREEN}Total VMs: $count${NC}"
}

create_vm() {
    print_header
    echo -e "${CYAN}╔══════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║                    Create New VM                         ║${NC}"
    echo -e "${CYAN}╚══════════════════════════════════════════════════════════╝${NC}"
    echo ""
    
    # Step 1: VM Name
    local vm_name=""
    while true; do
        read -p "Enter VM name (alphanumeric, underscores, hyphens): " vm_name
        if validate_vm_name "$vm_name"; then
            break
        else
            echo -e "${RED}Invalid VM name or already exists.${NC}"
        fi
    done
    
    # Step 2: Operating System Selection
    echo ""
    echo -e "${YELLOW}Select Operating System:${NC}"
    local os_options=()
    local i=1
    for os_key in "${!OS_INFO[@]}"; do
        echo "  $i. ${OS_INFO[$os_key]}"
        os_options[$i]="$os_key"
        ((i++))
    done
    echo "  $i. Custom URL"
    
    local os_choice=""
    while true; do
        read -p "Choice [1-$i]: " os_choice
        if validate_number "$os_choice" 1 $i; then
            break
        fi
    done
    
    local os_selected=""
    local os_user=""
    local os_url=""
    
    if [ "$os_choice" -eq $i ]; then
        # Custom URL
        read -p "Enter custom image URL: " os_url
        read -p "Enter default username: " os_user
        os_selected="custom"
    else
        os_selected="${os_options[$os_choice]}"
        os_user="${OS_DEFAULT_USER[$os_selected]}"
        os_url="${OS_URLS[$os_selected]}"
    fi
    
    # Step 3: Hostname
    local vm_hostname=""
    read -p "Enter hostname [$vm_name]: " vm_hostname
    vm_hostname=${vm_hostname:-$vm_name}
    
    # Step 4: Credentials
    echo ""
    echo -e "${YELLOW}Authentication Settings:${NC}"
    
    local vm_username=""
    while true; do
        read -p "Username [$os_user]: " vm_username
        vm_username=${vm_username:-$os_user}
        if validate_username "$vm_username"; then
            break
        else
            echo -e "${RED}Invalid username. Use lowercase letters, numbers, hyphens, underscores.${NC}"
        fi
    done
    
    local vm_password=""
    read -sp "Password: " vm_password
    echo ""
    if [ -z "$vm_password" ]; then
        vm_password=$(openssl rand -base64 12)
        echo -e "${GREEN}Generated password: $vm_password${NC}"
    fi
    
    # Step 5: Resource Allocation
    echo ""
    echo -e "${YELLOW}Resource Allocation:${NC}"
    
    local vm_cpus=""
    while true; do
        read -p "CPU cores [$DEFAULT_CPUS]: " vm_cpus
        vm_cpus=${vm_cpus:-$DEFAULT_CPUS}
        if validate_number "$vm_cpus" 1 $(nproc); then
            break
        else
            echo -e "${RED}Invalid number of CPUs. Max: $(nproc)${NC}"
        fi
    done
    
    local vm_memory=""
    while true; do
        read -p "Memory [$DEFAULT_MEMORY]: " vm_memory
        vm_memory=${vm_memory:-$DEFAULT_MEMORY}
        if validate_size "$vm_memory" && [[ ${vm_memory%?} -ge ${MIN_MEMORY%?} ]] && [[ ${vm_memory%?} -le ${MAX_MEMORY%?} ]]; then
            break
        else
            echo -e "${RED}Invalid memory size. Format: 512M, 2G, etc.${NC}"
        fi
    done
    
    local vm_disk=""
    while true; do
        read -p "Disk size [$DEFAULT_DISK]: " vm_disk
        vm_disk=${vm_disk:-$DEFAULT_DISK}
        if validate_size "$vm_disk" && [[ ${vm_disk%?} -ge ${MIN_DISK%?} ]] && [[ ${vm_disk%?} -le ${MAX_DISK%?} ]]; then
            break
        else
            echo -e "${RED}Invalid disk size. Format: 5G, 20G, etc.${NC}"
        fi
    done
    
    # Step 6: Network Configuration
    echo ""
    echo -e "${YELLOW}Network Configuration:${NC}"
    
    local ssh_port=""
    while true; do
        read -p "SSH port [$DEFAULT_SSH_PORT]: " ssh_port
        ssh_port=${ssh_port:-$DEFAULT_SSH_PORT}
        if validate_port "$ssh_port"; then
            break
        else
            echo -e "${RED}Invalid or already used port.${NC}"
        fi
    done
    
    local extra_ports=""
    read -p "Additional port forwards (format: 8080:80,3306:3306) []: " extra_ports
    
    # Step 7: Display Mode
    echo ""
    echo -e "${YELLOW}Display Settings:${NC}"
    echo "  1. Console only (headless)"
    echo "  2. GUI mode with VNC"
    read -p "Choice [1-2]: " display_choice
    local display_mode="console"
    if [ "$display_choice" = "2" ]; then
        display_mode="gui"
    fi
    
    # Step 8: Confirmation
    echo ""
    echo -e "${CYAN}╔══════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║                     Configuration Summary                ║${NC}"
    echo -e "${CYAN}╚══════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "${WHITE}VM Name:${NC} $vm_name"
    echo -e "${WHITE}OS:${NC} ${OS_INFO[$os_selected]:-$os_selected}"
    echo -e "${WHITE}Hostname:${NC} $vm_hostname"
    echo -e "${WHITE}Username:${NC} $vm_username"
    echo -e "${WHITE}Password:${NC} [hidden]"
    echo -e "${WHITE}CPUs:${NC} $vm_cpus"
    echo -e "${WHITE}Memory:${NC} $vm_memory"
    echo -e "${WHITE}Disk:${NC} $vm_disk"
    echo -e "${WHITE}SSH Port:${NC} $ssh_port"
    echo -e "${WHITE}Extra Ports:${NC} ${extra_ports:-none}"
    echo -e "${WHITE}Display:${NC} $display_mode"
    echo ""
    
    read -p "Create VM? [y/N]: " confirm
    if [[ ! $confirm =~ ^[Yy]$ ]]; then
        log_message "INFO" "VM creation cancelled"
        return
    fi
    
    # Create VM
    log_message "INFO" "Creating VM: $vm_name"
    
    # Download image if not exists
    local image_path="$IMAGE_DIR/$vm_name.img"
    if [ ! -f "$image_path" ]; then
        log_message "INFO" "Downloading OS image..."
        wget -q --show-progress -O "$image_path" "$os_url"
        if [ $? -ne 0 ]; then
            log_message "ERROR" "Failed to download image"
            return 1
        fi
    fi
    
    # Resize disk
    log_message "INFO" "Resizing disk to $vm_disk..."
    qemu-img resize "$image_path" "$vm_disk" > /dev/null 2>&1
    
    # Create cloud-init configuration
    create_cloudinit_config "$vm_name" "$vm_hostname" "$vm_username" "$vm_password"
    
    # Create seed ISO
    local seed_path="$SEED_DIR/$vm_name-seed.iso"
    log_message "INFO" "Creating cloud-init seed image..."
    cloud-localds "$seed_path" "$TEMP_DIR/user-data" "$TEMP_DIR/meta-data" 2>/dev/null
    
    # Save configuration
    save_vm_config "$vm_name" "$os_selected" "$vm_hostname" "$vm_username" \
                   "$vm_password" "$vm_cpus" "$vm_memory" "$vm_disk" \
                   "$ssh_port" "$extra_ports" "$display_mode"
    
    log_message "INFO" "VM '$vm_name' created successfully!"
    echo -e "${GREEN}VM created successfully!${NC}"
    echo -e "${YELLOW}To start:${NC} Select 'Start VM' from main menu"
    echo -e "${YELLOW}SSH connection:${NC} ssh -p $ssh_port $vm_username@localhost"
    
    print_footer
}

create_cloudinit_config() {
    local vm_name=$1
    local hostname=$2
    local username=$3
    local password=$4
    
    # Create user-data
    cat > "$TEMP_DIR/user-data" << EOF
#cloud-config
hostname: $hostname
manage_etc_hosts: true
users:
  - name: $username
    sudo: ALL=(ALL) NOPASSWD:ALL
    groups: users, admin
    home: /home/$username
    shell: /bin/bash
    lock_passwd: false
    passwd: $(echo "$password" | openssl passwd -6 -stdin)
    ssh_authorized_keys:
      - $(cat ~/.ssh/id_rsa.pub 2>/dev/null || echo "# No SSH key found")
chpasswd:
  list: |
    $username:$password
  expire: false
package_update: true
package_upgrade: true
packages:
  - qemu-guest-agent
  - curl
  - wget
  - vim
power_state:
  mode: reboot
  timeout: 120
  condition: true
EOF
    
    # Create meta-data
    cat > "$TEMP_DIR/meta-data" << EOF
instance-id: $vm_name
local-hostname: $hostname
EOF
}

save_vm_config() {
    local vm_name=$1 os=$2 hostname=$3 username=$4 password=$5
    local cpus=$6 memory=$7 disk=$8 ssh_port=$9 extra_ports=${10} display=${11}
    
    cat > "$CONFIG_DIR/$vm_name.conf" << EOF
# VM Configuration - $vm_name
VM_NAME="$vm_name"
VM_OS="$os"
VM_HOSTNAME="$hostname"
VM_USERNAME="$username"
VM_PASSWORD="$password"
VM_CPUS="$cpus"
VM_MEMORY="$memory"
VM_DISK_SIZE="$disk"
VM_SSH_PORT="$ssh_port"
VM_EXTRA_PORTS="$extra_ports"
VM_DISPLAY="$display"
VM_IMAGE="$IMAGE_DIR/$vm_name.img"
VM_SEED="$SEED_DIR/$vm_name-seed.iso"
VM_STATUS="stopped"
CREATED_DATE="$(date)"
LAST_STARTED=""
EOF
}

start_vm() {
    print_header
    echo -e "${CYAN}╔══════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║                       Start VM                          ║${NC}"
    echo -e "${CYAN}╚══════════════════════════════════════════════════════════╝${NC}"
    echo ""
    
    list_vms_brief
    
    local vm_name=""
    read -p "Enter VM name to start: " vm_name
    
    local config_file="$CONFIG_DIR/$vm_name.conf"
    if [ ! -f "$config_file" ]; then
        echo -e "${RED}VM '$vm_name' not found.${NC}"
        print_footer
        return
    fi
    
    source "$config_file"
    
    # Check if already running
    if ps aux | grep -q "[q]emu-system.*$vm_name"; then
        echo -e "${YELLOW}VM '$vm_name' is already running.${NC}"
        print_footer
        return
    fi
    
    log_message "INFO" "Starting VM: $vm_name"
    
    # Build QEMU command
    local qemu_cmd="qemu-system-x86_64"
    
    # Basic parameters
    qemu_cmd+=" -name $vm_name"
    qemu_cmd+=" -machine type=q35,accel=kvm"
    qemu_cmd+=" -cpu host"
    qemu_cmd+=" -smp $VM_CPUS"
    qemu_cmd+=" -m $VM_MEMORY"
    qemu_cmd+=" -object rng-random,id=rng0,filename=/dev/urandom"
    qemu_cmd+=" -device virtio-rng-pci,rng=rng0"
    
    # Storage
    qemu_cmd+=" -drive file=$VM_IMAGE,if=virtio,format=qcow2"
    qemu_cmd+=" -drive file=$VM_SEED,if=virtio,format=raw"
    
    # Network
    qemu_cmd+=" -netdev user,id=net0,hostfwd=tcp::$VM_SSH_PORT-:22"
    
    # Add extra port forwards
    IFS=',' read -ra PORTS <<< "$VM_EXTRA_PORTS"
    for port_pair in "${PORTS[@]}"; do
        if [ -n "$port_pair" ]; then
            local host_port="${port_pair%:*}"
            local guest_port="${port_pair#*:}"
            qemu_cmd+=",hostfwd=tcp::$host_port-:$guest_port"
        fi
    done
    
    qemu_cmd+=" -device virtio-net-pci,netdev=net0"
    
    # Add second network interface if needed
    if [ -n "$VM_EXTRA_PORTS" ]; then
        qemu_cmd+=" -netdev user,id=net1 -device virtio-net-pci,netdev=net1"
    fi
    
    # Display
    if [ "$VM_DISPLAY" = "gui" ]; then
        qemu_cmd+=" -vga virtio"
        qemu_cmd+=" -display gtk,gl=on"
    else
        qemu_cmd+=" -nographic"
        qemu_cmd+=" -serial mon:stdio"
    fi
    
    # Performance optimizations
    qemu_cmd+=" -device virtio-balloon"
    qemu_cmd+=" -enable-kvm"
    qemu_cmd+=" -rtc base=utc,clock=host"
    qemu_cmd+=" -boot order=c"
    
    # Start in background
    echo -e "${YELLOW}Starting VM...${NC}"
    nohup bash -c "$qemu_cmd > $VM_DIR/$vm_name.log 2>&1" &
    
    # Update config
    sed -i "s/VM_STATUS=\"stopped\"/VM_STATUS=\"running\"/" "$config_file"
    sed -i "s/LAST_STARTED=\"\"/LAST_STARTED=\"$(date)\"/" "$config_file"
    
    # Wait for SSH
    echo -ne "${YELLOW}Waiting for VM to boot..."
    local timeout=60
    local count=0
    while [ $count -lt $timeout ]; do
        if nc -z localhost $VM_SSH_PORT 2>/dev/null; then
            echo -e "${GREEN} Ready!${NC}"
            break
        fi
        echo -n "."
        sleep 1
        ((count++))
    done
    
    if [ $count -eq $timeout ]; then
        echo -e "${RED} Timeout! VM may still be booting.${NC}"
    fi
    
    log_message "INFO" "VM '$vm_name' started on SSH port $VM_SSH_PORT"
    echo ""
    echo -e "${GREEN}VM started successfully!${NC}"
    echo -e "${YELLOW}SSH connection:${NC} ssh -p $VM_SSH_PORT $VM_USERNAME@localhost"
    echo -e "${YELLOW}Log file:${NC} $VM_DIR/$vm_name.log"
    
    if [ -n "$VM_EXTRA_PORTS" ]; then
        echo -e "${YELLOW}Port forwards:${NC}"
        IFS=',' read -ra PORTS <<< "$VM_EXTRA_PORTS"
        for port_pair in "${PORTS[@]}"; do
            echo "  $port_pair"
        done
    fi
    
    print_footer
}

stop_vm() {
    print_header
    echo -e "${CYAN}╔══════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║                       Stop VM                           ║${NC}"
    echo -e "${CYAN}╚══════════════════════════════════════════════════════════╝${NC}"
    echo ""
    
    list_vms_brief
    
    local vm_name=""
    read -p "Enter VM name to stop: " vm_name
    
    local config_file="$CONFIG_DIR/$vm_name.conf"
    if [ ! -f "$config_file" ]; then
        echo -e "${RED}VM '$vm_name' not found.${NC}"
        print_footer
        return
    fi
    
    # Get PID
    local pid=$(pgrep -f "qemu-system.*$vm_name")
    
    if [ -z "$pid" ]; then
        echo -e "${YELLOW}VM '$vm_name' is not running.${NC}"
        print_footer
        return
    fi
    
    echo -e "${YELLOW}Stopping VM '$vm_name' (PID: $pid)...${NC}"
    
    # Try graceful shutdown first
    kill -TERM $pid
    sleep 5
    
    # Force kill if still running
    if ps -p $pid > /dev/null 2>&1; then
        echo -e "${YELLOW}Force stopping...${NC}"
        kill -KILL $pid
    fi
    
    # Update config
    sed -i "s/VM_STATUS=\"running\"/VM_STATUS=\"stopped\"/" "$config_file"
    
    log_message "INFO" "VM '$vm_name' stopped"
    echo -e "${GREEN}VM stopped successfully.${NC}"
    
    print_footer
}

delete_vm() {
    print_header
    echo -e "${CYAN}╔══════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║                      Delete VM                          ║${NC}"
    echo -e "${CYAN}╚══════════════════════════════════════════════════════════╝${NC}"
    echo ""
    
    list_vms_brief
    
    local vm_name=""
    read -p "Enter VM name to delete: " vm_name
    
    local config_file="$CONFIG_DIR/$vm_name.conf"
    if [ ! -f "$config_file" ]; then
        echo -e "${RED}VM '$vm_name' not found.${NC}"
        print_footer
        return
    fi
    
    # Check if running
    if pgrep -f "qemu-system.*$vm_name" > /dev/null; then
        echo -e "${RED}Cannot delete running VM. Stop it first.${NC}"
        print_footer
        return
    fi
    
    echo -e "${RED}WARNING: This will permanently delete:${NC}"
    echo "  - Configuration: $config_file"
    echo "  - Disk image: $IMAGE_DIR/$vm_name.img"
    echo "  - Seed image: $SEED_DIR/$vm_name-seed.iso"
    echo ""
    
    read -p "Type 'DELETE' to confirm: " confirm
    if [ "$confirm" != "DELETE" ]; then
        echo -e "${YELLOW}Deletion cancelled.${NC}"
        print_footer
        return
    fi
    
    # Delete files
    rm -f "$config_file"
    rm -f "$IMAGE_DIR/$vm_name.img"
    rm -f "$SEED_DIR/$vm_name-seed.iso"
    rm -f "$VM_DIR/$vm_name.log"
    
    log_message "INFO" "VM '$vm_name' deleted"
    echo -e "${GREEN}VM deleted successfully.${NC}"
    
    print_footer
}

edit_vm() {
    print_header
    echo -e "${CYAN}╔══════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║                      Edit VM Configuration              ║${NC}"
    echo -e "${CYAN}╚══════════════════════════════════════════════════════════╝${NC}"
    echo ""
    
    list_vms_brief
    
    local vm_name=""
    read -p "Enter VM name to edit: " vm_name
    
    local config_file="$CONFIG_DIR/$vm_name.conf"
    if [ ! -f "$config_file" ]; then
        echo -e "${RED}VM '$vm_name' not found.${NC}"
        print_footer
        return
    fi
    
    # Check if running
    if pgrep -f "qemu-system.*$vm_name" > /dev/null; then
        echo -e "${RED}Cannot edit running VM. Stop it first.${NC}"
        print_footer
        return
    fi
    
    source "$config_file"
    
    echo ""
    echo -e "${YELLOW}Current Configuration:${NC}"
    echo "  1. Memory: $VM_MEMORY"
    echo "  2. CPUs: $VM_CPUS"
    echo "  3. Disk size: $VM_DISK_SIZE"
    echo "  4. SSH port: $VM_SSH_PORT"
    echo "  5. Extra ports: $VM_EXTRA_PORTS"
    echo "  6. Display mode: $VM_DISPLAY"
    echo ""
    
    read -p "Select option to edit [1-6]: " option
    
    case $option in
        1)
            read -p "New memory [$VM_MEMORY]: " new_memory
            if [ -n "$new_memory" ] && validate_size "$new_memory"; then
                sed -i "s/VM_MEMORY=\"$VM_MEMORY\"/VM_MEMORY=\"$new_memory\"/" "$config_file"
                echo -e "${GREEN}Memory updated.${NC}"
            fi
            ;;
        2)
            read -p "New CPU count [$VM_CPUS]: " new_cpus
            if [ -n "$new_cpus" ] && validate_number "$new_cpus" 1 $(nproc); then
                sed -i "s/VM_CPUS=\"$VM_CPUS\"/VM_CPUS=\"$new_cpus\"/" "$config_file"
                echo -e "${GREEN}CPU count updated.${NC}"
            fi
            ;;
        3)
            read -p "New disk size [$VM_DISK_SIZE]: " new_disk
            if [ -n "$new_disk" ] && validate_size "$new_disk"; then
                # Resize disk image
                qemu-img resize "$VM_IMAGE" "$new_disk" > /dev/null 2>&1
                sed -i "s/VM_DISK_SIZE=\"$VM_DISK_SIZE\"/VM_DISK_SIZE=\"$new_disk\"/" "$config_file"
                echo -e "${GREEN}Disk size updated.${NC}"
            fi
            ;;
        4)
            read -p "New SSH port [$VM_SSH_PORT]: " new_port
            if [ -n "$new_port" ] && validate_port "$new_port"; then
                sed -i "s/VM_SSH_PORT=\"$VM_SSH_PORT\"/VM_SSH_PORT=\"$new_port\"/" "$config_file"
                echo -e "${GREEN}SSH port updated.${NC}"
            fi
            ;;
        5)
            read -p "New extra ports [$VM_EXTRA_PORTS]: " new_ports
            sed -i "s/VM_EXTRA_PORTS=\"$VM_EXTRA_PORTS\"/VM_EXTRA_PORTS=\"$new_ports\"/" "$config_file"
            echo -e "${GREEN}Extra ports updated.${NC}"
            ;;
        6)
            echo "Display modes:"
            echo "  1. Console (headless)"
            echo "  2. GUI (VNC)"
            read -p "Choice [1-2]: " disp_choice
            if [ "$disp_choice" = "1" ]; then
                sed -i "s/VM_DISPLAY=\"$VM_DISPLAY\"/VM_DISPLAY=\"console\"/" "$config_file"
                echo -e "${GREEN}Display mode set to console.${NC}"
            elif [ "$disp_choice" = "2" ]; then
                sed -i "s/VM_DISPLAY=\"$VM_DISPLAY\"/VM_DISPLAY=\"gui\"/" "$config_file"
                echo -e "${GREEN}Display mode set to GUI.${NC}"
            fi
            ;;
        *)
            echo -e "${RED}Invalid option.${NC}"
            ;;
    esac
    
    print_footer
}

# ============================================
# Monitoring & Information Functions
# ============================================

show_vm_info() {
    print_header
    echo -e "${CYAN}╔══════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║                     VM Information                       ║${NC}"
    echo -e "${CYAN}╚══════════════════════════════════════════════════════════╝${NC}"
    echo ""
    
    list_vms_brief
    
    local vm_name=""
    read -p "Enter VM name for details: " vm_name
    
    local config_file="$CONFIG_DIR/$vm_name.conf"
    if [ ! -f "$config_file" ]; then
        echo -e "${RED}VM '$vm_name' not found.${NC}"
        print_footer
        return
    fi
    
    source "$config_file"
    
    echo ""
    echo -e "${CYAN}════════════════════════════════════════════════════════════${NC}"
    echo -e "${WHITE}Virtual Machine: $VM_NAME${NC}"
    echo -e "${CYAN}════════════════════════════════════════════════════════════${NC}"
    echo ""
    
    # Basic Info
    echo -e "${YELLOW}Basic Information:${NC}"
    echo -e "  ${WHITE}OS:${NC} ${OS_INFO[$VM_OS]:-$VM_OS}"
    echo -e "  ${WHITE}Hostname:${NC} $VM_HOSTNAME"
    echo -e "  ${WHITE}Created:${NC} $CREATED_DATE"
    echo -e "  ${WHITE}Last Started:${NC} ${LAST_STARTED:-Never}"
    
    # Resource Info
    echo ""
    echo -e "${YELLOW}Resource Allocation:${NC}"
    echo -e "  ${WHITE}CPUs:${NC} $VM_CPUS"
    echo -e "  ${WHITE}Memory:${NC} $VM_MEMORY"
    echo -e "  ${WHITE}Disk:${NC} $VM_DISK_SIZE"
    echo -e "  ${WHITE}Display:${NC} $VM_DISPLAY"
    
    # Network Info
    echo ""
    echo -e "${YELLOW}Network Configuration:${NC}"
    echo -e "  ${WHITE}SSH Port:${NC} $VM_SSH_PORT"
    if [ -n "$VM_EXTRA_PORTS" ]; then
        echo -e "  ${WHITE}Port Forwards:${NC}"
        IFS=',' read -ra PORTS <<< "$VM_EXTRA_PORTS"
        for port_pair in "${PORTS[@]}"; do
            echo -e "    $port_pair"
        done
    fi
    
    # Status Info
    echo ""
    echo -e "${YELLOW}Current Status:${NC}"
    if pgrep -f "qemu-system.*$vm_name" > /dev/null; then
        echo -e "  ${GREEN}● Running${NC}"
        local pid=$(pgrep -f "qemu-system.*$vm_name")
        echo -e "  ${WHITE}PID:${NC} $pid"
        
        # Check SSH connectivity
        if nc -z localhost $VM_SSH_PORT 2>/dev/null; then
            echo -e "  ${WHITE}SSH:${NC} ${GREEN}Ready${NC}"
        else
            echo -e "  ${WHITE}SSH:${NC} ${YELLOW}Not responding${NC}"
        fi
    else
        echo -e "  ${RED}● Stopped${NC}"
    fi
    
    # File Info
    echo ""
    echo -e "${YELLOW}Files:${NC}"
    echo -e "  ${WHITE}Config:${NC} $config_file"
    echo -e "  ${WHITE}Disk Image:${NC} $VM_IMAGE"
    echo -e "  ${WHITE}Seed Image:${NC} $VM_SEED"
    
    # Disk usage
    if [ -f "$VM_IMAGE" ]; then
        local disk_usage=$(du -h "$VM_IMAGE" | cut -f1)
        echo -e "  ${WHITE}Disk Used:${NC} $disk_usage"
    fi
    
    echo ""
    echo -e "${CYAN}════════════════════════════════════════════════════════════${NC}"
    echo -e "${YELLOW}Connection Commands:${NC}"
    echo "  SSH: ssh -p $VM_SSH_PORT $VM_USERNAME@localhost"
    echo "  Copy files: scp -P $VM_SSH_PORT file.txt $VM_USERNAME@localhost:~/"
    
    print_footer
}

show_system_status() {
    print_header
    echo -e "${CYAN}╔══════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║                   System Status                          ║${NC}"
    echo -e "${CYAN}╚══════════════════════════════════════════════════════════╝${NC}"
    echo ""
    
    # System Resources
    echo -e "${YELLOW}System Resources:${NC}"
    echo -e "  ${WHITE}CPU Cores:${NC} $(nproc)"
    echo -e "  ${WHITE}Total RAM:${NC} $(free -h | awk '/^Mem:/ {print $2}')"
    echo -e "  ${WHITE}Available RAM:${NC} $(free -h | awk '/^Mem:/ {print $7}')"
    echo -e "  ${WHITE}Disk Space (VM Directory):${NC} $(df -h "$VM_DIR" | tail -1 | awk '{print $4}')"
    
    # KVM Status
    echo ""
    echo -e "${YELLOW}KVM Status:${NC}"
    if [ -e /dev/kvm ]; then
        echo -e "  ${GREEN}✓ KVM acceleration available${NC}"
    else
        echo -e "  ${RED}✗ KVM not available${NC}"
    fi
    
    if lsmod | grep -q kvm; then
        echo -e "  ${GREEN}✓ KVM module loaded${NC}"
    else
        echo -e "  ${RED}✗ KVM module not loaded${NC}"
    fi
    
    # Running VMs
    echo ""
    echo -e "${YELLOW}Running Virtual Machines:${NC}"
    local running_vms=$(pgrep -f "qemu-system" | wc -l)
    if [ "$running_vms" -eq 0 ]; then
        echo -e "  ${YELLOW}No VMs running${NC}"
    else
        echo -e "  ${GREEN}$running_vms VM(s) running${NC}"
        ps aux | grep "[q]emu-system" | awk '{print "  " $12 " (PID: " $2 ")"}'
    fi
    
    # Port Usage
    echo ""
    echo -e "${YELLOW}Port Usage:${NC}"
    for config in "$CONFIG_DIR"/*.conf; do
        [ -e "$config" ] || continue
        source "$config"
        if pgrep -f "qemu-system.*$VM_NAME" > /dev/null; then
            echo -e "  ${WHITE}$VM_NAME:${NC} SSH port $VM_SSH_PORT"
            if [ -n "$VM_EXTRA_PORTS" ]; then
                IFS=',' read -ra PORTS <<< "$VM_EXTRA_PORTS"
                for port_pair in "${PORTS[@]}"; do
                    local host_port="${port_pair%:*}"
                    echo -e "           Port $host_port"
                done
            fi
        fi
    done
    
    # Storage Usage
    echo ""
    echo -e "${YELLOW}Storage Usage:${NC}"
    echo -e "  ${WHITE}Total VMs:${NC} $(ls -1 "$CONFIG_DIR"/*.conf 2>/dev/null | wc -l)"
    echo -e "  ${WHITE}Total Disk Images:${NC} $(ls -1 "$IMAGE_DIR"/*.img 2>/dev/null | wc -l)"
    echo -e "  ${WHITE}VM Directory Size:${NC} $(du -sh "$VM_DIR" 2>/dev/null | cut -f1)"
    
    print_footer
}

# ============================================
# Helper Functions
# ============================================

list_vms_brief() {
    echo -e "${YELLOW}Available VMs:${NC}"
    if [ ! -d "$CONFIG_DIR" ] || [ -z "$(ls -A $CONFIG_DIR)" ]; then
        echo "  No VMs found"
        return
    fi
    
    for config in "$CONFIG_DIR"/*.conf; do
        [ -e "$config" ] || continue
        local vm_name=$(basename "$config" .conf)
        source "$config"
        local status="${RED}●${NC}"
        if pgrep -f "qemu-system.*$vm_name" > /dev/null; then
            status="${GREEN}●${NC}"
        fi
        echo -e "  $status $vm_name ($VM_OS) - SSH: $VM_SSH_PORT"
    done
    echo ""
}

# ============================================
# Main Menu
# ============================================

show_main_menu() {
    while true; do
        print_header
        
        echo -e "${CYAN}╔══════════════════════════════════════════════════════════╗${NC}"
        echo -e "${CYAN}║                        Main Menu                         ║${NC}"
        echo -e "${CYAN}╚══════════════════════════════════════════════════════════╝${NC}"
        echo ""
        
        echo -e "${WHITE}VM Management:${NC}"
        echo "  1. List all VMs"
        echo "  2. Create new VM"
        echo "  3. Start VM"
        echo "  4. Stop VM"
        echo "  5. Delete VM"
        echo "  6. Edit VM configuration"
        echo ""
        
        echo -e "${WHITE}Information & Monitoring:${NC}"
        echo "  7. Show VM details"
        echo "  8. Show system status"
        echo ""
        
        echo -e "${WHITE}Maintenance:${NC}"
        echo "  9. Check dependencies"
        echo "  10. Cleanup temporary files"
        echo ""
        
        echo -e "${WHITE}Exit:${NC}"
        echo "  0. Exit"
        echo ""
        
        read -p "Select option [0-10]: " choice
        
        case $choice in
            1) list_vms; print_footer ;;
            2) create_vm ;;
            3) start_vm ;;
            4) stop_vm ;;
            5) delete_vm ;;
            6) edit_vm ;;
            7) show_vm_info ;;
            8) show_system_status ;;
            9) check_dependencies; print_footer ;;
            10) cleanup_temp; echo -e "${GREEN}Temporary files cleaned.${NC}"; print_footer ;;
            0) 
                echo -e "${GREEN}Goodbye!${NC}"
                cleanup_temp
                exit 0
                ;;
            *) echo -e "${RED}Invalid option.${NC}"; sleep 1 ;;
        esac
    done
}

# ============================================
# Initialization
# ============================================

# Trap for cleanup on exit
trap 'cleanup_temp; echo -e "\n${YELLOW}Cleaning up...${NC}"' EXIT

# Check if running as root
if [ "$EUID" -eq 0 ]; then 
    echo -e "${RED}Warning: Running as root is not recommended.${NC}"
    read -p "Continue anyway? [y/N]: " root_confirm
    if [[ ! $root_confirm =~ ^[Yy]$ ]]; then
        exit 1
    fi
fi

# Initialize
echo -e "${CYAN}Initializing VM Manager...${NC}"
initialize_directories

if ! check_dependencies; then
    echo -e "${RED}Missing dependencies. Please install them first.${NC}"
    exit 1
fi

# Start main menu
show_main_menu
