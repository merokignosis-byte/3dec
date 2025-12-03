#!/bin/bash
# Filesystem Hardening Script
# Module: Filesystem
# Supports: scan, fix, rollback modes

MODE="${1:-scan}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DB_PATH="$SCRIPT_DIR/../hardening.db"
BACKUP_DIR="$SCRIPT_DIR/../backups/filesystem"
TOPIC="Filesystem"
MODULE_NAME="Filesystem"

mkdir -p "$BACKUP_DIR"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Counters
TOTAL_CHECKS=0
PASSED_CHECKS=0
FAILED_CHECKS=0
FIXED_CHECKS=0
MANUAL_CHECKS=0

# Track if fstab was modified
FSTAB_MODIFIED=false

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[FAIL]${NC} $1"
}

log_pass() {
    echo -e "${GREEN}[PASS]${NC} $1"
}

log_manual() {
    echo -e "${BLUE}[MANUAL]${NC} $1"
}

# Print formatted output
print_check_result() {
    local policy_id="$1"
    local policy_name="$2"
    local expected="$3"
    local current="$4"
    local status="$5"
    
    echo "=============================================="
    echo "Module Name    : $MODULE_NAME"
    echo "Policy ID      : $policy_id"
    echo "Policy Name    : $policy_name"
    echo "Expected Value : $expected"
    echo "Current Value  : $current"
    echo "Status         : $status"
    echo "=============================================="
}

# Save configuration to database
save_config() {
    local rule_id="$1"
    local rule_name="$2"
    local original_value="$3"
    local current_value="${4:-$original_value}"
    
    python3 -c "
import sqlite3
import sys
try:
    conn = sqlite3.connect('$DB_PATH')
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS configurations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            topic TEXT NOT NULL,
            rule_id TEXT NOT NULL UNIQUE,
            rule_name TEXT NOT NULL,
            original_value TEXT,
            current_value TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            status TEXT DEFAULT 'original'
        );
    ''')
    cursor.execute('''
        INSERT OR REPLACE INTO configurations 
        (topic, rule_id, rule_name, original_value, current_value, status)
        VALUES (?, ?, ?, ?, ?, 'stored')
    ''', ('$TOPIC', '$rule_id', '''$rule_name''', '''$original_value''', '''$current_value'''))
    conn.commit()
    conn.close()
except sqlite3.Error as e:
    print(f'Database error: {e}', file=sys.stderr)
    sys.exit(1)
"
}

get_original_config() {
    local rule_id="$1"
    python3 -c "
import sqlite3
import sys
try:
    conn = sqlite3.connect('$DB_PATH')
    cursor = conn.cursor()
    cursor.execute('SELECT original_value FROM configurations WHERE topic=? AND rule_id=?', ('$TOPIC', '$rule_id'))
    result = cursor.fetchone()
    conn.close()
    print(result[0] if result else '')
except Exception as e:
    print('', file=sys.stderr)
" 2>/dev/null
}

# Check if directory is on root filesystem
is_on_root_filesystem() {
    local dir="$1"
    
    if [ ! -d "$dir" ]; then
        return 2
    fi
    
    local dir_device
    local root_device
    dir_device=$(df "$dir" 2>/dev/null | tail -1 | awk '{print $1}')
    root_device=$(df / 2>/dev/null | tail -1 | awk '{print $1}')
    
    if [ -z "$dir_device" ] || [ -z "$root_device" ]; then
        return 2
    fi
    
    if [ "$dir_device" = "$root_device" ]; then
        return 0
    else
        return 1
    fi
}

# Check if directory exists in fstab
fstab_has_entry() {
    local partition="$1"
    grep -q "^[^#]*[[:space:]]$partition[[:space:]]" /etc/fstab 2>/dev/null
}

# Get current mount options
get_mount_options() {
    local partition="$1"
    mount | grep " on $partition " | sed 's/.*(\(.*\))/\1/' 2>/dev/null
}

# Check if mount has specific option
has_mount_option() {
    local options_list="$1"
    local option="$2"
    echo "$options_list" | grep -qw "$option"
}

# Check if partition is mounted
is_mounted() {
    local partition="$1"
    mount | grep -q " on $partition " 2>/dev/null
}

# ============================================================================
# 1.1 Filesystem Kernel Modules
# ============================================================================

check_kernel_module() {
    local module="$1"
    local policy_num="$2"
    local rule_id="FS-1.a.${policy_num}"
    local rule_name="Ensure $module kernel module is not available"
    
    ((TOTAL_CHECKS++))
    
    if [ "$MODE" = "scan" ]; then
        local is_loaded="No"
        local is_blacklisted="No"
        local status="FAIL"
        
        # Check if module is loaded
        if lsmod | grep -q "^$module "; then
            is_loaded="Yes"
        fi
        
        # Check if install directive exists
        if grep -rq "^[[:space:]]*install[[:space:]]\+$module[[:space:]]\+/bin/\(false\|true\)" /etc/modprobe.d/ 2>/dev/null; then
            is_blacklisted="Yes"
        fi
        
        if [ "$is_loaded" = "No" ] && [ "$is_blacklisted" = "Yes" ]; then
            status="PASS"
            ((PASSED_CHECKS++))
        else
            ((FAILED_CHECKS++))
        fi
        
        print_check_result "$rule_id" "$rule_name" \
            "Module not loaded and blacklisted" \
            "Loaded: $is_loaded, Blacklisted: $is_blacklisted" \
            "$status"
        
    elif [ "$MODE" = "fix" ]; then
        local current_state="not_disabled"
        if grep -rq "^[[:space:]]*install[[:space:]]\+$module[[:space:]]\+/bin/\(false\|true\)" /etc/modprobe.d/ 2>/dev/null; then
            current_state="disabled"
        fi
        save_config "$rule_id" "$rule_name" "$current_state"
        
        local modprobe_file="/etc/modprobe.d/$module-blacklist.conf"
        
        cat > "$modprobe_file" << EOF
# Disable $module module - Added by hardening script
install $module /bin/false
blacklist $module
EOF
        
        if [ $? -eq 0 ]; then
            log_info "Created blacklist configuration: $modprobe_file"
            
            if lsmod | grep -q "^$module "; then
                if rmmod "$module" 2>/dev/null || modprobe -r "$module" 2>/dev/null; then
                    log_info "Module $module unloaded successfully"
                else
                    log_warn "Could not unload module $module (may require reboot)"
                fi
            fi
            
            log_pass "Module $module has been disabled"
            ((FIXED_CHECKS++))
        fi
        
    elif [ "$MODE" = "rollback" ]; then
        local original
        original=$(get_original_config "$rule_id")
        if [ "$original" = "not_disabled" ]; then
            local modprobe_file="/etc/modprobe.d/$module-blacklist.conf"
            if [ -f "$modprobe_file" ]; then
                rm -f "$modprobe_file"
                log_info "Removed blacklist for $module"
            fi
        fi
    fi
}

check_all_kernel_modules() {
    log_info "=== 1.a Configure Filesystem Kernel Modules ==="
    
    check_kernel_module "cramfs" "i"
    check_kernel_module "freevxfs" "ii"
    check_kernel_module "hfs" "iii"
    check_kernel_module "hfsplus" "iv"
    check_kernel_module "jffs2" "v"
    check_kernel_module "overlayfs" "vi"
    check_kernel_module "squashfs" "vii"
    check_kernel_module "udf" "viii"
    check_kernel_module "usb-storage" "ix"
}

# ============================================================================
# Partition Checks
# ============================================================================

check_partition_exists() {
    local partition="$1"
    local policy_id="$2"
    local rule_name="Ensure $partition is a separate partition"
    
    ((TOTAL_CHECKS++))
    
    if [ ! -d "$partition" ]; then
        if [ "$MODE" = "scan" ]; then
            print_check_result "$policy_id" "$rule_name" \
                "Separate partition" \
                "Directory does not exist" \
                "FAIL"
            ((FAILED_CHECKS++))
        fi
        return 2
    fi
    
    if [ "$MODE" = "scan" ] || [ "$MODE" = "fix" ]; then
        local status="FAIL"
        local current="On root filesystem"
        
        if is_mounted "$partition"; then
            if is_on_root_filesystem "$partition"; then
                current="On root filesystem (not separate)"
            else
                status="PASS"
                current="Separate partition"
                ((PASSED_CHECKS++))
            fi
        else
            current="Not mounted"
        fi
        
        if [ "$status" = "FAIL" ]; then
            ((FAILED_CHECKS++))
        fi
        
        if [ "$MODE" = "scan" ]; then
            print_check_result "$policy_id" "$rule_name" \
                "Separate partition" \
                "$current" \
                "$status"
        fi
    fi
}

check_partition_option() {
    local partition="$1"
    local option="$2"
    local policy_id="$3"
    local rule_name="Ensure $option option set on $partition partition"
    
    ((TOTAL_CHECKS++))
    
    if [ ! -d "$partition" ] && [ "$partition" != "/dev/shm" ]; then
        if [ "$MODE" = "scan" ]; then
            print_check_result "$policy_id" "$rule_name" \
                "$option" \
                "Directory does not exist" \
                "FAIL"
            ((FAILED_CHECKS++))
        fi
        return 2
    fi
    
    if [ "$MODE" = "scan" ]; then
        local status="FAIL"
        local current="Not set"
        
        if ! is_mounted "$partition"; then
            current="Not mounted"
        else
            local current_options
            current_options=$(get_mount_options "$partition")
            
            if has_mount_option "$current_options" "$option"; then
                status="PASS"
                current="$option"
                ((PASSED_CHECKS++))
            else
                current="Option not set (current: $current_options)"
            fi
        fi
        
        if [ "$status" = "FAIL" ]; then
            ((FAILED_CHECKS++))
        fi
        
        print_check_result "$policy_id" "$rule_name" \
            "$option" \
            "$current" \
            "$status"
        
    elif [ "$MODE" = "fix" ]; then
        if ! is_mounted "$partition"; then
            log_error "Cannot fix: $partition is not mounted"
            return 1
        fi
        
        if ! fstab_has_entry "$partition"; then
            log_error "Cannot fix: No fstab entry found for $partition"
            ((MANUAL_CHECKS++))
            return 1
        fi
        
        local current_options
        current_options=$(get_mount_options "$partition")
        
        if has_mount_option "$current_options" "$option"; then
            log_pass "$partition already has $option option set"
            return 0
        fi
        
        cp /etc/fstab "$BACKUP_DIR/fstab.$(date +%Y%m%d_%H%M%S)"
        
        local original_line
        original_line=$(grep "^[^#]*[[:space:]]$partition[[:space:]]" /etc/fstab)
        save_config "$policy_id" "$rule_name" "$original_line"
        
        local temp_file
        temp_file=$(mktemp)
        awk -v partition="$partition" -v opt="$option" '
        $2 == partition {
            if ($4 == "defaults") {
                $4 = "defaults," opt
            } else if ($4 !~ opt) {
                $4 = $4 "," opt
            }
        }
        { print }
        ' /etc/fstab > "$temp_file" && mv "$temp_file" /etc/fstab
        
        if [ $? -eq 0 ]; then
            log_info "Added $option to $partition in fstab"
            FSTAB_MODIFIED=true
            ((FIXED_CHECKS++))
        fi
        
    elif [ "$MODE" = "rollback" ]; then
        local original_line
        original_line=$(get_original_config "$policy_id")
        
        if [ -n "$original_line" ]; then
            sed -i "\|[[:space:]]$partition[[:space:]]|d" /etc/fstab
            echo "$original_line" >> /etc/fstab
            log_info "Rolled back fstab configuration for $partition"
            FSTAB_MODIFIED=true
        fi
    fi
}

# Configure /tmp
check_tmp_partition() {
    log_info "=== 1.b Configure /tmp ==="
    check_partition_exists "/tmp" "FS-1.b.i"
    check_partition_option "/tmp" "nodev" "FS-1.b.ii"
    check_partition_option "/tmp" "nosuid" "FS-1.b.iii"
    check_partition_option "/tmp" "noexec" "FS-1.b.iv"
}

# Configure /dev/shm
check_dev_shm_partition() {
    log_info "=== 1.c Configure /dev/shm ==="
    check_partition_exists "/dev/shm" "FS-1.c.i"
    check_partition_option "/dev/shm" "nodev" "FS-1.c.ii"
    check_partition_option "/dev/shm" "nosuid" "FS-1.c.iii"
    check_partition_option "/dev/shm" "noexec" "FS-1.c.iv"
}

# Configure /home
check_home_partition() {
    log_info "=== 1.d Configure /home ==="
    check_partition_exists "/home" "FS-1.d.i"
    check_partition_option "/home" "nodev" "FS-1.d.ii"
    check_partition_option "/home" "nosuid" "FS-1.d.iii"
}

# Configure /var
check_var_partition() {
    log_info "=== 1.e Configure /var ==="
    check_partition_exists "/var" "FS-1.e.i"
    check_partition_option "/var" "nodev" "FS-1.e.ii"
    check_partition_option "/var" "nosuid" "FS-1.e.iii"
}

# Configure /var/tmp
check_var_tmp_partition() {
    log_info "=== 1.f Configure /var/tmp ==="
    check_partition_exists "/var/tmp" "FS-1.f.i"
    check_partition_option "/var/tmp" "nodev" "FS-1.f.ii"
    check_partition_option "/var/tmp" "nosuid" "FS-1.f.iii"
    check_partition_option "/var/tmp" "noexec" "FS-1.f.iv"
}

# Configure /var/log
check_var_log_partition() {
    log_info "=== 1.g Configure /var/log ==="
    check_partition_exists "/var/log" "FS-1.g.i"
    check_partition_option "/var/log" "nodev" "FS-1.g.ii"
    check_partition_option "/var/log" "nosuid" "FS-1.g.iii"
    check_partition_option "/var/log" "noexec" "FS-1.g.iv"
}

# Configure /var/log/audit
check_var_log_audit_partition() {
    log_info "=== 1.h Configure /var/log/audit ==="
    check_partition_exists "/var/log/audit" "FS-1.h"
    check_partition_option "/var/log/audit" "nodev" "FS-1.h.i"
    check_partition_option "/var/log/audit" "nosuid" "FS-1.h.ii"
    check_partition_option "/var/log/audit" "noexec" "FS-1.h.iii"
}

# ============================================================================
# Main Execution
# ============================================================================

main() {
    echo "========================================================================"
    echo "Filesystem Hardening Script"
    echo "Module: $MODULE_NAME"
    echo "Mode: $MODE"
    echo "========================================================================"
    
    if [ "$MODE" = "fix" ] || [ "$MODE" = "rollback" ]; then
        if [ "$EUID" -ne 0 ]; then
            log_error "This script must be run as root for $MODE mode"
            exit 1
        fi
    fi
    
    if [ "$MODE" = "scan" ] || [ "$MODE" = "fix" ]; then
        check_all_kernel_modules
        check_tmp_partition
        check_dev_shm_partition
        check_home_partition
        check_var_partition
        check_var_tmp_partition
        check_var_log_partition
        check_var_log_audit_partition
        
        if [ "$MODE" = "fix" ] && [ "$FSTAB_MODIFIED" = "true" ]; then
            echo ""
            log_info "Applying fstab changes..."
            
            if mount -a --test 2>/dev/null; then
                log_info "fstab syntax is valid"
                
                for part in /var/log/audit /var/log /var/tmp /var /home /tmp /dev/shm; do
                    if is_mounted "$part" && fstab_has_entry "$part"; then
                        if mount -o remount "$part" 2>/dev/null; then
                            log_pass "Remounted $part with new options"
                        fi
                    fi
                done
            fi
        fi
        
        echo ""
        echo "========================================================================"
        echo "Summary"
        echo "========================================================================"
        echo "Total Checks: $TOTAL_CHECKS"
        
        if [ "$MODE" = "scan" ]; then
            echo "Passed: $PASSED_CHECKS"
            echo "Failed: $FAILED_CHECKS"
            
            if [ $FAILED_CHECKS -eq 0 ]; then
                log_pass "All filesystem checks passed!"
            else
                log_warn "$FAILED_CHECKS checks failed. Run with 'fix' mode to remediate."
            fi
        else
            echo "Fixed: $FIXED_CHECKS"
            echo "Manual Actions Required: $MANUAL_CHECKS"
        fi
        
    elif [ "$MODE" = "rollback" ]; then
        log_info "Rolling back filesystem configurations..."
        
        for module in cramfs freevxfs hfs hfsplus jffs2 overlayfs squashfs udf usb-storage; do
            check_kernel_module "$module" "rollback"
        done
        
        local latest_backup
        latest_backup=$(ls -t "$BACKUP_DIR"/fstab.* 2>/dev/null | head -1)
        if [ -n "$latest_backup" ]; then
            cp "$latest_backup" /etc/fstab
            log_info "Restored fstab from backup"
            mount -a 2>/dev/null
        fi
        
        log_info "Rollback completed"
    else
        echo "Usage: $0 {scan|fix|rollback}"
        exit 1
    fi
}

main
