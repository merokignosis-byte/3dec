#!/bin/bash
# Network Hardening Script
# Module: Network
# Covers: Network Devices, Kernel Modules, Kernel Parameters

MODE="${1:-scan}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DB_PATH="$SCRIPT_DIR/hardening.db"
BACKUP_DIR="$SCRIPT_DIR/backups"
TOPIC="Network"
MODULE_NAME="Network"

mkdir -p "$BACKUP_DIR"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

TOTAL_CHECKS=0
PASSED_CHECKS=0
FAILED_CHECKS=0
FIXED_CHECKS=0

# Logging Functions
log_info()  { echo -e "${GREEN}[INFO]${NC} $1"; }
log_pass()  { echo -e "${GREEN}[PASS]${NC} $1"; ((PASSED_CHECKS++)); }
log_fixed() { echo -e "${BLUE}[FIXED]${NC} $1"; ((FIXED_CHECKS++)); }
log_warn()  { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[FAIL]${NC} $1"; ((FAILED_CHECKS++)); }

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

# Database Functions
initialize_db() {
    if [ ! -f "$DB_PATH" ]; then
        sqlite3 "$DB_PATH" "CREATE TABLE IF NOT EXISTS configurations (
            topic TEXT,
            rule_id TEXT PRIMARY KEY,
            rule_name TEXT,
            original_value TEXT,
            current_value TEXT,
            status TEXT
        );"
    fi
}

save_config() {
    local rule_id="$1"
    local rule_name="$2"
    local original_value="$3"
    local current_value="${4:-$original_value}"

    python3 - <<EOF
import sqlite3
conn = sqlite3.connect("$DB_PATH")
cursor = conn.cursor()
cursor.execute("""
INSERT OR REPLACE INTO configurations 
(topic, rule_id, rule_name, original_value, current_value, status)
VALUES (?, ?, ?, ?, ?, 'stored')
""", ("$TOPIC", "$rule_id", "$rule_name", "$original_value", "$current_value"))
conn.commit()
conn.close()
EOF
}

get_original_config() {
    local rule_id="$1"
    python3 - <<EOF
import sqlite3
conn = sqlite3.connect("$DB_PATH")
cursor = conn.cursor()
cursor.execute("SELECT original_value FROM configurations WHERE topic=? AND rule_id=?", 
               ("$TOPIC", "$rule_id"))
result = cursor.fetchone()
conn.close()
print(result[0] if result else "")
EOF
}

# ===================================================================
# 4.a Network Devices
# ===================================================================

check_ipv6_status() {
    local policy_id="NET-4.a.i"
    local policy_name="Ensure IPv6 status is identified"
    ((TOTAL_CHECKS++))

    if [ "$MODE" = "scan" ]; then
        local status="PASS"
        local current="Unable to determine"
        
        if sysctl net.ipv6.conf.all.disable_ipv6 &>/dev/null; then
            local state
            state=$(sysctl -n net.ipv6.conf.all.disable_ipv6)
            if [ "$state" = "0" ]; then
                current="IPv6 Enabled (disable_ipv6=0)"
            else
                current="IPv6 Disabled (disable_ipv6=1)"
            fi
            ((PASSED_CHECKS++))
        else
            status="FAIL"
            ((FAILED_CHECKS++))
        fi
        
        print_check_result "$policy_id" "$policy_name" \
            "IPv6 status identified" \
            "$current" \
            "$status"
    fi
}

check_disable_wireless() {
    local policy_id="NET-4.a.ii"
    local policy_name="Ensure wireless interfaces are disabled"
    ((TOTAL_CHECKS++))

    local wifi_iface
    wifi_iface=$(iw dev 2>/dev/null | awk '/Interface/ {print $2}')

    if [ "$MODE" = "scan" ]; then
        local status="PASS"
        local current="No wireless interfaces"
        
        if [ -z "$wifi_iface" ]; then
            ((PASSED_CHECKS++))
        else
            if ip link show "$wifi_iface" | grep -q "state DOWN"; then
                current="Wireless interface $wifi_iface is DOWN"
                ((PASSED_CHECKS++))
            else
                status="FAIL"
                current="Wireless interface $wifi_iface is UP"
                ((FAILED_CHECKS++))
            fi
        fi
        
        print_check_result "$policy_id" "$policy_name" \
            "Wireless interfaces disabled" \
            "$current" \
            "$status"

    elif [ "$MODE" = "fix" ]; then
        if [ -n "$wifi_iface" ]; then
            ip link set "$wifi_iface" down
            log_fixed "Disabled wireless interface $wifi_iface"
            save_config "$policy_id" "$policy_name" "enabled" "disabled"
        fi
    fi
}

check_bluetooth() {
    local policy_id="NET-4.a.iii"
    local policy_name="Ensure bluetooth services are not in use"
    ((TOTAL_CHECKS++))

    if [ "$MODE" = "scan" ]; then
        local status="PASS"
        local current="Disabled"
        
        if systemctl is-enabled bluetooth 2>/dev/null | grep -q "enabled"; then
            status="FAIL"
            current="Enabled"
            ((FAILED_CHECKS++))
        else
            ((PASSED_CHECKS++))
        fi
        
        print_check_result "$policy_id" "$policy_name" \
            "Bluetooth disabled" \
            "$current" \
            "$status"

    elif [ "$MODE" = "fix" ]; then
        systemctl disable bluetooth 2>/dev/null
        systemctl stop bluetooth 2>/dev/null
        log_fixed "Bluetooth service disabled"
        save_config "$policy_id" "$policy_name" "enabled" "disabled"
    fi
}

# ===================================================================
# 4.b Network Kernel Modules
# ===================================================================

disable_module_rule() {
    local module="$1"
    local policy_id="$2"
    local policy_name="$3"

    ((TOTAL_CHECKS++))

    if [ "$MODE" = "scan" ]; then
        local status="PASS"
        local is_loaded="No"
        local is_blacklisted="No"
        
        if lsmod | grep -q "^$module"; then
            is_loaded="Yes"
        fi
        
        if grep -q "^install $module /bin/true" /etc/modprobe.d/* 2>/dev/null; then
            is_blacklisted="Yes"
        fi
        
        local current="Loaded: $is_loaded, Blacklisted: $is_blacklisted"
        
        if [ "$is_loaded" = "Yes" ]; then
            status="FAIL"
            ((FAILED_CHECKS++))
        elif [ "$is_blacklisted" = "No" ]; then
            status="FAIL"
            ((FAILED_CHECKS++))
        else
            ((PASSED_CHECKS++))
        fi
        
        print_check_result "$policy_id" "$policy_name" \
            "Module not loaded and blacklisted" \
            "$current" \
            "$status"

    elif [ "$MODE" = "fix" ]; then
        echo "install $module /bin/true" > /etc/modprobe.d/"$module".conf
        modprobe -r "$module" 2>/dev/null
        log_fixed "Module $module disabled and blacklisted"
        save_config "$policy_id" "$policy_name" "loaded" "disabled"
    fi
}

check_dccp() { 
    disable_module_rule "dccp" "NET-4.b.i" "Ensure dccp kernel module is not available"
}

check_tipc() { 
    disable_module_rule "tipc" "NET-4.b.ii" "Ensure tipc kernel module is not available"
}

check_rds() { 
    disable_module_rule "rds" "NET-4.b.iii" "Ensure rds kernel module is not available"
}

check_sctp() { 
    disable_module_rule "sctp" "NET-4.b.iv" "Ensure sctp kernel module is not available"
}

# ===================================================================
# 4.c Network Kernel Parameters (sysctl)
# ===================================================================

sysctl_rule() {
    local policy_id="$1"
    local policy_name="$2"
    local key="$3"
    local good_val="$4"

    ((TOTAL_CHECKS++))

    local current
    current=$(sysctl -n "$key" 2>/dev/null)

    if [ "$MODE" = "scan" ]; then
        local status="FAIL"
        
        if [ "$current" = "$good_val" ]; then
            status="PASS"
            ((PASSED_CHECKS++))
        else
            ((FAILED_CHECKS++))
        fi
        
        print_check_result "$policy_id" "$policy_name" \
            "$good_val" \
            "$current" \
            "$status"

    elif [ "$MODE" = "fix" ]; then
        cp /etc/sysctl.conf "$BACKUP_DIR/sysctl.conf.$(date +%Y%m%d_%H%M%S)" 2>/dev/null
        save_config "$policy_id" "$policy_name" "$current"
        sysctl -w "$key=$good_val" >/dev/null

        if ! grep -q "^$key" /etc/sysctl.conf; then
            echo "$key = $good_val" >> /etc/sysctl.conf
        else
            sed -i "s|^$key.*|$key = $good_val|" /etc/sysctl.conf
        fi

        log_fixed "$key set to $good_val"
    fi
}

check_ip_forwarding() {
    sysctl_rule "NET-4.c.i" "Ensure ip forwarding is disabled" \
        "net.ipv4.ip_forward" "0"
}

check_redirect_sending() {
    sysctl_rule "NET-4.c.ii" "Ensure packet redirect sending is disabled" \
        "net.ipv4.conf.all.send_redirects" "0"
}

check_bogus_icmp() {
    sysctl_rule "NET-4.c.iii" "Ensure bogus icmp responses are ignored" \
        "net.ipv4.icmp_ignore_bogus_error_responses" "1"
}

check_broadcast_icmp() {
    sysctl_rule "NET-4.c.iv" "Ensure broadcast icmp requests are ignored" \
        "net.ipv4.icmp_echo_ignore_broadcasts" "1"
}

check_icmp_redirects() {
    sysctl_rule "NET-4.c.v" "Ensure icmp redirects are not accepted" \
        "net.ipv4.conf.all.accept_redirects" "0"
}

check_secure_redirects() {
    sysctl_rule "NET-4.c.xi" "Ensure secure icmp redirects are not accepted" \
        "net.ipv4.conf.all.secure_redirects" "0"
}

check_reverse_path_filter() {
    sysctl_rule "NET-4.c.xii" "Ensure reverse path filtering is enabled" \
        "net.ipv4.conf.all.rp_filter" "1"
}

check_source_routing() {
    sysctl_rule "NET-4.c.xiii" "Ensure source routed packets are not accepted" \
        "net.ipv4.conf.all.accept_source_route" "0"
}

check_log_martians() {
    sysctl_rule "NET-4.c.xiv" "Ensure suspicious packets are logged" \
        "net.ipv4.conf.all.log_martians" "1"
}

check_syn_cookies() {
    sysctl_rule "NET-4.c.xv" "Ensure tcp syn cookies is enabled" \
        "net.ipv4.tcp_syncookies" "1"
}

check_ipv6_ra() {
    sysctl_rule "NET-4.c.xvi" "Ensure ipv6 router advertisements are not accepted" \
        "net.ipv6.conf.all.accept_ra" "0"
}

# ===================================================================
# Main Execution
# ===================================================================

initialize_db

echo "========================================================================"
echo "Network Hardening Script"
echo "Module: $MODULE_NAME"
echo "Mode: $MODE"
echo "========================================================================"
echo ""

# 4.a Network Devices
log_info "=== 4.a Configure Network Devices ==="
check_ipv6_status
check_disable_wireless
check_bluetooth

echo ""

# 4.b Network Kernel Modules
log_info "=== 4.b Configure Network Kernel Modules ==="
check_dccp
check_tipc
check_rds
check_sctp

echo ""

# 4.c Network Kernel Parameters
log_info "=== 4.c Configure Network Kernel Parameters ==="
check_ip_forwarding
check_redirect_sending
check_bogus_icmp
check_broadcast_icmp
check_icmp_redirects
check_secure_redirects
check_reverse_path_filter
check_source_routing
check_log_martians
check_syn_cookies
check_ipv6_ra

# Summary
echo ""
echo "========================================================================"
echo "Summary"
echo "========================================================================"
echo "Total Checks: $TOTAL_CHECKS"
echo "Passed: $PASSED_CHECKS"
echo "Failed: $FAILED_CHECKS"
echo "Fixed:  $FIXED_CHECKS"
echo "========================================================================"

if [ "$FAILED_CHECKS" -gt 0 ]; then
    echo -e "${RED}[FAIL] Some checks failed.${NC}"
else
    echo -e "${GREEN}[PASS] All checks passed.${NC}"
fi
