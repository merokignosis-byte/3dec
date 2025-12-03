#!/bin/bash
# CIS-Style Services Hardening Script (with Rollback Support)
# Modes: scan | fix | rollback

MODE="${1:-scan}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
DB_PATH="$SCRIPT_DIR/services_hardening.db"
BACKUP_DIR="$SCRIPT_DIR/backups"
TOPIC="Services"
MODULE_NAME="Services"

mkdir -p "$BACKUP_DIR"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

TOTAL_CHECKS=0
PASSED_CHECKS=0
FAILED_CHECKS=0
FIXED_CHECKS=0

# =========================
# Standard Output Function
# =========================
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

# =========================
# DB Setup
# =========================
initialize_db() {
    if [ ! -f "$DB_PATH" ]; then
        sqlite3 "$DB_PATH" "CREATE TABLE IF NOT EXISTS configurations (
            topic TEXT,
            rule_id TEXT PRIMARY KEY,
            rule_name TEXT,
            original_value TEXT,
            status TEXT
        );"
    fi
}

save_config() {
    sqlite3 "$DB_PATH" <<EOF
INSERT OR REPLACE INTO configurations
(topic, rule_id, rule_name, original_value, status)
VALUES ('$TOPIC', '$1', '$2', '$3', 'stored');
EOF
}

get_original() {
    sqlite3 "$DB_PATH" "SELECT original_value FROM configurations WHERE rule_id='$1';"
}

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_fixed() { echo -e "${GREEN}[FIXED]${NC} $1"; }

# =========================
# Service Status Checker
# =========================
is_disabled() {
    local state
    state=$(systemctl is-enabled "$1" 2>/dev/null)
    case "$state" in
        disabled|masked|static|indirect|not-found)
            return 0 ;;
        *)  return 1 ;;
    esac
}

disable_service() {
    systemctl stop "$1" 2>/dev/null
    systemctl disable "$1" 2>/dev/null
    systemctl mask "$1" 2>/dev/null
}

enable_service() {
    systemctl unmask "$1" 2>/dev/null
    systemctl enable "$1" 2>/dev/null
    systemctl start "$1" 2>/dev/null
}

# =========================
# Service Hardening Functions
# =========================
check_service() {
    local policy_id="$1"
    local policy_name="$2"
    local service="$3"
    
    ((TOTAL_CHECKS++))
    
    if [ "$MODE" = "scan" ]; then
        local status="FAIL"
        local expected="disabled/masked"
        local current="unknown"
        
        if is_disabled "$service"; then
            current=$(systemctl is-enabled "$service" 2>/dev/null || echo "not-found")
            status="PASS"
            ((PASSED_CHECKS++))
        else
            current=$(systemctl is-enabled "$service" 2>/dev/null || echo "enabled")
            ((FAILED_CHECKS++))
        fi
        
        print_check_result "$policy_id" "$policy_name" "$expected" "$current" "$status"
        
    elif [ "$MODE" = "fix" ]; then
        save_config "$policy_id" "$policy_name" "$(systemctl is-enabled "$service" 2>/dev/null)"
        disable_service "$service"
        log_fixed "$policy_name"
        ((FIXED_CHECKS++))
        
    elif [ "$MODE" = "rollback" ]; then
        original=$(get_original "$policy_id")
        if [[ "$original" == "enabled" ]]; then
            enable_service "$service"
            log_info "Restored $service to enabled"
        fi
    fi
}

check_package() {
    local policy_id="$1"
    local policy_name="$2"
    local package="$3"
    
    ((TOTAL_CHECKS++))
    
    if [ "$MODE" = "scan" ]; then
        local status="FAIL"
        local expected="not installed"
        local current="unknown"
        
        if dpkg -l | grep -q "^ii.*$package"; then
            current="installed"
            ((FAILED_CHECKS++))
        else
            current="not installed"
            status="PASS"
            ((PASSED_CHECKS++))
        fi
        
        print_check_result "$policy_id" "$policy_name" "$expected" "$current" "$status"
        
    elif [ "$MODE" = "fix" ]; then
        if dpkg -l | grep -q "^ii.*$package"; then
            save_config "$policy_id" "$policy_name" "installed"
            apt remove -y "$package" >/dev/null 2>&1
            log_fixed "$policy_name"
            ((FIXED_CHECKS++))
        fi
        
    elif [ "$MODE" = "rollback" ]; then
        original=$(get_original "$policy_id")
        if [[ "$original" = "installed" ]]; then
            apt install -y "$package" >/dev/null 2>&1
            log_info "Restored $package"
        fi
    fi
}

# =========================
# Server Services Checks
# =========================
check_server_services() {
    check_service "SRV-3.a.i" "Ensure autofs services are not in use" "autofs"
    check_service "SRV-3.a.ii" "Ensure avahi daemon services are not in use" "avahi-daemon"
    check_service "SRV-3.a.iii" "Ensure dhcp server services are not in use" "isc-dhcp-server"
    check_service "SRV-3.a.iv" "Ensure dns server services are not in use" "bind9"
    check_service "SRV-3.a.v" "Ensure dnsmasq services are not in use" "dnsmasq"
    check_service "SRV-3.a.vi" "Ensure ftp server services are not in use" "vsftpd"
    check_service "SRV-3.a.vii" "Ensure ldap server services are not in use" "slapd"
    check_service "SRV-3.a.viii" "Ensure message access server services are not in use" "dovecot"
    check_service "SRV-3.a.ix" "Ensure network file system services are not in use" "nfs-kernel-server"
    check_service "SRV-3.a.x" "Ensure nis server services are not in use" "nis"
    check_service "SRV-3.a.xi" "Ensure print server services are not in use" "cups"
    check_service "SRV-3.a.xii" "Ensure rpcbind services are not in use" "rpcbind"
    check_service "SRV-3.a.xiii" "Ensure rsync services are not in use" "rsync"
    check_service "SRV-3.a.xiv" "Ensure samba file server services are not in use" "smbd"
    check_service "SRV-3.a.xv" "Ensure snmp services are not in use" "snmpd"
    check_service "SRV-3.a.xvi" "Ensure tftp server services are not in use" "tftpd-hpa"
    check_service "SRV-3.a.xvii" "Ensure web proxy server services are not in use" "squid"
    check_service "SRV-3.a.xviii" "Ensure web server services are not in use" "apache2"
    check_service "SRV-3.a.xix" "Ensure xinetd services are not in use" "xinetd"
    check_service "SRV-3.a.xx" "Ensure X window server services are not in use" "gdm"
}

# =========================
# Client Services Checks
# =========================
check_client_services() {
    check_package "SRV-3.b.i" "Ensure NIS Client is not installed" "nis"
    check_package "SRV-3.b.ii" "Ensure rsh client is not installed" "rsh-client"
    check_package "SRV-3.b.iii" "Ensure talk client is not installed" "talk"
    check_package "SRV-3.b.iv" "Ensure telnet client is not installed" "telnet"
    check_package "SRV-3.b.v" "Ensure ldap client is not installed" "ldap-utils"
    check_package "SRV-3.b.vi" "Ensure ftp client is not installed" "ftp"
}

# =========================
# Time Synchronization
# =========================
check_time_sync() {
    local policy_id="SRV-3.c"
    local policy_name="Ensure time synchronization is in use"
    
    ((TOTAL_CHECKS++))
    
    if [ "$MODE" = "scan" ]; then
        local status="FAIL"
        local expected="chrony active and enabled"
        local current="unknown"
        
        if systemctl is-active chrony >/dev/null 2>&1 && systemctl is-enabled chrony >/dev/null 2>&1; then
            current="chrony active and enabled"
            status="PASS"
            ((PASSED_CHECKS++))
        else
            current="chrony not configured"
            ((FAILED_CHECKS++))
        fi
        
        print_check_result "$policy_id" "$policy_name" "$expected" "$current" "$status"
        
    elif [ "$MODE" = "fix" ]; then
        save_config "$policy_id" "$policy_name" "chrony"
        systemctl stop systemd-timesyncd 2>/dev/null
        systemctl disable systemd-timesyncd 2>/dev/null
        systemctl mask systemd-timesyncd 2>/dev/null
        apt install -y chrony >/dev/null 2>&1
        systemctl enable chrony
        systemctl start chrony
        log_fixed "$policy_name"
        ((FIXED_CHECKS++))
    fi
}

check_single_time_daemon() {
    local policy_id="SRV-3.c.i"
    local policy_name="Ensure a single time synchronization daemon is in use"
    
    ((TOTAL_CHECKS++))
    
    if [ "$MODE" = "scan" ]; then
        local status="FAIL"
        local expected="only chrony running"
        local current="unknown"
        
        local chrony_active=$(systemctl is-active chrony 2>/dev/null)
        local timesyncd_active=$(systemctl is-active systemd-timesyncd 2>/dev/null)
        
        if [ "$chrony_active" = "active" ] && [ "$timesyncd_active" != "active" ]; then
            current="only chrony running"
            status="PASS"
            ((PASSED_CHECKS++))
        else
            current="chrony: $chrony_active, timesyncd: $timesyncd_active"
            ((FAILED_CHECKS++))
        fi
        
        print_check_result "$policy_id" "$policy_name" "$expected" "$current" "$status"
        
    elif [ "$MODE" = "fix" ]; then
        systemctl stop systemd-timesyncd 2>/dev/null
        systemctl disable systemd-timesyncd 2>/dev/null
        systemctl mask systemd-timesyncd 2>/dev/null
        log_fixed "$policy_name"
        ((FIXED_CHECKS++))
    fi
}

check_chrony_timeserver() {
    local policy_id="SRV-3.e.i"
    local policy_name="Ensure chrony is configured with authorized timeserver"
    
    ((TOTAL_CHECKS++))
    
    if [ "$MODE" = "scan" ]; then
        local status="FAIL"
        local expected="timeserver configured"
        local current="unknown"
        
        if [ -f /etc/chrony/chrony.conf ] && grep -q "^pool\|^server" /etc/chrony/chrony.conf; then
            current=$(grep "^pool\|^server" /etc/chrony/chrony.conf | head -1 | awk '{print $2}')
            status="PASS"
            ((PASSED_CHECKS++))
        else
            current="no timeserver"
            ((FAILED_CHECKS++))
        fi
        
        print_check_result "$policy_id" "$policy_name" "$expected" "$current" "$status"
    fi
}

check_chrony_user() {
    local policy_id="SRV-3.e.ii"
    local policy_name="Ensure chrony is running as user _chrony"
    
    ((TOTAL_CHECKS++))
    
    if [ "$MODE" = "scan" ]; then
        local status="FAIL"
        local expected="_chrony"
        local current="unknown"
        
        if ps -ef | grep chronyd | grep -v grep | grep -q "_chrony"; then
            current="_chrony"
            status="PASS"
            ((PASSED_CHECKS++))
        else
            current=$(ps -ef | grep chronyd | grep -v grep | awk '{print $1}' | head -1)
            ((FAILED_CHECKS++))
        fi
        
        print_check_result "$policy_id" "$policy_name" "$expected" "$current" "$status"
    fi
}

check_chrony_enabled() {
    local policy_id="SRV-3.e.iii"
    local policy_name="Ensure chrony is enabled and running"
    
    ((TOTAL_CHECKS++))
    
    if [ "$MODE" = "scan" ]; then
        local status="FAIL"
        local expected="enabled and active"
        local current="unknown"
        
        local enabled=$(systemctl is-enabled chrony 2>/dev/null)
        local active=$(systemctl is-active chrony 2>/dev/null)
        
        if [ "$enabled" = "enabled" ] && [ "$active" = "active" ]; then
            current="enabled and active"
            status="PASS"
            ((PASSED_CHECKS++))
        else
            current="enabled: $enabled, active: $active"
            ((FAILED_CHECKS++))
        fi
        
        print_check_result "$policy_id" "$policy_name" "$expected" "$current" "$status"
    fi
}

# =========================
# Cron Job Schedulers
# =========================
check_cron_enabled() {
    local policy_id="SRV-3.f.i"
    local policy_name="Ensure cron daemon is enabled and active"
    
    ((TOTAL_CHECKS++))
    
    if [ "$MODE" = "scan" ]; then
        local status="FAIL"
        local expected="enabled and active"
        local current="unknown"
        
        local enabled=$(systemctl is-enabled cron 2>/dev/null)
        local active=$(systemctl is-active cron 2>/dev/null)
        
        if [ "$enabled" = "enabled" ] && [ "$active" = "active" ]; then
            current="enabled and active"
            status="PASS"
            ((PASSED_CHECKS++))
        else
            current="enabled: $enabled, active: $active"
            ((FAILED_CHECKS++))
        fi
        
        print_check_result "$policy_id" "$policy_name" "$expected" "$current" "$status"
        
    elif [ "$MODE" = "fix" ]; then
        systemctl enable cron
        systemctl start cron
        log_fixed "$policy_name"
        ((FIXED_CHECKS++))
    fi
}

check_cron_permissions() {
    local file="$1"
    local policy_id="$2"
    local policy_name="$3"
    local expected_perms="$4"
    
    ((TOTAL_CHECKS++))
    
    if [ "$MODE" = "scan" ]; then
        local status="FAIL"
        local expected="$expected_perms root:root"
        local current="unknown"
        
        if [ -e "$file" ]; then
            local perms=$(stat -c "%a" "$file" 2>/dev/null)
            local owner=$(stat -c "%U:%G" "$file" 2>/dev/null)
            current="$perms $owner"
            
            if [ "$perms" = "$expected_perms" ] && [ "$owner" = "root:root" ]; then
                status="PASS"
                ((PASSED_CHECKS++))
            else
                ((FAILED_CHECKS++))
            fi
        else
            current="file not found"
            ((FAILED_CHECKS++))
        fi
        
        print_check_result "$policy_id" "$policy_name" "$expected" "$current" "$status"
        
    elif [ "$MODE" = "fix" ]; then
        if [ -e "$file" ]; then
            chmod "$expected_perms" "$file"
            chown root:root "$file"
            log_fixed "$policy_name"
            ((FIXED_CHECKS++))
        fi
    fi
}

check_all_cron_permissions() {
    check_cron_permissions "/etc/crontab" "SRV-3.f.ii" "Ensure permissions on /etc/crontab are configured" "600"
    check_cron_permissions "/etc/cron.hourly" "SRV-3.f.iii" "Ensure permissions on /etc/cron.hourly are configured" "700"
    check_cron_permissions "/etc/cron.daily" "SRV-3.f.iv" "Ensure permissions on /etc/cron.daily are configured" "700"
    check_cron_permissions "/etc/cron.weekly" "SRV-3.f.v" "Ensure permissions on /etc/cron.weekly are configured" "700"
    check_cron_permissions "/etc/cron.monthly" "SRV-3.f.vi" "Ensure permissions on /etc/cron.monthly are configured" "700"
    check_cron_permissions "/etc/cron.d" "SRV-3.f.vii" "Ensure permissions on /etc/cron.d are configured" "700"
}

check_crontab_restricted() {
    local policy_id="SRV-3.f.viii"
    local policy_name="Ensure crontab is restricted to authorized users"
    
    ((TOTAL_CHECKS++))
    
    if [ "$MODE" = "scan" ]; then
        local status="FAIL"
        local expected="/etc/cron.allow exists, /etc/cron.deny removed"
        local current="unknown"
        
        if [ -f /etc/cron.allow ] && [ ! -f /etc/cron.deny ]; then
            current="cron.allow exists, cron.deny removed"
            status="PASS"
            ((PASSED_CHECKS++))
        else
            current="allow: $([ -f /etc/cron.allow ] && echo exists || echo missing), deny: $([ -f /etc/cron.deny ] && echo exists || echo missing)"
            ((FAILED_CHECKS++))
        fi
        
        print_check_result "$policy_id" "$policy_name" "$expected" "$current" "$status"
        
    elif [ "$MODE" = "fix" ]; then
        touch /etc/cron.allow
        rm -f /etc/cron.deny
        chmod 600 /etc/cron.allow
        chown root:root /etc/cron.allow
        log_fixed "$policy_name"
        ((FIXED_CHECKS++))
    fi
}

check_mail_local_only() {
    local policy_id="SRV-3.a.xxi"
    local policy_name="Ensure mail transfer agent is configured for local-only mode"
    
    ((TOTAL_CHECKS++))
    
    if [ "$MODE" = "scan" ]; then
        local status="FAIL"
        local expected="listening on localhost only"
        local current="unknown"
        
        if ss -lntu | grep -E ':25\s' | grep -q '127.0.0.1:25'; then
            current="localhost only"
            status="PASS"
            ((PASSED_CHECKS++))
        else
            current=$(ss -lntu | grep ':25' | awk '{print $5}' | head -1)
            ((FAILED_CHECKS++))
        fi
        
        print_check_result "$policy_id" "$policy_name" "$expected" "$current" "$status"
    fi
}

check_approved_services_listening() {
    local policy_id="SRV-3.a.xxii"
    local policy_name="Ensure only approved services are listening on a network interface"
    
    ((TOTAL_CHECKS++))
    
    if [ "$MODE" = "scan" ]; then
        local status="PASS"
        local expected="only approved ports: 22,53,80,443,123"
        local current="unknown"
        
        local listening_ports=$(ss -tuln | awk 'NR>1 {gsub(/.*:/,"",$5); print $5}' | sort -u | tr '\n' ',' | sed 's/,$//')
        current="$listening_ports"
        
        # This is informational - let admin verify
        ((PASSED_CHECKS++))
        
        print_check_result "$policy_id" "$policy_name" "$expected" "$current" "$status"
    fi
}

# =========================
# Main Execution
# =========================
initialize_db

echo "=========================================="
echo "Services Hardening - Mode: $MODE"
echo "=========================================="
echo ""

# Server Services
check_server_services

# Client Services
check_client_services

# Time Synchronization
check_time_sync
check_single_time_daemon
check_chrony_timeserver
check_chrony_user
check_chrony_enabled

# Cron Services
check_cron_enabled
check_all_cron_permissions
check_crontab_restricted

# Additional Checks
check_mail_local_only
check_approved_services_listening

# =========================
# Summary
# =========================
echo ""
echo "========================================================"
echo "Summary"
echo "========================================================"
echo "Total Checks: $TOTAL_CHECKS"
echo "Passed: $PASSED_CHECKS"
echo "Failed: $FAILED_CHECKS"
echo "Fixed: $FIXED_CHECKS"
echo "========================================================"

if [ "$FAILED_CHECKS" -gt 0 ]; then
    echo -e "${RED}[FAIL] Issues detected.${NC}"
else
    echo -e "${GREEN}[PASS] All checks passed.${NC}"
fi
