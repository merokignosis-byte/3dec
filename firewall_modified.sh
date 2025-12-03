#!/bin/bash
# Host Based Firewall Hardening Script - Standardized Version
# Module: Host Based Firewall
# Policy ID Format: FW-X.X.X (from Annexure B)

MODE="${1:-scan}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DB_PATH="$SCRIPT_DIR/hardening.db"
BACKUP_DIR="$SCRIPT_DIR/backups/firewall"
TOPIC="Host Based Firewall"
MODULE_NAME="Host Based Firewall"

mkdir -p "$BACKUP_DIR"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

TOTAL_CHECKS=0
PASSED_CHECKS=0
FAILED_CHECKS=0
FIXED_CHECKS=0

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[FAIL]${NC} $1"; }
log_pass() { echo -e "${GREEN}[PASS]${NC} $1"; }

# ============================================================================
# Standard Output Function
# ============================================================================
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

# ============================================================================
# Database Functions
# ============================================================================
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
    python3 -c "
import sqlite3
conn = sqlite3.connect('$DB_PATH')
cursor = conn.cursor()
cursor.execute('''
    INSERT OR REPLACE INTO configurations 
    (topic, rule_id, rule_name, original_value, current_value, status)
    VALUES (?, ?, ?, ?, ?, 'stored')
''', ('$TOPIC', '$1', '''$2''', '''$3''', '''${4:-$3}'''))
conn.commit()
conn.close()
" 2>/dev/null
}

get_original_config() {
    python3 -c "
import sqlite3
conn = sqlite3.connect('$DB_PATH')
cursor = conn.cursor()
cursor.execute('SELECT original_value FROM configurations WHERE topic=? AND rule_id=?', ('$TOPIC', '$1'))
result = cursor.fetchone()
conn.close()
print(result[0] if result else '')
" 2>/dev/null
}

# ============================================================================
# 5.a Configure a single firewall utility
# ============================================================================

check_ufw_installed() {
    local policy_id="FW-5.a.i"
    local policy_name="Ensure ufw is installed"
    
    ((TOTAL_CHECKS++))
    
    if [ "$MODE" = "scan" ]; then
        local status="FAIL"
        local expected="installed"
        local current="not installed"
        
        if command -v ufw >/dev/null 2>&1; then
            current="installed"
            status="PASS"
            ((PASSED_CHECKS++))
        else
            ((FAILED_CHECKS++))
        fi
        
        print_check_result "$policy_id" "$policy_name" "$expected" "$current" "$status"
        
    elif [ "$MODE" = "fix" ]; then
        if ! command -v ufw >/dev/null 2>&1; then
            save_config "$policy_id" "$policy_name" "not_installed"
            
            apt-get update -y >/dev/null
            apt-get install -y ufw >/dev/null
            
            log_info "Fixed: $policy_name"
            ((FIXED_CHECKS++))
        else
            log_info "ufw is already installed"
        fi
        
    elif [ "$MODE" = "rollback" ]; then
        local original=$(get_original_config "$policy_id")
        if [ "$original" = "not_installed" ]; then
            apt-get remove -y ufw >/dev/null
            log_info "Rolled back: $policy_name"
        fi
    fi
}

check_iptables_persistent() {
    local policy_id="FW-5.a.ii"
    local policy_name="Ensure iptables-persistent is not installed with ufw"
    
    ((TOTAL_CHECKS++))
    
    if [ "$MODE" = "scan" ]; then
        local status="FAIL"
        local expected="not installed"
        local current="unknown"
        
        if dpkg -l | grep -q "^ii  iptables-persistent"; then
            current="installed (conflict with ufw)"
            ((FAILED_CHECKS++))
        else
            current="not installed"
            status="PASS"
            ((PASSED_CHECKS++))
        fi
        
        print_check_result "$policy_id" "$policy_name" "$expected" "$current" "$status"
        
    elif [ "$MODE" = "fix" ]; then
        if dpkg -l | grep -q "^ii  iptables-persistent"; then
            save_config "$policy_id" "$policy_name" "installed"
            
            apt-get purge -y iptables-persistent >/dev/null
            log_info "Fixed: $policy_name"
            ((FIXED_CHECKS++))
        else
            log_info "iptables-persistent is not installed"
        fi
        
    elif [ "$MODE" = "rollback" ]; then
        local original=$(get_original_config "$policy_id")
        if [ "$original" = "installed" ]; then
            apt-get install -y iptables-persistent >/dev/null
            log_info "Rolled back: $policy_name"
        fi
    fi
}

check_ufw_service_enabled() {
    local policy_id="FW-5.a.iii"
    local policy_name="Ensure ufw service is enabled"
    
    ((TOTAL_CHECKS++))
    
    if [ "$MODE" = "scan" ]; then
        local status="FAIL"
        local expected="enabled and active"
        local current="unknown"
        
        if ! command -v ufw >/dev/null 2>&1; then
            current="ufw not installed"
            ((FAILED_CHECKS++))
        elif systemctl is-enabled ufw >/dev/null 2>&1 && ufw status | grep -q "Status: active"; then
            current="enabled and active"
            status="PASS"
            ((PASSED_CHECKS++))
        else
            current="not enabled or not active"
            ((FAILED_CHECKS++))
        fi
        
        print_check_result "$policy_id" "$policy_name" "$expected" "$current" "$status"
        
    elif [ "$MODE" = "fix" ]; then
        if ! command -v ufw >/dev/null 2>&1; then
            log_error "ufw is not installed - install it first"
            return 1
        fi
        
        save_config "$policy_id" "$policy_name" "disabled"
        
        systemctl enable ufw >/dev/null
        ufw --force enable >/dev/null
        
        log_info "Fixed: $policy_name"
        ((FIXED_CHECKS++))
        
    elif [ "$MODE" = "rollback" ]; then
        systemctl disable ufw >/dev/null 2>&1
        ufw disable >/dev/null 2>&1
        log_info "Rolled back: $policy_name"
    fi
}

check_ufw_loopback() {
    local policy_id="FW-5.a.iv"
    local policy_name="Ensure ufw loopback traffic is configured"
    
    ((TOTAL_CHECKS++))
    
    if [ "$MODE" = "scan" ]; then
        local status="FAIL"
        local expected="loopback traffic allowed"
        local current="unknown"
        
        if ! command -v ufw >/dev/null 2>&1; then
            current="ufw not installed"
            ((FAILED_CHECKS++))
        else
            local ufw_status=$(ufw status verbose 2>/dev/null)
            
            if echo "$ufw_status" | grep -qE "ALLOW IN.*(lo|127\.0\.0\.1)" && \
               echo "$ufw_status" | grep -qE "ALLOW OUT.*(lo|127\.0\.0\.1)"; then
                current="loopback rules configured"
                status="PASS"
                ((PASSED_CHECKS++))
            else
                current="loopback rules missing"
                ((FAILED_CHECKS++))
            fi
        fi
        
        print_check_result "$policy_id" "$policy_name" "$expected" "$current" "$status"
        
    elif [ "$MODE" = "fix" ]; then
        if ! command -v ufw >/dev/null 2>&1; then
            log_error "ufw is not installed"
            return 1
        fi
        
        local snapshot=$(ufw status verbose 2>/dev/null)
        save_config "$policy_id" "$policy_name" "$snapshot"
        
        ufw allow in on lo >/dev/null
        ufw allow out on lo >/dev/null
        ufw allow in from 127.0.0.1 >/dev/null
        ufw allow out to 127.0.0.1 >/dev/null
        
        log_info "Fixed: $policy_name"
        ((FIXED_CHECKS++))
        
    elif [ "$MODE" = "rollback" ]; then
        local original=$(get_original_config "$policy_id")
        if [ -n "$original" ]; then
            ufw --force reset >/dev/null
            echo "$original" > /tmp/ufw_snapshot.txt
            log_info "Rolled back: $policy_name (review /tmp/ufw_snapshot.txt)"
        fi
    fi
}

check_ufw_outbound() {
    local policy_id="FW-5.a.v"
    local policy_name="Ensure ufw outbound connections are configured"
    
    ((TOTAL_CHECKS++))
    
    if [ "$MODE" = "scan" ]; then
        local status="PASS"
        local expected="manual review required"
        local current="unknown"
        
        if ! command -v ufw >/dev/null 2>&1; then
            current="ufw not installed"
            status="FAIL"
            ((FAILED_CHECKS++))
        else
            local ufw_status=$(ufw status verbose 2>/dev/null)
            
            if echo "$ufw_status" | grep -q "Default: deny (incoming), allow (outgoing)"; then
                current="default outbound: allow (manual review recommended)"
                ((PASSED_CHECKS++))
            else
                current="outbound policy needs review"
                ((PASSED_CHECKS++))
            fi
        fi
        
        print_check_result "$policy_id" "$policy_name" "$expected" "$current" "$status"
        
    elif [ "$MODE" = "fix" ]; then
        if ! command -v ufw >/dev/null 2>&1; then
            log_error "ufw is not installed"
            return 1
        fi
        
        ufw default allow outgoing >/dev/null
        log_info "Fixed: $policy_name (set to allow outgoing)"
        log_warn "Manual review recommended for specific outbound rules"
        ((FIXED_CHECKS++))
        
    elif [ "$MODE" = "rollback" ]; then
        log_info "Outbound policy rollback requires manual review"
    fi
}

check_ufw_open_ports() {
    local policy_id="FW-5.a.vi"
    local policy_name="Ensure ufw firewall rules exist for all open ports"
    
    ((TOTAL_CHECKS++))
    
    if [ "$MODE" = "scan" ]; then
        local status="FAIL"
        local expected="all open ports have firewall rules"
        local current="unknown"
        
        if ! command -v ufw >/dev/null 2>&1; then
            current="ufw not installed"
            ((FAILED_CHECKS++))
        else
            local ufw_rules=$(ufw status verbose 2>/dev/null)
            local open_ports=$(ss -tunl | awk 'NR>1 {gsub(/.*:/,"",$5); print $5}' | sort -u)
            
            local missing=0
            for port in $open_ports; do
                if ! echo "$ufw_rules" | grep -q "$port"; then
                    ((missing++))
                fi
            done
            
            if [ "$missing" -eq 0 ]; then
                current="all open ports have rules"
                status="PASS"
                ((PASSED_CHECKS++))
            else
                current="$missing open ports without rules"
                ((FAILED_CHECKS++))
            fi
        fi
        
        print_check_result "$policy_id" "$policy_name" "$expected" "$current" "$status"
        
    elif [ "$MODE" = "fix" ]; then
        if ! command -v ufw >/dev/null 2>&1; then
            log_error "ufw is not installed"
            return 1
        fi
        
        local ufw_rules=$(ufw status verbose 2>/dev/null)
        local open_ports=$(ss -tunl | awk 'NR>1 {gsub(/.*:/,"",$5); print $5}' | sort -u)
        
        local added=0
        for port in $open_ports; do
            if ! echo "$ufw_rules" | grep -q "$port"; then
                if ufw allow "$port"/tcp >/dev/null 2>&1; then
                    log_info "Added UFW rule for port: $port"
                    ((added++))
                fi
            fi
        done
        
        if [ "$added" -gt 0 ]; then
            ufw reload >/dev/null
            log_info "Fixed: $policy_name ($added rules added)"
            ((FIXED_CHECKS++))
        else
            log_info "No new rules needed"
        fi
        
    elif [ "$MODE" = "rollback" ]; then
        log_info "Open port rules rollback requires manual review"
    fi
}

check_ufw_default_deny() {
    local policy_id="FW-5.a.vii"
    local policy_name="Ensure ufw default deny firewall policy"
    
    ((TOTAL_CHECKS++))
    
    if [ "$MODE" = "scan" ]; then
        local status="FAIL"
        local expected="default deny incoming"
        local current="unknown"
        
        if ! command -v ufw >/dev/null 2>&1; then
            current="ufw not installed"
            ((FAILED_CHECKS++))
        else
            local default_policy=$(ufw status verbose 2>/dev/null | grep "Default:" | awk '{print $2}')
            
            if [ "$default_policy" = "deny" ]; then
                current="default deny incoming"
                status="PASS"
                ((PASSED_CHECKS++))
            else
                current="default policy: $default_policy"
                ((FAILED_CHECKS++))
            fi
        fi
        
        print_check_result "$policy_id" "$policy_name" "$expected" "$current" "$status"
        
    elif [ "$MODE" = "fix" ]; then
        if ! command -v ufw >/dev/null 2>&1; then
            log_error "ufw is not installed"
            return 1
        fi
        
        save_config "$policy_id" "$policy_name" "not_deny"
        
        ufw default deny incoming >/dev/null
        ufw default allow outgoing >/dev/null
        ufw reload >/dev/null
        
        log_info "Fixed: $policy_name"
        ((FIXED_CHECKS++))
        
    elif [ "$MODE" = "rollback" ]; then
        ufw default allow incoming >/dev/null
        ufw reload >/dev/null
        log_info "Rolled back: $policy_name"
    fi
}

check_ufw_iptables_conflict() {
    local policy_id="FW-5.a.viii"
    local policy_name="Ensure ufw is not in use with iptables"
    
    ((TOTAL_CHECKS++))
    
    if [ "$MODE" = "scan" ]; then
        local status="FAIL"
        local expected="no iptables conflict"
        local current="unknown"
        
        if ! command -v ufw >/dev/null 2>&1; then
            current="ufw not installed"
            ((FAILED_CHECKS++))
        else
            local ufw_active=$(ufw status | grep -q "Status: active" && echo "yes" || echo "no")
            local iptables_rules=$(iptables -L 2>/dev/null | grep -v "^Chain" | grep -v "^target" | wc -l)
            
            if [ "$ufw_active" = "yes" ] && [ "$iptables_rules" -gt 0 ]; then
                current="conflict detected (both ufw and raw iptables active)"
                ((FAILED_CHECKS++))
            else
                current="no conflict"
                status="PASS"
                ((PASSED_CHECKS++))
            fi
        fi
        
        print_check_result "$policy_id" "$policy_name" "$expected" "$current" "$status"
        
    elif [ "$MODE" = "fix" ]; then
        log_warn "Manual review required to resolve ufw/iptables conflict"
        log_info "Recommended: Use ufw exclusively, remove raw iptables rules"
        
    elif [ "$MODE" = "rollback" ]; then
        log_info "No automatic rollback for conflict resolution"
    fi
}

# ============================================================================
# Main Execution
# ============================================================================

main() {
    echo "========================================================================"
    echo "Host Based Firewall Hardening - Module: $MODULE_NAME"
    echo "Mode: $MODE"
    echo "========================================================================"
    
    initialize_db
    
    if [ "$MODE" = "scan" ] || [ "$MODE" = "fix" ]; then
        log_info "=== 5.a Configure a single firewall utility ==="
        check_ufw_installed
        check_iptables_persistent
        check_ufw_service_enabled
        check_ufw_loopback
        check_ufw_outbound
        check_ufw_open_ports
        check_ufw_default_deny
        check_ufw_iptables_conflict
        
        echo ""
        echo "========================================================================"
        echo "Summary"
        echo "========================================================================"
        echo "Total Checks: $TOTAL_CHECKS"
        
        if [ "$MODE" = "scan" ]; then
            echo "Passed: $PASSED_CHECKS"
            echo "Failed: $FAILED_CHECKS"
            
            if [ $FAILED_CHECKS -eq 0 ]; then
                log_pass "All firewall checks passed!"
            else
                log_warn "$FAILED_CHECKS checks failed. Run with 'fix' mode to remediate."
            fi
        else
            echo "Fixed: $FIXED_CHECKS"
            
            if [ $FIXED_CHECKS -gt 0 ]; then
                log_info "Fixes applied successfully"
                log_warn "Review firewall rules with: ufw status verbose"
            fi
        fi
        
    elif [ "$MODE" = "rollback" ]; then
        log_info "Rolling back firewall configurations..."
        check_ufw_installed
        check_iptables_persistent
        check_ufw_service_enabled
        check_ufw_loopback
        check_ufw_default_deny
        log_info "Rollback completed"
        
    else
        echo "Usage: $0 {scan|fix|rollback}"
        exit 1
    fi
}

main