#!/bin/bash
# Package Management Hardening Script
# Module: Package Management
# Mode: scan | fix

MODE="${1:-scan}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DB_PATH="$SCRIPT_DIR/hardening.db"
BACKUP_DIR="$SCRIPT_DIR/backups"
TOPIC="Package Management"
MODULE_NAME="Package Management"

mkdir -p "$BACKUP_DIR"

RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m'

TOTAL_CHECKS=0
PASSED_CHECKS=0
FAILED_CHECKS=0
FIXED_CHECKS=0

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
try:
    conn = sqlite3.connect('$DB_PATH')
    cursor = conn.cursor()
    cursor.execute('''
        INSERT OR REPLACE INTO configurations
        (topic, rule_id, rule_name, original_value, current_value, status)
        VALUES (?, ?, ?, ?, ?, 'stored')
    ''', ('$TOPIC', '$rule_id', '$rule_name', '$original_value', '$current_value'))
    conn.commit()
    conn.close()
except Exception as e:
    print(f"Error: {str(e)}")
EOF
}

get_original_config() {
    local rule_id="$1"
    python3 - <<EOF
import sqlite3
conn = sqlite3.connect('$DB_PATH')
cursor = conn.cursor()
cursor.execute('SELECT original_value FROM configurations WHERE topic=? AND rule_id=?', ('$TOPIC', '$rule_id'))
res = cursor.fetchone()
conn.close()
print(res[0] if res else '')
EOF
}

get_grub_cfg() {
    local grub_paths=(
        "/boot/grub/grub.cfg"
        "/boot/grub2/grub.cfg"
        "/boot/efi/EFI/kali/grub.cfg"
        "/boot/efi/EFI/ubuntu/grub.cfg"
    )
    for path in "${grub_paths[@]}"; do
        if [ -f "$path" ]; then
            echo "$path"
            return 0
        fi
    done
    return 1
}

# ============================================================================
# 2.a Configure Bootloader
# ============================================================================

check_bootloader_password() {
    local policy_id="PKG-2.a.i"
    local policy_name="Ensure bootloader password is set"
    ((TOTAL_CHECKS++))

    local grub_cfg
    grub_cfg=$(get_grub_cfg)
    
    if [ "$MODE" = "scan" ]; then
        local status="FAIL"
        local current="Not configured"
        
        if [ -n "$grub_cfg" ] && grep -q "^password_pbkdf2" "$grub_cfg" 2>/dev/null; then
            status="PASS"
            current="Password configured"
            ((PASSED_CHECKS++))
        else
            ((FAILED_CHECKS++))
        fi
        
        print_check_result "$policy_id" "$policy_name" \
            "Password configured" \
            "$current" \
            "$status"
            
    elif [ "$MODE" = "fix" ]; then
        if [ -n "$grub_cfg" ]; then
            chown root:root "$grub_cfg"
            chmod 400 "$grub_cfg"
        fi
        log_warn "Manual step: Add GRUB password hash to /etc/grub.d/40_custom, then run update-grub"
    fi
}

check_bootloader_config_permissions() {
    local policy_id="PKG-2.a.ii"
    local policy_name="Ensure access to bootloader config is configured"
    ((TOTAL_CHECKS++))

    local grub_cfg
    grub_cfg=$(get_grub_cfg)
    
    if [ "$MODE" = "scan" ]; then
        local status="FAIL"
        local current="Not configured"
        
        if [ -n "$grub_cfg" ]; then
            local perms owner group
            perms=$(stat -c %a "$grub_cfg")
            owner=$(stat -c %U "$grub_cfg")
            group=$(stat -c %G "$grub_cfg")
            current="$perms $owner:$group"
            
            if [ "$perms" = "400" ] && [ "$owner" = "root" ] && [ "$group" = "root" ]; then
                status="PASS"
                ((PASSED_CHECKS++))
            else
                ((FAILED_CHECKS++))
            fi
        else
            ((FAILED_CHECKS++))
        fi
        
        print_check_result "$policy_id" "$policy_name" \
            "400 root:root" \
            "$current" \
            "$status"
            
    elif [ "$MODE" = "fix" ]; then
        if [ -n "$grub_cfg" ]; then
            chown root:root "$grub_cfg"
            chmod 400 "$grub_cfg"
            log_fixed "Bootloader config permissions set to 400 root:root"
        fi
    fi
}

# ============================================================================
# 2.b Configure Additional Process Hardening
# ============================================================================

check_aslr() {
    local policy_id="PKG-2.b.i"
    local policy_name="Ensure address space layout randomization is enabled"
    ((TOTAL_CHECKS++))

    if [ "$MODE" = "scan" ]; then
        local value
        value=$(sysctl -n kernel.randomize_va_space 2>/dev/null)
        local status="FAIL"
        
        if [ "$value" = "2" ]; then
            status="PASS"
            ((PASSED_CHECKS++))
        else
            ((FAILED_CHECKS++))
        fi
        
        print_check_result "$policy_id" "$policy_name" \
            "2" \
            "$value" \
            "$status"
            
    elif [ "$MODE" = "fix" ]; then
        save_config "$policy_id" "$policy_name" "$(sysctl -n kernel.randomize_va_space 2>/dev/null)"
        sysctl -w kernel.randomize_va_space=2
        grep -q "kernel.randomize_va_space" /etc/sysctl.conf || echo "kernel.randomize_va_space = 2" >> /etc/sysctl.conf
        sed -i 's/^kernel.randomize_va_space.*/kernel.randomize_va_space = 2/' /etc/sysctl.conf
        log_fixed "ASLR enabled"
    fi
}

check_ptrace_scope() {
    local policy_id="PKG-2.b.ii"
    local policy_name="Ensure ptrace_scope is restricted"
    ((TOTAL_CHECKS++))

    if [ "$MODE" = "scan" ]; then
        local value
        value=$(sysctl -n kernel.yama.ptrace_scope 2>/dev/null)
        local status="FAIL"
        
        if [ "$value" = "1" ] || [ "$value" = "2" ]; then
            status="PASS"
            ((PASSED_CHECKS++))
        else
            ((FAILED_CHECKS++))
        fi
        
        print_check_result "$policy_id" "$policy_name" \
            "1 or 2" \
            "$value" \
            "$status"
            
    elif [ "$MODE" = "fix" ]; then
        save_config "$policy_id" "$policy_name" "$(sysctl -n kernel.yama.ptrace_scope 2>/dev/null)"
        sysctl -w kernel.yama.ptrace_scope=1
        grep -q "kernel.yama.ptrace_scope" /etc/sysctl.conf || echo "kernel.yama.ptrace_scope = 1" >> /etc/sysctl.conf
        sed -i 's/^kernel.yama.ptrace_scope.*/kernel.yama.ptrace_scope = 1/' /etc/sysctl.conf
        log_fixed "ptrace_scope restricted"
    fi
}

check_core_dumps() {
    local policy_id="PKG-2.b.iii"
    local policy_name="Ensure core dumps are restricted"
    ((TOTAL_CHECKS++))

    if [ "$MODE" = "scan" ]; then
        local suid_dumpable
        suid_dumpable=$(sysctl -n fs.suid_dumpable 2>/dev/null)
        local limits_check=$(grep -q "* hard core 0" /etc/security/limits.conf 2>/dev/null && echo "Yes" || echo "No")
        local status="FAIL"
        local current="suid_dumpable=$suid_dumpable, limits=$limits_check"
        
        if [ "$limits_check" = "Yes" ] && [ "$suid_dumpable" = "0" ]; then
            status="PASS"
            ((PASSED_CHECKS++))
        else
            ((FAILED_CHECKS++))
        fi
        
        print_check_result "$policy_id" "$policy_name" \
            "Core dumps disabled" \
            "$current" \
            "$status"
            
    elif [ "$MODE" = "fix" ]; then
        cp /etc/security/limits.conf "$BACKUP_DIR/limits.conf.$(date +%Y%m%d_%H%M%S)"
        save_config "$policy_id" "$policy_name" "not_restricted"
        grep -q "* hard core" /etc/security/limits.conf || echo "* hard core 0" >> /etc/security/limits.conf
        sysctl -w fs.suid_dumpable=0
        grep -q "fs.suid_dumpable" /etc/sysctl.conf || echo "fs.suid_dumpable = 0" >> /etc/sysctl.conf
        log_fixed "Core dumps restricted"
    fi
}

check_prelink() {
    local policy_id="PKG-2.b.iv"
    local policy_name="Ensure prelink is not installed"
    ((TOTAL_CHECKS++))

    if [ "$MODE" = "scan" ]; then
        local status="PASS"
        local current="Not installed"
        
        if dpkg -l | grep -q "^ii.*prelink"; then
            status="FAIL"
            current="Installed"
            ((FAILED_CHECKS++))
        else
            ((PASSED_CHECKS++))
        fi
        
        print_check_result "$policy_id" "$policy_name" \
            "Not installed" \
            "$current" \
            "$status"
            
    elif [ "$MODE" = "fix" ]; then
        if dpkg -l | grep -q "^ii.*prelink"; then
            save_config "$policy_id" "$policy_name" "installed"
            apt-get remove -y prelink 2>/dev/null
            log_fixed "prelink removed"
        fi
    fi
}

check_apport() {
    local policy_id="PKG-2.b.v"
    local policy_name="Ensure Automatic Error Reporting is not enabled"
    ((TOTAL_CHECKS++))

    if [ "$MODE" = "scan" ]; then
        local status="PASS"
        local current="Disabled"
        
        if systemctl is-enabled apport 2>/dev/null | grep -q "enabled"; then
            status="FAIL"
            current="Enabled"
            ((FAILED_CHECKS++))
        else
            ((PASSED_CHECKS++))
        fi
        
        print_check_result "$policy_id" "$policy_name" \
            "Disabled" \
            "$current" \
            "$status"
            
    elif [ "$MODE" = "fix" ]; then
        if systemctl is-enabled apport 2>/dev/null | grep -q "enabled"; then
            save_config "$policy_id" "$policy_name" "enabled"
            systemctl disable apport
            systemctl stop apport
            log_fixed "Apport disabled"
        fi
    fi
}

# ============================================================================
# 2.c Configure Command Line Warning Banners
# ============================================================================

check_issue_banner() {
    local policy_id="PKG-2.c.i"
    local policy_name="Ensure local login warning banner is configured properly"
    ((TOTAL_CHECKS++))

    if [ "$MODE" = "scan" ]; then
        local status="FAIL"
        local current="Not configured"
        
        if [ -f /etc/issue ] && [ -s /etc/issue ] && ! grep -qE "\\\\v|\\\\r|\\\\m|\\\\s" /etc/issue; then
            status="PASS"
            current="Configured"
            ((PASSED_CHECKS++))
        else
            ((FAILED_CHECKS++))
        fi
        
        print_check_result "$policy_id" "$policy_name" \
            "Warning banner configured" \
            "$current" \
            "$status"
            
    elif [ "$MODE" = "fix" ]; then
        cp /etc/issue "$BACKUP_DIR/issue.$(date +%Y%m%d_%H%M%S)" 2>/dev/null
        cat > /etc/issue << 'EOF'
***************************************************************************
                            NOTICE TO USERS
This computer system is for authorized use only.
***************************************************************************
EOF
        log_fixed "/etc/issue banner configured"
    fi
}

check_issue_net_banner() {
    local policy_id="PKG-2.c.ii"
    local policy_name="Ensure remote login warning banner is configured properly"
    ((TOTAL_CHECKS++))

    if [ "$MODE" = "scan" ]; then
        local status="FAIL"
        local current="Not configured"
        
        if [ -f /etc/issue.net ] && [ -s /etc/issue.net ] && ! grep -qE "\\\\v|\\\\r|\\\\m|\\\\s" /etc/issue.net; then
            status="PASS"
            current="Configured"
            ((PASSED_CHECKS++))
        else
            ((FAILED_CHECKS++))
        fi
        
        print_check_result "$policy_id" "$policy_name" \
            "Warning banner configured" \
            "$current" \
            "$status"
            
    elif [ "$MODE" = "fix" ]; then
        cp /etc/issue.net "$BACKUP_DIR/issue.net.$(date +%Y%m%d_%H%M%S)" 2>/dev/null
        cat > /etc/issue.net << 'EOF'
***************************************************************************
                            NOTICE TO REMOTE USERS
This system is for authorized use only.
***************************************************************************
EOF
        log_fixed "/etc/issue.net banner configured"
    fi
}

check_motd_access() {
    local policy_id="PKG-2.c.iii"
    local policy_name="Ensure access to /etc/motd is configured"
    ((TOTAL_CHECKS++))

    if [ "$MODE" = "scan" ]; then
        local status="PASS"
        local current="644 root:root"
        
        if [ -f /etc/motd ]; then
            local perms=$(stat -c %a /etc/motd)
            local owner=$(stat -c %U /etc/motd)
            local group=$(stat -c %G /etc/motd)
            current="$perms $owner:$group"
            
            if [ "$perms" = "644" ] && [ "$owner" = "root" ] && [ "$group" = "root" ]; then
                ((PASSED_CHECKS++))
            else
                status="FAIL"
                ((FAILED_CHECKS++))
            fi
        else
            current="File not found"
        fi
        
        print_check_result "$policy_id" "$policy_name" \
            "644 root:root" \
            "$current" \
            "$status"
            
    elif [ "$MODE" = "fix" ]; then
        if [ -f /etc/motd ]; then
            chown root:root /etc/motd
            chmod 644 /etc/motd
            log_fixed "/etc/motd permissions set"
        fi
    fi
}

check_issue_access() {
    local policy_id="PKG-2.c.iv"
    local policy_name="Ensure access to /etc/issue is configured"
    ((TOTAL_CHECKS++))

    if [ "$MODE" = "scan" ]; then
        local status="FAIL"
        local current="Not found"
        
        if [ -f /etc/issue ]; then
            local perms=$(stat -c %a /etc/issue)
            local owner=$(stat -c %U /etc/issue)
            local group=$(stat -c %G /etc/issue)
            current="$perms $owner:$group"
            
            if [ "$perms" = "644" ] && [ "$owner" = "root" ] && [ "$group" = "root" ]; then
                status="PASS"
                ((PASSED_CHECKS++))
            else
                ((FAILED_CHECKS++))
            fi
        else
            ((FAILED_CHECKS++))
        fi
        
        print_check_result "$policy_id" "$policy_name" \
            "644 root:root" \
            "$current" \
            "$status"
            
    elif [ "$MODE" = "fix" ]; then
        if [ -f /etc/issue ]; then
            chown root:root /etc/issue
            chmod 644 /etc/issue
            log_fixed "/etc/issue permissions set"
        fi
    fi
}

check_issue_net_access() {
    local policy_id="PKG-2.c.v"
    local policy_name="Ensure access to /etc/issue.net is configured"
    ((TOTAL_CHECKS++))

    if [ "$MODE" = "scan" ]; then
        local status="FAIL"
        local current="Not found"
        
        if [ -f /etc/issue.net ]; then
            local perms=$(stat -c %a /etc/issue.net)
            local owner=$(stat -c %U /etc/issue.net)
            local group=$(stat -c %G /etc/issue.net)
            current="$perms $owner:$group"
            
            if [ "$perms" = "644" ] && [ "$owner" = "root" ] && [ "$group" = "root" ]; then
                status="PASS"
                ((PASSED_CHECKS++))
            else
                ((FAILED_CHECKS++))
            fi
        else
            ((FAILED_CHECKS++))
        fi
        
        print_check_result "$policy_id" "$policy_name" \
            "644 root:root" \
            "$current" \
            "$status"
            
    elif [ "$MODE" = "fix" ]; then
        if [ -f /etc/issue.net ]; then
            chown root:root /etc/issue.net
            chmod 644 /etc/issue.net
            log_fixed "/etc/issue.net permissions set"
        fi
    fi
}

# ============================================================================
# Main Execution
# ============================================================================

initialize_db

echo "========================================================================"
echo "Package Management Hardening"
echo "Module: $MODULE_NAME"
echo "Mode: $MODE"
echo "========================================================================"

log_info "=== 2.a Configure Bootloader ==="
check_bootloader_password
check_bootloader_config_permissions

log_info "=== 2.b Configure Additional Process Hardening ==="
check_aslr
check_ptrace_scope
check_core_dumps
check_prelink
check_apport

log_info "=== 2.c Configure Command Line Warning Banners ==="
check_issue_banner
check_issue_net_banner
check_motd_access
check_issue_access
check_issue_net_access

echo ""
echo "========================================================================"
echo "Summary"
echo "========================================================================"
echo "Total Checks: $TOTAL_CHECKS"
echo "Passed: $PASSED_CHECKS"
echo "Failed: $FAILED_CHECKS"
echo "Fixed: $FIXED_CHECKS"
echo "========================================================================"

if [ "$FAILED_CHECKS" -gt 0 ]; then
    echo -e "${RED}[FAIL] Some checks failed.${NC}"
else
    echo -e "${GREEN}[PASS] All checks passed.${NC}"
fi
