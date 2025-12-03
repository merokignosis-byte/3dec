#!/bin/bash
# Comprehensive User Accounts and Environment Hardening Script
# Covers: Shadow Password Suite, Root Account, System Accounts, User Environment

MODE="${1:-scan}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DB_PATH="$SCRIPT_DIR/../hardening.db"
BACKUP_DIR="$SCRIPT_DIR/../backups/user_accounts"
TOPIC="User Accounts"
MODULE_NAME="User Accounts and Environment"

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

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[FAIL]${NC} $1"; }

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
# Shadow Password Suite Parameters
# ============================================================================

check_login_defs_param() {
    local param="$1"
    local expected_value="$2"
    local rule_id="$3"
    local rule_name="$4"
    
    ((TOTAL_CHECKS++))
    
    if [ "$MODE" = "scan" ]; then
        local status="FAIL"
        local current="not set"
        
        if [ -f /etc/login.defs ]; then
            current=$(grep "^$param" /etc/login.defs | awk '{print $2}')
            
            if [ -z "$current" ]; then
                current="not set"
                ((FAILED_CHECKS++))
            elif [ "$current" = "$expected_value" ] || [ "$current" -le "$expected_value" ] 2>/dev/null; then
                status="PASS"
                ((PASSED_CHECKS++))
            else
                ((FAILED_CHECKS++))
            fi
        else
            ((FAILED_CHECKS++))
        fi
        
        print_check_result "$rule_id" "$rule_name" "$expected_value" "$current" "$status"
        
    elif [ "$MODE" = "fix" ]; then
        if [ -f /etc/login.defs ]; then
            local current=$(grep "^$param" /etc/login.defs | awk '{print $2}')
            save_config "$rule_id" "$rule_name" "$current"
            
            cp /etc/login.defs "$BACKUP_DIR/login.defs.$(date +%Y%m%d_%H%M%S)"
            
            if grep -q "^$param" /etc/login.defs; then
                sed -i "s/^$param.*/$param\t$expected_value/" /etc/login.defs
            else
                echo "$param\t$expected_value" >> /etc/login.defs
            fi
            
            log_info "Set $param = $expected_value"
            ((FIXED_CHECKS++))
        fi
        
    elif [ "$MODE" = "rollback" ]; then
        local backup=$(ls -t "$BACKUP_DIR"/login.defs.* 2>/dev/null | head -1)
        if [ -n "$backup" ]; then
            cp "$backup" /etc/login.defs
            log_info "Restored login.defs from backup"
        fi
    fi
}

check_password_hashing() {
    local rule_id="UA-7.a.iv"
    local rule_name="Ensure strong password hashing algorithm is configured"
    
    ((TOTAL_CHECKS++))
    
    if [ "$MODE" = "scan" ]; then
        local status="FAIL"
        local expected="SHA512 or yescrypt"
        local current="not set"
        
        local encrypt_method=$(grep "^ENCRYPT_METHOD" /etc/login.defs | awk '{print $2}')
        
        if [ -n "$encrypt_method" ]; then
            current="$encrypt_method"
            if [ "$encrypt_method" = "SHA512" ] || [ "$encrypt_method" = "yescrypt" ]; then
                status="PASS"
                ((PASSED_CHECKS++))
            else
                ((FAILED_CHECKS++))
            fi
        else
            ((FAILED_CHECKS++))
        fi
        
        print_check_result "$rule_id" "$rule_name" "$expected" "$current" "$status"
        
    elif [ "$MODE" = "fix" ]; then
        local current=$(grep "^ENCRYPT_METHOD" /etc/login.defs | awk '{print $2}')
        save_config "$rule_id" "$rule_name" "$current"
        
        cp /etc/login.defs "$BACKUP_DIR/login.defs.hash.$(date +%Y%m%d_%H%M%S)"
        sed -i 's/^ENCRYPT_METHOD.*/ENCRYPT_METHOD SHA512/' /etc/login.defs
        log_info "Set password hashing to SHA512"
        ((FIXED_CHECKS++))
        
    elif [ "$MODE" = "rollback" ]; then
        local original=$(get_original_config "$rule_id")
        if [ -n "$original" ]; then
            sed -i "s/^ENCRYPT_METHOD.*/ENCRYPT_METHOD $original/" /etc/login.defs
            log_info "Restored password hashing algorithm to: $original"
        fi
    fi
}

check_inactive_password_lock() {
    local rule_id="UA-7.a.v"
    local rule_name="Ensure inactive password lock is configured"
    
    ((TOTAL_CHECKS++))
    
    if [ "$MODE" = "scan" ]; then
        local status="FAIL"
        local expected="30 days or less"
        local current="not set"
        
        local inactive=$(useradd -D | grep INACTIVE | cut -d= -f2)
        
        if [ -n "$inactive" ]; then
            current="$inactive days"
            if [ "$inactive" -le 30 ] && [ "$inactive" -gt 0 ] 2>/dev/null; then
                status="PASS"
                ((PASSED_CHECKS++))
            else
                ((FAILED_CHECKS++))
            fi
        else
            ((FAILED_CHECKS++))
        fi
        
        print_check_result "$rule_id" "$rule_name" "$expected" "$current" "$status"
        
    elif [ "$MODE" = "fix" ]; then
        local current=$(useradd -D | grep INACTIVE | cut -d= -f2)
        save_config "$rule_id" "$rule_name" "$current"
        
        useradd -D -f 30
        log_info "Set inactive password lock to 30 days"
        ((FIXED_CHECKS++))
        
    elif [ "$MODE" = "rollback" ]; then
        local original=$(get_original_config "$rule_id")
        if [ -n "$original" ]; then
            useradd -D -f "$original"
            log_info "Restored inactive password lock to: $original days"
        fi
    fi
}

check_password_change_dates() {
    local rule_id="UA-7.a.vi"
    local rule_name="Ensure all users last password change date is in the past"
    
    ((TOTAL_CHECKS++))
    
    if [ "$MODE" = "scan" ]; then
        local status="PASS"
        local expected="all dates in past"
        local current="checking..."
        
        local invalid_dates=""
        local current_date=$(date +%s)
        
        while IFS=: read -r username password lastchange rest; do
            if [[ "$username" != "#"* ]] && [ -n "$lastchange" ] && [ "$lastchange" != "0" ]; then
                local change_date=$((lastchange * 86400))
                if [ "$change_date" -gt "$current_date" ]; then
                    invalid_dates="${invalid_dates}${username} "
                fi
            fi
        done < /etc/shadow
        
        if [ -z "$invalid_dates" ]; then
            current="all valid"
            ((PASSED_CHECKS++))
        else
            current="invalid: $invalid_dates"
            status="FAIL"
            ((FAILED_CHECKS++))
        fi
        
        print_check_result "$rule_id" "$rule_name" "$expected" "$current" "$status"
        
    elif [ "$MODE" = "fix" ]; then
        local users_fixed=""
        local current_days=$(($(date +%s) / 86400))
        
        while IFS=: read -r username password lastchange rest; do
            if [[ "$username" != "#"* ]] && [ -n "$lastchange" ] && [ "$lastchange" != "0" ]; then
                if [ "$lastchange" -gt "$current_days" ]; then
                    chage -d 0 "$username"
                    users_fixed="${users_fixed}${username} "
                fi
            fi
        done < /etc/shadow
        
        if [ -n "$users_fixed" ]; then
            save_config "$rule_id" "$rule_name" "$users_fixed"
            log_info "Reset password change dates for: $users_fixed"
            ((FIXED_CHECKS++))
        fi
    fi
}

# ============================================================================
# Root and System Accounts
# ============================================================================

check_root_uid_zero() {
    local rule_id="UA-7.a.vii"
    local rule_name="Ensure root is the only UID 0 account"
    
    ((TOTAL_CHECKS++))
    
    if [ "$MODE" = "scan" ]; then
        local status="PASS"
        local expected="root only"
        local current="checking..."
        
        local uid_zero_accounts=$(awk -F: '($3 == 0) { print $1 }' /etc/passwd)
        current="$uid_zero_accounts"
        
        if [ "$uid_zero_accounts" = "root" ]; then
            ((PASSED_CHECKS++))
        else
            status="FAIL"
            ((FAILED_CHECKS++))
        fi
        
        print_check_result "$rule_id" "$rule_name" "$expected" "$current" "$status"
        
    elif [ "$MODE" = "fix" ]; then
        local other_uid_zero=$(awk -F: '($3 == 0 && $1 != "root") { print $1 }' /etc/passwd)
        
        if [ -n "$other_uid_zero" ]; then
            save_config "$rule_id" "$rule_name" "$other_uid_zero"
            log_warn "Found non-root UID 0 accounts: $other_uid_zero"
            log_warn "MANUAL INTERVENTION REQUIRED - Review and modify these accounts"
        fi
    fi
}

check_root_gid_zero() {
    local rule_id="UA-7.a.viii"
    local rule_name="Ensure root is the only GID 0 account"
    
    ((TOTAL_CHECKS++))
    
    if [ "$MODE" = "scan" ]; then
        local status="PASS"
        local expected="root only"
        local current="checking..."
        
        local gid_zero_accounts=$(awk -F: '($4 == 0 && $1 != "root") { print $1 }' /etc/passwd)
        
        if [ -z "$gid_zero_accounts" ]; then
            current="root only"
            ((PASSED_CHECKS++))
        else
            current="$gid_zero_accounts"
            status="FAIL"
            ((FAILED_CHECKS++))
        fi
        
        print_check_result "$rule_id" "$rule_name" "$expected" "$current" "$status"
    fi
}

check_group_root_gid_zero() {
    local rule_id="UA-7.a.ix"
    local rule_name="Ensure group root is the only GID 0 group"
    
    ((TOTAL_CHECKS++))
    
    if [ "$MODE" = "scan" ]; then
        local status="PASS"
        local expected="root group only"
        local current="checking..."
        
        local gid_zero_groups=$(awk -F: '($3 == 0) { print $1 }' /etc/group)
        current="$gid_zero_groups"
        
        if [ "$gid_zero_groups" = "root" ]; then
            ((PASSED_CHECKS++))
        else
            status="FAIL"
            ((FAILED_CHECKS++))
        fi
        
        print_check_result "$rule_id" "$rule_name" "$expected" "$current" "$status"
    fi
}

check_root_access_controlled() {
    local rule_id="UA-7.a.x"
    local rule_name="Ensure root account access is controlled"
    
    ((TOTAL_CHECKS++))
    
    if [ "$MODE" = "scan" ]; then
        local status="PASS"
        local expected="SSH disabled, password locked"
        local current="checking..."
        
        local issues=0
        local ssh_status="unknown"
        local pwd_status="unknown"
        
        if grep -q "^PermitRootLogin yes" /etc/ssh/sshd_config 2>/dev/null; then
            ssh_status="enabled"
            ((issues++))
        else
            ssh_status="disabled"
        fi
        
        if grep "^root:" /etc/shadow | cut -d: -f2 | grep -q "^!"; then
            pwd_status="locked"
        else
            pwd_status="set"
            ((issues++))
        fi
        
        current="SSH: $ssh_status, Password: $pwd_status"
        
        if [ $issues -eq 0 ]; then
            ((PASSED_CHECKS++))
        else
            status="FAIL"
            ((FAILED_CHECKS++))
        fi
        
        print_check_result "$rule_id" "$rule_name" "$expected" "$current" "$status"
        
    elif [ "$MODE" = "fix" ]; then
        save_config "$rule_id" "$rule_name" "configured"
        
        if [ -f /etc/ssh/sshd_config ]; then
            cp /etc/ssh/sshd_config "$BACKUP_DIR/sshd_config.$(date +%Y%m%d_%H%M%S)"
            sed -i 's/^PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config
            log_info "Disabled root SSH login"
        fi
        
        log_warn "Consider locking root password with: passwd -l root"
        ((FIXED_CHECKS++))
    fi
}

check_root_umask() {
    local rule_id="UA-7.a.xii"
    local rule_name="Ensure root user umask is configured"
    
    ((TOTAL_CHECKS++))
    
    if [ "$MODE" = "scan" ]; then
        local status="FAIL"
        local expected="027 or 077"
        local current="not configured"
        
        local root_umask_files="/root/.bashrc /root/.bash_profile /root/.profile"
        
        for file in $root_umask_files; do
            if [ -f "$file" ]; then
                if grep -q "^umask 0[02]7" "$file"; then
                    current=$(grep "^umask" "$file" | awk '{print $2}')
                    status="PASS"
                    ((PASSED_CHECKS++))
                    break
                fi
            fi
        done
        
        if [ "$status" = "FAIL" ]; then
            ((FAILED_CHECKS++))
        fi
        
        print_check_result "$rule_id" "$rule_name" "$expected" "$current" "$status"
        
    elif [ "$MODE" = "fix" ]; then
        save_config "$rule_id" "$rule_name" "not_configured"
        
        for file in /root/.bashrc /root/.bash_profile; do
            if [ -f "$file" ]; then
                cp "$file" "$BACKUP_DIR/$(basename $file).$(date +%Y%m%d_%H%M%S)"
                
                if grep -q "^umask" "$file"; then
                    sed -i 's/^umask.*/umask 027/' "$file"
                else
                    echo "umask 027" >> "$file"
                fi
            fi
        done
        
        log_info "Set root umask to 027"
        ((FIXED_CHECKS++))
    fi
}

check_system_accounts_nologin() {
    local rule_id="UA-7.a.xiii"
    local rule_name="Ensure system accounts do not have a valid login shell"
    
    ((TOTAL_CHECKS++))
    
    if [ "$MODE" = "scan" ]; then
        local status="PASS"
        local expected="nologin or false"
        local current="checking..."
        
        local system_with_shell=$(awk -F: '($3 < 1000 && $1 != "root" && $7 !~ /nologin|false/) {print $1}' /etc/passwd)
        
        if [ -z "$system_with_shell" ]; then
            current="all correct"
            ((PASSED_CHECKS++))
        else
            current="$system_with_shell"
            status="FAIL"
            ((FAILED_CHECKS++))
        fi
        
        print_check_result "$rule_id" "$rule_name" "$expected" "$current" "$status"
        
    elif [ "$MODE" = "fix" ]; then
        local system_accounts=$(awk -F: '($3 < 1000 && $1 != "root" && $7 !~ /nologin|false/) {print $1}' /etc/passwd)
        
        if [ -n "$system_accounts" ]; then
            cp /etc/passwd "$BACKUP_DIR/passwd.$(date +%Y%m%d_%H%M%S)"
            save_config "$rule_id" "$rule_name" "$system_accounts"
            
            for account in $system_accounts; do
                usermod -s /usr/sbin/nologin "$account" 2>/dev/null || \
                usermod -s /sbin/nologin "$account" 2>/dev/null
                log_info "Set $account shell to nologin"
            done
            
            ((FIXED_CHECKS++))
        fi
    fi
}

# ============================================================================
# User Default Environment
# ============================================================================

check_nologin_not_in_shells() {
    local rule_id="UA-7.b.i"
    local rule_name="Ensure nologin is not listed in /etc/shells"
    
    ((TOTAL_CHECKS++))
    
    if [ "$MODE" = "scan" ]; then
        local status="PASS"
        local expected="not present"
        local current="checking..."
        
        if grep -q "nologin" /etc/shells 2>/dev/null; then
            current="present"
            status="FAIL"
            ((FAILED_CHECKS++))
        else
            current="not present"
            ((PASSED_CHECKS++))
        fi
        
        print_check_result "$rule_id" "$rule_name" "$expected" "$current" "$status"
        
    elif [ "$MODE" = "fix" ]; then
        if grep -q "nologin" /etc/shells; then
            cp /etc/shells "$BACKUP_DIR/shells.$(date +%Y%m%d_%H%M%S)"
            save_config "$rule_id" "$rule_name" "present"
            
            sed -i '/nologin/d' /etc/shells
            log_info "Removed nologin from /etc/shells"
            ((FIXED_CHECKS++))
        fi
    fi
}

check_shell_timeout() {
    local rule_id="UA-7.b.ii"
    local rule_name="Ensure default user shell timeout is configured"
    
    ((TOTAL_CHECKS++))
    
    if [ "$MODE" = "scan" ]; then
        local status="FAIL"
        local expected="TMOUT=900 (15 min)"
        local current="not configured"
        
        for file in /etc/bash.bashrc /etc/profile /etc/profile.d/*.sh; do
            if [ -f "$file" ]; then
                if grep -q "^TMOUT=" "$file" 2>/dev/null || grep -q "^readonly TMOUT" "$file" 2>/dev/null; then
                    current=$(grep "^TMOUT=" "$file" | head -1)
                    status="PASS"
                    ((PASSED_CHECKS++))
                    break
                fi
            fi
        done
        
        if [ "$status" = "FAIL" ]; then
            ((FAILED_CHECKS++))
        fi
        
        print_check_result "$rule_id" "$rule_name" "$expected" "$current" "$status"
        
    elif [ "$MODE" = "fix" ]; then
        save_config "$rule_id" "$rule_name" "not_configured"
        
        cat > /etc/profile.d/tmout.sh << 'EOF'
TMOUT=900
readonly TMOUT
export TMOUT
EOF
        
        chmod 644 /etc/profile.d/tmout.sh
        log_info "Configured shell timeout to 900 seconds"
        ((FIXED_CHECKS++))
    fi
}

check_default_user_umask() {
    local rule_id="UA-7.b.iii"
    local rule_name="Ensure default user umask is configured"
    
    ((TOTAL_CHECKS++))
    
    if [ "$MODE" = "scan" ]; then
        local status="FAIL"
        local expected="027 or 077"
        local current="not configured"
        
        for file in /etc/bash.bashrc /etc/profile /etc/profile.d/*.sh; do
            if [ -f "$file" ]; then
                if grep -q "^umask" "$file" 2>/dev/null; then
                    local umask_val=$(grep "^umask" "$file" | awk '{print $2}' | head -1)
                    current="$umask_val"
                    
                    if [ "$umask_val" = "027" ] || [ "$umask_val" = "077" ]; then
                        status="PASS"
                        ((PASSED_CHECKS++))
                        break
                    fi
                fi
            fi
        done
        
        if [ "$status" = "FAIL" ]; then
            ((FAILED_CHECKS++))
        fi
        
        print_check_result "$rule_id" "$rule_name" "$expected" "$current" "$status"
        
    elif [ "$MODE" = "fix" ]; then
        save_config "$rule_id" "$rule_name" "not_configured"
        
        cat > /etc/profile.d/umask.sh << 'EOF'
umask 027
EOF
        
        chmod 644 /etc/profile.d/umask.sh
        log_info "Configured default user umask to 027"
        ((FIXED_CHECKS++))
    fi
}

# ============================================================================
# Main Execution
# ============================================================================

main() {
    echo "=========================================="
    echo "User Accounts and Environment Hardening"
    echo "Mode: $MODE"
    echo "=========================================="
    echo ""
    
    # Shadow Password Suite Parameters
    check_login_defs_param "PASS_MAX_DAYS" "365" "UA-7.a.i" "Ensure password expiration is configured"
    check_login_defs_param "PASS_MIN_DAYS" "1" "UA-7.a.ii" "Ensure minimum password days is configured"
    check_login_defs_param "PASS_WARN_AGE" "7" "UA-7.a.iii" "Ensure password expiration warning days is configured"
    check_password_hashing
    check_inactive_password_lock
    check_password_change_dates
    
    # Root and System Accounts
    check_root_uid_zero
    check_root_gid_zero
    check_group_root_gid_zero
    check_root_access_controlled
    check_root_umask
    check_system_accounts_nologin
    
    # User Default Environment
    check_nologin_not_in_shells
    check_shell_timeout
    check_default_user_umask
    
    # Summary
    echo ""
    echo "=========================================="
    echo "Summary"
    echo "=========================================="
    echo "Total Checks: $TOTAL_CHECKS"
    echo "Passed: $PASSED_CHECKS"
    echo "Failed: $FAILED_CHECKS"
    echo "Fixed: $FIXED_CHECKS"
    echo "=========================================="
    
    if [ "$FAILED_CHECKS" -gt 0 ]; then
        echo -e "${RED}[FAIL] Issues detected.${NC}"
    else
        echo -e "${GREEN}[PASS] All checks passed.${NC}"
    fi
}

main
exit 0
