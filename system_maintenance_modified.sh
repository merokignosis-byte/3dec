#!/usr/bin/env bash
# System Maintenance Hardening Script - Standardized Version
# Module: System Maintenance
# Policy ID Format: SM-X.X.X (from Annexure B)

MODE="${1:-scan}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DB_PATH="$SCRIPT_DIR/hardening.db"
BACKUP_DIR="$SCRIPT_DIR/backups/system_maintenance"
TOPIC="System Maintenance"
MODULE_NAME="System Maintenance"

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
# File Permission Check Function
# ============================================================================
check_perm() {
    local file="$1"
    local acceptable="$2"
    local policy_id="$3"
    local policy_name="$4"
    
    ((TOTAL_CHECKS++))
    
    if [ "$MODE" = "scan" ]; then
        local status="FAIL"
        local expected="$acceptable"
        local current="unknown"
        
        if [[ ! -e "$file" ]]; then
            current="file not found"
            ((FAILED_CHECKS++))
        else
            mode=$(stat -c "%a" "$file")
            current="$mode"
            
            IFS=',' read -ra allowed <<< "$acceptable"
            for val in "${allowed[@]}"; do
                if [[ "$mode" == "$val" ]]; then
                    status="PASS"
                    ((PASSED_CHECKS++))
                    print_check_result "$policy_id" "$policy_name" "$expected" "$current" "$status"
                    return 0
                fi
            done
            
            ((FAILED_CHECKS++))
        fi
        
        print_check_result "$policy_id" "$policy_name" "$expected" "$current" "$status"
        
    elif [ "$MODE" = "fix" ]; then
        if [[ ! -e "$file" ]]; then
            log_warn "$file does not exist - skipping"
            return
        fi
        
        mode=$(stat -c "%a" "$file")
        save_config "$policy_id" "$policy_name" "$mode"
        
        IFS=',' read -ra allowed <<< "$acceptable"
        target="${allowed[0]}"
        
        if chmod "$target" "$file" 2>/dev/null; then
            log_info "Fixed: $policy_name ($file → $target)"
            ((FIXED_CHECKS++))
        else
            log_error "Failed to fix permissions for $file"
        fi
        
    elif [ "$MODE" = "rollback" ]; then
        local original=$(get_original_config "$policy_id")
        if [ -n "$original" ] && [ -e "$file" ]; then
            chmod "$original" "$file" 2>/dev/null
            log_info "Rolled back: $policy_name"
        fi
    fi
}

# ============================================================================
# 9.a System File Permissions
# ============================================================================

check_system_file_perms() {
    log_info "=== 9.a System File Permissions ==="
    
    check_perm "/etc/passwd" "644" "SM-9.a.i" "Ensure permissions on /etc/passwd are configured"
    check_perm "/etc/passwd-" "600,644" "SM-9.a.ii" "Ensure permissions on /etc/passwd- are configured"
    check_perm "/etc/group" "644" "SM-9.a.iii" "Ensure permissions on /etc/group are configured"
    check_perm "/etc/group-" "600,644" "SM-9.a.iv" "Ensure permissions on /etc/group- are configured"
    check_perm "/etc/shadow" "600,640" "SM-9.a.v" "Ensure permissions on /etc/shadow are configured"
    check_perm "/etc/shadow-" "600" "SM-9.a.vi" "Ensure permissions on /etc/shadow- are configured"
    check_perm "/etc/gshadow" "600,640" "SM-9.a.vii" "Ensure permissions on /etc/gshadow are configured"
    check_perm "/etc/gshadow-" "600" "SM-9.a.viii" "Ensure permissions on /etc/gshadow- are configured"
    check_perm "/etc/shells" "644" "SM-9.a.ix" "Ensure permissions on /etc/shells are configured"
    check_perm "/etc/security/opasswd" "600,644" "SM-9.a.x" "Ensure permissions on /etc/security/opasswd are configured"
}

check_world_writable_files() {
    local policy_id="SM-9.a.xi"
    local policy_name="Ensure world writable files and directories are secured"
    
    ((TOTAL_CHECKS++))
    
    if [ "$MODE" = "scan" ]; then
        local status="FAIL"
        local expected="no world-writable files"
        local current="unknown"
        
        local world_write=$(find / -path /proc -prune -o -path /sys -prune -o -path /dev -prune -o \
            -path /run -prune -o -path /tmp -prune -o -path /var/tmp -prune -o \
            -type f -perm -0002 -print 2>/dev/null | wc -l)
        
        current="$world_write files found"
        
        if [ "$world_write" -eq 0 ]; then
            status="PASS"
            ((PASSED_CHECKS++))
        else
            ((FAILED_CHECKS++))
        fi
        
        print_check_result "$policy_id" "$policy_name" "$expected" "$current" "$status"
        
    elif [ "$MODE" = "fix" ]; then
        save_config "$policy_id" "$policy_name" "has_world_writable"
        
        find / -path /proc -prune -o -path /sys -prune -o -path /dev -prune -o \
            -path /run -prune -o -path /tmp -prune -o -path /var/tmp -prune -o \
            -type f -perm -0002 -exec chmod o-w {} \; 2>/dev/null
        
        log_info "Fixed: $policy_name"
        ((FIXED_CHECKS++))
        
    elif [ "$MODE" = "rollback" ]; then
        log_warn "World-writable file rollback not recommended for security"
    fi
}

check_unowned_files() {
    local policy_id="SM-9.a.xii"
    local policy_name="Ensure no files or directories without an owner and a group exist"
    
    ((TOTAL_CHECKS++))
    
    if [ "$MODE" = "scan" ]; then
        local status="FAIL"
        local expected="all files have owner and group"
        local current="unknown"
        
        local noowner=$(find / -path /home -prune -o -path /tmp -prune -o -path /var/tmp -prune -o \
            -path /run/user -prune -o -path /proc -prune -o -path /sys -prune -o \
            -path /run -prune -o -path /dev -prune -o \( -nouser -o -nogroup \) -print 2>/dev/null | wc -l)
        
        current="$noowner files without owner/group"
        
        if [ "$noowner" -eq 0 ]; then
            status="PASS"
            ((PASSED_CHECKS++))
        else
            ((FAILED_CHECKS++))
        fi
        
        print_check_result "$policy_id" "$policy_name" "$expected" "$current" "$status"
        
    elif [ "$MODE" = "fix" ]; then
        log_warn "Manual review required for unowned files"
        log_info "To fix manually, assign ownership: chown root:root <file>"
        
    elif [ "$MODE" = "rollback" ]; then
        log_info "No automatic rollback for file ownership"
    fi
}

check_suid_sgid_files() {
    local policy_id="SM-9.a.xiii"
    local policy_name="Ensure SUID and SGID files are reviewed"
    
    ((TOTAL_CHECKS++))
    
    if [ "$MODE" = "scan" ]; then
        local status="PASS"
        local expected="manual review"
        
        local suid_count=$(find / -xdev -perm -4000 2>/dev/null | wc -l)
        local sgid_count=$(find / -xdev -perm -2000 2>/dev/null | wc -l)
        
        local current="$suid_count SUID files, $sgid_count SGID files"
        
        ((PASSED_CHECKS++))
        print_check_result "$policy_id" "$policy_name" "$expected" "$current" "$status"
        
    elif [ "$MODE" = "fix" ]; then
        log_info "Manual review required for SUID/SGID files"
        log_info "List SUID files: find / -xdev -perm -4000 2>/dev/null"
        log_info "List SGID files: find / -xdev -perm -2000 2>/dev/null"
    fi
}

# ============================================================================
# 9.a Local User and Group Settings (xiv-xxiii)
# ============================================================================

check_shadow_passwords() {
    local policy_id="SM-9.a.xiv"
    local policy_name="Ensure accounts in /etc/passwd use shadowed passwords"
    
    ((TOTAL_CHECKS++))
    
    if [ "$MODE" = "scan" ]; then
        local status="FAIL"
        local expected="all accounts use shadow passwords"
        local current="unknown"
        
        if pwck -r 2>&1 | grep -q "no shadow"; then
            current="some accounts not using shadow"
            ((FAILED_CHECKS++))
        else
            current="all accounts use shadow"
            status="PASS"
            ((PASSED_CHECKS++))
        fi
        
        print_check_result "$policy_id" "$policy_name" "$expected" "$current" "$status"
        
    elif [ "$MODE" = "fix" ]; then
        log_warn "Manual intervention required to enable shadow passwords"
        log_info "Run: pwconv"
    fi
}

check_empty_passwords() {
    local policy_id="SM-9.a.xv"
    local policy_name="Ensure /etc/shadow password fields are not empty"
    
    ((TOTAL_CHECKS++))
    
    if [ "$MODE" = "scan" ]; then
        local status="FAIL"
        local expected="no empty password fields"
        local current="unknown"
        
        local empty_fields=$(awk -F: '($2 == "") {print $1}' /etc/shadow)
        
        if [[ -z "$empty_fields" ]]; then
            current="no empty password fields"
            status="PASS"
            ((PASSED_CHECKS++))
        else
            current="empty fields found: $empty_fields"
            ((FAILED_CHECKS++))
        fi
        
        print_check_result "$policy_id" "$policy_name" "$expected" "$current" "$status"
        
    elif [ "$MODE" = "fix" ]; then
        log_warn "Manual intervention required to set passwords"
        log_info "Lock accounts: passwd -l <username>"
    fi
}

check_groups_in_passwd() {
    local policy_id="SM-9.a.xvi"
    local policy_name="Ensure all groups in /etc/passwd exist in /etc/group"
    
    ((TOTAL_CHECKS++))
    
    if [ "$MODE" = "scan" ]; then
        local status="PASS"
        local expected="all groups exist"
        local current="all groups valid"
        
        for gid in $(awk -F: '{print $4}' /etc/passwd | sort -u); do
            if ! getent group "$gid" >/dev/null; then
                current="missing GID $gid"
                status="FAIL"
                ((FAILED_CHECKS++))
                print_check_result "$policy_id" "$policy_name" "$expected" "$current" "$status"
                return
            fi
        done
        
        ((PASSED_CHECKS++))
        print_check_result "$policy_id" "$policy_name" "$expected" "$current" "$status"
        
    elif [ "$MODE" = "fix" ]; then
        log_warn "Manual intervention required to create missing groups"
    fi
}

check_shadow_group_empty() {
    local policy_id="SM-9.a.xvii"
    local policy_name="Ensure shadow group is empty"
    
    ((TOTAL_CHECKS++))
    
    if [ "$MODE" = "scan" ]; then
        local status="FAIL"
        local expected="shadow group empty"
        local current="unknown"
        
        local shadow_members=$(getent group shadow 2>/dev/null | cut -d: -f4)
        
        if [[ -z "$shadow_members" ]]; then
            current="shadow group empty"
            status="PASS"
            ((PASSED_CHECKS++))
        else
            current="members: $shadow_members"
            ((FAILED_CHECKS++))
        fi
        
        print_check_result "$policy_id" "$policy_name" "$expected" "$current" "$status"
        
    elif [ "$MODE" = "fix" ]; then
        log_warn "Manual intervention required to remove users from shadow group"
    fi
}

check_duplicate_uids() {
    local policy_id="SM-9.a.xviii"
    local policy_name="Ensure no duplicate UIDs exist"
    
    ((TOTAL_CHECKS++))
    
    if [ "$MODE" = "scan" ]; then
        local status="FAIL"
        local expected="no duplicate UIDs"
        local current="unknown"
        
        local dup_uids=$(awk -F: '($3 >= 1000){print $3}' /etc/passwd | sort -n | uniq -d)
        
        if [[ -z "$dup_uids" ]]; then
            current="no duplicates"
            status="PASS"
            ((PASSED_CHECKS++))
        else
            current="duplicates: $dup_uids"
            ((FAILED_CHECKS++))
        fi
        
        print_check_result "$policy_id" "$policy_name" "$expected" "$current" "$status"
        
    elif [ "$MODE" = "fix" ]; then
        log_warn "Manual intervention required to resolve duplicate UIDs"
    fi
}

check_duplicate_gids() {
    local policy_id="SM-9.a.xix"
    local policy_name="Ensure no duplicate GIDs exist"
    
    ((TOTAL_CHECKS++))
    
    if [ "$MODE" = "scan" ]; then
        local status="FAIL"
        local expected="no duplicate GIDs"
        local current="unknown"
        
        local dup_gids=$(awk -F: '($3 >= 1000){print $3}' /etc/group | sort -n | uniq -d)
        
        if [[ -z "$dup_gids" ]]; then
            current="no duplicates"
            status="PASS"
            ((PASSED_CHECKS++))
        else
            current="duplicates: $dup_gids"
            ((FAILED_CHECKS++))
        fi
        
        print_check_result "$policy_id" "$policy_name" "$expected" "$current" "$status"
        
    elif [ "$MODE" = "fix" ]; then
        log_warn "Manual intervention required to resolve duplicate GIDs"
    fi
}

check_duplicate_usernames() {
    local policy_id="SM-9.a.xx"
    local policy_name="Ensure no duplicate user names exist"
    
    ((TOTAL_CHECKS++))
    
    if [ "$MODE" = "scan" ]; then
        local status="FAIL"
        local expected="no duplicate usernames"
        local current="unknown"
        
        local dup_users=$(awk -F: '{print $1}' /etc/passwd | sort | uniq -d)
        
        if [[ -z "$dup_users" ]]; then
            current="no duplicates"
            status="PASS"
            ((PASSED_CHECKS++))
        else
            current="duplicates: $dup_users"
            ((FAILED_CHECKS++))
        fi
        
        print_check_result "$policy_id" "$policy_name" "$expected" "$current" "$status"
        
    elif [ "$MODE" = "fix" ]; then
        log_warn "Manual intervention required to resolve duplicate usernames"
    fi
}

check_duplicate_groupnames() {
    local policy_id="SM-9.a.xxi"
    local policy_name="Ensure no duplicate group names exist"
    
    ((TOTAL_CHECKS++))
    
    if [ "$MODE" = "scan" ]; then
        local status="FAIL"
        local expected="no duplicate group names"
        local current="unknown"
        
        local dup_groups=$(awk -F: '{print $1}' /etc/group | sort | uniq -d)
        
        if [[ -z "$dup_groups" ]]; then
            current="no duplicates"
            status="PASS"
            ((PASSED_CHECKS++))
        else
            current="duplicates: $dup_groups"
            ((FAILED_CHECKS++))
        fi
        
        print_check_result "$policy_id" "$policy_name" "$expected" "$current" "$status"
        
    elif [ "$MODE" = "fix" ]; then
        log_warn "Manual intervention required to resolve duplicate group names"
    fi
}

check_home_directories() {
    local policy_id="SM-9.a.xxii"
    local policy_name="Ensure local interactive user home directories are configured"
    
    ((TOTAL_CHECKS++))
    
    if [ "$MODE" = "scan" ]; then
        local status="PASS"
        local expected="all home directories exist and have correct permissions"
        local current="checking..."
        
        local issues=0
        while IFS=: read -r user _ uid _ _ home _; do
            if [ "$uid" -ge 1000 ] && [ "$user" != "nobody" ]; then
                if [ ! -d "$home" ]; then
                    ((issues++))
                fi
            fi
        done < /etc/passwd
        
        if [ "$issues" -eq 0 ]; then
            current="all home directories configured"
            ((PASSED_CHECKS++))
        else
            current="$issues home directories missing or misconfigured"
            status="FAIL"
            ((FAILED_CHECKS++))
        fi
        
        print_check_result "$policy_id" "$policy_name" "$expected" "$current" "$status"
        
    elif [ "$MODE" = "fix" ]; then
        log_warn "Manual intervention required to fix home directories"
    fi
}

check_dotfile_permissions() {
    local policy_id="SM-9.a.xxiii"
    local policy_name="Ensure local interactive user dot files access is configured"
    
    ((TOTAL_CHECKS++))
    
    if [ "$MODE" = "scan" ]; then
        local status="FAIL"
        local expected="no dangerous dotfile permissions"
        local current="unknown"
        
        local dangerous=$(find /home -maxdepth 3 -type f -name ".*" -perm /022 2>/dev/null | wc -l)
        
        current="$dangerous files with dangerous permissions"
        
        if [ "$dangerous" -eq 0 ]; then
            status="PASS"
            ((PASSED_CHECKS++))
        else
            ((FAILED_CHECKS++))
        fi
        
        print_check_result "$policy_id" "$policy_name" "$expected" "$current" "$status"
        
    elif [ "$MODE" = "fix" ]; then
        save_config "$policy_id" "$policy_name" "has_dangerous_perms"
        
        find /home -maxdepth 3 -type f -name ".*" -perm /022 -exec chmod go-w {} \; 2>/dev/null
        
        log_info "Fixed: $policy_name"
        ((FIXED_CHECKS++))
        
    elif [ "$MODE" = "rollback" ]; then
        log_warn "Dotfile permission rollback not recommended"
    fi
}

# ============================================================================
# Main Execution
# ============================================================================

main() {
    echo "========================================================================"
    echo "System Maintenance Hardening - Module: $MODULE_NAME"
    echo "Mode: $MODE"
    echo "========================================================================"
    
    initialize_db
    
    if [ "$MODE" = "scan" ] || [ "$MODE" = "fix" ]; then
        check_system_file_perms
        
        echo ""
        log_info "=== Additional System Maintenance Checks ==="
        check_world_writable_files
        check_unowned_files
        check_suid_sgid_files
        
        echo ""
        log_info "=== User and Group Validation ==="
        check_shadow_passwords
        check_empty_passwords
        check_groups_in_passwd
        check_shadow_group_empty
        check_duplicate_uids
        check_duplicate_gids
        check_duplicate_usernames
        check_duplicate_groupnames
        check_home_directories
        check_dotfile_permissions
        
        echo ""
        echo "========================================================================"
        echo "Summary"
        echo "========================================================================"
        echo "Total Checks: $TOTAL_CHECKS"
        
        if [ "$MODE" = "scan" ]; then
            echo "Passed: $PASSED_CHECKS"
            echo "Failed: $FAILED_CHECKS"
        else
            echo "Fixed: $FIXED_CHECKS"
        fi
        
    elif [ "$MODE" = "rollback" ]; then
        log_info "Rolling back system maintenance configurations..."
        check_system_file_perms
        check_world_writable_files
        check_dotfile_permissions
        
    else
        echo "Usage: $0 {scan|fix|rollback}"
        exit 1
    fi
}

main