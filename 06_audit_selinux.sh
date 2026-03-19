#!/system/bin/sh
# DROID FORENSIC - SELinux Policy Audit
# Comprehensive SELinux security configuration assessment
# Usage: sh 06_audit_selinux.sh [output_directory]

OUTPUT_DIR="${1:-.}"
OUTPUT_FILE="${OUTPUT_DIR}/audit_selinux.txt"

echo "[*] Auditing SELinux configuration and policy..."

{
    echo "═══════════════════════════════════════════════════════════════"
    echo "  SELINUX POLICY AUDIT"
    echo "  Timestamp: $(date)"
    echo "═══════════════════════════════════════════════════════════════"
    echo ""
    echo "SELinux provides Mandatory Access Control (MAC) enforcement."
    echo "Misconfigurations can lead to privilege escalation vulnerabilities."
    echo ""

    # Basic SELinux status
    echo "┌─────────────────────────────────────────────────────────────┐"
    echo "│ SELINUX ENFORCEMENT STATUS                                 │"
    echo "└─────────────────────────────────────────────────────────────┘"
    
    ENFORCE_STATUS=$(getenforce 2>/dev/null)
    if [ -n "$ENFORCE_STATUS" ]; then
        echo "Current Mode: $ENFORCE_STATUS"
        
        case "$ENFORCE_STATUS" in
            Enforcing)
                echo "  [OK] SELinux is enforcing - access denials are blocked"
                ;;
            Permissive)
                echo "  [WARNING] SELinux is permissive - denials logged but NOT blocked!"
                echo "  This is a security risk in production!"
                ;;
            Disabled)
                echo "  [CRITICAL] SELinux is DISABLED - no MAC protection!"
                ;;
        esac
    else
        echo "getenforce not available - checking alternatives..."
        cat /sys/fs/selinux/enforce 2>/dev/null && echo "(0=permissive, 1=enforcing)"
    fi
    echo ""

    # SELinux kernel support
    echo "┌─────────────────────────────────────────────────────────────┐"
    echo "│ SELINUX KERNEL SUPPORT                                     │"
    echo "└─────────────────────────────────────────────────────────────┘"
    
    if [ -d /sys/fs/selinux ]; then
        echo "[OK] SELinux filesystem mounted at /sys/fs/selinux"
        ls -la /sys/fs/selinux/ 2>/dev/null | head -20
    else
        echo "[WARNING] SELinux filesystem not mounted"
    fi
    echo ""

    # Policy version
    echo "┌─────────────────────────────────────────────────────────────┐"
    echo "│ SELINUX POLICY VERSION                                     │"
    echo "└─────────────────────────────────────────────────────────────┘"
    
    if [ -f /sys/fs/selinux/policyvers ]; then
        POLICY_VER=$(cat /sys/fs/selinux/policyvers 2>/dev/null)
        echo "Policy Version: $POLICY_VER"
    fi
    
    # Check for policy files
    echo ""
    echo "Policy file locations:"
    for policy_path in /sepolicy /sys/fs/selinux/policy /vendor/etc/selinux /system/etc/selinux /odm/etc/selinux; do
        if [ -e "$policy_path" ]; then
            echo "  [FOUND] $policy_path"
            ls -la "$policy_path" 2>/dev/null | head -5 | sed 's/^/    /'
        fi
    done
    echo ""

    # Current process context
    echo "┌─────────────────────────────────────────────────────────────┐"
    echo "│ CURRENT PROCESS SELINUX CONTEXT                            │"
    echo "└─────────────────────────────────────────────────────────────┘"
    
    CURRENT_CONTEXT=$(cat /proc/self/attr/current 2>/dev/null)
    echo "Current Context: $CURRENT_CONTEXT"
    echo ""
    
    echo "Context breakdown:"
    if [ -n "$CURRENT_CONTEXT" ]; then
        USER=$(echo "$CURRENT_CONTEXT" | cut -d: -f1)
        ROLE=$(echo "$CURRENT_CONTEXT" | cut -d: -f2)
        TYPE=$(echo "$CURRENT_CONTEXT" | cut -d: -f3)
        LEVEL=$(echo "$CURRENT_CONTEXT" | cut -d: -f4)
        echo "  User:  $USER"
        echo "  Role:  $ROLE"
        echo "  Type:  $TYPE"
        echo "  Level: $LEVEL"
    fi
    echo ""

    # Check for permissive domains
    echo "┌─────────────────────────────────────────────────────────────┐"
    echo "│ PERMISSIVE DOMAINS (Security Risk)                         │"
    echo "└─────────────────────────────────────────────────────────────┘"
    echo ""
    echo "Permissive domains bypass SELinux enforcement!"
    echo ""
    
    # Method 1: Check seinfo if available
    if command -v seinfo >/dev/null 2>&1; then
        echo "Permissive domains (via seinfo):"
        seinfo --permissive 2>/dev/null | head -50
    fi
    
    # Method 2: Check process contexts for known permissive types
    echo ""
    echo "Scanning running processes for permissive contexts..."
    ps -AZ 2>/dev/null | grep -E "permissive|:s0:s0" | head -30
    echo ""

    # Check for unconfined domains
    echo "┌─────────────────────────────────────────────────────────────┐"
    echo "│ UNCONFINED/PRIVILEGED DOMAINS                              │"
    echo "└─────────────────────────────────────────────────────────────┘"
    echo ""
    
    echo "Processes running in privileged domains:"
    ps -AZ 2>/dev/null | grep -E "init|kernel|su|magisk|supersu|unconfined" | head -30
    echo ""

    # Domain transitions
    echo "┌─────────────────────────────────────────────────────────────┐"
    echo "│ PROCESS DOMAIN DISTRIBUTION                                │"
    echo "└─────────────────────────────────────────────────────────────┘"
    echo ""
    
    echo "Unique SELinux domains in use (top 30):"
    ps -AZ 2>/dev/null | awk '{print $1}' | cut -d: -f3 | sort | uniq -c | sort -rn | head -30
    echo ""

    # File contexts
    echo "┌─────────────────────────────────────────────────────────────┐"
    echo "│ FILE CONTEXT CONFIGURATION                                 │"
    echo "└─────────────────────────────────────────────────────────────┘"
    echo ""
    
    # Check for file_contexts files
    for fc_path in /system/etc/selinux/plat_file_contexts /vendor/etc/selinux/vendor_file_contexts /file_contexts /plat_file_contexts; do
        if [ -f "$fc_path" ]; then
            echo "--- $fc_path (first 30 lines) ---"
            head -30 "$fc_path" 2>/dev/null
            echo "..."
            echo ""
        fi
    done

    # Property contexts
    echo "┌─────────────────────────────────────────────────────────────┐"
    echo "│ PROPERTY CONTEXTS                                          │"
    echo "└─────────────────────────────────────────────────────────────┘"
    echo ""
    
    for pc_path in /system/etc/selinux/plat_property_contexts /vendor/etc/selinux/vendor_property_contexts /property_contexts; do
        if [ -f "$pc_path" ]; then
            echo "--- $pc_path (first 30 lines) ---"
            head -30 "$pc_path" 2>/dev/null
            echo "..."
            echo ""
        fi
    done

    # Service contexts
    echo "┌─────────────────────────────────────────────────────────────┐"
    echo "│ SERVICE CONTEXTS                                           │"
    echo "└─────────────────────────────────────────────────────────────┘"
    echo ""
    
    for sc_path in /system/etc/selinux/plat_service_contexts /vendor/etc/selinux/vendor_service_contexts /service_contexts; do
        if [ -f "$sc_path" ]; then
            echo "--- $sc_path (first 30 lines) ---"
            head -30 "$sc_path" 2>/dev/null
            echo "..."
            echo ""
        fi
    done

    # SELinux denials from logs
    echo "┌─────────────────────────────────────────────────────────────┐"
    echo "│ RECENT SELINUX DENIALS (AVC)                               │"
    echo "└─────────────────────────────────────────────────────────────┘"
    echo ""
    echo "Recent access denials indicate policy violations or attacks:"
    echo ""
    
    # Try dmesg first
    echo "--- From dmesg ---"
    dmesg 2>/dev/null | grep -E "avc:|selinux" | tail -50
    echo ""
    
    # Try logcat
    echo "--- From logcat (last 50 AVC denials) ---"
    logcat -d 2>/dev/null | grep -E "avc:|SELinux" | tail -50
    echo ""

    # Critical file contexts
    echo "┌─────────────────────────────────────────────────────────────┐"
    echo "│ CRITICAL FILE SELINUX LABELS                               │"
    echo "└─────────────────────────────────────────────────────────────┘"
    echo ""
    
    CRITICAL_FILES="/init /system/bin/sh /system/bin/app_process /system/bin/app_process64 /data/local/tmp /dev/null /dev/zero /dev/random"
    
    for f in $CRITICAL_FILES; do
        if [ -e "$f" ]; then
            CONTEXT=$(ls -Z "$f" 2>/dev/null | awk '{print $1}')
            echo "$f: $CONTEXT"
        fi
    done
    echo ""

    # Critical directory contexts
    echo "┌─────────────────────────────────────────────────────────────┐"
    echo "│ CRITICAL DIRECTORY SELINUX LABELS                          │"
    echo "└─────────────────────────────────────────────────────────────┘"
    echo ""
    
    CRITICAL_DIRS="/system /vendor /data /data/data /data/local /data/local/tmp /sdcard /mnt"
    
    for d in $CRITICAL_DIRS; do
        if [ -d "$d" ]; then
            CONTEXT=$(ls -Zd "$d" 2>/dev/null | awk '{print $1}')
            echo "$d: $CONTEXT"
        fi
    done
    echo ""

    # App data directory contexts
    echo "┌─────────────────────────────────────────────────────────────┐"
    echo "│ APP DATA DIRECTORY CONTEXTS (Sample)                       │"
    echo "└─────────────────────────────────────────────────────────────┘"
    echo ""
    
    ls -Z /data/data/ 2>/dev/null | head -30
    echo ""

    # SELinux booleans (if available)
    echo "┌─────────────────────────────────────────────────────────────┐"
    echo "│ SELINUX BOOLEANS                                           │"
    echo "└─────────────────────────────────────────────────────────────┘"
    echo ""
    
    if [ -d /sys/fs/selinux/booleans ]; then
        echo "SELinux booleans:"
        for bool in /sys/fs/selinux/booleans/*; do
            if [ -f "$bool" ]; then
                BOOL_NAME=$(basename "$bool")
                BOOL_VAL=$(cat "$bool" 2>/dev/null)
                echo "  $BOOL_NAME = $BOOL_VAL"
            fi
        done | head -30
    else
        echo "No SELinux booleans directory found"
    fi
    echo ""

    # seapp_contexts (app labeling)
    echo "┌─────────────────────────────────────────────────────────────┐"
    echo "│ APP SELINUX CONTEXT RULES (seapp_contexts)                 │"
    echo "└─────────────────────────────────────────────────────────────┘"
    echo ""
    
    for seapp_path in /system/etc/selinux/plat_seapp_contexts /vendor/etc/selinux/vendor_seapp_contexts /seapp_contexts; do
        if [ -f "$seapp_path" ]; then
            echo "--- $seapp_path ---"
            cat "$seapp_path" 2>/dev/null | head -40
            echo "..."
            echo ""
        fi
    done

    # MLS/MCS check
    echo "┌─────────────────────────────────────────────────────────────┐"
    echo "│ MLS/MCS (Multi-Level Security) STATUS                      │"
    echo "└─────────────────────────────────────────────────────────────┘"
    echo ""
    
    if [ -f /sys/fs/selinux/mls ]; then
        MLS_STATUS=$(cat /sys/fs/selinux/mls 2>/dev/null)
        echo "MLS Enabled: $MLS_STATUS (1=yes, 0=no)"
    fi
    echo ""

    # Summary and recommendations
    echo "┌─────────────────────────────────────────────────────────────┐"
    echo "│ SELINUX AUDIT SUMMARY                                      │"
    echo "└─────────────────────────────────────────────────────────────┘"
    echo ""
    
    echo "Enforcement Status: $ENFORCE_STATUS"
    
    if [ "$ENFORCE_STATUS" = "Enforcing" ]; then
        echo "[OK] SELinux is properly enforcing"
    else
        echo "[CRITICAL] SELinux is NOT enforcing - security risk!"
    fi
    
    # Count permissive domains
    PERMISSIVE_COUNT=$(ps -AZ 2>/dev/null | awk '{print $1}' | grep -c "permissive" 2>/dev/null || echo "0")
    echo "Permissive Processes: $PERMISSIVE_COUNT"
    
    # Count unique domains
    DOMAIN_COUNT=$(ps -AZ 2>/dev/null | awk '{print $1}' | cut -d: -f3 | sort -u | wc -l)
    echo "Unique Domains in Use: $DOMAIN_COUNT"
    
    # Count recent denials
    DENIAL_COUNT=$(dmesg 2>/dev/null | grep -c "avc:.*denied" 2>/dev/null || echo "0")
    echo "Recent AVC Denials (dmesg): $DENIAL_COUNT"
    
    echo ""
    echo "Recommendations:"
    if [ "$ENFORCE_STATUS" != "Enforcing" ]; then
        echo "  [!] Set SELinux to enforcing mode for production"
    fi
    if [ "$DENIAL_COUNT" -gt 0 ]; then
        echo "  [!] Review AVC denials - may indicate policy gaps or attacks"
    fi
    if [ "$PERMISSIVE_COUNT" -gt 0 ]; then
        echo "  [!] Remove permissive domains from production policy"
    fi
    echo ""

} > "${OUTPUT_FILE}" 2>&1

echo "[+] SELinux audit saved to: ${OUTPUT_FILE}"
