#!/system/bin/sh
# DROID FORENSIC - Special File Permissions Audit
# Identifies files with special permissions or owned by privileged UIDs
# Usage: sh 16_audit_special_perms.sh [output_directory]

OUTPUT_DIR="${1:-.}"
OUTPUT_FILE="${OUTPUT_DIR}/audit_special_perms.txt"

echo "[*] Auditing special file permissions..."

{
    echo "═══════════════════════════════════════════════════════════════"
    echo "  SPECIAL FILE PERMISSIONS AUDIT"
    echo "  Timestamp: $(date)"
    echo "═══════════════════════════════════════════════════════════════"
    echo ""

    # World-writable files in system partitions
    echo "┌─────────────────────────────────────────────────────────────┐"
    echo "│ [CRITICAL] WORLD-WRITABLE FILES IN SYSTEM PATHS            │"
    echo "└─────────────────────────────────────────────────────────────┘"
    echo "Files writable by any user in protected partitions"
    echo ""
    
    for dir in /system /vendor /product /odm; do
        if [ -d "$dir" ]; then
            echo "--- $dir ---"
            result=$(find "$dir" -perm -0002 -type f 2>/dev/null)
            if [ -n "$result" ]; then
                echo "$result" | while read f; do
                    echo "[WORLD-WRITABLE] $f"
                    ls -la "$f" 2>/dev/null | sed 's/^/  /'
                done
            else
                echo "  None found"
            fi
            echo ""
        fi
    done
    echo ""

    # World-writable directories
    echo "┌─────────────────────────────────────────────────────────────┐"
    echo "│ [HIGH] WORLD-WRITABLE DIRECTORIES                          │"
    echo "└─────────────────────────────────────────────────────────────┘"
    
    for dir in /system /vendor /product /odm; do
        if [ -d "$dir" ]; then
            echo "--- $dir ---"
            find "$dir" -perm -0002 -type d 2>/dev/null | while read d; do
                echo "[WORLD-WRITABLE DIR] $d"
                ls -ld "$d" 2>/dev/null | sed 's/^/  /'
            done
        fi
    done
    echo ""

    # Group-writable files in system
    echo "┌─────────────────────────────────────────────────────────────┐"
    echo "│ [MEDIUM] GROUP-WRITABLE FILES IN /system                   │"
    echo "└─────────────────────────────────────────────────────────────┘"
    
    find /system -perm -0020 -type f 2>/dev/null | head -50 | while read f; do
        group=$(ls -la "$f" 2>/dev/null | awk '{print $4}')
        echo "[GROUP-WRITABLE] $f (group: $group)"
    done
    echo "[truncated to 50]"
    echo ""

    # Files owned by network-capable UIDs
    echo "┌─────────────────────────────────────────────────────────────┐"
    echo "│ [HIGH] FILES OWNED BY NETWORK-CAPABLE UIDs                 │"
    echo "└─────────────────────────────────────────────────────────────┘"
    echo "These UIDs have special network capabilities"
    echo ""
    
    # AID_NET_RAW (3004) - can capture packets
    echo "--- UID 3004 (net_raw) - Packet Capture Capable ---"
    find /system /vendor -user 3004 -type f 2>/dev/null | while read f; do
        echo "[NET_RAW] $f"
        ls -la "$f" 2>/dev/null | sed 's/^/  /'
    done
    echo ""
    
    # AID_NET_ADMIN (3005) - network admin
    echo "--- UID 3005 (net_admin) - Network Admin ---"
    find /system /vendor -user 3005 -type f 2>/dev/null | while read f; do
        echo "[NET_ADMIN] $f"
        ls -la "$f" 2>/dev/null | sed 's/^/  /'
    done
    echo ""
    
    # AID_INET (3003) - internet access
    echo "--- GID 3003 (inet) - Internet Access ---"
    find /system /vendor -group 3003 -type f 2>/dev/null | head -20 | while read f; do
        echo "[INET] $f"
    done
    echo ""

    # Config files with weak permissions
    echo "┌─────────────────────────────────────────────────────────────┐"
    echo "│ [MEDIUM] CONFIG FILES WITH WEAK PERMISSIONS                │"
    echo "└─────────────────────────────────────────────────────────────┘"
    
    echo "Writable config files (.conf, .xml, .prop, .cfg):"
    for pattern in "*.conf" "*.xml" "*.prop" "*.cfg" "*.ini"; do
        find /system/etc /vendor/etc -name "$pattern" -perm /022 -type f 2>/dev/null | while read f; do
            echo "[WRITABLE CONFIG] $f"
            ls -la "$f" 2>/dev/null | sed 's/^/  /'
        done
    done
    echo ""

    # Non-binary files with execute permission
    echo "┌─────────────────────────────────────────────────────────────┐"
    echo "│ [INFO] NON-BINARY FILES WITH EXECUTE BIT                   │"
    echo "└─────────────────────────────────────────────────────────────┘"
    echo "Data files that shouldn't be executable:"
    
    for pattern in "*.xml" "*.conf" "*.txt" "*.json" "*.prop"; do
        find /system/etc /vendor/etc -name "$pattern" -perm /111 -type f 2>/dev/null | while read f; do
            echo "[EXECUTABLE DATA] $f"
        done
    done
    echo ""

    # Files with capabilities
    echo "┌─────────────────────────────────────────────────────────────┐"
    echo "│ [HIGH] FILES WITH LINUX CAPABILITIES                       │"
    echo "└─────────────────────────────────────────────────────────────┘"
    
    for dir in /system/bin /system/xbin /vendor/bin /sbin; do
        if [ -d "$dir" ]; then
            echo "--- $dir ---"
            getcap -r "$dir" 2>/dev/null || echo "[getcap not available]"
        fi
    done
    echo ""

    # Immutable files
    echo "┌─────────────────────────────────────────────────────────────┐"
    echo "│ [INFO] FILES WITH IMMUTABLE ATTRIBUTE                      │"
    echo "└─────────────────────────────────────────────────────────────┘"
    
    lsattr -R /system/bin 2>/dev/null | grep -E "^....i" | head -20
    echo ""

    # SELinux contexts of interest
    echo "┌─────────────────────────────────────────────────────────────┐"
    echo "│ SELINUX FILE CONTEXTS                                      │"
    echo "└─────────────────────────────────────────────────────────────┘"
    
    echo "System binaries SELinux contexts:"
    ls -Z /system/bin/ 2>/dev/null | head -30
    echo ""
    
    echo "Vendor binaries SELinux contexts:"
    ls -Z /vendor/bin/ 2>/dev/null | head -30
    echo ""

    # Sensitive file permissions summary
    echo "┌─────────────────────────────────────────────────────────────┐"
    echo "│ SENSITIVE FILE CHECKS                                      │"
    echo "└─────────────────────────────────────────────────────────────┘"
    
    SENSITIVE_FILES="/system/build.prop /vendor/build.prop /default.prop /system/etc/hosts /data/misc/wifi/wpa_supplicant.conf"
    
    for f in $SENSITIVE_FILES; do
        if [ -e "$f" ]; then
            echo "File: $f"
            ls -la "$f" 2>/dev/null | sed 's/^/  /'
            ls -Z "$f" 2>/dev/null | sed 's/^/  SELinux: /'
            echo ""
        fi
    done
    echo ""

    # Summary
    echo "┌─────────────────────────────────────────────────────────────┐"
    echo "│ SUMMARY                                                    │"
    echo "└─────────────────────────────────────────────────────────────┘"
    
    WW_SYSTEM=$(find /system -perm -0002 -type f 2>/dev/null | wc -l)
    WW_VENDOR=$(find /vendor -perm -0002 -type f 2>/dev/null | wc -l)
    
    echo "World-writable files in /system: $WW_SYSTEM"
    echo "World-writable files in /vendor: $WW_VENDOR"
    
    if [ "$WW_SYSTEM" -gt 0 ] || [ "$WW_VENDOR" -gt 0 ]; then
        echo ""
        echo "[ALERT] World-writable files found in system partitions!"
    fi
    echo ""

} > "${OUTPUT_FILE}" 2>&1

echo "[+] Special permissions audit saved to: ${OUTPUT_FILE}"
