#!/system/bin/sh
# DROID FORENSIC - SUID/SGID Executable Audit
# Identifies executables with elevated permission bits
# Usage: sh 11_audit_setuid.sh [output_directory]

OUTPUT_DIR="${1:-.}"
OUTPUT_FILE="${OUTPUT_DIR}/audit_setuid.txt"

echo "[*] Auditing SUID/SGID executables..."

{
    echo "═══════════════════════════════════════════════════════════════"
    echo "  SUID/SGID EXECUTABLE AUDIT"
    echo "  Timestamp: $(date)"
    echo "═══════════════════════════════════════════════════════════════"
    echo ""
    echo "RISK LEVELS:"
    echo "  [CRITICAL] - SUID root binaries, direct privilege escalation risk"
    echo "  [HIGH]     - SGID or SUID to privileged users"
    echo "  [MEDIUM]   - Special permissions on unusual binaries"
    echo ""

    # SUID root binaries (most critical)
    echo "┌─────────────────────────────────────────────────────────────┐"
    echo "│ [CRITICAL] SUID ROOT BINARIES (Execute as UID 0)           │"
    echo "└─────────────────────────────────────────────────────────────┘"
    echo "These execute with root privileges regardless of caller"
    echo ""
    
    for dir in /system /vendor /product /odm /sbin /data; do
        if [ -d "$dir" ]; then
            find "$dir" -perm -4000 -user 0 -type f 2>/dev/null | while read f; do
                echo "[CRITICAL] $f"
                ls -la "$f" 2>/dev/null | sed 's/^/  /'
                file "$f" 2>/dev/null | sed 's/^/  Type: /'
                # Check if binary is a shell or interpreter
                case "$(basename "$f")" in
                    sh|bash|zsh|ksh|csh|tcsh|ash|dash|busybox|toybox)
                        echo "  WARNING: Shell binary with SUID!"
                        ;;
                esac
                echo ""
            done
        fi
    done
    echo ""

    # All SUID binaries (any owner)
    echo "┌─────────────────────────────────────────────────────────────┐"
    echo "│ [HIGH] ALL SUID BINARIES                                   │"
    echo "└─────────────────────────────────────────────────────────────┘"
    
    for dir in /system /vendor /product /odm; do
        if [ -d "$dir" ]; then
            echo "--- Searching $dir ---"
            find "$dir" -perm -4000 -type f 2>/dev/null | while read f; do
                owner=$(ls -la "$f" 2>/dev/null | awk '{print $3}')
                echo "[SUID] $f (owner: $owner)"
                ls -la "$f" 2>/dev/null | sed 's/^/  /'
            done
            echo ""
        fi
    done
    echo ""

    # SGID binaries
    echo "┌─────────────────────────────────────────────────────────────┐"
    echo "│ [HIGH] SGID BINARIES (Execute with Group Privileges)       │"
    echo "└─────────────────────────────────────────────────────────────┘"
    
    for dir in /system /vendor /product /odm; do
        if [ -d "$dir" ]; then
            echo "--- Searching $dir ---"
            find "$dir" -perm -2000 -type f 2>/dev/null | while read f; do
                group=$(ls -la "$f" 2>/dev/null | awk '{print $4}')
                echo "[SGID] $f (group: $group)"
                ls -la "$f" 2>/dev/null | sed 's/^/  /'
                
                # Check for sensitive groups
                case "$group" in
                    root|system|radio|bluetooth|wifi|net_raw|net_admin)
                        echo "  WARNING: SGID to privileged group: $group"
                        ;;
                esac
            done
            echo ""
        fi
    done
    echo ""

    # Both SUID and SGID
    echo "┌─────────────────────────────────────────────────────────────┐"
    echo "│ [CRITICAL] BOTH SUID AND SGID SET                          │"
    echo "└─────────────────────────────────────────────────────────────┘"
    
    for dir in /system /vendor /product /odm /data; do
        if [ -d "$dir" ]; then
            find "$dir" -perm -6000 -type f 2>/dev/null | while read f; do
                echo "[SUID+SGID] $f"
                ls -la "$f" 2>/dev/null | sed 's/^/  /'
                echo ""
            done
        fi
    done
    echo ""

    # SUID/SGID in writable locations
    echo "┌─────────────────────────────────────────────────────────────┐"
    echo "│ [CRITICAL] SUID/SGID IN WRITABLE LOCATIONS                 │"
    echo "└─────────────────────────────────────────────────────────────┘"
    echo "SUID binaries in /data or other writable paths are highly suspicious"
    echo ""
    
    for dir in /data /sdcard /mnt/sdcard /storage; do
        if [ -d "$dir" ]; then
            echo "--- Searching $dir ---"
            find "$dir" -perm /6000 -type f 2>/dev/null | while read f; do
                echo "[SUSPICIOUS] $f"
                ls -la "$f" 2>/dev/null | sed 's/^/  /'
            done
        fi
    done
    echo ""

    # Sticky bit directories
    echo "┌─────────────────────────────────────────────────────────────┐"
    echo "│ [INFO] STICKY BIT DIRECTORIES                              │"
    echo "└─────────────────────────────────────────────────────────────┘"
    
    for dir in /tmp /data/local/tmp /var/tmp; do
        if [ -d "$dir" ]; then
            perms=$(ls -ld "$dir" 2>/dev/null)
            echo "$dir: $perms"
        fi
    done
    
    find /system /vendor -perm -1000 -type d 2>/dev/null | head -20 | while read d; do
        ls -ld "$d" 2>/dev/null
    done
    echo ""

    # Summary statistics
    echo "┌─────────────────────────────────────────────────────────────┐"
    echo "│ SUMMARY STATISTICS                                         │"
    echo "└─────────────────────────────────────────────────────────────┘"
    
    SUID_SYSTEM=$(find /system -perm -4000 -type f 2>/dev/null | wc -l)
    SUID_VENDOR=$(find /vendor -perm -4000 -type f 2>/dev/null | wc -l)
    SUID_DATA=$(find /data -perm -4000 -type f 2>/dev/null | wc -l)
    SGID_SYSTEM=$(find /system -perm -2000 -type f 2>/dev/null | wc -l)
    SGID_VENDOR=$(find /vendor -perm -2000 -type f 2>/dev/null | wc -l)
    
    echo "SUID binaries in /system: $SUID_SYSTEM"
    echo "SUID binaries in /vendor: $SUID_VENDOR"
    echo "SUID binaries in /data:   $SUID_DATA"
    echo "SGID binaries in /system: $SGID_SYSTEM"
    echo "SGID binaries in /vendor: $SGID_VENDOR"
    echo ""

    if [ "$SUID_DATA" -gt 0 ]; then
        echo "[ALERT] SUID binaries found in /data - requires investigation!"
    fi
    echo ""

} > "${OUTPUT_FILE}" 2>&1

echo "[+] SUID/SGID audit saved to: ${OUTPUT_FILE}"
