#!/system/bin/sh
# DROID FORENSIC - Writable System Files Audit
# Identifies system files that could be modified for persistence/escalation
# Usage: sh 15_audit_writable_system.sh [output_directory]

OUTPUT_DIR="${1:-.}"
OUTPUT_FILE="${OUTPUT_DIR}/audit_writable_system.txt"

echo "[*] Auditing writable system files..."

{
    echo "═══════════════════════════════════════════════════════════════"
    echo "  WRITABLE SYSTEM FILES AUDIT"
    echo "  Timestamp: $(date)"
    echo "═══════════════════════════════════════════════════════════════"
    echo ""
    echo "Looking for files in system partitions that can be modified"
    echo "This could indicate misconfiguration or tampering opportunities"
    echo ""

    # Check mount options first
    echo "┌─────────────────────────────────────────────────────────────┐"
    echo "│ MOUNT OPTIONS (Read-Only Status)                           │"
    echo "└─────────────────────────────────────────────────────────────┘"
    
    mount 2>/dev/null | grep -E "^/dev" | while read line; do
        echo "$line"
    done
    echo ""
    
    echo "Checking if system partitions are mounted read-only:"
    for part in /system /vendor /product /odm; do
        if mount | grep -q " $part "; then
            if mount | grep " $part " | grep -q "ro,\|ro "; then
                echo "  $part: READ-ONLY [OK]"
            else
                echo "  $part: READ-WRITE [WARNING]"
            fi
        else
            echo "  $part: [not a separate mount]"
        fi
    done
    echo ""

    # Writable by current user in /system
    echo "┌─────────────────────────────────────────────────────────────┐"
    echo "│ FILES WRITABLE BY CURRENT USER IN /system                  │"
    echo "└─────────────────────────────────────────────────────────────┘"
    
    find /system -type f -writable 2>/dev/null | while read f; do
        echo "[WRITABLE] $f"
        ls -la "$f" 2>/dev/null | sed 's/^/  /'
    done
    echo ""

    # Writable by current user in /vendor
    echo "┌─────────────────────────────────────────────────────────────┐"
    echo "│ FILES WRITABLE BY CURRENT USER IN /vendor                  │"
    echo "└─────────────────────────────────────────────────────────────┘"
    
    find /vendor -type f -writable 2>/dev/null | while read f; do
        echo "[WRITABLE] $f"
        ls -la "$f" 2>/dev/null | sed 's/^/  /'
    done
    echo ""

    # Directories writable by current user
    echo "┌─────────────────────────────────────────────────────────────┐"
    echo "│ DIRECTORIES WRITABLE BY CURRENT USER                       │"
    echo "└─────────────────────────────────────────────────────────────┘"
    
    for dir in /system /vendor /product /odm; do
        if [ -d "$dir" ]; then
            echo "--- $dir ---"
            find "$dir" -type d -writable 2>/dev/null | while read d; do
                echo "[WRITABLE DIR] $d"
                ls -ld "$d" 2>/dev/null | sed 's/^/  /'
            done
        fi
    done
    echo ""

    # Shell scripts in system that are writable
    echo "┌─────────────────────────────────────────────────────────────┐"
    echo "│ WRITABLE SHELL SCRIPTS IN SYSTEM                           │"
    echo "└─────────────────────────────────────────────────────────────┘"
    
    find /system /vendor -name "*.sh" -type f 2>/dev/null | while read f; do
        if [ -w "$f" ]; then
            echo "[WRITABLE SCRIPT] $f"
            ls -la "$f" 2>/dev/null | sed 's/^/  /'
        fi
    done
    echo ""

    # RC files that are writable
    echo "┌─────────────────────────────────────────────────────────────┐"
    echo "│ WRITABLE RC/INIT FILES                                     │"
    echo "└─────────────────────────────────────────────────────────────┘"
    
    find /system /vendor / -maxdepth 3 -name "*.rc" -type f 2>/dev/null | while read f; do
        if [ -w "$f" ]; then
            echo "[WRITABLE RC] $f"
            ls -la "$f" 2>/dev/null | sed 's/^/  /'
        fi
    done
    echo ""

    # Shared libraries that are writable (library injection risk)
    echo "┌─────────────────────────────────────────────────────────────┐"
    echo "│ WRITABLE SHARED LIBRARIES (Injection Risk)                 │"
    echo "└─────────────────────────────────────────────────────────────┘"
    
    for libdir in /system/lib /system/lib64 /vendor/lib /vendor/lib64; do
        if [ -d "$libdir" ]; then
            echo "--- $libdir ---"
            find "$libdir" -name "*.so" -type f -writable 2>/dev/null | while read f; do
                echo "[WRITABLE LIB] $f"
                ls -la "$f" 2>/dev/null | sed 's/^/  /'
            done
        fi
    done
    echo ""

    # APKs that are writable
    echo "┌─────────────────────────────────────────────────────────────┐"
    echo "│ WRITABLE APK FILES                                         │"
    echo "└─────────────────────────────────────────────────────────────┘"
    
    for apkdir in /system/app /system/priv-app /vendor/app /product/app; do
        if [ -d "$apkdir" ]; then
            echo "--- $apkdir ---"
            find "$apkdir" -name "*.apk" -type f -writable 2>/dev/null | while read f; do
                echo "[WRITABLE APK] $f"
                ls -la "$f" 2>/dev/null | sed 's/^/  /'
            done
        fi
    done
    echo ""

    # Binaries that are writable
    echo "┌─────────────────────────────────────────────────────────────┐"
    echo "│ WRITABLE BINARIES                                          │"
    echo "└─────────────────────────────────────────────────────────────┘"
    
    for bindir in /system/bin /system/xbin /vendor/bin /sbin; do
        if [ -d "$bindir" ]; then
            echo "--- $bindir ---"
            find "$bindir" -type f -writable 2>/dev/null | while read f; do
                echo "[WRITABLE BIN] $f"
                ls -la "$f" 2>/dev/null | sed 's/^/  /'
            done
        fi
    done
    echo ""

    # Check /data locations that could affect system behavior
    echo "┌─────────────────────────────────────────────────────────────┐"
    echo "│ SENSITIVE /data LOCATIONS                                  │"
    echo "└─────────────────────────────────────────────────────────────┘"
    
    SENSITIVE_DATA="/data/local /data/local/tmp /data/misc /data/system"
    
    for dir in $SENSITIVE_DATA; do
        if [ -d "$dir" ]; then
            echo "Directory: $dir"
            ls -la "$dir" 2>/dev/null | head -20 | sed 's/^/  /'
            echo ""
        fi
    done
    echo ""

    # Summary
    echo "┌─────────────────────────────────────────────────────────────┐"
    echo "│ SUMMARY                                                    │"
    echo "└─────────────────────────────────────────────────────────────┘"
    
    W_SYSTEM_FILES=$(find /system -type f -writable 2>/dev/null | wc -l)
    W_SYSTEM_DIRS=$(find /system -type d -writable 2>/dev/null | wc -l)
    W_VENDOR_FILES=$(find /vendor -type f -writable 2>/dev/null | wc -l)
    
    echo "Writable files in /system:      $W_SYSTEM_FILES"
    echo "Writable directories in /system: $W_SYSTEM_DIRS"
    echo "Writable files in /vendor:      $W_VENDOR_FILES"
    
    TOTAL_WRITABLE=$((W_SYSTEM_FILES + W_VENDOR_FILES))
    if [ "$TOTAL_WRITABLE" -gt 0 ]; then
        echo ""
        echo "[ALERT] Writable files found in system partitions!"
        echo "This may indicate:"
        echo "  - System partition mounted read-write"
        echo "  - Rooted device with remounted partitions"
        echo "  - Misconfigured file permissions"
    fi
    echo ""

} > "${OUTPUT_FILE}" 2>&1

echo "[+] Writable system files audit saved to: ${OUTPUT_FILE}"
