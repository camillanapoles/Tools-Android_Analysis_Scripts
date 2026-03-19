#!/system/bin/sh
# DROID FORENSIC - Boot Executable Audit
# Identifies executables started at boot time
# Usage: sh 18_audit_boot.sh [output_directory]

OUTPUT_DIR="${1:-.}"
OUTPUT_FILE="${OUTPUT_DIR}/audit_boot.txt"

echo "[*] Auditing boot-time executables..."

{
    echo "═══════════════════════════════════════════════════════════════"
    echo "  BOOT EXECUTABLE AUDIT"
    echo "  Timestamp: $(date)"
    echo "═══════════════════════════════════════════════════════════════"
    echo ""

    # Init RC files
    echo "┌─────────────────────────────────────────────────────────────┐"
    echo "│ INIT RC FILES                                              │"
    echo "└─────────────────────────────────────────────────────────────┘"
    
    echo "Root level init files:"
    ls -la /init* 2>/dev/null
    ls -la /*.rc 2>/dev/null
    echo ""
    
    echo "System init directory:"
    ls -la /system/etc/init/ 2>/dev/null | head -30
    echo ""
    
    echo "Vendor init directory:"
    ls -la /vendor/etc/init/ 2>/dev/null | head -30
    echo ""
    
    echo "Product init directory:"
    ls -la /product/etc/init/ 2>/dev/null | head -20
    echo ""
    
    echo "ODM init directory:"
    ls -la /odm/etc/init/ 2>/dev/null | head -20
    echo ""

    # Services defined in init
    echo "┌─────────────────────────────────────────────────────────────┐"
    echo "│ SERVICES DEFINED IN RC FILES                               │"
    echo "└─────────────────────────────────────────────────────────────┘"
    echo "Format: service <name> <path> [args]"
    echo ""
    
    # Extract service definitions
    for rc_dir in / /system/etc/init /vendor/etc/init /product/etc/init /odm/etc/init; do
        if [ -d "$rc_dir" ] || [ -f "${rc_dir}.rc" ]; then
            echo "--- Services from $rc_dir ---"
            cat ${rc_dir}/*.rc ${rc_dir}.rc 2>/dev/null | grep -E "^service\s+" | head -50
            echo ""
        fi
    done
    echo ""

    # Services with elevated privileges
    echo "┌─────────────────────────────────────────────────────────────┐"
    echo "│ SERVICES RUNNING AS ROOT/SYSTEM                            │"
    echo "└─────────────────────────────────────────────────────────────┘"
    
    for rc_dir in /system/etc/init /vendor/etc/init; do
        if [ -d "$rc_dir" ]; then
            echo "--- $rc_dir ---"
            for rc_file in "$rc_dir"/*.rc; do
                if [ -f "$rc_file" ]; then
                    # Look for services that run as root or don't drop privileges
                    service_name=""
                    while IFS= read -r line; do
                        case "$line" in
                            service\ *)
                                service_name=$(echo "$line" | awk '{print $2}')
                                service_path=$(echo "$line" | awk '{print $3}')
                                ;;
                            *user\ root*|*group\ root*)
                                if [ -n "$service_name" ]; then
                                    echo "[ROOT] $service_name: $service_path"
                                    echo "  File: $rc_file"
                                fi
                                ;;
                        esac
                    done < "$rc_file"
                fi
            done 2>/dev/null
            echo ""
        fi
    done
    echo ""

    # Zygote configuration
    echo "┌─────────────────────────────────────────────────────────────┐"
    echo "│ ZYGOTE CONFIGURATION                                       │"
    echo "└─────────────────────────────────────────────────────────────┘"
    
    grep -r "zygote" /system/etc/init/*.rc /init*.rc 2>/dev/null | head -20
    echo ""
    
    echo "Zygote binaries:"
    ls -la /system/bin/*zygote* /system/bin/app_process* 2>/dev/null
    echo ""

    # Boot completed receivers (apps)
    echo "┌─────────────────────────────────────────────────────────────┐"
    echo "│ APPS WITH BOOT_COMPLETED PERMISSION                        │"
    echo "└─────────────────────────────────────────────────────────────┘"
    
    # Using dumpsys to find apps with RECEIVE_BOOT_COMPLETED
    dumpsys package 2>/dev/null | grep -B5 "android.permission.RECEIVE_BOOT_COMPLETED" | grep "Package \[" | head -30
    echo ""
    
    # Alternative: pm command
    echo "Packages requesting BOOT_COMPLETED:"
    pm list packages -f 2>/dev/null | while read pkg_line; do
        pkg=$(echo "$pkg_line" | sed 's/package://' | cut -d'=' -f2)
        if dumpsys package "$pkg" 2>/dev/null | grep -q "RECEIVE_BOOT_COMPLETED"; then
            echo "  $pkg"
        fi
    done 2>/dev/null | head -50
    echo "[truncated to 50]"
    echo ""

    # Persistent apps
    echo "┌─────────────────────────────────────────────────────────────┐"
    echo "│ PERSISTENT APPS (android:persistent=true)                  │"
    echo "└─────────────────────────────────────────────────────────────┘"
    
    dumpsys package 2>/dev/null | grep -B10 "PERSISTENT" | grep "Package \[" | head -20
    echo ""

    # Property triggers
    echo "┌─────────────────────────────────────────────────────────────┐"
    echo "│ PROPERTY TRIGGERS IN RC FILES                              │"
    echo "└─────────────────────────────────────────────────────────────┘"
    echo "Actions triggered by property changes:"
    
    for rc_dir in /system/etc/init /vendor/etc/init; do
        if [ -d "$rc_dir" ]; then
            grep -h "on property:" "$rc_dir"/*.rc 2>/dev/null | head -30
        fi
    done
    echo ""

    # Critical boot services status
    echo "┌─────────────────────────────────────────────────────────────┐"
    echo "│ CURRENT RUNNING SERVICES (from init)                       │"
    echo "└─────────────────────────────────────────────────────────────┘"
    
    getprop | grep "init.svc." | head -50
    echo "[truncated to 50]"
    echo ""

    # Kernel modules loaded at boot
    echo "┌─────────────────────────────────────────────────────────────┐"
    echo "│ LOADED KERNEL MODULES                                      │"
    echo "└─────────────────────────────────────────────────────────────┘"
    
    lsmod 2>/dev/null || cat /proc/modules 2>/dev/null | head -30
    echo ""

    # Early mount and fstab
    echo "┌─────────────────────────────────────────────────────────────┐"
    echo "│ FSTAB / MOUNT CONFIGURATION                                │"
    echo "└─────────────────────────────────────────────────────────────┘"
    
    cat /vendor/etc/fstab.* /fstab.* 2>/dev/null | head -30
    echo ""

} > "${OUTPUT_FILE}" 2>&1

echo "[+] Boot executable audit saved to: ${OUTPUT_FILE}"
