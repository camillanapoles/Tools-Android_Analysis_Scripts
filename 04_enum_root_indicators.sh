#!/system/bin/sh
# 04_enum_root_indicators.sh - Android Root Framework Detection & Indicators
# Detects Magisk, KernelSU, APatch, SuperSU, and other rooting artifacts
# POSIX sh only - Android 8.0+ compatible

OUTPUT_DIR="${1:-.}"
OUTPUT_FILE="${OUTPUT_DIR}/root_indicators.txt"

echo "[*] Scanning for root indicators..."

{
    echo "╔════════════════════════════════════════════════════════════════╗"
    echo "║           ANDROID ROOT FRAMEWORK DETECTION SCANNER              ║"
    echo "║          Enumeration: SU, Magisk, KSU, APatch, SuperSU         ║"
    echo "╚════════════════════════════════════════════════════════════════╝"
    echo ""
    echo "Scan Date: $(date '+%Y-%m-%d %H:%M:%S')"
    echo "Device: $(getprop ro.product.model 2>/dev/null || echo 'Unknown')"
    echo "Android Version: $(getprop ro.build.version.release 2>/dev/null || echo 'Unknown')"
    echo ""

    # ─────────────────────────────────────────────────────────────────────
    # SECTION: SU BINARY DETECTION
    # ─────────────────────────────────────────────────────────────────────
    echo "╔═══════════════════════════════════════════════════════════════╗"
    echo "║              1. SU BINARY DETECTION                            ║"
    echo "╚═══════════════════════════════════════════════════════════════╝"
    echo ""

    SU_FOUND=0
    SU_LOCATIONS="/system/bin/su /system/xbin/su /sbin/su /vendor/bin/su /data/local/su /data/local/bin/su /data/local/xbin/su /system/sd/xbin/su /system/bin/failsafe/su /dev/su"

    for su_path in $SU_LOCATIONS; do
        if [ -f "$su_path" ]; then
            SU_FOUND=1
            echo "[HIGH] SU binary found: $su_path"
            ls -la "$su_path" 2>/dev/null | sed 's/^/  /'
            stat -c "  Owner UID: %U (%u) | GID: %G (%g)" "$su_path" 2>/dev/null || \
                stat -f "  Owner: %Su | GID: %Sg" "$su_path" 2>/dev/null || \
                echo "  (stat not available)"
            # Attempt SELinux context
            ls -Z "$su_path" 2>/dev/null | awk '{print "  SELinux: " $1}' || true
            echo ""
        fi
    done

    if [ $SU_FOUND -eq 0 ]; then
        echo "[OK] No SU binary found in common locations"
        echo ""
    fi

    # ─────────────────────────────────────────────────────────────────────
    # SECTION: MAGISK DETECTION
    # ─────────────────────────────────────────────────────────────────────
    echo "╔═══════════════════════════════════════════════════════════════╗"
    echo "║              2. MAGISK FRAMEWORK DETECTION                     ║"
    echo "╚═══════════════════════════════════════════════════════════════╝"
    echo ""

    MAGISK_FOUND=0

    # Check Magisk directories
    MAGISK_DIRS="/sbin/.magisk /data/adb/magisk /data/magisk /cache/.disable_magisk /data/adb/modules"
    for mag_dir in $MAGISK_DIRS; do
        if [ -d "$mag_dir" ]; then
            MAGISK_FOUND=1
            echo "[HIGH] Magisk directory found: $mag_dir"
            ls -la "$mag_dir" 2>/dev/null | head -10 | sed 's/^/  /'
            echo ""
        fi
    done

    # Check Magisk database files
    if [ -f "/data/adb/magisk.db" ]; then
        MAGISK_FOUND=1
        echo "[HIGH] Magisk database found: /data/adb/magisk.db"
        ls -la /data/adb/magisk.db 2>/dev/null | sed 's/^/  /'
        echo ""
    fi

    if [ -f "/data/adb/magisk.img" ]; then
        MAGISK_FOUND=1
        echo "[HIGH] Magisk image found: /data/adb/magisk.img"
        ls -la /data/adb/magisk.img 2>/dev/null | sed 's/^/  /'
        echo ""
    fi

    # Check for magisk command
    if command -v magisk >/dev/null 2>&1; then
        MAGISK_FOUND=1
        echo "[HIGH] 'magisk' command available in PATH"
        magisk --version 2>/dev/null | sed 's/^/  Version: /'
        echo ""
    fi

    # Check system properties
    MAGISK_PROPS=$(getprop 2>/dev/null | grep -i magisk | wc -l)
    if [ "$MAGISK_PROPS" -gt 0 ]; then
        MAGISK_FOUND=1
        echo "[HIGH] Magisk-related system properties detected:"
        getprop 2>/dev/null | grep -i magisk | sed 's/^/  /'
        echo ""
    fi

    # Check mounts
    if grep -q magisk /proc/mounts 2>/dev/null; then
        MAGISK_FOUND=1
        echo "[HIGH] Magisk mounts detected:"
        grep magisk /proc/mounts 2>/dev/null | sed 's/^/  /'
        echo ""
    fi

    # Check for Zygisk modules
    if [ -d "/data/adb/modules" ]; then
        ZYGISK_COUNT=$(ls /data/adb/modules 2>/dev/null | wc -l)
        if [ "$ZYGISK_COUNT" -gt 0 ]; then
            MAGISK_FOUND=1
            echo "[HIGH] Magisk modules detected ($ZYGISK_COUNT total):"
            ls -1 /data/adb/modules 2>/dev/null | sed 's/^/  - /'
            echo ""
        fi
    fi

    if [ $MAGISK_FOUND -eq 0 ]; then
        echo "[OK] No Magisk artifacts detected"
        echo ""
    fi

    # ─────────────────────────────────────────────────────────────────────
    # SECTION: KERNELSU DETECTION
    # ─────────────────────────────────────────────────────────────────────
    echo "╔═══════════════════════════════════════════════════════════════╗"
    echo "║              3. KERNELSU FRAMEWORK DETECTION                   ║"
    echo "╚═══════════════════════════════════════════════════════════════╝"
    echo ""

    KSU_FOUND=0

    # Check KernelSU directories
    if [ -f "/data/adb/ksud" ] || [ -d "/data/adb/ksud" ]; then
        KSU_FOUND=1
        echo "[HIGH] KernelSU daemon found: /data/adb/ksud"
        ls -la /data/adb/ksud 2>/dev/null | sed 's/^/  /'
        echo ""
    fi

    if [ -f "/data/adb/ksu" ] || [ -d "/data/adb/ksu" ]; then
        KSU_FOUND=1
        echo "[HIGH] KernelSU directory/file found: /data/adb/ksu"
        ls -la /data/adb/ksu 2>/dev/null | sed 's/^/  /'
        echo ""
    fi

    # Check KernelSU system properties
    KSU_PROPS=$(getprop 2>/dev/null | grep -i kernelsu | wc -l)
    if [ "$KSU_PROPS" -gt 0 ]; then
        KSU_FOUND=1
        echo "[HIGH] KernelSU-related system properties detected:"
        getprop 2>/dev/null | grep -i kernelsu | sed 's/^/  /'
        echo ""
    fi

    # Check KernelSU sysfs interface
    if [ -d "/sys/kernel/ksu" ]; then
        KSU_FOUND=1
        echo "[HIGH] KernelSU sysfs interface detected: /sys/kernel/ksu"
        ls -la /sys/kernel/ksu 2>/dev/null | sed 's/^/  /'
        echo ""
    fi

    # Check for ksud binary in PATH
    if command -v ksud >/dev/null 2>&1; then
        KSU_FOUND=1
        echo "[HIGH] 'ksud' command available in PATH"
        which ksud 2>/dev/null | sed 's/^/  Location: /'
        echo ""
    fi

    if [ $KSU_FOUND -eq 0 ]; then
        echo "[OK] No KernelSU artifacts detected"
        echo ""
    fi

    # ─────────────────────────────────────────────────────────────────────
    # SECTION: APATCH DETECTION
    # ─────────────────────────────────────────────────────────────────────
    echo "╔═══════════════════════════════════════════════════════════════╗"
    echo "║              4. APATCH FRAMEWORK DETECTION                     ║"
    echo "╚═══════════════════════════════════════════════════════════════╝"
    echo ""

    APATCH_FOUND=0

    if [ -d "/data/adb/apatch" ]; then
        APATCH_FOUND=1
        echo "[HIGH] APatch directory found: /data/adb/apatch"
        ls -la /data/adb/apatch 2>/dev/null | sed 's/^/  /'
        echo ""
    fi

    if [ -d "/data/adb/ap" ]; then
        APATCH_FOUND=1
        echo "[HIGH] APatch directory found: /data/adb/ap"
        ls -la /data/adb/ap 2>/dev/null | sed 's/^/  /'
        echo ""
    fi

    APATCH_PROPS=$(getprop 2>/dev/null | grep -i apatch | wc -l)
    if [ "$APATCH_PROPS" -gt 0 ]; then
        APATCH_FOUND=1
        echo "[HIGH] APatch-related system properties detected:"
        getprop 2>/dev/null | grep -i apatch | sed 's/^/  /'
        echo ""
    fi

    if [ $APATCH_FOUND -eq 0 ]; then
        echo "[OK] No APatch artifacts detected"
        echo ""
    fi

    # ─────────────────────────────────────────────────────────────────────
    # SECTION: SUPERSU / LEGACY ROOT DETECTION
    # ─────────────────────────────────────────────────────────────────────
    echo "╔═══════════════════════════════════════════════════════════════╗"
    echo "║              5. SUPERSU / LEGACY ROOT DETECTION                ║"
    echo "╚═══════════════════════════════════════════════════════════════╝"
    echo ""

    LEGACY_FOUND=0

    if [ -f "/system/xbin/daemonsu" ]; then
        LEGACY_FOUND=1
        echo "[HIGH] SuperSU daemon found: /system/xbin/daemonsu"
        ls -la /system/xbin/daemonsu 2>/dev/null | sed 's/^/  /'
        echo ""
    fi

    if [ -f "/system/etc/.installed_su_daemon" ]; then
        LEGACY_FOUND=1
        echo "[HIGH] SuperSU marker found: /system/etc/.installed_su_daemon"
        ls -la /system/etc/.installed_su_daemon 2>/dev/null | sed 's/^/  /'
        echo ""
    fi

    if [ -f "/system/etc/install-recovery.sh" ]; then
        echo "[MEDIUM] install-recovery.sh found (may be modified for root persistence)"
        ls -la /system/etc/install-recovery.sh 2>/dev/null | sed 's/^/  /'
        head -5 /system/etc/install-recovery.sh 2>/dev/null | sed 's/^/  /'
        echo ""
    fi

    if [ -d "/system/.supersu" ]; then
        LEGACY_FOUND=1
        echo "[HIGH] SuperSU directory found: /system/.supersu"
        ls -la /system/.supersu 2>/dev/null | sed 's/^/  /'
        echo ""
    fi

    if [ -d "/data/.supersu" ]; then
        LEGACY_FOUND=1
        echo "[HIGH] SuperSU directory found: /data/.supersu"
        ls -la /data/.supersu 2>/dev/null | sed 's/^/  /'
        echo ""
    fi

    # Check for SuperSU package
    SUPERSU_PKG=$(pm list packages 2>/dev/null | grep -i supersu | head -1)
    if [ -n "$SUPERSU_PKG" ]; then
        LEGACY_FOUND=1
        echo "[HIGH] SuperSU package installed: $SUPERSU_PKG"
        echo ""
    fi

    if [ $LEGACY_FOUND -eq 0 ]; then
        echo "[OK] No SuperSU / legacy root artifacts detected"
        echo ""
    fi

    # ─────────────────────────────────────────────────────────────────────
    # SECTION: BUSYBOX / TOOLBOX INDICATORS
    # ─────────────────────────────────────────────────────────────────────
    echo "╔═══════════════════════════════════════════════════════════════╗"
    echo "║              6. BUSYBOX / TOOLBOX INDICATORS                   ║"
    echo "╚═══════════════════════════════════════════════════════════════╝"
    echo ""

    BUSYBOX_FOUND=0

    # Check busybox in PATH
    BUSYBOX_PATH=$(which busybox 2>/dev/null)
    if [ -n "$BUSYBOX_PATH" ]; then
        echo "[INFO] Busybox found in PATH: $BUSYBOX_PATH"
        ls -la "$BUSYBOX_PATH" 2>/dev/null | sed 's/^/  /'
        busybox --version 2>/dev/null | head -2 | sed 's/^/  /'
        echo ""
    fi

    # Search for busybox in common/suspicious locations
    echo "[INFO] Searching for busybox binaries (system-wide)..."
    BUSYBOX_SEARCH=$(find /system /vendor /sbin /data/local -name "busybox" -type f 2>/dev/null | head -10)
    if [ -n "$BUSYBOX_SEARCH" ]; then
        echo "$BUSYBOX_SEARCH" | while read bb_loc; do
            # Check if location is non-standard
            case "$bb_loc" in
                /vendor/bin/busybox)
                    echo "[OK] Standard busybox location: $bb_loc"
                    ;;
                *)
                    echo "[MEDIUM] Busybox in unusual location: $bb_loc"
                    BUSYBOX_FOUND=1
                    ;;
            esac
            ls -la "$bb_loc" 2>/dev/null | sed 's/^/  /'
        done
        echo ""
    else
        echo "[OK] No busybox binaries found (or limited permission)"
        echo ""
    fi

    # ─────────────────────────────────────────────────────────────────────
    # SECTION: MODIFIED SYSTEM PROPERTIES
    # ─────────────────────────────────────────────────────────────────────
    echo "╔═══════════════════════════════════════════════════════════════╗"
    echo "║              7. MODIFIED SYSTEM PROPERTIES                     ║"
    echo "╚═══════════════════════════════════════════════════════════════╝"
    echo ""

    echo "[INFO] Critical system properties (root frameworks may modify these):"
    echo ""

    # ro.build.tags
    BUILD_TAGS=$(getprop ro.build.tags 2>/dev/null)
    if [ "$BUILD_TAGS" != "release-keys" ]; then
        echo "[MEDIUM] ro.build.tags = '$BUILD_TAGS' (expected: 'release-keys')"
    else
        echo "[OK] ro.build.tags = '$BUILD_TAGS' (production)"
    fi

    # ro.debuggable
    DEBUGGABLE=$(getprop ro.debuggable 2>/dev/null)
    if [ "$DEBUGGABLE" = "1" ]; then
        echo "[MEDIUM] ro.debuggable = 1 (debugging enabled)"
    else
        echo "[OK] ro.debuggable = '$DEBUGGABLE' (debugging disabled)"
    fi

    # ro.secure
    SECURE=$(getprop ro.secure 2>/dev/null)
    if [ "$SECURE" != "1" ]; then
        echo "[HIGH] ro.secure = '$SECURE' (expected: '1' — security compromised)"
    else
        echo "[OK] ro.secure = '1' (secure boot verified)"
    fi

    # ro.build.selinux
    SELINUX=$(getprop ro.build.selinux 2>/dev/null)
    echo "[INFO] ro.build.selinux = '$SELINUX'"

    # ro.boot.verifiedbootstate
    VERIFIED_BOOT=$(getprop ro.boot.verifiedbootstate 2>/dev/null)
    if [ "$VERIFIED_BOOT" != "green" ]; then
        echo "[MEDIUM] ro.boot.verifiedbootstate = '$VERIFIED_BOOT' (expected: 'green')"
    else
        echo "[OK] ro.boot.verifiedbootstate = 'green' (verified boot)"
    fi

    # ro.oem_unlock_supported
    OEM_UNLOCK=$(getprop ro.oem_unlock_supported 2>/dev/null)
    echo "[INFO] ro.oem_unlock_supported = '$OEM_UNLOCK'"

    echo ""

    # ─────────────────────────────────────────────────────────────────────
    # SECTION: SUSPICIOUS MOUNTS (Overlayfs/Bind)
    # ─────────────────────────────────────────────────────────────────────
    echo "╔═══════════════════════════════════════════════════════════════╗"
    echo "║              8. SUSPICIOUS MOUNTS (Overlayfs/Bind)             ║"
    echo "╚═══════════════════════════════════════════════════════════════╝"
    echo ""

    echo "[INFO] Checking /proc/mounts for suspicious overlay/bind mounts..."
    echo ""

    SUSPICIOUS_MOUNTS=0

    # Check for overlayfs on system paths
    if grep -q "overlay.*system" /proc/mounts 2>/dev/null; then
        SUSPICIOUS_MOUNTS=1
        echo "[HIGH] Overlayfs mount detected on /system (Magisk likely):"
        grep "overlay.*system" /proc/mounts 2>/dev/null | sed 's/^/  /'
        echo ""
    fi

    if grep -q "overlay.*vendor" /proc/mounts 2>/dev/null; then
        SUSPICIOUS_MOUNTS=1
        echo "[HIGH] Overlayfs mount detected on /vendor (Magisk likely):"
        grep "overlay.*vendor" /proc/mounts 2>/dev/null | sed 's/^/  /'
        echo ""
    fi

    # Check for tmpfs on critical paths
    TMPFS_CRITICAL=$(grep -E "tmpfs.*/(system|vendor|sbin|boot)" /proc/mounts 2>/dev/null | wc -l)
    if [ "$TMPFS_CRITICAL" -gt 0 ]; then
        SUSPICIOUS_MOUNTS=1
        echo "[HIGH] tmpfs mounts on critical system paths (root likely):"
        grep -E "tmpfs.*/(system|vendor|sbin|boot)" /proc/mounts 2>/dev/null | sed 's/^/  /'
        echo ""
    fi

    # List all non-standard mounts
    echo "[INFO] All mounts (filtered):"
    grep -v "^/dev/block\|^/dev/fuse\|^tmpfs\|^proc\|^sysfs\|^cgroup\|^devpts\|^debugfs\|^tracefs\|^selinuxfs\|^bpf\|^pstore\|^configfs\|adb\|mtp" /proc/mounts 2>/dev/null | head -20 | sed 's/^/  /'
    echo ""

    if [ $SUSPICIOUS_MOUNTS -eq 0 ]; then
        echo "[OK] No suspicious overlay/tmpfs mounts detected"
        echo ""
    fi

    # ─────────────────────────────────────────────────────────────────────
    # SECTION: /data/adb DIRECTORY AUDIT
    # ─────────────────────────────────────────────────────────────────────
    echo "╔═══════════════════════════════════════════════════════════════╗"
    echo "║              9. /data/adb DIRECTORY AUDIT                      ║"
    echo "╚═══════════════════════════════════════════════════════════════╝"
    echo ""

    if [ -d "/data/adb" ]; then
        echo "[HIGH] /data/adb directory exists (strong root indicator)"
        ls -la /data/adb 2>/dev/null | sed 's/^/  /'
        echo ""

        if [ -d "/data/adb/modules" ]; then
            MODULES_COUNT=$(ls -1 /data/adb/modules 2>/dev/null | wc -l)
            echo "[HIGH] Modules directory found ($MODULES_COUNT modules):"
            ls -1 /data/adb/modules 2>/dev/null | sed 's/^/  - /'
            echo ""
        fi

        if [ -d "/data/adb/service.d" ]; then
            echo "[HIGH] service.d directory found (post-boot scripts):"
            ls -1 /data/adb/service.d 2>/dev/null | sed 's/^/  - /'
            echo ""
        fi

        if [ -d "/data/adb/post-fs-data.d" ]; then
            echo "[HIGH] post-fs-data.d directory found (boot-time scripts):"
            ls -1 /data/adb/post-fs-data.d 2>/dev/null | sed 's/^/  - /'
            echo ""
        fi
    else
        echo "[OK] /data/adb directory does not exist"
        echo ""
    fi

    # ─────────────────────────────────────────────────────────────────────
    # SECTION: SELINUX STATUS vs ROOT FRAMEWORK
    # ─────────────────────────────────────────────────────────────────────
    echo "╔═══════════════════════════════════════════════════════════════╗"
    echo "║              10. SELINUX STATUS vs ROOT FRAMEWORK              ║"
    echo "╚═══════════════════════════════════════════════════════════════╝"
    echo ""

    SELINUX_STATUS=$(getenforce 2>/dev/null)
    if [ -z "$SELINUX_STATUS" ]; then
        SELINUX_STATUS=$(cat /sys/fs/selinux/enforce 2>/dev/null)
        if [ -z "$SELINUX_STATUS" ]; then
            SELINUX_STATUS="(unknown — /sys/fs/selinux not accessible)"
        fi
    fi

    case "$SELINUX_STATUS" in
        0|Permissive)
            echo "[CRITICAL] SELinux Status: PERMISSIVE"
            echo "  Root has unrestricted access — no SELinux policy enforcement"
            ;;
        1|Enforcing)
            echo "[INFO] SELinux Status: ENFORCING"
            echo "  If root is present: framework likely handles SELinux policy injection"
            ;;
        *)
            echo "[INFO] SELinux Status: $SELINUX_STATUS"
            ;;
    esac
    echo ""

    echo "[INFO] SELinux domain status (top 10):"
    cat /sys/fs/selinux/policy_capabilities 2>/dev/null | head -10 | sed 's/^/  /'
    echo ""

    # ─────────────────────────────────────────────────────────────────────
    # SECTION: SUMMARY & RISK ASSESSMENT
    # ─────────────────────────────────────────────────────────────────────
    echo "╔═══════════════════════════════════════════════════════════════╗"
    echo "║              11. ROOT FRAMEWORK ASSESSMENT SUMMARY             ║"
    echo "╚═══════════════════════════════════════════════════════════════╝"
    echo ""

    # Count what was found
    TOTAL_INDICATORS=$((SU_FOUND + MAGISK_FOUND + KSU_FOUND + APATCH_FOUND + LEGACY_FOUND + SUSPICIOUS_MOUNTS))

    echo "[*] Indicator Summary:"
    echo "  SU binary:              $([ $SU_FOUND -eq 1 ] && echo 'YES' || echo 'NO')"
    echo "  Magisk framework:       $([ $MAGISK_FOUND -eq 1 ] && echo 'YES' || echo 'NO')"
    echo "  KernelSU framework:     $([ $KSU_FOUND -eq 1 ] && echo 'YES' || echo 'NO')"
    echo "  APatch framework:       $([ $APATCH_FOUND -eq 1 ] && echo 'YES' || echo 'NO')"
    echo "  SuperSU / Legacy:       $([ $LEGACY_FOUND -eq 1 ] && echo 'YES' || echo 'NO')"
    echo "  Suspicious mounts:      $([ $SUSPICIOUS_MOUNTS -eq 1 ] && echo 'YES' || echo 'NO')"
    echo ""

    if [ $TOTAL_INDICATORS -gt 2 ]; then
        echo "[CRITICAL] ROOT FRAMEWORK DETECTED - Device is rooted"
        if [ $MAGISK_FOUND -eq 1 ]; then
            echo "  Primary Framework: Magisk"
        elif [ $KSU_FOUND -eq 1 ]; then
            echo "  Primary Framework: KernelSU"
        elif [ $APATCH_FOUND -eq 1 ]; then
            echo "  Primary Framework: APatch"
        elif [ $LEGACY_FOUND -eq 1 ]; then
            echo "  Primary Framework: SuperSU / Legacy"
        fi
        echo "  Risk Level: CRITICAL — Device has elevated privileges"
    elif [ $TOTAL_INDICATORS -eq 1 ] || [ $TOTAL_INDICATORS -eq 2 ]; then
        echo "[HIGH] LIKELY ROOTED - 2+ root indicators found"
        echo "  Risk Level: HIGH — Device probably has root access"
    elif [ $TOTAL_INDICATORS -eq 0 ]; then
        echo "[OK] NO ROOT INDICATORS - Device appears unrooted"
        echo "  Risk Level: LOW (standard security posture)"
    fi

    echo ""
    echo "═════════════════════════════════════════════════════════════════"
    echo "Scan completed: $(date '+%Y-%m-%d %H:%M:%S')"
    echo "═════════════════════════════════════════════════════════════════"

} > "${OUTPUT_FILE}" 2>&1

echo "[+] Root indicator scan saved to: ${OUTPUT_FILE}"
