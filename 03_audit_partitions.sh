#!/system/bin/sh
# DROID FORENSIC - Partition & Bootloader Audit
# Enumerates partition layout, A/B slots, dm-verity, AVB, bootloader state
# Usage: sh 03_audit_partitions.sh [output_directory]

OUTPUT_DIR="${1:-.}"
OUTPUT_FILE="${OUTPUT_DIR}/audit_partitions.txt"

echo "[*] Auditing partitions and bootloader configuration..."

{
    echo "═══════════════════════════════════════════════════════════════"
    echo "  PARTITION & BOOTLOADER AUDIT"
    echo "  Timestamp: $(date)"
    echo "═══════════════════════════════════════════════════════════════"
    echo ""
    echo "Partition layout and bootloader state are critical for device"
    echo "integrity assessment and forensic analysis."
    echo ""

    # =========================================================================
    # SECTION 1: Bootloader Status
    # =========================================================================
    
    echo "┌─────────────────────────────────────────────────────────────┐"
    echo "│ BOOTLOADER STATUS                                          │"
    echo "└─────────────────────────────────────────────────────────────┘"
    echo ""

    echo "=== Bootloader Lock State ==="
    
    # Various properties indicating bootloader state
    FLASH_LOCKED=$(getprop ro.boot.flash.locked 2>/dev/null)
    VERIFIED_STATE=$(getprop ro.boot.verifiedbootstate 2>/dev/null)
    VBMETA_STATE=$(getprop ro.boot.vbmeta.device_state 2>/dev/null)
    SECURE_BOOT=$(getprop ro.boot.secureboot 2>/dev/null)
    WARRANTY=$(getprop ro.boot.warranty_bit 2>/dev/null)
    OEM_UNLOCK=$(getprop ro.oem_unlock_supported 2>/dev/null)
    FRP_STATE=$(getprop ro.frp.pst 2>/dev/null)

    echo "ro.boot.flash.locked:        ${FLASH_LOCKED:-not set}"
    echo "ro.boot.verifiedbootstate:   ${VERIFIED_STATE:-not set}"
    echo "ro.boot.vbmeta.device_state: ${VBMETA_STATE:-not set}"
    echo "ro.boot.secureboot:          ${SECURE_BOOT:-not set}"
    echo "ro.boot.warranty_bit:        ${WARRANTY:-not set}"
    echo "ro.oem_unlock_supported:     ${OEM_UNLOCK:-not set}"
    echo "ro.frp.pst:                  ${FRP_STATE:-not set}"
    echo ""

    # Interpret bootloader state
    echo "=== Bootloader State Analysis ==="
    
    BOOTLOADER_SECURE=1
    
    if [ "$FLASH_LOCKED" = "0" ]; then
        echo "██ [CRITICAL] Bootloader is UNLOCKED (flash.locked=0)"
        BOOTLOADER_SECURE=0
    elif [ "$FLASH_LOCKED" = "1" ]; then
        echo "[OK] Bootloader is LOCKED (flash.locked=1)"
    fi

    case "$VERIFIED_STATE" in
        green)
            echo "[OK] Verified boot state: GREEN (fully verified)"
            ;;
        yellow)
            echo "[WARNING] Verified boot state: YELLOW (custom root of trust)"
            ;;
        orange)
            echo "██ [CRITICAL] Verified boot state: ORANGE (unlocked)"
            BOOTLOADER_SECURE=0
            ;;
        red)
            echo "██ [CRITICAL] Verified boot state: RED (verification failed)"
            BOOTLOADER_SECURE=0
            ;;
        *)
            echo "[INFO] Verified boot state: ${VERIFIED_STATE:-unknown}"
            ;;
    esac

    if [ "$VBMETA_STATE" = "unlocked" ]; then
        echo "██ [CRITICAL] vbmeta device state: UNLOCKED"
        BOOTLOADER_SECURE=0
    elif [ "$VBMETA_STATE" = "locked" ]; then
        echo "[OK] vbmeta device state: LOCKED"
    fi
    echo ""

    # =========================================================================
    # SECTION 2: A/B Partition Scheme
    # =========================================================================
    
    echo "┌─────────────────────────────────────────────────────────────┐"
    echo "│ A/B PARTITION SCHEME                                       │"
    echo "└─────────────────────────────────────────────────────────────┘"
    echo ""

    # Check for A/B support
    AB_UPDATE=$(getprop ro.build.ab_update 2>/dev/null)
    SLOT_SUFFIX=$(getprop ro.boot.slot_suffix 2>/dev/null)
    CURRENT_SLOT=$(getprop ro.boot.slot 2>/dev/null)

    echo "A/B Update Support: ${AB_UPDATE:-not set}"
    echo "Current Slot Suffix: ${SLOT_SUFFIX:-not set}"
    echo "Current Slot: ${CURRENT_SLOT:-not set}"
    echo ""

    if [ "$AB_UPDATE" = "true" ] || [ -n "$SLOT_SUFFIX" ]; then
        echo "[INFO] Device uses A/B (seamless) update scheme"
        echo ""
        
        # Get slot info from bootctl if available
        if command -v bootctl >/dev/null 2>&1; then
            echo "=== Slot Information (bootctl) ==="
            bootctl get-current-slot 2>/dev/null
            bootctl get-suffix 0 2>/dev/null
            bootctl get-suffix 1 2>/dev/null
            echo ""
        fi
        
        # Check slot properties
        echo "=== Slot Properties ==="
        getprop 2>/dev/null | grep -iE "slot|suffix" | sort
        echo ""
    else
        echo "[INFO] Device uses traditional (non-A/B) partition scheme"
    fi
    echo ""

    # =========================================================================
    # SECTION 3: Partition Layout
    # =========================================================================
    
    echo "┌─────────────────────────────────────────────────────────────┐"
    echo "│ PARTITION LAYOUT                                           │"
    echo "└─────────────────────────────────────────────────────────────┘"
    echo ""

    echo "=== Block Devices by Name ==="
    if [ -d /dev/block/by-name ]; then
        ls -la /dev/block/by-name/ 2>/dev/null | sort -k9
    else
        echo "by-name symlinks not available, trying alternatives..."
        ls -la /dev/block/platform/*/by-name/ 2>/dev/null | head -50
        ls -la /dev/block/bootdevice/by-name/ 2>/dev/null | head -50
    fi
    echo ""

    echo "=== Partition Table (if available) ==="
    # Try various partition list methods
    if [ -f /proc/partitions ]; then
        echo "--- /proc/partitions ---"
        cat /proc/partitions 2>/dev/null
        echo ""
    fi

    # GPT partition info
    echo "=== GPT Partition Info ==="
    for disk in /dev/block/mmcblk0 /dev/block/sda; do
        if [ -e "$disk" ]; then
            echo "Disk: $disk"
            # Try sgdisk if available
            sgdisk -p "$disk" 2>/dev/null || fdisk -l "$disk" 2>/dev/null | head -30
            echo ""
        fi
    done

    # =========================================================================
    # SECTION 4: Critical Partition Analysis
    # =========================================================================
    
    echo "┌─────────────────────────────────────────────────────────────┐"
    echo "│ CRITICAL PARTITION ANALYSIS                                │"
    echo "└─────────────────────────────────────────────────────────────┘"
    echo ""

    CRITICAL_PARTITIONS="boot recovery system vendor vbmeta dtbo super product odm"

    for part in $CRITICAL_PARTITIONS; do
        # Find partition path
        PART_PATH=""
        for prefix in /dev/block/by-name /dev/block/bootdevice/by-name /dev/block/platform/*/by-name; do
            if [ -e "${prefix}/${part}" ]; then
                PART_PATH="${prefix}/${part}"
                break
            elif [ -e "${prefix}/${part}${SLOT_SUFFIX}" ]; then
                PART_PATH="${prefix}/${part}${SLOT_SUFFIX}"
                break
            fi
        done

        if [ -n "$PART_PATH" ] && [ -e "$PART_PATH" ]; then
            REAL_PATH=$(readlink -f "$PART_PATH" 2>/dev/null)
            SIZE=$(blockdev --getsize64 "$REAL_PATH" 2>/dev/null || echo "unknown")
            
            echo "Partition: $part"
            echo "  Path: $PART_PATH"
            echo "  Device: $REAL_PATH"
            echo "  Size: $SIZE bytes"
            
            # Check if mounted
            MOUNT_INFO=$(mount 2>/dev/null | grep "$REAL_PATH\|/$part ")
            if [ -n "$MOUNT_INFO" ]; then
                echo "  Mount: $MOUNT_INFO"
            fi
            echo ""
        fi
    done

    # =========================================================================
    # SECTION 5: dm-verity Status
    # =========================================================================
    
    echo "┌─────────────────────────────────────────────────────────────┐"
    echo "│ DM-VERITY STATUS                                           │"
    echo "└─────────────────────────────────────────────────────────────┘"
    echo ""

    echo "=== dm-verity Properties ==="
    getprop 2>/dev/null | grep -iE "verity|avb|verify" | sort
    echo ""

    echo "=== Verity Block Devices ==="
    ls -la /dev/block/dm-* 2>/dev/null
    echo ""

    echo "=== Device Mapper Status ==="
    if [ -f /sys/block/dm-0/dm/name ]; then
        for dm in /sys/block/dm-*/; do
            if [ -d "$dm" ]; then
                DM_NAME=$(basename "$dm")
                DM_TARGET=$(cat "${dm}dm/name" 2>/dev/null)
                echo "$DM_NAME: $DM_TARGET"
            fi
        done
    fi
    echo ""

    echo "=== dmsetup Info ==="
    dmsetup ls 2>/dev/null
    dmsetup status 2>/dev/null | head -20
    echo ""

    # Check verity state in dmesg
    echo "=== dm-verity Messages (dmesg) ==="
    dmesg 2>/dev/null | grep -iE "verity|dm-[0-9]" | tail -20
    echo ""

    # =========================================================================
    # SECTION 6: Android Verified Boot (AVB)
    # =========================================================================
    
    echo "┌─────────────────────────────────────────────────────────────┐"
    echo "│ ANDROID VERIFIED BOOT (AVB) STATUS                         │"
    echo "└─────────────────────────────────────────────────────────────┘"
    echo ""

    echo "=== AVB Properties ==="
    getprop 2>/dev/null | grep -iE "^ro\.boot\.avb\|^ro\.boot\.vbmeta" | sort
    echo ""

    # AVB version
    AVB_VERSION=$(getprop ro.boot.avb_version 2>/dev/null)
    echo "AVB Version: ${AVB_VERSION:-not set}"
    echo ""

    # vbmeta digest
    VBMETA_DIGEST=$(getprop ro.boot.vbmeta.digest 2>/dev/null)
    echo "vbmeta Digest: ${VBMETA_DIGEST:-not set}"
    echo ""

    # vbmeta hash algorithm
    VBMETA_HASH=$(getprop ro.boot.vbmeta.hash_alg 2>/dev/null)
    echo "vbmeta Hash Algorithm: ${VBMETA_HASH:-not set}"
    echo ""

    # =========================================================================
    # SECTION 7: Mount Points and Filesystem Status
    # =========================================================================
    
    echo "┌─────────────────────────────────────────────────────────────┐"
    echo "│ MOUNT POINTS & FILESYSTEM STATUS                           │"
    echo "└─────────────────────────────────────────────────────────────┘"
    echo ""

    echo "=== Current Mounts ==="
    mount 2>/dev/null | grep -E "^/dev/block|^/dev/dm" | sort
    echo ""

    echo "=== Read-Only vs Read-Write Analysis ==="
    echo ""
    echo "System Partitions (should be RO):"
    mount 2>/dev/null | grep -E "/system|/vendor|/product|/odm" | while read line; do
        if echo "$line" | grep -q " ro,\| ro "; then
            echo "  [OK] (RO) $line"
        else
            echo "  ██ [WARNING] (RW) $line"
        fi
    done
    echo ""

    echo "Data Partitions (typically RW):"
    mount 2>/dev/null | grep -E "/data|/cache|/sdcard|/storage" | head -10
    echo ""

    # =========================================================================
    # SECTION 8: fstab Analysis
    # =========================================================================
    
    echo "┌─────────────────────────────────────────────────────────────┐"
    echo "│ FSTAB CONFIGURATION                                        │"
    echo "└─────────────────────────────────────────────────────────────┘"
    echo ""

    # Find fstab files
    FSTAB_LOCATIONS="/vendor/etc/fstab.* /fstab.* /system/etc/fstab.* /odm/etc/fstab.*"
    
    for fstab in $FSTAB_LOCATIONS; do
        for f in $fstab; do
            if [ -f "$f" ]; then
                echo "=== $f ==="
                cat "$f" 2>/dev/null
                echo ""
            fi
        done
    done

    # =========================================================================
    # SECTION 9: Boot Image Analysis
    # =========================================================================
    
    echo "┌─────────────────────────────────────────────────────────────┐"
    echo "│ BOOT IMAGE INFORMATION                                     │"
    echo "└─────────────────────────────────────────────────────────────┘"
    echo ""

    echo "=== Boot Properties ==="
    getprop 2>/dev/null | grep "^ro\.boot\." | sort | head -40
    echo ""

    echo "=== Kernel Command Line ==="
    cat /proc/cmdline 2>/dev/null
    echo ""
    echo ""

    echo "=== Boot Reason ==="
    BOOT_REASON=$(getprop ro.boot.bootreason 2>/dev/null)
    echo "Boot Reason: ${BOOT_REASON:-not set}"
    echo ""

    # =========================================================================
    # SECTION 10: Factory Reset Protection (FRP)
    # =========================================================================
    
    echo "┌─────────────────────────────────────────────────────────────┐"
    echo "│ FACTORY RESET PROTECTION (FRP)                             │"
    echo "└─────────────────────────────────────────────────────────────┘"
    echo ""

    echo "=== FRP Partition ==="
    # Look for FRP/PDB partition
    for prefix in /dev/block/by-name /dev/block/bootdevice/by-name; do
        for frp_name in frp persistent pdb config; do
            if [ -e "${prefix}/${frp_name}" ]; then
                echo "FRP Partition: ${prefix}/${frp_name}"
                ls -la "${prefix}/${frp_name}" 2>/dev/null
            fi
        done
    done
    echo ""

    echo "=== FRP Properties ==="
    getprop 2>/dev/null | grep -iE "frp|persistent|pdb" | sort
    echo ""

    # =========================================================================
    # SECTION 11: Partition Hashes (Integrity)
    # =========================================================================
    
    echo "┌─────────────────────────────────────────────────────────────┐"
    echo "│ PARTITION INTEGRITY (Sample Hashes)                        │"
    echo "└─────────────────────────────────────────────────────────────┘"
    echo ""
    echo "Hashing first 1MB of critical partitions for baseline..."
    echo "(Full partition hashes require more time/permissions)"
    echo ""

    for part in boot vbmeta; do
        PART_PATH=""
        for prefix in /dev/block/by-name /dev/block/bootdevice/by-name; do
            if [ -e "${prefix}/${part}${SLOT_SUFFIX}" ]; then
                PART_PATH="${prefix}/${part}${SLOT_SUFFIX}"
                break
            elif [ -e "${prefix}/${part}" ]; then
                PART_PATH="${prefix}/${part}"
                break
            fi
        done

        if [ -n "$PART_PATH" ] && [ -e "$PART_PATH" ]; then
            HASH=$(dd if="$PART_PATH" bs=1M count=1 2>/dev/null | sha256sum 2>/dev/null | awk '{print $1}')
            echo "$part: $HASH (first 1MB)"
        fi
    done
    echo ""

    # =========================================================================
    # SECTION 12: Summary
    # =========================================================================
    
    echo "┌─────────────────────────────────────────────────────────────┐"
    echo "│ PARTITION & BOOTLOADER SUMMARY                             │"
    echo "└─────────────────────────────────────────────────────────────┘"
    echo ""

    # Count partitions
    PART_COUNT=$(ls /dev/block/by-name/ 2>/dev/null | wc -l || echo "N/A")
    
    echo "Partition Statistics:"
    echo "  Total Partitions: $PART_COUNT"
    echo "  Update Scheme:    $([ "$AB_UPDATE" = "true" ] && echo "A/B (Seamless)" || echo "Traditional")"
    echo "  Current Slot:     ${SLOT_SUFFIX:-N/A}"
    echo ""

    echo "Security Status:"
    if [ "$BOOTLOADER_SECURE" = "1" ]; then
        echo "  [OK] Bootloader appears to be LOCKED"
    else
        echo "  ██ [CRITICAL] Bootloader is UNLOCKED or verification failed"
    fi

    # dm-verity check
    if mount 2>/dev/null | grep -q "dm-"; then
        echo "  [OK] dm-verity appears to be active"
    else
        echo "  [WARNING] dm-verity status unclear"
    fi

    # System partition RO check
    if mount 2>/dev/null | grep "/system" | grep -q " ro,\| ro "; then
        echo "  [OK] System partition is read-only"
    else
        echo "  ██ [WARNING] System partition may be read-write"
    fi
    echo ""

    echo "Forensic Notes:"
    echo "  - Unlocked bootloader invalidates verified boot chain"
    echo "  - A/B devices maintain two copies of boot-critical partitions"
    echo "  - dm-verity protects system integrity at runtime"
    echo "  - FRP partition contains factory reset protection data"
    echo ""

} > "${OUTPUT_FILE}" 2>&1

echo "[+] Partition and bootloader audit saved to: ${OUTPUT_FILE}"
