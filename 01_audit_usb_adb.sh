#!/system/bin/sh
# DROID FORENSIC - USB/ADB Security Audit
# Enumerates USB configuration, ADB authorization, debug settings, OEM unlock status
# Usage: sh 01_audit_usb_adb.sh [output_directory]

OUTPUT_DIR="${1:-.}"
OUTPUT_FILE="${OUTPUT_DIR}/audit_usb_adb.txt"

echo "[*] Auditing USB and ADB security configuration..."

{
    echo "═══════════════════════════════════════════════════════════════"
    echo "  USB & ADB SECURITY AUDIT"
    echo "  Timestamp: $(date)"
    echo "═══════════════════════════════════════════════════════════════"
    echo ""
    echo "USB debugging and ADB access are primary vectors for physical attacks."
    echo "Misconfigured USB settings can expose the device to unauthorized access."
    echo ""

    # =========================================================================
    # SECTION 1: ADB Status and Configuration
    # =========================================================================
    
    echo "┌─────────────────────────────────────────────────────────────┐"
    echo "│ ADB DEBUGGING STATUS                                       │"
    echo "└─────────────────────────────────────────────────────────────┘"
    echo ""

    # Check if ADB is enabled
    ADB_ENABLED=$(settings get global adb_enabled 2>/dev/null)
    echo "ADB Enabled (settings): $ADB_ENABLED"
    
    if [ "$ADB_ENABLED" = "1" ]; then
        echo "  ██ [WARNING] USB Debugging is ENABLED"
    else
        echo "  [OK] USB Debugging is disabled"
    fi
    echo ""

    # ADB over network
    ADB_WIFI_ENABLED=$(settings get global adb_wifi_enabled 2>/dev/null)
    echo "ADB over WiFi Enabled: $ADB_WIFI_ENABLED"
    
    if [ "$ADB_WIFI_ENABLED" = "1" ]; then
        echo "  ██ [CRITICAL] Wireless ADB is ENABLED - network attack vector!"
    fi
    echo ""

    # ADB port
    SERVICE_ADB_TCP_PORT=$(getprop service.adb.tcp.port 2>/dev/null)
    echo "ADB TCP Port: ${SERVICE_ADB_TCP_PORT:-not set}"
    
    if [ -n "$SERVICE_ADB_TCP_PORT" ] && [ "$SERVICE_ADB_TCP_PORT" != "-1" ]; then
        echo "  ██ [CRITICAL] ADB listening on TCP port $SERVICE_ADB_TCP_PORT"
    fi
    echo ""

    # =========================================================================
    # SECTION 2: ADB Authorization
    # =========================================================================
    
    echo "┌─────────────────────────────────────────────────────────────┐"
    echo "│ ADB AUTHORIZATION KEYS                                     │"
    echo "└─────────────────────────────────────────────────────────────┘"
    echo ""

    # ADB authorized keys location
    ADB_KEYS_PATHS="/data/misc/adb/adb_keys /data/adb/adb_keys /adb_keys"
    
    for keys_path in $ADB_KEYS_PATHS; do
        if [ -f "$keys_path" ]; then
            echo "Authorized ADB Keys: $keys_path"
            ls -la "$keys_path" 2>/dev/null | sed 's/^/  /'
            echo ""
            echo "  Key count: $(wc -l < "$keys_path" 2>/dev/null || echo 0)"
            echo ""
            echo "  Authorized public keys:"
            cat "$keys_path" 2>/dev/null | while read key; do
                # Extract key fingerprint (last part after space is usually identifier)
                KEY_ID=$(echo "$key" | awk '{print $NF}')
                KEY_TYPE=$(echo "$key" | awk '{print $1}')
                echo "    Type: $KEY_TYPE"
                echo "    ID: $KEY_ID"
                echo ""
            done
        fi
    done
    
    # Check if any keys are authorized
    TOTAL_KEYS=0
    for keys_path in $ADB_KEYS_PATHS; do
        if [ -f "$keys_path" ]; then
            COUNT=$(wc -l < "$keys_path" 2>/dev/null || echo 0)
            TOTAL_KEYS=$((TOTAL_KEYS + COUNT))
        fi
    done
    
    if [ "$TOTAL_KEYS" -gt 0 ]; then
        echo "  ██ [INFO] $TOTAL_KEYS ADB key(s) authorized on this device"
    else
        echo "  [OK] No ADB keys authorized"
    fi
    echo ""

    # ADB secure setting
    ADB_SECURE=$(getprop ro.adb.secure 2>/dev/null)
    echo "ro.adb.secure: ${ADB_SECURE:-not set}"
    if [ "$ADB_SECURE" = "0" ]; then
        echo "  ██ [CRITICAL] ADB runs as root without authorization!"
    elif [ "$ADB_SECURE" = "1" ]; then
        echo "  [OK] ADB requires authorization"
    fi
    echo ""

    # =========================================================================
    # SECTION 3: USB Configuration
    # =========================================================================
    
    echo "┌─────────────────────────────────────────────────────────────┐"
    echo "│ USB CONFIGURATION                                          │"
    echo "└─────────────────────────────────────────────────────────────┘"
    echo ""

    echo "=== Current USB Configuration ==="
    
    # USB config properties
    USB_CONFIG=$(getprop sys.usb.config 2>/dev/null)
    USB_STATE=$(getprop sys.usb.state 2>/dev/null)
    USB_CONFIGFS=$(getprop sys.usb.configfs 2>/dev/null)
    USB_CONTROLLER=$(getprop sys.usb.controller 2>/dev/null)
    PERSIST_USB_CONFIG=$(getprop persist.sys.usb.config 2>/dev/null)
    
    echo "sys.usb.config:         ${USB_CONFIG:-not set}"
    echo "sys.usb.state:          ${USB_STATE:-not set}"
    echo "persist.sys.usb.config: ${PERSIST_USB_CONFIG:-not set}"
    echo "sys.usb.configfs:       ${USB_CONFIGFS:-not set}"
    echo "sys.usb.controller:     ${USB_CONTROLLER:-not set}"
    echo ""

    # Analyze USB functions
    echo "=== USB Functions Analysis ==="
    for config in $USB_CONFIG $USB_STATE $PERSIST_USB_CONFIG; do
        if [ -n "$config" ]; then
            echo "Config: $config"
            
            # Check for specific functions
            if echo "$config" | grep -q "mtp"; then
                echo "  [MTP] Media Transfer Protocol - file access enabled"
            fi
            if echo "$config" | grep -q "ptp"; then
                echo "  [PTP] Picture Transfer Protocol - image access enabled"
            fi
            if echo "$config" | grep -q "adb"; then
                echo "  ██ [ADB] Android Debug Bridge - debug access enabled"
            fi
            if echo "$config" | grep -q "mass_storage"; then
                echo "  ██ [MASS STORAGE] Direct storage access enabled"
            fi
            if echo "$config" | grep -q "rndis"; then
                echo "  ██ [RNDIS] USB Ethernet - network interface exposed"
            fi
            if echo "$config" | grep -q "ncm"; then
                echo "  ██ [NCM] USB Network - network interface exposed"
            fi
            if echo "$config" | grep -q "accessory"; then
                echo "  [ACCESSORY] Android Open Accessory mode"
            fi
            if echo "$config" | grep -q "audio"; then
                echo "  [AUDIO] USB Audio device mode"
            fi
            if echo "$config" | grep -q "midi"; then
                echo "  [MIDI] USB MIDI device mode"
            fi
            if echo "$config" | grep -q "diag"; then
                echo "  ██ [CRITICAL] DIAG mode - Qualcomm diagnostics exposed!"
            fi
            echo ""
        fi
    done

    # =========================================================================
    # SECTION 4: Developer Options
    # =========================================================================
    
    echo "┌─────────────────────────────────────────────────────────────┐"
    echo "│ DEVELOPER OPTIONS STATUS                                   │"
    echo "└─────────────────────────────────────────────────────────────┘"
    echo ""

    # Developer options enabled
    DEV_OPTIONS=$(settings get global development_settings_enabled 2>/dev/null)
    echo "Developer Options Enabled: ${DEV_OPTIONS:-unknown}"
    
    if [ "$DEV_OPTIONS" = "1" ]; then
        echo "  ██ [WARNING] Developer Options are ENABLED"
    fi
    echo ""

    # Stay awake while charging
    STAY_AWAKE=$(settings get global stay_on_while_plugged_in 2>/dev/null)
    echo "Stay Awake (USB): ${STAY_AWAKE:-0}"
    echo ""

    # OEM Unlocking
    OEM_UNLOCK_ENABLED=$(settings get global oem_unlock_enabled 2>/dev/null)
    echo "OEM Unlock Enabled (settings): ${OEM_UNLOCK_ENABLED:-unknown}"
    
    if [ "$OEM_UNLOCK_ENABLED" = "1" ]; then
        echo "  ██ [CRITICAL] OEM Unlocking is ENABLED - bootloader can be unlocked!"
    fi
    echo ""

    # Verify apps over USB
    VERIFY_APPS_USB=$(settings get global verifier_verify_adb_installs 2>/dev/null)
    echo "Verify Apps over USB: ${VERIFY_APPS_USB:-unknown}"
    echo ""

    # =========================================================================
    # SECTION 5: Bootloader Status
    # =========================================================================
    
    echo "┌─────────────────────────────────────────────────────────────┐"
    echo "│ BOOTLOADER STATUS                                          │"
    echo "└─────────────────────────────────────────────────────────────┘"
    echo ""

    # Bootloader unlock status from properties
    UNLOCKED=$(getprop ro.boot.flash.locked 2>/dev/null)
    echo "ro.boot.flash.locked:     ${UNLOCKED:-not set}"
    
    UNLOCK_STATUS=$(getprop ro.boot.verifiedbootstate 2>/dev/null)
    echo "ro.boot.verifiedbootstate: ${UNLOCK_STATUS:-not set}"
    
    SECURE_BOOT=$(getprop ro.boot.secureboot 2>/dev/null)
    echo "ro.boot.secureboot:       ${SECURE_BOOT:-not set}"
    
    WARRANTY=$(getprop ro.boot.warranty_bit 2>/dev/null)
    echo "ro.boot.warranty_bit:     ${WARRANTY:-not set}"
    
    VBMETA_STATE=$(getprop ro.boot.vbmeta.device_state 2>/dev/null)
    echo "ro.boot.vbmeta.device_state: ${VBMETA_STATE:-not set}"
    echo ""

    # Interpret bootloader state
    if [ "$UNLOCKED" = "0" ] || [ "$VBMETA_STATE" = "unlocked" ]; then
        echo "  ██ [CRITICAL] BOOTLOADER IS UNLOCKED"
        echo "  Device integrity cannot be guaranteed!"
    elif [ "$UNLOCK_STATUS" = "orange" ]; then
        echo "  ██ [CRITICAL] Boot state is ORANGE - bootloader unlocked"
    elif [ "$UNLOCK_STATUS" = "green" ]; then
        echo "  [OK] Boot state is GREEN - verified boot"
    fi
    echo ""

    # =========================================================================
    # SECTION 6: USB Debugging Security Properties
    # =========================================================================
    
    echo "┌─────────────────────────────────────────────────────────────┐"
    echo "│ USB/DEBUG SECURITY PROPERTIES                              │"
    echo "└─────────────────────────────────────────────────────────────┘"
    echo ""

    echo "=== Debug-Related Properties ==="
    getprop 2>/dev/null | grep -iE "debug|adb|usb|unlock|secure" | sort | while read prop; do
        echo "  $prop"
    done
    echo ""

    # Specific security properties
    echo "=== Security-Critical Properties ==="
    
    RO_DEBUGGABLE=$(getprop ro.debuggable 2>/dev/null)
    echo "ro.debuggable:            ${RO_DEBUGGABLE:-not set}"
    if [ "$RO_DEBUGGABLE" = "1" ]; then
        echo "  ██ [CRITICAL] Device is debuggable - engineering/userdebug build!"
    fi
    
    RO_SECURE=$(getprop ro.secure 2>/dev/null)
    echo "ro.secure:                ${RO_SECURE:-not set}"
    if [ "$RO_SECURE" = "0" ]; then
        echo "  ██ [CRITICAL] ro.secure=0 - ADB runs as root!"
    fi
    
    ALLOW_MOCK=$(getprop ro.allow.mock.location 2>/dev/null)
    echo "ro.allow.mock.location:   ${ALLOW_MOCK:-not set}"
    
    PERSIST_ADB_NOTIFY=$(getprop persist.adb.notify 2>/dev/null)
    echo "persist.adb.notify:       ${PERSIST_ADB_NOTIFY:-not set}"
    echo ""

    # =========================================================================
    # SECTION 7: USB Device Nodes
    # =========================================================================
    
    echo "┌─────────────────────────────────────────────────────────────┐"
    echo "│ USB DEVICE NODES                                           │"
    echo "└─────────────────────────────────────────────────────────────┘"
    echo ""

    echo "=== USB Gadget Configuration ==="
    if [ -d /config/usb_gadget ]; then
        echo "USB Gadget ConfigFS:"
        find /config/usb_gadget -type f 2>/dev/null | while read f; do
            echo "  $f: $(cat "$f" 2>/dev/null | tr '\n' ' ')"
        done
    else
        echo "ConfigFS USB gadget not available"
    fi
    echo ""

    echo "=== USB Device Nodes ==="
    ls -la /dev/usb* /dev/bus/usb/* 2>/dev/null | head -30
    echo ""

    echo "=== Android USB Device ==="
    ls -la /dev/android_adb /dev/usb_accessory /dev/mtp_usb 2>/dev/null
    echo ""

    # =========================================================================
    # SECTION 8: ADB Shell Capabilities
    # =========================================================================
    
    echo "┌─────────────────────────────────────────────────────────────┐"
    echo "│ ADB SHELL CAPABILITIES                                     │"
    echo "└─────────────────────────────────────────────────────────────┘"
    echo ""

    echo "Current shell identity:"
    id 2>/dev/null
    echo ""

    echo "Shell SELinux context:"
    cat /proc/self/attr/current 2>/dev/null
    echo ""

    # Check if we can run as root
    echo "Root access test:"
    if su -c "id" 2>/dev/null | grep -q "uid=0"; then
        echo "  ██ [CRITICAL] Root access available via su!"
    else
        echo "  [OK] No root access via su"
    fi
    echo ""

    # Check run-as capability
    echo "run-as capability:"
    if command -v run-as >/dev/null 2>&1; then
        echo "  run-as command available"
    else
        echo "  run-as not available"
    fi
    echo ""

    # =========================================================================
    # SECTION 9: USB Accessory Mode
    # =========================================================================
    
    echo "┌─────────────────────────────────────────────────────────────┐"
    echo "│ USB ACCESSORY MODE                                         │"
    echo "└─────────────────────────────────────────────────────────────┘"
    echo ""

    echo "=== Android Open Accessory (AOA) ==="
    
    # Check for accessory mode support
    if [ -e /dev/usb_accessory ]; then
        echo "USB Accessory device: /dev/usb_accessory"
        ls -la /dev/usb_accessory 2>/dev/null | sed 's/^/  /'
    else
        echo "USB Accessory device not present"
    fi
    echo ""

    # USB host mode
    echo "=== USB Host Mode ==="
    if [ -d /sys/bus/usb/devices ]; then
        echo "Connected USB devices:"
        ls /sys/bus/usb/devices/ 2>/dev/null | while read dev; do
            if [ -f "/sys/bus/usb/devices/$dev/product" ]; then
                PRODUCT=$(cat "/sys/bus/usb/devices/$dev/product" 2>/dev/null)
                VENDOR=$(cat "/sys/bus/usb/devices/$dev/manufacturer" 2>/dev/null)
                echo "  $dev: $VENDOR $PRODUCT"
            fi
        done
    fi
    echo ""

    # =========================================================================
    # SECTION 10: Charging/USB Port Status
    # =========================================================================
    
    echo "┌─────────────────────────────────────────────────────────────┐"
    echo "│ USB PORT STATUS                                            │"
    echo "└─────────────────────────────────────────────────────────────┘"
    echo ""

    # Power supply info
    if [ -d /sys/class/power_supply ]; then
        for supply in /sys/class/power_supply/*; do
            if [ -d "$supply" ]; then
                TYPE=$(cat "$supply/type" 2>/dev/null)
                if echo "$TYPE" | grep -qiE "usb|mains"; then
                    echo "Power Supply: $(basename "$supply")"
                    echo "  Type: $TYPE"
                    cat "$supply/online" 2>/dev/null | sed 's/^/  Online: /'
                    cat "$supply/status" 2>/dev/null | sed 's/^/  Status: /'
                    echo ""
                fi
            fi
        done
    fi

    # USB Type-C status
    echo "=== USB Type-C Status ==="
    find /sys -name "*typec*" -o -name "*tcpc*" 2>/dev/null | head -10 | while read f; do
        if [ -f "$f" ]; then
            echo "  $f: $(cat "$f" 2>/dev/null)"
        fi
    done
    echo ""

    # =========================================================================
    # SECTION 11: Summary
    # =========================================================================
    
    echo "┌─────────────────────────────────────────────────────────────┐"
    echo "│ USB/ADB SECURITY SUMMARY                                   │"
    echo "└─────────────────────────────────────────────────────────────┘"
    echo ""

    CRITICAL_COUNT=0
    WARNING_COUNT=0

    # Tally findings
    [ "$ADB_ENABLED" = "1" ] && WARNING_COUNT=$((WARNING_COUNT + 1))
    [ "$ADB_WIFI_ENABLED" = "1" ] && CRITICAL_COUNT=$((CRITICAL_COUNT + 1))
    [ "$ADB_SECURE" = "0" ] && CRITICAL_COUNT=$((CRITICAL_COUNT + 1))
    [ "$RO_DEBUGGABLE" = "1" ] && CRITICAL_COUNT=$((CRITICAL_COUNT + 1))
    [ "$RO_SECURE" = "0" ] && CRITICAL_COUNT=$((CRITICAL_COUNT + 1))
    [ "$OEM_UNLOCK_ENABLED" = "1" ] && CRITICAL_COUNT=$((CRITICAL_COUNT + 1))
    [ "$UNLOCKED" = "0" ] && CRITICAL_COUNT=$((CRITICAL_COUNT + 1))
    [ "$DEV_OPTIONS" = "1" ] && WARNING_COUNT=$((WARNING_COUNT + 1))
    echo "$USB_CONFIG" | grep -q "diag" && CRITICAL_COUNT=$((CRITICAL_COUNT + 1))

    echo "Security Assessment:"
    echo "  Critical Issues: $CRITICAL_COUNT"
    echo "  Warnings:        $WARNING_COUNT"
    echo "  Authorized ADB Keys: $TOTAL_KEYS"
    echo ""

    if [ "$CRITICAL_COUNT" -gt 0 ]; then
        echo "████████████████████████████████████████████████████████████"
        echo "██ CRITICAL SECURITY ISSUES DETECTED ██"
        echo "████████████████████████████████████████████████████████████"
        echo ""
        echo "This device has significant USB/ADB security weaknesses:"
        [ "$ADB_WIFI_ENABLED" = "1" ] && echo "  - Wireless ADB enabled (network attack vector)"
        [ "$ADB_SECURE" = "0" ] && echo "  - ADB runs without authorization"
        [ "$RO_DEBUGGABLE" = "1" ] && echo "  - Device is debuggable (eng/userdebug build)"
        [ "$RO_SECURE" = "0" ] && echo "  - ADB shell runs as root"
        [ "$OEM_UNLOCK_ENABLED" = "1" ] && echo "  - OEM unlocking is enabled"
        [ "$UNLOCKED" = "0" ] && echo "  - Bootloader is unlocked"
        echo "$USB_CONFIG" | grep -q "diag" && echo "  - DIAG mode exposed"
        echo ""
    else
        echo "[OK] No critical USB/ADB security issues detected"
    fi

    echo ""
    echo "Recommendations:"
    echo "  1. Disable USB debugging when not in use"
    echo "  2. Never enable wireless ADB on untrusted networks"
    echo "  3. Revoke unused ADB authorizations"
    echo "  4. Disable OEM unlocking on production devices"
    echo "  5. Use charge-only USB mode when possible"
    echo ""

} > "${OUTPUT_FILE}" 2>&1

echo "[+] USB/ADB security audit saved to: ${OUTPUT_FILE}"
