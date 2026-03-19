#!/system/bin/sh
# 02_audit_properties.sh — Comprehensive system property audit for Android forensics
# Audits critical security flags, signing, SELinux, encryption, and device identification

OUTPUT_DIR="${1:-.}"
OUTPUT_FILE="${OUTPUT_DIR}/audit_properties.txt"

echo "[*] Auditing system properties..."

{
    echo "╔════════════════════════════════════════════════════════════════════════════════╗"
    echo "║                        SYSTEM PROPERTIES AUDIT                                 ║"
    echo "╚════════════════════════════════════════════════════════════════════════════════╝"
    echo ""

    # Helper function to get property value
    get_prop() {
        getprop "$1" 2>/dev/null || echo "(not set)"
    }

    # Helper function to format risk label
    risk_label() {
        case "$1" in
            CRITICAL) echo "[CRITICAL]" ;;
            HIGH)     echo "[HIGH]" ;;
            MEDIUM)   echo "[MEDIUM]" ;;
            INFO)     echo "[INFO]" ;;
            OK)       echo "[OK]" ;;
            *)        echo "[$1]" ;;
        esac
    }

    # ─────────────────────────────────────────────────────────────────────────────────────
    # SECTION 1: CRITICAL SECURITY FLAGS
    # ─────────────────────────────────────────────────────────────────────────────────────
    echo "┌─ CRITICAL SECURITY FLAGS ────────────────────────────────────────────────────┐"
    echo ""

    # ro.debuggable
    DEBUGGABLE=$(get_prop "ro.debuggable")
    if [ "$DEBUGGABLE" = "1" ]; then
        echo "  ro.debuggable: $DEBUGGABLE"
        echo "    $(risk_label CRITICAL) Device is debuggable — full root access likely available"
    else
        echo "  ro.debuggable: $DEBUGGABLE"
        echo "    $(risk_label OK)"
    fi
    echo ""

    # ro.secure
    SECURE=$(get_prop "ro.secure")
    if [ "$SECURE" = "0" ]; then
        echo "  ro.secure: $SECURE"
        echo "    $(risk_label CRITICAL) ro.secure=0 — ADB runs as root"
    else
        echo "  ro.secure: $SECURE"
        echo "    $(risk_label OK)"
    fi
    echo ""

    # ro.adb.secure
    ADB_SECURE=$(get_prop "ro.adb.secure")
    if [ "$ADB_SECURE" = "0" ]; then
        echo "  ro.adb.secure: $ADB_SECURE"
        echo "    $(risk_label HIGH) ADB does not require authentication"
    else
        echo "  ro.adb.secure: $ADB_SECURE"
        echo "    $(risk_label OK)"
    fi
    echo ""

    # service.adb.root
    ADB_ROOT=$(get_prop "service.adb.root")
    if [ "$ADB_ROOT" = "1" ]; then
        echo "  service.adb.root: $ADB_ROOT"
        echo "    $(risk_label CRITICAL) ADB is running as root"
    else
        echo "  service.adb.root: $ADB_ROOT"
        echo "    $(risk_label OK)"
    fi
    echo ""

    # ro.boot.verifiedbootstate
    VERIFIED_BOOT=$(get_prop "ro.boot.verifiedbootstate")
    case "$VERIFIED_BOOT" in
        green)
            echo "  ro.boot.verifiedbootstate: $VERIFIED_BOOT"
            echo "    $(risk_label OK)"
            ;;
        yellow)
            echo "  ro.boot.verifiedbootstate: $VERIFIED_BOOT"
            echo "    $(risk_label MEDIUM) Device may have modified firmware"
            ;;
        orange)
            echo "  ro.boot.verifiedbootstate: $VERIFIED_BOOT"
            echo "    $(risk_label HIGH) Verified Boot disabled or warning state"
            ;;
        red)
            echo "  ro.boot.verifiedbootstate: $VERIFIED_BOOT"
            echo "    $(risk_label CRITICAL) Verified Boot failed — potential compromise"
            ;;
        *)
            echo "  ro.boot.verifiedbootstate: $VERIFIED_BOOT"
            echo "    $(risk_label INFO)"
            ;;
    esac
    echo ""

    # ro.boot.flash.locked
    FLASH_LOCKED=$(get_prop "ro.boot.flash.locked")
    if [ "$FLASH_LOCKED" = "0" ]; then
        echo "  ro.boot.flash.locked: $FLASH_LOCKED"
        echo "    $(risk_label HIGH) Bootloader is unlocked — allows custom firmware"
    else
        echo "  ro.boot.flash.locked: $FLASH_LOCKED"
        echo "    $(risk_label OK)"
    fi
    echo ""

    # ro.boot.veritymode
    VERITY_MODE=$(get_prop "ro.boot.veritymode")
    if [ "$VERITY_MODE" = "enforcing" ]; then
        echo "  ro.boot.veritymode: $VERITY_MODE"
        echo "    $(risk_label OK)"
    else
        echo "  ro.boot.veritymode: $VERITY_MODE"
        echo "    $(risk_label HIGH) Verity protection not enforcing"
    fi
    echo ""
    echo "└───────────────────────────────────────────────────────────────────────────────┘"
    echo ""

    # ─────────────────────────────────────────────────────────────────────────────────────
    # SECTION 2: BUILD & SIGNING
    # ─────────────────────────────────────────────────────────────────────────────────────
    echo "┌─ BUILD & SIGNING ────────────────────────────────────────────────────────────┐"
    echo ""

    # ro.build.tags
    BUILD_TAGS=$(get_prop "ro.build.tags")
    echo "  ro.build.tags: $BUILD_TAGS"
    case "$BUILD_TAGS" in
        release-keys)
            echo "    $(risk_label OK) Official release build"
            ;;
        test-keys)
            echo "    $(risk_label HIGH) Test build — may have reduced security"
            ;;
        dev-keys)
            echo "    $(risk_label HIGH) Development build — security features may be disabled"
            ;;
        *)
            echo "    $(risk_label INFO)"
            ;;
    esac
    echo ""

    # ro.build.type
    BUILD_TYPE=$(get_prop "ro.build.type")
    echo "  ro.build.type: $BUILD_TYPE"
    case "$BUILD_TYPE" in
        user)
            echo "    $(risk_label OK)"
            ;;
        userdebug)
            echo "    $(risk_label MEDIUM) Userdebug build — debugging enabled"
            ;;
        eng)
            echo "    $(risk_label HIGH) Engineering build — extensive debugging, reduced security"
            ;;
        *)
            echo "    $(risk_label INFO)"
            ;;
    esac
    echo ""

    # ro.build.version.release
    echo "  ro.build.version.release: $(get_prop "ro.build.version.release")"
    echo ""

    # ro.build.version.sdk
    echo "  ro.build.version.sdk: $(get_prop "ro.build.version.sdk")"
    echo ""

    # ro.build.version.security_patch
    SECURITY_PATCH=$(get_prop "ro.build.version.security_patch")
    echo "  ro.build.version.security_patch: $SECURITY_PATCH"
    if [ -n "$SECURITY_PATCH" ] && [ "$SECURITY_PATCH" != "(not set)" ]; then
        PATCH_YEAR=$(echo "$SECURITY_PATCH" | cut -d'-' -f1)
        PATCH_MONTH=$(echo "$SECURITY_PATCH" | cut -d'-' -f2)
        CURRENT_YEAR=2026
        CURRENT_MONTH=3
        MONTHS_DIFF=$(( (CURRENT_YEAR - PATCH_YEAR) * 12 + (CURRENT_MONTH - PATCH_MONTH) ))

        if [ "$MONTHS_DIFF" -gt 24 ]; then
            echo "    $(risk_label HIGH) Security patch is older than 24 months"
        elif [ "$MONTHS_DIFF" -gt 12 ]; then
            echo "    $(risk_label MEDIUM) Security patch is older than 12 months"
        else
            echo "    $(risk_label OK) Security patch is current"
        fi
    fi
    echo ""

    # ro.build.fingerprint
    echo "  ro.build.fingerprint: $(get_prop "ro.build.fingerprint")"
    echo ""
    echo "└───────────────────────────────────────────────────────────────────────────────┘"
    echo ""

    # ─────────────────────────────────────────────────────────────────────────────────────
    # SECTION 3: SELinux PROPERTIES
    # ─────────────────────────────────────────────────────────────────────────────────────
    echo "┌─ SELinux PROPERTIES ─────────────────────────────────────────────────────────┐"
    echo ""

    # ro.build.selinux
    echo "  ro.build.selinux: $(get_prop "ro.build.selinux")"
    echo ""

    # ro.boot.selinux
    SELINUX_MODE=$(get_prop "ro.boot.selinux")
    echo "  ro.boot.selinux: $SELINUX_MODE"
    case "$SELINUX_MODE" in
        enforcing)
            echo "    $(risk_label OK) SELinux enforcing — mandatory access control active"
            ;;
        permissive)
            echo "    $(risk_label CRITICAL) SELinux permissive — access violations logged but not enforced"
            ;;
        disabled)
            echo "    $(risk_label CRITICAL) SELinux disabled — no mandatory access control"
            ;;
        *)
            echo "    $(risk_label INFO)"
            ;;
    esac
    echo ""

    # persist.sys.disable_hmac
    HMAC_DISABLED=$(get_prop "persist.sys.disable_hmac")
    if [ -n "$HMAC_DISABLED" ] && [ "$HMAC_DISABLED" != "(not set)" ]; then
        echo "  persist.sys.disable_hmac: $HMAC_DISABLED"
        echo "    $(risk_label MEDIUM) HMAC verification disabled"
        echo ""
    fi
    echo "└───────────────────────────────────────────────────────────────────────────────┘"
    echo ""

    # ─────────────────────────────────────────────────────────────────────────────────────
    # SECTION 4: USB & ADB PROPERTIES
    # ─────────────────────────────────────────────────────────────────────────────────────
    echo "┌─ USB & ADB PROPERTIES ───────────────────────────────────────────────────────┐"
    echo ""

    # sys.usb.state
    echo "  sys.usb.state: $(get_prop "sys.usb.state")"
    echo ""

    # sys.usb.config
    echo "  sys.usb.config: $(get_prop "sys.usb.config")"
    echo ""

    # persist.sys.usb.config
    echo "  persist.sys.usb.config: $(get_prop "persist.sys.usb.config")"
    echo ""

    # ro.usb.vid / ro.usb.pid
    echo "  ro.usb.vid: $(get_prop "ro.usb.vid")"
    echo "  ro.usb.pid: $(get_prop "ro.usb.pid")"
    echo ""

    # Check if ADB is in USB config
    USB_STATE=$(get_prop "sys.usb.state")
    USB_CONFIG=$(get_prop "sys.usb.config")
    if echo "$USB_STATE" | grep -q "adb" || echo "$USB_CONFIG" | grep -q "adb"; then
        echo "  $(risk_label INFO) ADB is available in USB configuration"
    fi
    echo ""
    echo "└───────────────────────────────────────────────────────────────────────────────┘"
    echo ""

    # ─────────────────────────────────────────────────────────────────────────────────────
    # SECTION 5: CRYPTO & ENCRYPTION
    # ─────────────────────────────────────────────────────────────────────────────────────
    echo "┌─ CRYPTO & ENCRYPTION ────────────────────────────────────────────────────────┐"
    echo ""

    # ro.crypto.state
    CRYPTO_STATE=$(get_prop "ro.crypto.state")
    echo "  ro.crypto.state: $CRYPTO_STATE"
    case "$CRYPTO_STATE" in
        encrypted)
            echo "    $(risk_label OK) Device storage is encrypted"
            ;;
        unencrypted)
            echo "    $(risk_label CRITICAL) Device storage is NOT encrypted"
            ;;
        *)
            echo "    $(risk_label INFO)"
            ;;
    esac
    echo ""

    # ro.crypto.type
    CRYPTO_TYPE=$(get_prop "ro.crypto.type")
    echo "  ro.crypto.type: $CRYPTO_TYPE"
    case "$CRYPTO_TYPE" in
        file)
            echo "    $(risk_label OK) File-based encryption"
            ;;
        block)
            echo "    $(risk_label INFO) Full-disk (block) encryption"
            ;;
        *)
            echo "    $(risk_label INFO)"
            ;;
    esac
    echo ""

    # vold.decrypt
    echo "  vold.decrypt: $(get_prop "vold.decrypt")"
    echo ""

    # ro.crypto.volume.metadata.encryption
    echo "  ro.crypto.volume.metadata.encryption: $(get_prop "ro.crypto.volume.metadata.encryption")"
    echo ""
    echo "└───────────────────────────────────────────────────────────────────────────────┘"
    echo ""

    # ─────────────────────────────────────────────────────────────────────────────────────
    # SECTION 6: PERSISTENT/MUTABLE PROPERTIES (Tamper Indicators)
    # ─────────────────────────────────────────────────────────────────────────────────────
    echo "┌─ PERSISTENT/MUTABLE PROPERTIES (Tamper Indicators) ───────────────────────────┐"
    echo ""
    echo "  Properties that can be changed at runtime (may indicate tampering or misconfig):"
    echo ""

    PERSIST_PROPS=$(getprop 2>/dev/null | grep "^\[persist" | sort)

    if [ -z "$PERSIST_PROPS" ]; then
        echo "  (No persist.* properties found)"
    else
        echo "$PERSIST_PROPS" | while read -r line; do
            KEY=$(echo "$line" | sed 's/\[\(.*\)\].*/\1/')
            VALUE=$(echo "$line" | sed 's/.*\]: \[\(.*\)\]/\1/')

            # Flag security-related persist properties
            if echo "$KEY" | grep -qE "adb|root|secure|debug|selinux|encryption"; then
                echo "  $KEY: $VALUE"
                echo "    $(risk_label MEDIUM)"
            else
                echo "  $KEY: $VALUE"
            fi
        done
    fi
    echo ""
    echo "└───────────────────────────────────────────────────────────────────────────────┘"
    echo ""

    # ─────────────────────────────────────────────────────────────────────────────────────
    # SECTION 7: DEBUG & DEVELOPMENT PROPERTIES
    # ─────────────────────────────────────────────────────────────────────────────────────
    echo "┌─ DEBUG & DEVELOPMENT PROPERTIES ─────────────────────────────────────────────┐"
    echo ""

    DEBUG_PROPS=$(getprop 2>/dev/null | grep -E "debug\.|\.debug|dev\.|test\." | sort)

    if [ -z "$DEBUG_PROPS" ]; then
        echo "  (No debug properties detected)"
    else
        echo "  Detected debug/development properties:"
        echo ""
        echo "$DEBUG_PROPS" | while read -r line; do
            KEY=$(echo "$line" | sed 's/\[\(.*\)\].*/\1/')
            VALUE=$(echo "$line" | sed 's/.*\]: \[\(.*\)\]/\1/')
            echo "  $KEY: $VALUE"

            if [ "$VALUE" = "1" ] || [ "$VALUE" = "true" ]; then
                echo "    $(risk_label HIGH) Debug feature enabled"
            fi
        done
    fi
    echo ""

    # ro.allow.mock.location
    MOCK_LOCATION=$(get_prop "ro.allow.mock.location")
    if [ "$MOCK_LOCATION" = "1" ]; then
        echo "  ro.allow.mock.location: $MOCK_LOCATION"
        echo "    $(risk_label MEDIUM) Mock location provider allowed"
        echo ""
    fi

    # ro.test_harness
    TEST_HARNESS=$(get_prop "ro.test_harness")
    if [ "$TEST_HARNESS" = "1" ]; then
        echo "  ro.test_harness: $TEST_HARNESS"
        echo "    $(risk_label MEDIUM) Test harness mode enabled"
        echo ""
    fi
    echo "└───────────────────────────────────────────────────────────────────────────────┘"
    echo ""

    # ─────────────────────────────────────────────────────────────────────────────────────
    # SECTION 8: NETWORK PROPERTIES
    # ─────────────────────────────────────────────────────────────────────────────────────
    echo "┌─ NETWORK PROPERTIES ─────────────────────────────────────────────────────────┐"
    echo ""

    # net.hostname
    echo "  net.hostname: $(get_prop "net.hostname")"
    echo ""

    # DHCP properties
    DHCP_PROPS=$(getprop 2>/dev/null | grep "^\\[dhcp" | sort)
    if [ -n "$DHCP_PROPS" ]; then
        echo "  DHCP Properties:"
        echo "$DHCP_PROPS" | while read -r line; do
            KEY=$(echo "$line" | sed 's/\[\(.*\)\].*/\1/')
            VALUE=$(echo "$line" | sed 's/.*\]: \[\(.*\)\]/\1/')
            echo "    $KEY: $VALUE"
        done
        echo ""
    fi

    # WiFi properties (if exposed)
    WIFI_PROPS=$(getprop 2>/dev/null | grep "^\\[wifi" | head -10 | sort)
    if [ -n "$WIFI_PROPS" ]; then
        echo "  WiFi Properties (first 10):"
        echo "$WIFI_PROPS" | while read -r line; do
            KEY=$(echo "$line" | sed 's/\[\(.*\)\].*/\1/')
            VALUE=$(echo "$line" | sed 's/.*\]: \[\(.*\)\]/\1/')
            echo "    $KEY: $VALUE"
        done
        echo ""
    fi
    echo "└───────────────────────────────────────────────────────────────────────────────┘"
    echo ""

    # ─────────────────────────────────────────────────────────────────────────────────────
    # SECTION 9: HARDWARE IDENTIFICATION
    # ─────────────────────────────────────────────────────────────────────────────────────
    echo "┌─ HARDWARE IDENTIFICATION ────────────────────────────────────────────────────┐"
    echo ""

    echo "  ro.product.manufacturer: $(get_prop "ro.product.manufacturer")"
    echo "  ro.product.model: $(get_prop "ro.product.model")"
    echo "  ro.product.name: $(get_prop "ro.product.name")"
    echo ""

    echo "  ro.product.board: $(get_prop "ro.product.board")"
    echo "  ro.product.platform: $(get_prop "ro.product.platform")"
    echo ""

    echo "  ro.hardware: $(get_prop "ro.hardware")"
    echo "  ro.hardware.chipname: $(get_prop "ro.hardware.chipname")"
    echo ""

    echo "  ro.soc.manufacturer: $(get_prop "ro.soc.manufacturer")"
    echo "  ro.soc.model: $(get_prop "ro.soc.model")"
    echo ""

    echo "  ro.serialno: $(get_prop "ro.serialno")"
    echo "  ro.boot.serialno: $(get_prop "ro.boot.serialno")"
    echo ""
    echo "└───────────────────────────────────────────────────────────────────────────────┘"
    echo ""

    # ─────────────────────────────────────────────────────────────────────────────────────
    # SECTION 10: FULL PROPERTY DUMP (REFERENCE)
    # ─────────────────────────────────────────────────────────────────────────────────────
    echo "┌─ FULL PROPERTY DUMP (REFERENCE) ─────────────────────────────────────────────┐"
    echo ""
    getprop 2>/dev/null | sort
    echo ""
    echo "└───────────────────────────────────────────────────────────────────────────────┘"
    echo ""

    # ─────────────────────────────────────────────────────────────────────────────────────
    # SECTION 11: SUMMARY
    # ─────────────────────────────────────────────────────────────────────────────────────
    echo "╔════════════════════════════════════════════════════════════════════════════════╗"
    echo "║                         AUDIT SUMMARY & FINDINGS                               ║"
    echo "╚════════════════════════════════════════════════════════════════════════════════╝"
    echo ""

    CRITICAL_FINDINGS=0
    HIGH_FINDINGS=0
    MEDIUM_FINDINGS=0

    # Count CRITICAL findings
    [ "$DEBUGGABLE" = "1" ] && CRITICAL_FINDINGS=$((CRITICAL_FINDINGS + 1))
    [ "$SECURE" = "0" ] && CRITICAL_FINDINGS=$((CRITICAL_FINDINGS + 1))
    [ "$ADB_ROOT" = "1" ] && CRITICAL_FINDINGS=$((CRITICAL_FINDINGS + 1))
    [ "$VERIFIED_BOOT" = "red" ] && CRITICAL_FINDINGS=$((CRITICAL_FINDINGS + 1))
    [ "$SELINUX_MODE" = "permissive" ] || [ "$SELINUX_MODE" = "disabled" ] && CRITICAL_FINDINGS=$((CRITICAL_FINDINGS + 1))
    [ "$CRYPTO_STATE" = "unencrypted" ] && CRITICAL_FINDINGS=$((CRITICAL_FINDINGS + 1))

    # Count HIGH findings
    [ "$ADB_SECURE" = "0" ] && HIGH_FINDINGS=$((HIGH_FINDINGS + 1))
    [ "$FLASH_LOCKED" = "0" ] && HIGH_FINDINGS=$((HIGH_FINDINGS + 1))
    [ "$VERITY_MODE" != "enforcing" ] && HIGH_FINDINGS=$((HIGH_FINDINGS + 1))
    [ "$BUILD_TYPE" = "eng" ] && HIGH_FINDINGS=$((HIGH_FINDINGS + 1))
    [ -n "$SECURITY_PATCH" ] && [ "$(echo "$SECURITY_PATCH" | cut -d'-' -f1)" -lt 2024 ] && HIGH_FINDINGS=$((HIGH_FINDINGS + 1))

    echo "  CRITICAL findings: $CRITICAL_FINDINGS"
    echo "  HIGH findings: $HIGH_FINDINGS"
    echo "  MEDIUM findings: (see sections above)"
    echo ""

    if [ "$CRITICAL_FINDINGS" -gt 0 ]; then
        echo "  $(risk_label CRITICAL) CRITICAL ISSUES DETECTED:"
        [ "$DEBUGGABLE" = "1" ] && echo "    • Device is debuggable (ro.debuggable=1)"
        [ "$SECURE" = "0" ] && echo "    • ADB runs as root (ro.secure=0)"
        [ "$ADB_ROOT" = "1" ] && echo "    • ADB root service enabled (service.adb.root=1)"
        [ "$VERIFIED_BOOT" = "red" ] && echo "    • Verified Boot failed (ro.boot.verifiedbootstate=red)"
        if [ "$SELINUX_MODE" = "permissive" ] || [ "$SELINUX_MODE" = "disabled" ]; then
            echo "    • SELinux not enforcing (ro.boot.selinux=$SELINUX_MODE)"
        fi
        [ "$CRYPTO_STATE" = "unencrypted" ] && echo "    • Storage not encrypted (ro.crypto.state=unencrypted)"
        echo ""
    fi

    echo "  Detailed findings are noted above in each section."
    echo ""
    echo "╔════════════════════════════════════════════════════════════════════════════════╗"
    echo ""

    # ─────────────────────────────────────────────────────────────────────────────────────
    # SECTION 12: WARRANTY & FRP INDICATORS
    # ─────────────────────────────────────────────────────────────────────────────────────
    echo "┌─ WARRANTY & FRP INDICATORS ──────────────────────────────────────────────────┐"
    echo ""

    # ro.boot.warranty_bit
    WARRANTY_BIT=$(get_prop "ro.boot.warranty_bit")
    if [ -n "$WARRANTY_BIT" ] && [ "$WARRANTY_BIT" != "(not set)" ]; then
        echo "  ro.boot.warranty_bit: $WARRANTY_BIT"
        if [ "$WARRANTY_BIT" = "0" ]; then
            echo "    $(risk_label INFO) Warranty void bit clear"
        else
            echo "    $(risk_label MEDIUM) Warranty void bit set — device may have been tampered"
        fi
        echo ""
    fi

    # ro.frp.pst
    FRP_PST=$(get_prop "ro.frp.pst")
    if [ -n "$FRP_PST" ] && [ "$FRP_PST" != "(not set)" ]; then
        echo "  ro.frp.pst: $FRP_PST"
        echo "    $(risk_label INFO) FRP (Factory Reset Protection) partition identified"
        echo ""
    fi

    # ro.oem_unlock_supported
    OEM_UNLOCK=$(get_prop "ro.oem_unlock_supported")
    if [ -n "$OEM_UNLOCK" ] && [ "$OEM_UNLOCK" != "(not set)" ]; then
        echo "  ro.oem_unlock_supported: $OEM_UNLOCK"
        if [ "$OEM_UNLOCK" = "1" ]; then
            echo "    $(risk_label MEDIUM) OEM unlocking is supported"
        else
            echo "    $(risk_label OK) OEM unlocking is not supported"
        fi
        echo ""
    fi

    echo "└───────────────────────────────────────────────────────────────────────────────┘"
    echo ""

    # ─────────────────────────────────────────────────────────────────────────────────────
    # SECTION 13: PERSIST PROPERTIES (ROOT/HOOKING INDICATORS)
    # ─────────────────────────────────────────────────────────────────────────────────────
    echo "┌─ PERSIST PROPERTIES (ROOT/HOOKING INDICATORS) ───────────────────────────────┐"
    echo ""

    ROOT_HOOKING_PROPS=$(getprop 2>/dev/null | grep -iE "persist.*\\.*(root|su|magisk|xposed|frida|debug)")

    if [ -z "$ROOT_HOOKING_PROPS" ]; then
        echo "  (No suspicious persist properties detected)"
    else
        echo "  Suspicious persist.* properties found:"
        echo ""
        echo "$ROOT_HOOKING_PROPS" | while read -r line; do
            KEY=$(echo "$line" | sed 's/\[\(.*\)\].*/\1/')
            VALUE=$(echo "$line" | sed 's/.*\]: \[\(.*\)\]/\1/')

            echo "  $KEY: $VALUE"

            # Risk assessment
            if echo "$KEY" | grep -qiE "root|su"; then
                echo "    $(risk_label CRITICAL) Root access indicator"
            elif echo "$KEY" | grep -qiE "magisk"; then
                echo "    $(risk_label CRITICAL) Magisk (root framework) detected"
            elif echo "$KEY" | grep -qiE "xposed|frida|cydia"; then
                echo "    $(risk_label HIGH) Hooking framework indicator"
            elif echo "$KEY" | grep -qiE "debug"; then
                echo "    $(risk_label MEDIUM) Debug property"
            fi
        done
    fi
    echo ""
    echo "└───────────────────────────────────────────────────────────────────────────────┘"
    echo ""

    # ─────────────────────────────────────────────────────────────────────────────────────
    # SECTION 14: HOOKING FRAMEWORK DETECTION (XPOSED/FRIDA/CYDIA)
    # ─────────────────────────────────────────────────────────────────────────────────────
    echo "┌─ HOOKING FRAMEWORK DETECTION ────────────────────────────────────────────────┐"
    echo ""

    HOOK_DETECTED=0

    echo "  Scanning for Xposed/Frida/Cydia indicators..."
    echo ""

    # Xposed indicators
    XPOSED_PROPS=$(getprop 2>/dev/null | grep -iE "xposed")
    if [ -n "$XPOSED_PROPS" ]; then
        echo "  $(risk_label CRITICAL) Xposed Framework detected:"
        echo "$XPOSED_PROPS" | while read -r line; do
            KEY=$(echo "$line" | sed 's/\[\(.*\)\].*/\1/')
            VALUE=$(echo "$line" | sed 's/.*\]: \[\(.*\)\]/\1/')
            echo "    $KEY: $VALUE"
        done
        HOOK_DETECTED=1
        echo ""
    fi

    # Frida indicators
    FRIDA_PROPS=$(getprop 2>/dev/null | grep -iE "frida")
    if [ -n "$FRIDA_PROPS" ]; then
        echo "  $(risk_label CRITICAL) Frida (runtime instrumentation) detected:"
        echo "$FRIDA_PROPS" | while read -r line; do
            KEY=$(echo "$line" | sed 's/\[\(.*\)\].*/\1/')
            VALUE=$(echo "$line" | sed 's/.*\]: \[\(.*\)\]/\1/')
            echo "    $KEY: $VALUE"
        done
        HOOK_DETECTED=1
        echo ""
    fi

    # Cydia/Substrate indicators
    CYDIA_PROPS=$(getprop 2>/dev/null | grep -iE "cydia|substrate")
    if [ -n "$CYDIA_PROPS" ]; then
        echo "  $(risk_label CRITICAL) Cydia/Substrate (iOS/jailbreak port) detected:"
        echo "$CYDIA_PROPS" | while read -r line; do
            KEY=$(echo "$line" | sed 's/\[\(.*\)\].*/\1/')
            VALUE=$(echo "$line" | sed 's/.*\]: \[\(.*\)\]/\1/')
            echo "    $KEY: $VALUE"
        done
        HOOK_DETECTED=1
        echo ""
    fi

    if [ "$HOOK_DETECTED" = "0" ]; then
        echo "  [OK] No property-based hooking framework indicators detected"
    fi
    echo ""
    echo "└───────────────────────────────────────────────────────────────────────────────┘"
    echo ""

    # ─────────────────────────────────────────────────────────────────────────────────────
    # SECTION 15: KEYMASTER/KEYMINT PROPERTIES
    # ─────────────────────────────────────────────────────────────────────────────────────
    echo "┌─ KEYMASTER/KEYMINT PROPERTIES ───────────────────────────────────────────────┐"
    echo ""

    # Primary keystore hardware
    KEYSTORE_HW=$(get_prop "ro.hardware.keystore")
    echo "  ro.hardware.keystore: $KEYSTORE_HW"
    case "$KEYSTORE_HW" in
        msm8996|msm8998|sdm845|sdm855|sdm865)
            echo "    $(risk_label INFO) Qualcomm Secure Execution Environment (SEE)"
            ;;
        exynos|exynos9*)
            echo "    $(risk_label INFO) Samsung Knox Keystore"
            ;;
        mtk|mediatek)
            echo "    $(risk_label INFO) MediaTek Secure Processor"
            ;;
        trustzone)
            echo "    $(risk_label INFO) ARM TrustZone-based keystore"
            ;;
        *)
            if [ -n "$KEYSTORE_HW" ] && [ "$KEYSTORE_HW" != "(not set)" ]; then
                echo "    $(risk_label INFO)"
            fi
            ;;
    esac
    echo ""

    # Keymint/Keymaster vendor properties
    KEYMINT_PROPS=$(getprop 2>/dev/null | grep -iE "ro\\.vendor\\.keymint|persist\\.vendor\\.keymint|keymint\\.version|keymaster\\.version" | sort)

    if [ -n "$KEYMINT_PROPS" ]; then
        echo "  Keymint/Keymaster Configuration:"
        echo ""
        echo "$KEYMINT_PROPS" | while read -r line; do
            KEY=$(echo "$line" | sed 's/\[\(.*\)\].*/\1/')
            VALUE=$(echo "$line" | sed 's/.*\]: \[\(.*\)\]/\1/')
            echo "    $KEY: $VALUE"
        done
        echo ""
    fi

    # Strongbox availability
    STRONGBOX=$(get_prop "ro.hardware.strongbox_keystore")
    if [ -n "$STRONGBOX" ] && [ "$STRONGBOX" != "(not set)" ]; then
        echo "  ro.hardware.strongbox_keystore: $STRONGBOX"
        echo "    $(risk_label INFO) StrongBox Keymaster available (dedicated secure processor)"
        echo ""
    fi

    echo "└───────────────────────────────────────────────────────────────────────────────┘"
    echo ""

} > "${OUTPUT_FILE}" 2>&1

echo "[+] Properties audit saved to: ${OUTPUT_FILE}"
