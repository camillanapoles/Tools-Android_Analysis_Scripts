#!/system/bin/sh
# DROID FORENSIC - Vendor/OEM Customizations Enumeration
# Identifies OEM-specific apps, services, frameworks, and hidden functionality
# Usage: sh 20_enum_vendor_customizations.sh [output_directory]

OUTPUT_DIR="${1:-.}"
OUTPUT_FILE="${OUTPUT_DIR}/vendor_customizations.txt"

echo "[*] Enumerating vendor/OEM customizations..."

{
    echo "═══════════════════════════════════════════════════════════════"
    echo "  VENDOR/OEM CUSTOMIZATIONS ENUMERATION"
    echo "  Timestamp: $(date)"
    echo "═══════════════════════════════════════════════════════════════"
    echo ""
    echo "OEM customizations may include hidden functionality, backdoors,"
    echo "proprietary services, and non-standard security configurations."
    echo ""

    # =========================================================================
    # SECTION 1: Device Identification
    # =========================================================================
    
    echo "┌─────────────────────────────────────────────────────────────┐"
    echo "│ DEVICE IDENTIFICATION                                      │"
    echo "└─────────────────────────────────────────────────────────────┘"
    echo ""

    echo "=== Manufacturer & Model ==="
    echo "Manufacturer:     $(getprop ro.product.manufacturer 2>/dev/null)"
    echo "Brand:            $(getprop ro.product.brand 2>/dev/null)"
    echo "Model:            $(getprop ro.product.model 2>/dev/null)"
    echo "Device:           $(getprop ro.product.device 2>/dev/null)"
    echo "Product:          $(getprop ro.product.name 2>/dev/null)"
    echo "Hardware:         $(getprop ro.hardware 2>/dev/null)"
    echo "Board:            $(getprop ro.product.board 2>/dev/null)"
    echo "Platform:         $(getprop ro.board.platform 2>/dev/null)"
    echo ""

    echo "=== Build Information ==="
    echo "Build ID:         $(getprop ro.build.id 2>/dev/null)"
    echo "Build Display:    $(getprop ro.build.display.id 2>/dev/null)"
    echo "Build Fingerprint: $(getprop ro.build.fingerprint 2>/dev/null)"
    echo "Build Description: $(getprop ro.build.description 2>/dev/null)"
    echo ""

    # Detect manufacturer
    MANUFACTURER=$(getprop ro.product.manufacturer 2>/dev/null | tr '[:upper:]' '[:lower:]')
    echo "Detected manufacturer: $MANUFACTURER"
    echo ""

    # =========================================================================
    # SECTION 2: OEM-Specific Properties
    # =========================================================================
    
    echo "┌─────────────────────────────────────────────────────────────┐"
    echo "│ OEM-SPECIFIC SYSTEM PROPERTIES                             │"
    echo "└─────────────────────────────────────────────────────────────┘"
    echo ""

    # Common OEM property prefixes
    OEM_PREFIXES="samsung huawei xiaomi oppo vivo oneplus realme asus sony lg htc motorola lenovo zte meizu nubia honor redmi poco nokia google pixel qcom qualcomm mtk mediatek exynos sprd"

    for prefix in $OEM_PREFIXES; do
        PROPS=$(getprop 2>/dev/null | grep -i "$prefix" | head -30)
        if [ -n "$PROPS" ]; then
            echo "=== ${prefix^^} Properties ==="
            echo "$PROPS" | sed 's/^/  /'
            echo ""
        fi
    done

    # Vendor-specific properties
    echo "=== ro.vendor.* Properties ==="
    getprop 2>/dev/null | grep "^\[ro\.vendor\." | head -40 | sed 's/^/  /'
    echo ""

    echo "=== persist.vendor.* Properties ==="
    getprop 2>/dev/null | grep "^\[persist\.vendor\." | head -30 | sed 's/^/  /'
    echo ""

    # =========================================================================
    # SECTION 3: OEM Applications
    # =========================================================================
    
    echo "┌─────────────────────────────────────────────────────────────┐"
    echo "│ OEM/VENDOR APPLICATIONS                                    │"
    echo "└─────────────────────────────────────────────────────────────┘"
    echo ""

    echo "=== Vendor Partition Apps (/vendor/app) ==="
    if [ -d /vendor/app ]; then
        ls -la /vendor/app/ 2>/dev/null
        echo ""
        echo "Package count: $(ls /vendor/app/ 2>/dev/null | wc -l)"
    else
        echo "No /vendor/app directory"
    fi
    echo ""

    echo "=== Vendor Priv-Apps (/vendor/priv-app) ==="
    if [ -d /vendor/priv-app ]; then
        ls -la /vendor/priv-app/ 2>/dev/null
        echo ""
        echo "Package count: $(ls /vendor/priv-app/ 2>/dev/null | wc -l)"
    else
        echo "No /vendor/priv-app directory"
    fi
    echo ""

    echo "=== Product Apps (/product/app) ==="
    if [ -d /product/app ]; then
        ls -la /product/app/ 2>/dev/null | head -30
        echo ""
        echo "Package count: $(ls /product/app/ 2>/dev/null | wc -l)"
    else
        echo "No /product/app directory"
    fi
    echo ""

    echo "=== Product Priv-Apps (/product/priv-app) ==="
    if [ -d /product/priv-app ]; then
        ls -la /product/priv-app/ 2>/dev/null | head -30
        echo ""
        echo "Package count: $(ls /product/priv-app/ 2>/dev/null | wc -l)"
    else
        echo "No /product/priv-app directory"
    fi
    echo ""

    echo "=== ODM Apps (/odm/app) ==="
    if [ -d /odm/app ]; then
        ls -la /odm/app/ 2>/dev/null
    else
        echo "No /odm/app directory"
    fi
    echo ""

    echo "=== System_ext Apps (/system_ext/app) ==="
    if [ -d /system_ext/app ]; then
        ls -la /system_ext/app/ 2>/dev/null | head -20
    else
        echo "No /system_ext/app directory"
    fi
    echo ""

    # =========================================================================
    # SECTION 4: OEM Packages by Name Pattern
    # =========================================================================
    
    echo "┌─────────────────────────────────────────────────────────────┐"
    echo "│ OEM PACKAGES (By Name Pattern)                             │"
    echo "└─────────────────────────────────────────────────────────────┘"
    echo ""

    # Manufacturer-specific packages
    case "$MANUFACTURER" in
        samsung*)
            echo "=== Samsung Packages ==="
            pm list packages 2>/dev/null | grep -iE "samsung|sec\.|samsungapps|galaxy|bixby|smartthings|scloud|svoice|spay|samsunghealth|knox|mdm" | sort
            ;;
        huawei*|honor*)
            echo "=== Huawei/Honor Packages ==="
            pm list packages 2>/dev/null | grep -iE "huawei|honor|hicloud|hisuite|hwid|emui|hicare|hms|hiapp" | sort
            ;;
        xiaomi*|redmi*|poco*)
            echo "=== Xiaomi/Redmi/POCO Packages ==="
            pm list packages 2>/dev/null | grep -iE "xiaomi|miui|redmi|poco|mipay|micloud|mi\.com|milink" | sort
            ;;
        oppo*)
            echo "=== OPPO Packages ==="
            pm list packages 2>/dev/null | grep -iE "oppo|coloros|heytap|nearme" | sort
            ;;
        vivo*)
            echo "=== Vivo Packages ==="
            pm list packages 2>/dev/null | grep -iE "vivo|funtouch|bbk" | sort
            ;;
        oneplus*)
            echo "=== OnePlus Packages ==="
            pm list packages 2>/dev/null | grep -iE "oneplus|oxygenos" | sort
            ;;
        google*)
            echo "=== Google/Pixel Packages ==="
            pm list packages 2>/dev/null | grep -iE "google|pixel|android\." | grep -v "com\.android\." | sort | head -30
            ;;
        *)
            echo "=== Vendor Packages (generic search) ==="
            pm list packages 2>/dev/null | grep -iE "vendor|oem|$MANUFACTURER" | sort | head -30
            ;;
    esac
    echo ""

    # =========================================================================
    # SECTION 5: OEM Services
    # =========================================================================
    
    echo "┌─────────────────────────────────────────────────────────────┐"
    echo "│ OEM/VENDOR SERVICES                                        │"
    echo "└─────────────────────────────────────────────────────────────┘"
    echo ""

    echo "=== Vendor Binder Services ==="
    service list 2>/dev/null | grep -iE "vendor|oem|$MANUFACTURER" | head -30
    echo ""

    echo "=== Vendor HAL Services ==="
    if command -v lshal >/dev/null 2>&1; then
        lshal 2>/dev/null | grep -iE "vendor\.|$MANUFACTURER" | head -40
    fi
    echo ""

    echo "=== Vendor Init Services ==="
    getprop 2>/dev/null | grep "^\[init\.svc\." | grep -iE "vendor|$MANUFACTURER" | head -20
    echo ""

    # =========================================================================
    # SECTION 6: OEM Frameworks & Libraries
    # =========================================================================
    
    echo "┌─────────────────────────────────────────────────────────────┐"
    echo "│ OEM FRAMEWORKS & LIBRARIES                                 │"
    echo "└─────────────────────────────────────────────────────────────┘"
    echo ""

    echo "=== Vendor Framework JARs ==="
    ls -la /vendor/framework/*.jar 2>/dev/null | head -20
    ls -la /system/framework/*vendor*.jar /system/framework/*oem*.jar 2>/dev/null
    echo ""

    echo "=== Product Framework JARs ==="
    ls -la /product/framework/*.jar 2>/dev/null | head -20
    echo ""

    echo "=== Vendor Native Libraries ==="
    echo "Libraries in /vendor/lib64:"
    ls /vendor/lib64/*.so 2>/dev/null | wc -l
    echo ""
    echo "Sample vendor libraries:"
    ls /vendor/lib64/*.so 2>/dev/null | head -20
    echo ""

    echo "=== Custom System Libraries ==="
    ls -la /system/lib64/*vendor*.so /system/lib64/*oem*.so 2>/dev/null | head -10
    echo ""

    # =========================================================================
    # SECTION 7: OEM Configuration Files
    # =========================================================================
    
    echo "┌─────────────────────────────────────────────────────────────┐"
    echo "│ OEM CONFIGURATION FILES                                    │"
    echo "└─────────────────────────────────────────────────────────────┘"
    echo ""

    echo "=== Vendor etc Directory ==="
    ls -la /vendor/etc/ 2>/dev/null | head -30
    echo ""

    echo "=== Vendor Permissions ==="
    ls -la /vendor/etc/permissions/ 2>/dev/null
    echo ""

    echo "=== Product Permissions ==="
    ls -la /product/etc/permissions/ 2>/dev/null
    echo ""

    echo "=== Custom Feature Definitions ==="
    for perm_dir in /vendor/etc/permissions /product/etc/permissions /system/etc/permissions; do
        if [ -d "$perm_dir" ]; then
            echo "Features in $perm_dir:"
            cat "$perm_dir"/*.xml 2>/dev/null | grep -oE 'name="[^"]+"' | sort -u | head -30 | sed 's/^/  /'
            echo ""
        fi
    done

    # =========================================================================
    # SECTION 8: Hidden/Diagnostic Features
    # =========================================================================
    
    echo "┌─────────────────────────────────────────────────────────────┐"
    echo "│ HIDDEN/DIAGNOSTIC FEATURES                                 │"
    echo "└─────────────────────────────────────────────────────────────┘"
    echo ""

    echo "=== Secret Dialer Codes ==="
    dumpsys package 2>/dev/null | grep -B10 "SECRET_CODE" | grep -E "package:|host=" | head -30
    echo ""

    echo "=== Factory Test/Engineering Packages ==="
    pm list packages 2>/dev/null | grep -iE "factory|engineer|test|diag|debug|ftm|cit|hidden|secret" | sort
    echo ""

    echo "=== Diagnostic Activities ==="
    dumpsys package 2>/dev/null | grep -iE "DiagActivity|FactoryTest|EngineerMode|HiddenMenu|ServiceMode" | head -20
    echo ""

    echo "=== Debug/Engineering Properties ==="
    getprop 2>/dev/null | grep -iE "factory|engineer|diag|ftm|test\.mode|debug\.mode" | head -20
    echo ""

    # =========================================================================
    # SECTION 9: OEM Security Components
    # =========================================================================
    
    echo "┌─────────────────────────────────────────────────────────────┐"
    echo "│ OEM SECURITY COMPONENTS                                    │"
    echo "└─────────────────────────────────────────────────────────────┘"
    echo ""

    echo "=== MDM/Enterprise Packages ==="
    pm list packages 2>/dev/null | grep -iE "mdm|knox|enterprise|device.?policy|device.?admin|afwkit" | sort
    echo ""

    echo "=== Security/Antivirus Packages ==="
    pm list packages 2>/dev/null | grep -iE "security|antivirus|guard|protect|safe|avast|avg|mcafee|norton|kaspersky|bitdefender" | sort
    echo ""

    echo "=== TEE/TrustZone Apps ==="
    ls -la /vendor/app/*trust* /vendor/app/*tee* /vendor/app/*secure* 2>/dev/null
    find /vendor -name "*.ta" -o -name "*.trustlet" 2>/dev/null | head -10
    echo ""

    echo "=== Secure Element Apps ==="
    pm list packages 2>/dev/null | grep -iE "secure.?element|nfc|ese|sim.?alliance" | sort
    echo ""

    # =========================================================================
    # SECTION 10: OEM Data Collection
    # =========================================================================
    
    echo "┌─────────────────────────────────────────────────────────────┐"
    echo "│ OEM DATA COLLECTION/ANALYTICS                              │"
    echo "└─────────────────────────────────────────────────────────────┘"
    echo ""

    echo "=== Analytics/Telemetry Packages ==="
    pm list packages 2>/dev/null | grep -iE "analytics|telemetry|statistics|metrics|usage|feedback|diagnostic|crash|bugly|umeng|flurry|appsflyer|adjust|branch" | sort
    echo ""

    echo "=== OEM Cloud Services ==="
    pm list packages 2>/dev/null | grep -iE "cloud|sync|backup|account|login|sso" | grep -iE "samsung|huawei|xiaomi|oppo|vivo|$MANUFACTURER" | sort
    echo ""

    # =========================================================================
    # SECTION 11: Non-Standard Permissions
    # =========================================================================
    
    echo "┌─────────────────────────────────────────────────────────────┐"
    echo "│ OEM CUSTOM PERMISSIONS                                     │"
    echo "└─────────────────────────────────────────────────────────────┘"
    echo ""

    echo "=== Vendor-Defined Permissions ==="
    dumpsys package 2>/dev/null | grep -E "permission.*vendor|permission.*oem|permission.*$MANUFACTURER" -i | head -30
    echo ""

    echo "=== Signature-Level Vendor Permissions ==="
    for perm_file in /vendor/etc/permissions/*.xml /product/etc/permissions/*.xml; do
        if [ -f "$perm_file" ]; then
            CUSTOM_PERMS=$(grep -oE 'android:name="[^"]+permission[^"]+"' "$perm_file" 2>/dev/null | grep -v "android.permission")
            if [ -n "$CUSTOM_PERMS" ]; then
                echo "From $(basename "$perm_file"):"
                echo "$CUSTOM_PERMS" | head -10 | sed 's/^/  /'
            fi
        fi
    done
    echo ""

    # =========================================================================
    # SECTION 12: Bootloader/Recovery Customizations
    # =========================================================================
    
    echo "┌─────────────────────────────────────────────────────────────┐"
    echo "│ BOOTLOADER/RECOVERY CUSTOMIZATIONS                         │"
    echo "└─────────────────────────────────────────────────────────────┘"
    echo ""

    echo "=== OEM Partitions ==="
    ls -la /dev/block/by-name/ 2>/dev/null | grep -iE "oem|vendor|odm|product|cust|preload|carrier|oppo|vivo|xiaomi|samsung" | head -20
    echo ""

    echo "=== Custom Recovery ==="
    getprop 2>/dev/null | grep -iE "recovery|twrp|cwm|orange.?fox|pitch.?black" | head -10
    echo ""

    # =========================================================================
    # SECTION 13: Network/Carrier Customizations
    # =========================================================================
    
    echo "┌─────────────────────────────────────────────────────────────┐"
    echo "│ CARRIER/NETWORK CUSTOMIZATIONS                             │"
    echo "└─────────────────────────────────────────────────────────────┘"
    echo ""

    echo "=== Carrier Packages ==="
    pm list packages 2>/dev/null | grep -iE "carrier|mcc|mnc|plmn|operator|sprint|verizon|att|tmobile|vodafone|china.?mobile|china.?unicom|china.?telecom" | sort | head -20
    echo ""

    echo "=== Carrier Properties ==="
    getprop 2>/dev/null | grep -iE "carrier|operator|mcc|mnc|plmn|ril\." | head -20
    echo ""

    echo "=== APN Configurations ==="
    if [ -f /system/etc/apns-conf.xml ]; then
        echo "System APNs present: /system/etc/apns-conf.xml"
        wc -l /system/etc/apns-conf.xml
    fi
    if [ -f /vendor/etc/apns-conf.xml ]; then
        echo "Vendor APNs present: /vendor/etc/apns-conf.xml"
    fi
    echo ""

    # =========================================================================
    # SECTION 14: Summary
    # =========================================================================
    
    echo "┌─────────────────────────────────────────────────────────────┐"
    echo "│ VENDOR CUSTOMIZATION SUMMARY                               │"
    echo "└─────────────────────────────────────────────────────────────┘"
    echo ""

    # Count various customizations
    VENDOR_APPS=$(ls /vendor/app /vendor/priv-app 2>/dev/null | wc -l)
    PRODUCT_APPS=$(ls /product/app /product/priv-app 2>/dev/null | wc -l)
    OEM_PACKAGES=$(pm list packages 2>/dev/null | grep -icE "vendor|oem|$MANUFACTURER")
    VENDOR_SERVICES=$(service list 2>/dev/null | grep -icE "vendor|$MANUFACTURER")
    HIDDEN_MENUS=$(pm list packages 2>/dev/null | grep -icE "factory|engineer|hidden|diag")

    echo "Device: $(getprop ro.product.manufacturer) $(getprop ro.product.model)"
    echo ""
    echo "Customization Statistics:"
    echo "  Vendor/ODM Apps:         ~$VENDOR_APPS"
    echo "  Product Apps:            ~$PRODUCT_APPS"
    echo "  OEM Packages:            ~$OEM_PACKAGES"
    echo "  Vendor Services:         ~$VENDOR_SERVICES"
    echo "  Hidden/Diag Menus:       ~$HIDDEN_MENUS"
    echo ""

    if [ "$HIDDEN_MENUS" -gt 0 ]; then
        echo "██ [INFO] Hidden/diagnostic menus detected"
        echo "  These may provide access to undocumented features"
    fi
    echo ""

    echo "Security Recommendations:"
    echo "  1. Audit OEM packages for unnecessary permissions"
    echo "  2. Review hidden/engineering menus for security risks"
    echo "  3. Check OEM analytics for privacy concerns"
    echo "  4. Verify MDM/enterprise components if unexpected"
    echo "  5. Test secret dialer codes for hidden functionality"
    echo ""

} > "${OUTPUT_FILE}" 2>&1

echo "[+] Vendor customizations enumeration saved to: ${OUTPUT_FILE}"
