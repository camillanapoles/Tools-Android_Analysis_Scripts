#!/system/bin/sh
# DROID FORENSIC - Input Device & Key Mapping Enumeration
# Enumerates /dev/input devices, kernel input events, and key mapping configurations
# Usage: sh 38_enum_input_devices.sh [output_directory]

OUTPUT_DIR="${1:-.}"
OUTPUT_FILE="${OUTPUT_DIR}/input_devices.txt"

echo "[*] Enumerating input devices and key mappings..."

{
    echo "═══════════════════════════════════════════════════════════════"
    echo "  INPUT DEVICE & KEY MAPPING ENUMERATION"
    echo "  Timestamp: $(date)"
    echo "═══════════════════════════════════════════════════════════════"
    echo ""
    echo "Input devices can be vectors for keylogging, injection attacks,"
    echo "and unauthorized input simulation. Custom key mappings may expose"
    echo "hidden functionality or debug modes."
    echo ""

    # =========================================================================
    # SECTION 1: /dev/input Device Enumeration
    # =========================================================================
    
    echo "┌─────────────────────────────────────────────────────────────┐"
    echo "│ /dev/input DEVICE ENUMERATION                              │"
    echo "└─────────────────────────────────────────────────────────────┘"
    echo ""
    
    echo "=== Input Device Nodes ==="
    ls -la /dev/input/ 2>/dev/null
    echo ""

    # Event device details
    echo "=== Event Device Details (/proc/bus/input/devices) ==="
    if [ -f /proc/bus/input/devices ]; then
        cat /proc/bus/input/devices 2>/dev/null
    else
        echo "[Not available]"
    fi
    echo ""

    # =========================================================================
    # SECTION 2: getevent Enumeration
    # =========================================================================
    
    echo "┌─────────────────────────────────────────────────────────────┐"
    echo "│ KERNEL INPUT EVENT ENUMERATION (getevent)                  │"
    echo "└─────────────────────────────────────────────────────────────┘"
    echo ""

    # Check if getevent is available
    if command -v getevent >/dev/null 2>&1; then
        echo "=== Input Device Properties (getevent -lp) ==="
        echo "Lists all input devices with their supported event types"
        echo ""
        getevent -lp 2>/dev/null
        echo ""
        
        echo "=== Input Device Summary (getevent -pl) ==="
        getevent -pl 2>/dev/null
        echo ""
        
        echo "=== Input Device Info (getevent -i) ==="
        getevent -i 2>/dev/null
        echo ""
        
        # Scan for specific device types
        echo "=== Detected Input Device Types ==="
        echo ""
        
        # Touchscreen devices
        echo "--- Touchscreen Devices ---"
        getevent -lp 2>/dev/null | grep -B 20 "ABS_MT_POSITION\|ABS_MT_TOUCH" | grep -E "^add device|name:" | sed 's/^/  /'
        echo ""
        
        # Keyboard devices
        echo "--- Keyboard Devices ---"
        getevent -lp 2>/dev/null | grep -B 20 "KEY_A\|KEY_ENTER\|KEY_SPACE" | grep -E "^add device|name:" | sed 's/^/  /'
        echo ""
        
        # Button/GPIO devices
        echo "--- Button/GPIO Devices ---"
        getevent -lp 2>/dev/null | grep -B 20 "KEY_POWER\|KEY_VOLUMEUP\|KEY_VOLUMEDOWN\|KEY_HOME\|KEY_BACK" | grep -E "^add device|name:" | sed 's/^/  /'
        echo ""
        
        # Sensor devices
        echo "--- Sensor Input Devices ---"
        getevent -lp 2>/dev/null | grep -B 20 "ABS_MISC\|ABS_DISTANCE\|ABS_PRESSURE" | grep -E "^add device|name:" | sed 's/^/  /'
        echo ""
        
    else
        echo "[WARNING] getevent not available"
        echo "Falling back to /proc enumeration..."
    fi

    # =========================================================================
    # SECTION 3: Key Layout Files (.kl)
    # =========================================================================
    
    echo "┌─────────────────────────────────────────────────────────────┐"
    echo "│ KEY LAYOUT FILES (.kl)                                     │"
    echo "└─────────────────────────────────────────────────────────────┘"
    echo ""
    echo "Key layout files map Linux input codes to Android key codes."
    echo "Custom layouts may enable hidden keys or debug functions."
    echo ""

    KL_DIRS="/system/usr/keylayout /vendor/usr/keylayout /odm/usr/keylayout /product/usr/keylayout /data/system/devices/keylayout"
    
    for kl_dir in $KL_DIRS; do
        if [ -d "$kl_dir" ]; then
            echo "═══════════════════════════════════════════════════════════"
            echo "Directory: $kl_dir"
            echo "═══════════════════════════════════════════════════════════"
            ls -la "$kl_dir" 2>/dev/null
            echo ""
            
            # Analyze each key layout file
            for kl_file in "$kl_dir"/*.kl; do
                if [ -f "$kl_file" ]; then
                    KL_NAME=$(basename "$kl_file")
                    echo "--- $KL_NAME ---"
                    
                    # Count key mappings
                    KEY_COUNT=$(grep -c "^key " "$kl_file" 2>/dev/null || echo "0")
                    AXIS_COUNT=$(grep -c "^axis " "$kl_file" 2>/dev/null || echo "0")
                    echo "  Key mappings: $KEY_COUNT"
                    echo "  Axis mappings: $AXIS_COUNT"
                    
                    # Check for interesting mappings
                    echo "  Special keys defined:"
                    grep -iE "POWER|VOLUME|HOME|BACK|MENU|SEARCH|CAMERA|FOCUS|APP_SWITCH|ASSIST|VOICE_ASSIST|SYSRQ|BREAK" "$kl_file" 2>/dev/null | head -10 | sed 's/^/    /'
                    
                    # Check for hidden/debug keys
                    echo "  Debug/Hidden keys:"
                    grep -iE "DEBUG|TEST|FACTORY|ENGINEER|HIDDEN|SECRET|DIAG|FTM" "$kl_file" 2>/dev/null | head -5 | sed 's/^/    /'
                    
                    # Check for function keys
                    echo "  Function keys (F1-F12):"
                    grep -E "KEY_F[0-9]+" "$kl_file" 2>/dev/null | head -5 | sed 's/^/    /'
                    
                    echo ""
                fi
            done
        fi
    done

    # =========================================================================
    # SECTION 4: Key Character Map Files (.kcm)
    # =========================================================================
    
    echo "┌─────────────────────────────────────────────────────────────┐"
    echo "│ KEY CHARACTER MAP FILES (.kcm)                             │"
    echo "└─────────────────────────────────────────────────────────────┘"
    echo ""
    echo "Character maps define how key presses translate to characters."
    echo ""

    KCM_DIRS="/system/usr/keychars /vendor/usr/keychars /odm/usr/keychars /product/usr/keychars /data/system/devices/keychars"
    
    for kcm_dir in $KCM_DIRS; do
        if [ -d "$kcm_dir" ]; then
            echo "═══════════════════════════════════════════════════════════"
            echo "Directory: $kcm_dir"
            echo "═══════════════════════════════════════════════════════════"
            ls -la "$kcm_dir" 2>/dev/null
            echo ""
            
            for kcm_file in "$kcm_dir"/*.kcm; do
                if [ -f "$kcm_file" ]; then
                    KCM_NAME=$(basename "$kcm_file")
                    echo "--- $KCM_NAME ---"
                    
                    # Show keyboard type
                    grep "^type " "$kcm_file" 2>/dev/null | sed 's/^/  /'
                    
                    # Count character mappings
                    CHAR_COUNT=$(grep -c "^key " "$kcm_file" 2>/dev/null || echo "0")
                    echo "  Character mappings: $CHAR_COUNT"
                    
                    # Show first few mappings as sample
                    echo "  Sample mappings:"
                    grep "^key " "$kcm_file" 2>/dev/null | head -5 | sed 's/^/    /'
                    echo ""
                fi
            done
        fi
    done

    # =========================================================================
    # SECTION 5: Input Device Configuration Files (.idc)
    # =========================================================================
    
    echo "┌─────────────────────────────────────────────────────────────┐"
    echo "│ INPUT DEVICE CONFIGURATION FILES (.idc)                    │"
    echo "└─────────────────────────────────────────────────────────────┘"
    echo ""
    echo "IDC files configure touch screens, trackpads, and other inputs."
    echo ""

    IDC_DIRS="/system/usr/idc /vendor/usr/idc /odm/usr/idc /product/usr/idc /data/system/devices/idc"
    
    for idc_dir in $IDC_DIRS; do
        if [ -d "$idc_dir" ]; then
            echo "═══════════════════════════════════════════════════════════"
            echo "Directory: $idc_dir"
            echo "═══════════════════════════════════════════════════════════"
            ls -la "$idc_dir" 2>/dev/null
            echo ""
            
            for idc_file in "$idc_dir"/*.idc; do
                if [ -f "$idc_file" ]; then
                    IDC_NAME=$(basename "$idc_file")
                    echo "--- $IDC_NAME ---"
                    
                    # Show device type and properties
                    grep -E "^device\.|^touch\.|^keyboard\." "$idc_file" 2>/dev/null | head -15 | sed 's/^/  /'
                    echo ""
                fi
            done
        fi
    done

    # =========================================================================
    # SECTION 6: Virtual Key Definitions
    # =========================================================================
    
    echo "┌─────────────────────────────────────────────────────────────┐"
    echo "│ VIRTUAL KEY DEFINITIONS                                    │"
    echo "└─────────────────────────────────────────────────────────────┘"
    echo ""
    echo "Virtual keys are touch-sensitive areas mapped to hardware keys."
    echo ""

    # Check for virtualkeys files
    VKEY_DIRS="/sys/board_properties/virtualkeys /sys/devices"
    
    echo "=== /sys Virtual Key Files ==="
    find /sys -name "virtualkeys*" -type f 2>/dev/null | while read vkey_file; do
        echo "File: $vkey_file"
        cat "$vkey_file" 2>/dev/null | sed 's/^/  /'
        echo ""
    done

    # Check for virtual key configs in firmware
    echo "=== Firmware Virtual Key Configs ==="
    for dir in /system/etc /vendor/etc /odm/etc; do
        find "$dir" -name "*virtual*key*" -type f 2>/dev/null | while read vkey_file; do
            echo "File: $vkey_file"
            cat "$vkey_file" 2>/dev/null | head -20 | sed 's/^/  /'
            echo ""
        done
    done

    # =========================================================================
    # SECTION 7: Input Method Information
    # =========================================================================
    
    echo "┌─────────────────────────────────────────────────────────────┐"
    echo "│ INPUT METHOD (IME) INFORMATION                             │"
    echo "└─────────────────────────────────────────────────────────────┘"
    echo ""

    echo "=== Installed Input Methods ==="
    ime list -a 2>/dev/null || pm list packages -f 2>/dev/null | grep -iE "keyboard|input|ime"
    echo ""

    echo "=== Current Input Method ==="
    settings get secure default_input_method 2>/dev/null
    echo ""

    echo "=== Enabled Input Methods ==="
    settings get secure enabled_input_methods 2>/dev/null
    echo ""

    # =========================================================================
    # SECTION 8: Input Device Permissions & Security
    # =========================================================================
    
    echo "┌─────────────────────────────────────────────────────────────┐"
    echo "│ INPUT DEVICE SECURITY ANALYSIS                             │"
    echo "└─────────────────────────────────────────────────────────────┘"
    echo ""

    echo "=== /dev/input Permissions ==="
    ls -la /dev/input/ 2>/dev/null | while read line; do
        # Check for overly permissive devices
        if echo "$line" | grep -qE "^crw.{6}rw|^crw.{3}rw"; then
            echo "[WARNING] World-accessible: $line"
        else
            echo "$line"
        fi
    done
    echo ""

    echo "=== Input Device SELinux Contexts ==="
    ls -laZ /dev/input/ 2>/dev/null
    echo ""

    echo "=== Input Device Group Ownership ==="
    echo "Devices readable by 'input' group can be accessed by apps with INPUT permission"
    ls -la /dev/input/ 2>/dev/null | grep "input" | head -20
    echo ""

    # =========================================================================
    # SECTION 9: Hardware Key Mapping Analysis
    # =========================================================================
    
    echo "┌─────────────────────────────────────────────────────────────┐"
    echo "│ HARDWARE KEY CODE ANALYSIS                                 │"
    echo "└─────────────────────────────────────────────────────────────┘"
    echo ""

    echo "=== Scancode to Keycode Mappings (from active .kl files) ==="
    echo "Looking for non-standard or suspicious mappings..."
    echo ""

    # Find all loaded key layouts and check for unusual mappings
    for kl_dir in $KL_DIRS; do
        if [ -d "$kl_dir" ]; then
            for kl_file in "$kl_dir"/*.kl; do
                if [ -f "$kl_file" ]; then
                    # Check for unusual key codes
                    UNUSUAL=$(grep -iE "UNKNOWN|RESERVED|VENDOR|CUSTOM|OEM|DEBUG|TEST|FACTORY" "$kl_file" 2>/dev/null)
                    if [ -n "$UNUSUAL" ]; then
                        echo "██ [INTERESTING] $(basename "$kl_file")"
                        echo "$UNUSUAL" | sed 's/^/  /'
                        echo ""
                    fi
                fi
            done
        fi
    done

    echo "=== Secret Code Key Combinations ==="
    echo "Checking for hidden key combinations in layouts..."
    for kl_dir in $KL_DIRS; do
        if [ -d "$kl_dir" ]; then
            grep -rh "WAKE\|WAKEUP\|BOOT\|RECOVERY\|FASTBOOT\|DOWNLOAD\|SPECIAL" "$kl_dir" 2>/dev/null | sort -u | sed 's/^/  /'
        fi
    done
    echo ""

    # =========================================================================
    # SECTION 10: dumpsys Input Information
    # =========================================================================
    
    echo "┌─────────────────────────────────────────────────────────────┐"
    echo "│ ANDROID INPUT SYSTEM STATE (dumpsys)                       │"
    echo "└─────────────────────────────────────────────────────────────┘"
    echo ""

    echo "=== Input Devices (dumpsys input) ==="
    dumpsys input 2>/dev/null | sed -n '/Input Devices:/,/^[A-Z]/p' | head -100
    echo ""

    echo "=== Input Reader State ==="
    dumpsys input 2>/dev/null | sed -n '/Input Reader State:/,/Input Dispatcher State:/p' | head -50
    echo ""

    echo "=== Input Configuration ==="
    dumpsys input 2>/dev/null | sed -n '/Input Manager Service/,/Input Devices:/p' | head -30
    echo ""

    # =========================================================================
    # SECTION 11: Touchscreen Calibration
    # =========================================================================
    
    echo "┌─────────────────────────────────────────────────────────────┐"
    echo "│ TOUCHSCREEN CALIBRATION DATA                               │"
    echo "└─────────────────────────────────────────────────────────────┘"
    echo ""

    # Look for calibration files
    CALIB_LOCATIONS="/data/system /data/misc /persist /efs /mnt/vendor"
    
    for loc in $CALIB_LOCATIONS; do
        find "$loc" -name "*calib*" -o -name "*touch*" 2>/dev/null | grep -v ".apk\|.jar\|.so" | while read calib_file; do
            if [ -f "$calib_file" ]; then
                echo "Calibration file: $calib_file"
                ls -la "$calib_file" 2>/dev/null | sed 's/^/  /'
                # Show content if text
                if file "$calib_file" 2>/dev/null | grep -q "text\|ASCII"; then
                    head -10 "$calib_file" 2>/dev/null | sed 's/^/  /'
                fi
                echo ""
            fi
        done
    done

    # =========================================================================
    # SECTION 12: Summary
    # =========================================================================
    
    echo "┌─────────────────────────────────────────────────────────────┐"
    echo "│ SUMMARY                                                    │"
    echo "└─────────────────────────────────────────────────────────────┘"
    echo ""

    # Count devices and files
    INPUT_DEV_COUNT=$(ls /dev/input/event* 2>/dev/null | wc -l)
    KL_FILE_COUNT=$(find $KL_DIRS -name "*.kl" 2>/dev/null | wc -l)
    KCM_FILE_COUNT=$(find $KCM_DIRS -name "*.kcm" 2>/dev/null | wc -l)
    IDC_FILE_COUNT=$(find $IDC_DIRS -name "*.idc" 2>/dev/null | wc -l)

    echo "Input Statistics:"
    echo "  Event devices (/dev/input):  $INPUT_DEV_COUNT"
    echo "  Key layout files (.kl):      $KL_FILE_COUNT"
    echo "  Key character maps (.kcm):   $KCM_FILE_COUNT"
    echo "  Input device configs (.idc): $IDC_FILE_COUNT"
    echo ""

    # Security observations
    WORLD_READABLE=$(ls -la /dev/input/ 2>/dev/null | grep -cE "^crw.{6}rw|^crw.{3}rw")
    if [ "$WORLD_READABLE" -gt 0 ]; then
        echo "[WARNING] $WORLD_READABLE input devices are world-accessible"
        echo "  Risk: Any app could potentially read input events (keylogger risk)"
    fi
    echo ""

    echo "Key Mapping Analysis:"
    echo "  Review .kl files for hidden debug keys or factory modes"
    echo "  Check for non-standard VENDOR/OEM key codes"
    echo "  Verify virtual key mappings match physical layout"
    echo ""

    echo "Security Recommendations:"
    echo "  1. Restrict /dev/input permissions to 'input' group only"
    echo "  2. Remove debug/factory key mappings from production builds"
    echo "  3. Audit custom key layouts for hidden functionality"
    echo "  4. Monitor for unauthorized input device access"
    echo ""

} > "${OUTPUT_FILE}" 2>&1

echo "[+] Input device enumeration saved to: ${OUTPUT_FILE}"
