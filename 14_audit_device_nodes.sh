#!/system/bin/sh
# 14_audit_device_nodes.sh
# Android Device Node Security Audit
# Enumeration of /dev, /dev/socket, /dev/block with permission analysis
# Detects world-writable char/block devices, readable sensitive nodes, vendor-specific risks

OUTPUT_DIR="${1:-.}"
OUTPUT_FILE="${OUTPUT_DIR}/device_nodes.txt"

echo "[*] Auditing device nodes..."

{
    echo "┌─────────────────────────────────────────────────────────────┐"
    echo "│ ANDROID DEVICE NODE SECURITY AUDIT                          │"
    echo "└─────────────────────────────────────────────────────────────┘"
    echo ""
    echo "Timestamp: $(date '+%Y-%m-%d %H:%M:%S')"
    echo "Device: $(getprop ro.product.model 2>/dev/null || echo 'Unknown')"
    echo ""

    # ─────────────────────────────────────────────────────────────
    echo "┌─────────────────────────────────────────────────────────────┐"
    echo "│ SECTION 1: /dev OVERVIEW                                    │"
    echo "└─────────────────────────────────────────────────────────────┘"
    echo ""

    echo "[*] Total device nodes in /dev:"
    dev_count=$(ls /dev 2>/dev/null | wc -l)
    echo "    ${dev_count} entries"
    echo ""

    echo "[*] Character vs Block device counts:"
    char_count=$(find /dev -maxdepth 1 -type c 2>/dev/null | wc -l)
    block_count=$(find /dev -maxdepth 1 -type b 2>/dev/null | wc -l)
    echo "    Character devices: ${char_count}"
    echo "    Block devices: ${block_count}"
    echo ""

    echo "[*] Full /dev listing (ls -la /dev):"
    echo "────────────────────────────────────────"
    ls -la /dev 2>/dev/null | head -60
    echo ""
    if [ "$(ls /dev 2>/dev/null | wc -l)" -gt 60 ]; then
        echo "    ... ($(expr $dev_count - 60) more entries)"
    fi
    echo ""

    # ─────────────────────────────────────────────────────────────
    echo "┌─────────────────────────────────────────────────────────────┐"
    echo "│ SECTION 2: WORLD-WRITABLE DEVICE NODES [CRITICAL]          │"
    echo "└─────────────────────────────────────────────────────────────┘"
    echo ""

    echo "[*] Scanning for world-writable character devices..."
    world_writable_char=$(find /dev -maxdepth 1 -perm -002 -type c 2>/dev/null)

    if [ -z "$world_writable_char" ]; then
        echo "    [OK] No world-writable character devices found"
    else
        echo "    [CRITICAL] Found world-writable character device(s):"
        for device in $world_writable_char; do
            echo ""
            echo "      Device: $device"
            ls -la "$device" 2>/dev/null | sed 's/^/        /'
            if command -v ls >/dev/null 2>&1 && ls -Z "$device" >/dev/null 2>&1; then
                echo "        SELinux context:"
                ls -Z "$device" 2>/dev/null | sed 's/^/          /'
            fi
        done
    fi
    echo ""

    echo "[*] Scanning for world-writable block devices..."
    world_writable_block=$(find /dev -maxdepth 1 -perm -002 -type b 2>/dev/null)

    if [ -z "$world_writable_block" ]; then
        echo "    [OK] No world-writable block devices found"
    else
        echo "    [CRITICAL] Found world-writable block device(s):"
        for device in $world_writable_block; do
            echo ""
            echo "      Device: $device"
            ls -la "$device" 2>/dev/null | sed 's/^/        /'
            if command -v ls >/dev/null 2>&1 && ls -Z "$device" >/dev/null 2>&1; then
                echo "        SELinux context:"
                ls -Z "$device" 2>/dev/null | sed 's/^/          /'
            fi
        done
    fi
    echo ""

    # ─────────────────────────────────────────────────────────────
    echo "┌─────────────────────────────────────────────────────────────┐"
    echo "│ SECTION 3: WORLD-READABLE SENSITIVE DEVICES [HIGH]         │"
    echo "└─────────────────────────────────────────────────────────────┘"
    echo ""

    sensitive_devices="/dev/mem /dev/kmem /dev/port /dev/kcore"
    risk_found=0

    for device in $sensitive_devices; do
        if [ -e "$device" ]; then
            echo "[*] Checking $device:"
            perms=$(ls -la "$device" 2>/dev/null | awk '{print $1}')

            # Check if world-readable (last char 'r' in permissions)
            if echo "$perms" | grep -q '...r$'; then
                echo "    [HIGH] Device is WORLD-READABLE:"
                risk_found=$((risk_found + 1))
            else
                echo "    [OK] Device is not world-readable:"
            fi

            ls -la "$device" 2>/dev/null | sed 's/^/      /'
            echo ""
        fi
    done

    if [ $risk_found -eq 0 ]; then
        echo "[OK] No world-readable sensitive devices found"
        echo ""
    fi

    # ─────────────────────────────────────────────────────────────
    echo "┌─────────────────────────────────────────────────────────────┐"
    echo "│ SECTION 4: ALLWINNER-SPECIFIC DEVICE NODES [HIGH]          │"
    echo "└─────────────────────────────────────────────────────────────┘"
    echo ""

    echo "[*] Scanning for Allwinner vendor-specific devices..."
    echo "    Note: World-accessible Allwinner media/GPU nodes have"
    echo "          historically enabled privilege escalation"
    echo ""

    allwinner_devices="cedar_dev sunxi_cedar_dev disp g2d ion ump mali mali0 mali_kbase ve sunxi_gmac sunxi_emac"
    allwinner_found=0

    for dev_name in $allwinner_devices; do
        if [ -e "/dev/$dev_name" ]; then
            allwinner_found=$((allwinner_found + 1))
            echo "[*] Found: /dev/$dev_name"

            perms=$(ls -la "/dev/$dev_name" 2>/dev/null | awk '{print $1}')

            # Check world-readable or world-writable
            if echo "$perms" | grep -q '...r$' || echo "$perms" | grep -q '..w$'; then
                echo "    [HIGH] RISK: Device is world-accessible"
            else
                echo "    [INFO] Device not world-accessible"
            fi

            ls -la "/dev/$dev_name" 2>/dev/null | sed 's/^/      /'

            if command -v ls >/dev/null 2>&1 && ls -Z "/dev/$dev_name" >/dev/null 2>&1; then
                echo "    SELinux context:"
                ls -Z "/dev/$dev_name" 2>/dev/null | sed 's/^/      /'
            fi
            echo ""
        fi
    done

    if [ $allwinner_found -eq 0 ]; then
        echo "[OK] No Allwinner-specific device nodes found (expected on non-Allwinner SoCs)"
        echo ""
    else
        echo "[INFO] Found ${allwinner_found} Allwinner vendor device(s)"
        echo ""
    fi

    # ─────────────────────────────────────────────────────────────
    echo "┌─────────────────────────────────────────────────────────────┐"
    echo "│ SECTION 5: /dev/socket AUDIT                               │"
    echo "└─────────────────────────────────────────────────────────────┘"
    echo ""

    if [ -d /dev/socket ]; then
        echo "[*] Unix domain sockets in /dev/socket:"
        ls -la /dev/socket 2>/dev/null | head -30
        echo ""

        if [ "$(ls /dev/socket 2>/dev/null | wc -l)" -gt 30 ]; then
            extra=$(($(ls /dev/socket 2>/dev/null | wc -l) - 30))
            echo "    ... (${extra} more sockets)"
            echo ""
        fi

        socket_risks=$(find /dev/socket -perm -002 -o -perm -004 2>/dev/null)
        if [ -n "$socket_risks" ]; then
            echo "[HIGH] World-accessible socket(s) detected:"
            for socket in $socket_risks; do
                echo "    $(ls -la "$socket" 2>/dev/null | awk '{print $9, "(" $1 ")"}')"
            done
            echo ""
        else
            echo "[OK] No world-accessible sockets in /dev/socket"
            echo ""
        fi
    else
        echo "[INFO] /dev/socket directory not present"
        echo ""
    fi

    # ─────────────────────────────────────────────────────────────
    echo "┌─────────────────────────────────────────────────────────────┐"
    echo "│ SECTION 6: BLOCK DEVICES                                   │"
    echo "└─────────────────────────────────────────────────────────────┘"
    echo ""

    if [ -d /dev/block ]; then
        echo "[*] Block devices in /dev/block:"
        ls -la /dev/block 2>/dev/null | head -50
        echo ""

        echo "[*] Scanning for world-accessible block devices..."
        world_readable_blocks=$(find /dev/block -type b -perm -004 2>/dev/null)
        world_writable_blocks=$(find /dev/block -type b -perm -002 2>/dev/null)

        if [ -n "$world_readable_blocks" ]; then
            echo "[CRITICAL] World-readable block device(s):"
            for device in $world_readable_blocks; do
                echo "    $(ls -la "$device" 2>/dev/null)"
            done
            echo ""
        fi

        if [ -n "$world_writable_blocks" ]; then
            echo "[CRITICAL] World-writable block device(s):"
            for device in $world_writable_blocks; do
                echo "    $(ls -la "$device" 2>/dev/null)"
            done
            echo ""
        fi

        if [ -z "$world_readable_blocks" ] && [ -z "$world_writable_blocks" ]; then
            echo "[OK] No world-accessible block devices found"
            echo ""
        fi
    else
        echo "[INFO] /dev/block directory not present"
        echo ""
    fi

    # ─────────────────────────────────────────────────────────────
    echo "┌─────────────────────────────────────────────────────────────┐"
    echo "│ SECTION 7: UNUSUAL/SUSPICIOUS DEVICE NODES                 │"
    echo "└─────────────────────────────────────────────────────────────┘"
    echo ""

    echo "[*] Character devices (excluding /dev/block and /dev/socket):"
    unusual_devices=$(find /dev -maxdepth 1 -not -path '/dev/block/*' -not -path '/dev/socket/*' -type c 2>/dev/null | sort)

    echo "$unusual_devices" | head -40 | while read device; do
        perms=$(ls -l "$device" 2>/dev/null | awk '{print $1}')
        owner=$(ls -l "$device" 2>/dev/null | awk '{print $3}')

        # Flag world-writable or unusual ownership
        if echo "$perms" | grep -q '.w$'; then
            echo "  [HIGH] $(basename "$device") - WORLD-WRITABLE ($perms, owner: $owner)"
        elif [ "$owner" != "root" ] && [ "$owner" != "system" ]; then
            echo "  [MEDIUM] $(basename "$device") - Unusual owner: $owner ($perms)"
        else
            echo "  [OK] $(basename "$device") ($perms, owner: $owner)"
        fi
    done
    echo ""

    echo "[*] Critical permission checks:"
    for critical_dev in /dev/ptmx /dev/tty /dev/console; do
        if [ -e "$critical_dev" ]; then
            perms=$(ls -la "$critical_dev" 2>/dev/null | awk '{print $1}')
            echo "  $critical_dev: $perms"
        fi
    done
    echo ""

    # ─────────────────────────────────────────────────────────────
    echo "┌─────────────────────────────────────────────────────────────┐"
    echo "│ SECTION 8: /proc/devices REGISTERED DEVICE MAJORS          │"
    echo "└─────────────────────────────────────────────────────────────┘"
    echo ""

    if [ -f /proc/devices ]; then
        echo "[*] Registered character devices:"
        sed -n '/^Character devices:/,/^Block devices:/p' /proc/devices 2>/dev/null | head -40
        echo ""
        echo "[*] Registered block devices:"
        sed -n '/^Block devices:/,$p' /proc/devices 2>/dev/null | head -40
        echo ""
    else
        echo "[INFO] /proc/devices not available"
        echo ""
    fi

    # ─────────────────────────────────────────────────────────────
    echo "┌─────────────────────────────────────────────────────────────┐"
    echo "│ SUMMARY & RISK ASSESSMENT                                   │"
    echo "└─────────────────────────────────────────────────────────────┘"
    echo ""

    # Count risks
    world_writable_all=$(find /dev -maxdepth 1 -perm -002 2>/dev/null | wc -l)
    world_readable_sensitive=0
    for device in /dev/mem /dev/kmem /dev/port /dev/kcore; do
        if [ -e "$device" ]; then
            perms=$(ls -la "$device" 2>/dev/null | awk '{print $1}')
            if echo "$perms" | grep -q '...r$'; then
                world_readable_sensitive=$((world_readable_sensitive + 1))
            fi
        fi
    done

    echo "[*] Audit Summary:"
    echo "    Total /dev entries: ${dev_count}"
    echo "    Character devices: ${char_count}"
    echo "    Block devices: ${block_count}"
    echo "    World-writable devices: ${world_writable_all}"
    echo "    World-readable sensitive devices: ${world_readable_sensitive}"
    echo "    Allwinner vendor nodes found: ${allwinner_found}"
    echo ""

    if [ $world_writable_all -gt 0 ]; then
        echo "[CRITICAL] Risk Level: CRITICAL - World-writable device(s) detected"
    elif [ $world_readable_sensitive -gt 0 ]; then
        echo "[HIGH] Risk Level: HIGH - World-readable sensitive device(s) detected"
    elif [ $allwinner_found -gt 0 ]; then
        echo "[HIGH] Risk Level: MEDIUM-HIGH - Allwinner vendor devices present"
    else
        echo "[OK] Risk Level: LOW - No major device node vulnerabilities detected"
    fi
    echo ""

    echo "─────────────────────────────────────────────────────────────"
    echo "End of Device Node Audit Report"
    echo "─────────────────────────────────────────────────────────────"

} > "${OUTPUT_FILE}" 2>&1

echo "[+] Device node audit saved to: ${OUTPUT_FILE}"
