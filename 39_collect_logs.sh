#!/system/bin/sh
# DROID FORENSIC - Forensic Log Collection
# Collects logcat, dmesg, tombstones, ANR traces, dropbox entries
# Usage: sh 39_collect_logs.sh [output_directory]

OUTPUT_DIR="${1:-.}"
OUTPUT_FILE="${OUTPUT_DIR}/forensic_logs.txt"

echo "[*] Collecting forensic logs..."

{
    echo "═══════════════════════════════════════════════════════════════"
    echo "  FORENSIC LOG COLLECTION"
    echo "  Timestamp: $(date)"
    echo "═══════════════════════════════════════════════════════════════"
    echo ""
    echo "Logs contain evidence of system events, crashes, security"
    echo "violations, and application behavior for forensic analysis."
    echo ""

    # =========================================================================
    # SECTION 1: System Logcat
    # =========================================================================
    
    echo "┌─────────────────────────────────────────────────────────────┐"
    echo "│ SYSTEM LOGCAT                                              │"
    echo "└─────────────────────────────────────────────────────────────┘"
    echo ""

    echo "=== Logcat Buffer Sizes ==="
    logcat -g 2>/dev/null
    echo ""

    echo "=== Recent System Log (last 500 lines) ==="
    logcat -d -b main -b system -t 500 2>/dev/null
    echo ""

    # =========================================================================
    # SECTION 2: Security-Related Logs
    # =========================================================================
    
    echo "┌─────────────────────────────────────────────────────────────┐"
    echo "│ SECURITY-RELATED LOG ENTRIES                               │"
    echo "└─────────────────────────────────────────────────────────────┘"
    echo ""

    echo "=== SELinux Denials (avc) ==="
    logcat -d -b all 2>/dev/null | grep -iE "avc.*denied|selinux" | tail -100
    echo ""

    echo "=== Security Events ==="
    logcat -d -b security 2>/dev/null | tail -200
    echo ""

    echo "=== Authentication Events ==="
    logcat -d 2>/dev/null | grep -iE "auth|login|password|credential|keyguard|lockscreen|fingerprint|biometric|face.?unlock" | tail -100
    echo ""

    echo "=== Permission Denials ==="
    logcat -d 2>/dev/null | grep -iE "permission.*denied|not allowed|security exception" | tail -100
    echo ""

    echo "=== Root/SU Activity ==="
    logcat -d 2>/dev/null | grep -iE "su\[|superuser|magisk|root" | tail -50
    echo ""

    # =========================================================================
    # SECTION 3: Kernel Ring Buffer (dmesg)
    # =========================================================================
    
    echo "┌─────────────────────────────────────────────────────────────┐"
    echo "│ KERNEL RING BUFFER (dmesg)                                 │"
    echo "└─────────────────────────────────────────────────────────────┘"
    echo ""

    echo "=== Full dmesg Output ==="
    dmesg 2>/dev/null | tail -500
    echo ""

    echo "=== Kernel Security Messages ==="
    dmesg 2>/dev/null | grep -iE "selinux|audit|security|violation|denied|panic|oops|bug|warning" | tail -100
    echo ""

    echo "=== USB Events ==="
    dmesg 2>/dev/null | grep -iE "usb|gadget|udc|otg" | tail -50
    echo ""

    echo "=== Storage Events ==="
    dmesg 2>/dev/null | grep -iE "mmc|emmc|ufs|sdcard|partition|mount" | tail -50
    echo ""

    # =========================================================================
    # SECTION 4: Tombstones (Native Crashes)
    # =========================================================================
    
    echo "┌─────────────────────────────────────────────────────────────┐"
    echo "│ TOMBSTONES (Native Crashes)                                │"
    echo "└─────────────────────────────────────────────────────────────┘"
    echo ""

    TOMBSTONE_DIR="/data/tombstones"
    
    if [ -d "$TOMBSTONE_DIR" ]; then
        echo "=== Tombstone Directory Listing ==="
        ls -la "$TOMBSTONE_DIR" 2>/dev/null
        echo ""
        
        TOMBSTONE_COUNT=$(ls "$TOMBSTONE_DIR" 2>/dev/null | wc -l)
        echo "Total tombstones: $TOMBSTONE_COUNT"
        echo ""
        
        # Show recent tombstones
        echo "=== Recent Tombstones (Headers) ==="
        for tomb in $(ls -t "$TOMBSTONE_DIR" 2>/dev/null | head -5); do
            echo "--- $tomb ---"
            head -50 "$TOMBSTONE_DIR/$tomb" 2>/dev/null
            echo ""
        done
    else
        echo "Tombstone directory not accessible"
    fi
    echo ""

    # =========================================================================
    # SECTION 5: ANR Traces
    # =========================================================================
    
    echo "┌─────────────────────────────────────────────────────────────┐"
    echo "│ ANR TRACES (Application Not Responding)                    │"
    echo "└─────────────────────────────────────────────────────────────┘"
    echo ""

    ANR_PATHS="/data/anr /data/system/anr"
    
    for anr_dir in $ANR_PATHS; do
        if [ -d "$anr_dir" ]; then
            echo "=== ANR Directory: $anr_dir ==="
            ls -la "$anr_dir" 2>/dev/null
            echo ""
            
            # Show recent ANR traces
            echo "=== Recent ANR Traces (Headers) ==="
            for anr in $(ls -t "$anr_dir"/*.txt "$anr_dir"/anr_* 2>/dev/null | head -3); do
                echo "--- $(basename "$anr") ---"
                head -100 "$anr" 2>/dev/null
                echo ""
            done
        fi
    done
    echo ""

    # =========================================================================
    # SECTION 6: Dropbox (System Event Archive)
    # =========================================================================
    
    echo "┌─────────────────────────────────────────────────────────────┐"
    echo "│ DROPBOX (System Event Archive)                             │"
    echo "└─────────────────────────────────────────────────────────────┘"
    echo ""

    DROPBOX_DIR="/data/system/dropbox"
    
    if [ -d "$DROPBOX_DIR" ]; then
        echo "=== Dropbox Directory Listing ==="
        ls -la "$DROPBOX_DIR" 2>/dev/null | tail -50
        echo ""
        
        echo "=== Dropbox Entry Types ==="
        ls "$DROPBOX_DIR" 2>/dev/null | sed 's/@[0-9]*$//' | sort | uniq -c | sort -rn | head -20
        echo ""
        
        # Interesting dropbox entries
        echo "=== Recent Crash Entries ==="
        ls -t "$DROPBOX_DIR"/*crash* "$DROPBOX_DIR"/*CRASH* 2>/dev/null | head -5 | while read f; do
            echo "--- $(basename "$f") ---"
            # Decompress if gzipped
            if echo "$f" | grep -q "\.gz$"; then
                zcat "$f" 2>/dev/null | head -50
            else
                head -50 "$f" 2>/dev/null
            fi
            echo ""
        done
        
        echo "=== Recent ANR Entries ==="
        ls -t "$DROPBOX_DIR"/*anr* "$DROPBOX_DIR"/*ANR* 2>/dev/null | head -3 | while read f; do
            echo "--- $(basename "$f") ---"
            if echo "$f" | grep -q "\.gz$"; then
                zcat "$f" 2>/dev/null | head -50
            else
                head -50 "$f" 2>/dev/null
            fi
            echo ""
        done

        echo "=== Recent Wtf (What a Terrible Failure) Entries ==="
        ls -t "$DROPBOX_DIR"/*wtf* "$DROPBOX_DIR"/*WTF* 2>/dev/null | head -3 | while read f; do
            echo "--- $(basename "$f") ---"
            if echo "$f" | grep -q "\.gz$"; then
                zcat "$f" 2>/dev/null | head -30
            else
                head -30 "$f" 2>/dev/null
            fi
            echo ""
        done
        
    else
        echo "Dropbox directory not accessible"
    fi
    echo ""

    # =========================================================================
    # SECTION 7: Event Log
    # =========================================================================
    
    echo "┌─────────────────────────────────────────────────────────────┐"
    echo "│ EVENT LOG                                                  │"
    echo "└─────────────────────────────────────────────────────────────┘"
    echo ""

    echo "=== Recent Events (logcat -b events) ==="
    logcat -d -b events -t 200 2>/dev/null
    echo ""

    echo "=== Activity Manager Events ==="
    logcat -d -b events 2>/dev/null | grep -E "am_|activity_" | tail -100
    echo ""

    echo "=== Package Manager Events ==="
    logcat -d -b events 2>/dev/null | grep -E "pm_|package_" | tail -50
    echo ""

    # =========================================================================
    # SECTION 8: Radio/Modem Logs
    # =========================================================================
    
    echo "┌─────────────────────────────────────────────────────────────┐"
    echo "│ RADIO/MODEM LOGS                                           │"
    echo "└─────────────────────────────────────────────────────────────┘"
    echo ""

    echo "=== Radio Log (last 200 entries) ==="
    logcat -d -b radio -t 200 2>/dev/null
    echo ""

    # =========================================================================
    # SECTION 9: Crash Reports
    # =========================================================================
    
    echo "┌─────────────────────────────────────────────────────────────┐"
    echo "│ CRASH REPORTS                                              │"
    echo "└─────────────────────────────────────────────────────────────┘"
    echo ""

    echo "=== Recent Crash Logs ==="
    logcat -d 2>/dev/null | grep -iE "fatal|crash|exception|died|killing" | tail -100
    echo ""

    echo "=== Java Exceptions ==="
    logcat -d 2>/dev/null | grep -A5 "FATAL EXCEPTION" | tail -100
    echo ""

    echo "=== Native Crashes ==="
    logcat -d 2>/dev/null | grep -iE "signal.*SIGSEGV|signal.*SIGABRT|signal.*SIGBUS|DEBUG.*:.*pid" | tail -50
    echo ""

    # =========================================================================
    # SECTION 10: Boot Logs
    # =========================================================================
    
    echo "┌─────────────────────────────────────────────────────────────┐"
    echo "│ BOOT LOGS                                                  │"
    echo "└─────────────────────────────────────────────────────────────┘"
    echo ""

    echo "=== Last Boot Time ==="
    uptime 2>/dev/null
    echo ""

    echo "=== Boot Completed Events ==="
    logcat -d -b events 2>/dev/null | grep -iE "boot|startup|BOOT_COMPLETED" | tail -30
    echo ""

    echo "=== Init Service Startups ==="
    logcat -d 2>/dev/null | grep -E "init.*starting|init.*service" | tail -50
    echo ""

    # Check for last_kmsg
    echo "=== Last Kernel Messages (if available) ==="
    for last_log in /sys/fs/pstore/console-ramoops* /proc/last_kmsg /data/last_kmsg; do
        if [ -f "$last_log" ]; then
            echo "Found: $last_log"
            tail -100 "$last_log" 2>/dev/null
            echo ""
        fi
    done

    # =========================================================================
    # SECTION 11: Network Logs
    # =========================================================================
    
    echo "┌─────────────────────────────────────────────────────────────┐"
    echo "│ NETWORK LOGS                                               │"
    echo "└─────────────────────────────────────────────────────────────┘"
    echo ""

    echo "=== WiFi Events ==="
    logcat -d 2>/dev/null | grep -iE "wifi|wlan|wpa_supplicant|hostapd" | tail -100
    echo ""

    echo "=== Bluetooth Events ==="
    logcat -d 2>/dev/null | grep -iE "bluetooth|bt_|bluedroid" | tail -50
    echo ""

    echo "=== Network Connectivity ==="
    logcat -d 2>/dev/null | grep -iE "connectivity|network|mobile.?data|LTE|5G|NR" | tail -50
    echo ""

    # =========================================================================
    # SECTION 12: Audit Log
    # =========================================================================
    
    echo "┌─────────────────────────────────────────────────────────────┐"
    echo "│ AUDIT LOG                                                  │"
    echo "└─────────────────────────────────────────────────────────────┘"
    echo ""

    echo "=== Kernel Audit Messages ==="
    dmesg 2>/dev/null | grep -E "audit|AUDIT" | tail -100
    echo ""

    echo "=== Audit Events from Logcat ==="
    logcat -d 2>/dev/null | grep -iE "audit" | tail -100
    echo ""

    # =========================================================================
    # SECTION 13: Application Logs (Suspicious)
    # =========================================================================
    
    echo "┌─────────────────────────────────────────────────────────────┐"
    echo "│ SUSPICIOUS APPLICATION ACTIVITY                            │"
    echo "└─────────────────────────────────────────────────────────────┘"
    echo ""

    echo "=== Potential Data Exfiltration ==="
    logcat -d 2>/dev/null | grep -iE "upload|exfil|send.*data|http.*post|socket.*connect" | tail -50
    echo ""

    echo "=== Potential Surveillance Activity ==="
    logcat -d 2>/dev/null | grep -iE "camera.*start|microphone|record|capture|screenshot|location.*request" | tail -50
    echo ""

    echo "=== Potential Malware Indicators ==="
    logcat -d 2>/dev/null | grep -iE "dex.*load|classloader|reflect|native.*load|dlopen|inject" | tail -50
    echo ""

    # =========================================================================
    # SECTION 14: Battery & Power Logs
    # =========================================================================
    
    echo "┌─────────────────────────────────────────────────────────────┐"
    echo "│ BATTERY & POWER LOGS                                       │"
    echo "└─────────────────────────────────────────────────────────────┘"
    echo ""

    echo "=== Battery Stats Summary ==="
    dumpsys batterystats 2>/dev/null | head -100
    echo ""

    echo "=== Recent Power Events ==="
    logcat -d 2>/dev/null | grep -iE "battery|power|charging|wake.?lock|doze" | tail -50
    echo ""

    # =========================================================================
    # SECTION 15: System Server Logs
    # =========================================================================
    
    echo "┌─────────────────────────────────────────────────────────────┐"
    echo "│ SYSTEM SERVER LOGS                                         │"
    echo "└─────────────────────────────────────────────────────────────┘"
    echo ""

    echo "=== System Server Events ==="
    logcat -d 2>/dev/null | grep -E "system_server|SystemServer" | tail -50
    echo ""

    echo "=== Service Start/Stop ==="
    logcat -d 2>/dev/null | grep -iE "service.*start|service.*stop|binding|unbinding" | tail -50
    echo ""

    # =========================================================================
    # SECTION 16: Persistent Log Files
    # =========================================================================
    
    echo "┌─────────────────────────────────────────────────────────────┐"
    echo "│ PERSISTENT LOG FILES                                       │"
    echo "└─────────────────────────────────────────────────────────────┘"
    echo ""

    echo "=== Log Files in /data ==="
    find /data -name "*.log" -type f 2>/dev/null | head -30
    echo ""

    echo "=== Log Files in /cache ==="
    find /cache -name "*.log" -type f 2>/dev/null | head -20
    echo ""

    echo "=== Vendor Log Files ==="
    find /data/vendor -name "*.log" -type f 2>/dev/null | head -20
    ls -la /data/vendor/log* /data/log* 2>/dev/null | head -20
    echo ""

    # =========================================================================
    # SECTION 17: Summary
    # =========================================================================
    
    echo "┌─────────────────────────────────────────────────────────────┐"
    echo "│ LOG COLLECTION SUMMARY                                     │"
    echo "└─────────────────────────────────────────────────────────────┘"
    echo ""

    # Count various log sources
    TOMBSTONE_COUNT=$(ls /data/tombstones 2>/dev/null | wc -l)
    DROPBOX_COUNT=$(ls /data/system/dropbox 2>/dev/null | wc -l)
    ANR_COUNT=$(ls /data/anr/*.txt /data/system/anr/*.txt 2>/dev/null | wc -l)
    SELINUX_DENIALS=$(logcat -d 2>/dev/null | grep -c "avc.*denied" 2>/dev/null || echo "0")
    CRASHES=$(logcat -d 2>/dev/null | grep -c "FATAL EXCEPTION" 2>/dev/null || echo "0")

    echo "Log Statistics:"
    echo "  Tombstones:          $TOMBSTONE_COUNT"
    echo "  Dropbox Entries:     $DROPBOX_COUNT"
    echo "  ANR Traces:          $ANR_COUNT"
    echo "  SELinux Denials:     $SELINUX_DENIALS"
    echo "  Java Crashes:        $CRASHES"
    echo ""

    echo "Log Buffer Status:"
    logcat -g 2>/dev/null | grep -E "size:|consumed:" | head -10
    echo ""

    if [ "$SELINUX_DENIALS" -gt 50 ]; then
        echo "██ [WARNING] High number of SELinux denials detected"
        echo "  This may indicate policy issues or attack attempts"
    fi

    if [ "$TOMBSTONE_COUNT" -gt 10 ]; then
        echo "██ [WARNING] Many tombstones present - system stability issues"
    fi
    echo ""

    echo "Forensic Notes:"
    echo "  - Logs may be rotated/overwritten - collect promptly"
    echo "  - Tombstones contain native crash evidence"
    echo "  - Dropbox preserves historical events (crashes, ANRs, etc.)"
    echo "  - SELinux denials may indicate security boundary violations"
    echo "  - Radio logs may contain call/SMS metadata"
    echo ""

} > "${OUTPUT_FILE}" 2>&1

echo "[+] Forensic log collection saved to: ${OUTPUT_FILE}"
