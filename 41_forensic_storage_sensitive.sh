#!/system/bin/sh
# 41_forensic_storage_sensitive.sh — Sensitive storage accessible from shell
# Usage: sh 41_forensic_storage_sensitive.sh [output_directory]
OUTPUT_DIR="${1:-.}"
OUTPUT_FILE="${OUTPUT_DIR}/forensic_storage_sensitive.txt"

{
    echo "============================================================"
    echo "  43 — Forensic: Sensitive Storage Accessible From Shell"
    echo "============================================================"
    echo ""

    # ----------------------------------------------------------------
    echo "=== Section 1: World-Readable Files in /data (top-level) ==="
    echo ""
    echo "--- /data (maxdepth 3, excluding common Android/Google app dirs) ---"
    echo "[HIGH] Unexpected world-readable /data files:"
    find /data -maxdepth 3 -perm -o+r -type f 2>/dev/null \
        | grep -v "^/data/data/com\.android\|^/data/data/com\.google" \
        | head -50 \
        | while read f; do echo "  [HIGH] $f"; done
    echo ""

    echo "--- /data/data app private files world-readable (maxdepth 2) ---"
    echo "[HIGH] App private files with world-read bit set:"
    find /data/data -maxdepth 2 -perm -o+r -type f 2>/dev/null | head -30 \
        | while read f; do echo "  [HIGH] $f"; done
    echo ""

    # ----------------------------------------------------------------
    echo "=== Section 2: SQLite Databases Accessible From Shell ==="
    echo ""
    echo "Readable .db files under /data:"
    find /data -name "*.db" -readable 2>/dev/null | head -40 | while read db; do
        ls -la "$db" 2>/dev/null

        # Determine risk label based on filename
        case "$db" in
            *mmssms* | *telephony* | *contacts2* | *accounts*)
                echo "  [CRITICAL] Sensitive DB accessible: $db"
                ;;
            *browser* | *downloads* | *media* | *history*)
                echo "  [HIGH] Browser/media DB accessible: $db"
                ;;
            *)
                echo "  [MEDIUM] DB accessible: $db"
                ;;
        esac

        # Show schema for DBs with sensitive path keywords
        case "$db" in
            *contact* | *sms* | *mms* | *telephony* | *account* | *password* | *secret* | *credential* | *browser* | *call*)
                echo "  Schema (.tables):"
                sqlite3 "$db" ".tables" 2>/dev/null | sed 's/^/    /'
                ;;
        esac
        echo ""
    done

    # ----------------------------------------------------------------
    echo "=== Section 3: /sdcard Sensitive Pattern Scan ==="
    echo ""
    echo "--- Cryptographic key and credential files ---"
    find /sdcard -maxdepth 4 \( \
        -name "*.key" \
        -o -name "*.pem" \
        -o -name "*.p12" \
        -o -name "*.pfx" \
        -o -name "*.kdbx" \
        -o -name "*.wallet" \
        -o -name "*.seed" \
        -o -name "*password*" \
        -o -name "*secret*" \
        -o -name "*credential*" \
        -o -name "*private*" \
    \) 2>/dev/null | head -30 | while read f; do
        case "$f" in
            *.key | *.pem | *.p12 | *.pfx | *.kdbx | *.wallet | *.seed)
                echo "  [CRITICAL] Crypto key file: $f"
                ;;
            *)
                echo "  [HIGH] Credential/password file: $f"
                ;;
        esac
    done
    echo ""

    # ----------------------------------------------------------------
    echo "=== Section 4: /sdcard Screenshot and Sensitive Media ==="
    echo ""
    jpg_count=$(find /sdcard -name "*.jpg" 2>/dev/null | wc -l)
    png_count=$(find /sdcard -name "*.png" 2>/dev/null | wc -l)
    mp4_count=$(find /sdcard -name "*.mp4" 2>/dev/null | wc -l)
    vid3gp_count=$(find /sdcard -name "*.3gp" 2>/dev/null | wc -l)
    echo "  [INFO] JPEG images on /sdcard: $jpg_count"
    echo "  [INFO] PNG images on /sdcard:  $png_count"
    echo "  [INFO] MP4 videos on /sdcard:  $mp4_count"
    echo "  [INFO] 3GP videos on /sdcard:  $vid3gp_count"
    echo ""

    echo "--- Recent media files in /sdcard/DCIM (newer than /sdcard/Android) ---"
    if [ -d /sdcard/DCIM ]; then
        find /sdcard/DCIM -maxdepth 3 -newer /sdcard/Android 2>/dev/null | head -10 \
            | while read f; do echo "  [INFO] Recent: $f"; done
    else
        echo "  [N/A] /sdcard/DCIM not present"
    fi
    echo ""

    # ----------------------------------------------------------------
    echo "=== Section 5: App Shared Preferences (World-Readable) ==="
    echo ""
    find /data/data -name "shared_prefs" -type d 2>/dev/null | while read dir; do
        if [ -r "$dir" ]; then
            ls "$dir" 2>/dev/null | head -5 | while read f; do
                echo "  [HIGH] READABLE shared_prefs: $dir/$f"
            done
        fi
    done | head -30
    echo ""

    # ----------------------------------------------------------------
    echo "=== Section 6: Log Files Accessible From Shell ==="
    echo ""
    echo "--- Readable log files under /data/log, /data/vendor/log, /data/misc/logd ---"
    for logdir in /data/log /data/vendor/log /data/misc/logd; do
        if [ -d "$logdir" ]; then
            find "$logdir" -type f -readable 2>/dev/null | head -20 \
                | while read f; do
                    ls -la "$f" 2>/dev/null
                    echo "  [HIGH] Readable log: $f"
                done
        fi
    done
    echo ""

    echo "--- Tombstones (crash dumps) ---"
    if [ -d /data/tombstones ]; then
        ls -la /data/tombstones/ 2>/dev/null | head -10
        echo "  [HIGH] Tombstones present — may contain stack traces with sensitive data"
    else
        echo "  [N/A] /data/tombstones not accessible"
    fi
    echo ""

    echo "--- ANR traces ---"
    if [ -d /data/anr ]; then
        ls -la /data/anr/ 2>/dev/null | head -5
        echo "  [HIGH] ANR traces present — may contain thread dumps with sensitive data"
    else
        echo "  [N/A] /data/anr not accessible"
    fi
    echo ""

    # ----------------------------------------------------------------
    echo "=== Section 7: /proc/PID/environ Readable (Env Variable Leaks) ==="
    echo ""
    echo "Checking first 20 PIDs from ps for readable environ:"
    ps -A 2>/dev/null | awk 'NR>1 && NR<=21 {print $1}' | while read pid; do
        case "$pid" in
            ''|*[!0-9]*) continue ;;
        esac
        if [ -r "/proc/$pid/environ" ]; then
            comm=$(cat "/proc/$pid/comm" 2>/dev/null)
            echo "  [HIGH] environ readable: PID=$pid comm=$comm (may contain tokens/API keys)"
        fi
    done | head -10
    echo ""

    # ----------------------------------------------------------------
    echo "=== Section 8: Summary ==="
    echo ""
    echo "Counts are approximate — output above may be truncated at head limits."
    critical=$(grep -c "\[CRITICAL\]" "${OUTPUT_FILE}" 2>/dev/null || echo 0)
    high=$(grep -c "\[HIGH\]" "${OUTPUT_FILE}" 2>/dev/null || echo 0)
    echo "  [CRITICAL] findings in this report: $critical"
    echo "  [HIGH]     findings in this report: $high"
    echo ""
    echo "NOTE: Only paths and permissions are reported — file contents are NOT extracted."
    echo "      SQLite schema (.tables) shown for high-value databases only."
    echo ""
    echo "============================================================"
    echo "  END — forensic_storage_sensitive"
    echo "============================================================"

} > "${OUTPUT_FILE}" 2>&1
