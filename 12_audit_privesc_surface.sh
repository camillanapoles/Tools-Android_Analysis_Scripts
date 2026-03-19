#!/system/bin/sh
# 12_audit_privesc_surface.sh — Privilege escalation surface enumeration
# Usage: sh 12_audit_privesc_surface.sh [output_directory]

OUTPUT_DIR="${1:-.}"
OUTPUT_FILE="${OUTPUT_DIR}/audit_privesc_surface.txt"

echo "[*] Auditing privilege escalation surface..."

{
    echo "═══════════════════════════════════════════════════════════════"
    echo "  PRIVILEGE ESCALATION SURFACE AUDIT"
    echo "  Timestamp: $(date)"
    echo "═══════════════════════════════════════════════════════════════"
    echo ""

    # ──────────────────────────────────────────────────────────────
    # 1. WRITABLE PATH DIRECTORIES
    # ──────────────────────────────────────────────────────────────
    echo "┌─────────────────────────────────────────────────────────────┐"
    echo "│ 1. WRITABLE PATH DIRECTORIES                               │"
    echo "└─────────────────────────────────────────────────────────────┘"
    echo "Current PATH: $PATH"
    echo ""

    echo "--- Checking each PATH component ---"
    OLD_IFS="$IFS"
    IFS=":"
    for dir in $PATH; do
        IFS="$OLD_IFS"
        if [ -z "$dir" ]; then
            dir="."
        fi
        if [ ! -d "$dir" ]; then
            echo "  [INFO] $dir — not a directory or does not exist"
        elif [ -w "$dir" ]; then
            perms=$(ls -ld "$dir" 2>/dev/null | cut -c1-10)
            case "$perms" in
                *??????w??) echo "  [CRITICAL] $dir — world-writable ($perms)" ;;
                *)          echo "  [CRITICAL] $dir — writable by current user ($perms)" ;;
            esac
        else
            echo "  [OK] $dir — not writable"
        fi
        IFS=":"
    done
    IFS="$OLD_IFS"
    echo ""

    echo "--- Checking common Android PATH dirs ---"
    for dir in /system/bin /system/xbin /vendor/bin /data/local/tmp; do
        if [ ! -d "$dir" ]; then
            echo "  [INFO] $dir — does not exist"
        elif [ -w "$dir" ]; then
            perms=$(ls -ld "$dir" 2>/dev/null | cut -c1-10)
            case "$perms" in
                *??????w??) echo "  [CRITICAL] $dir — world-writable ($perms)" ;;
                *)          echo "  [CRITICAL] $dir — writable by current user ($perms)" ;;
            esac
        else
            echo "  [OK] $dir — not writable"
        fi
    done
    echo ""

    # ──────────────────────────────────────────────────────────────
    # 2. WRITABLE ROOT-OWNED FILES
    # ──────────────────────────────────────────────────────────────
    echo "┌─────────────────────────────────────────────────────────────┐"
    echo "│ 2. WRITABLE ROOT-OWNED FILES                               │"
    echo "└─────────────────────────────────────────────────────────────┘"
    echo "Scanning /system/bin, /system/etc, /vendor/bin, /vendor/etc (depth 2)..."
    echo ""

    for scandir in /system/bin /system/etc /vendor/bin /vendor/etc; do
        if [ -d "$scandir" ]; then
            results=$(find "$scandir" -maxdepth 2 -user root -perm -o+w 2>/dev/null)
            if [ -n "$results" ]; then
                echo "$results" | while read f; do
                    echo "  [CRITICAL] World-writable root-owned file: $f"
                    ls -la "$f" 2>/dev/null | sed 's/^/    /'
                done
            else
                echo "  [OK] No world-writable root-owned files in $scandir"
            fi
        else
            echo "  [INFO] $scandir — does not exist"
        fi
    done
    echo ""

    # ──────────────────────────────────────────────────────────────
    # 3. SUID/SGID BINARIES
    # ──────────────────────────────────────────────────────────────
    echo "┌─────────────────────────────────────────────────────────────┐"
    echo "│ 3. SUID/SGID BINARIES                                      │"
    echo "└─────────────────────────────────────────────────────────────┘"

    for bindir in /system/bin /system/xbin /vendor/bin; do
        if [ -d "$bindir" ]; then
            echo "--- $bindir ---"
            find "$bindir" -maxdepth 1 \( -perm -4000 -o -perm -2000 \) 2>/dev/null | while read f; do
                perms=$(ls -la "$f" 2>/dev/null | awk '{print $1}')
                case "$perms" in
                    ???s*) echo "  [CRITICAL] SUID: $f  ($perms)" ;;
                    *) echo "  [HIGH] SUID/SGID: $f  ($perms)" ;;
                esac
                ls -la "$f" 2>/dev/null | sed 's/^/    /'
            done
        fi
    done
    echo ""

    # ──────────────────────────────────────────────────────────────
    # 4. LINKER NAMESPACE CONFIGS
    # ──────────────────────────────────────────────────────────────
    echo "┌─────────────────────────────────────────────────────────────┐"
    echo "│ 4. LINKER NAMESPACE CONFIGS                                │"
    echo "└─────────────────────────────────────────────────────────────┘"

    for ldcfg in /system/etc/ld.config.txt /linkerconfig/ld.config.txt; do
        if [ -f "$ldcfg" ]; then
            echo "--- $ldcfg (first 50 lines) ---"
            head -50 "$ldcfg" 2>/dev/null
            echo ""
            if grep -q "/data/" "$ldcfg" 2>/dev/null; then
                echo "  [HIGH] $ldcfg references /data/ path — potential library injection vector"
            fi
        else
            echo "  [INFO] $ldcfg — not found"
        fi
    done

    echo ""
    echo "--- Versioned ld.config files in /system/etc ---"
    ls /system/etc/ld.config.*.txt 2>/dev/null | while read f; do
        echo "  Found: $f"
        if grep -q "/data/" "$f" 2>/dev/null; then
            echo "  [HIGH] $f references /data/ path"
        fi
    done
    echo ""

    # ──────────────────────────────────────────────────────────────
    # 5. INIT.RC EXEC PATHS
    # ──────────────────────────────────────────────────────────────
    echo "┌─────────────────────────────────────────────────────────────┐"
    echo "│ 5. INIT.RC EXEC PATHS                                      │"
    echo "└─────────────────────────────────────────────────────────────┘"

    echo "--- All .rc files in /system/etc/init and /vendor/etc/init ---"
    for initdir in /system/etc/init /vendor/etc/init; do
        if [ -d "$initdir" ]; then
            find "$initdir" -name "*.rc" 2>/dev/null | while read f; do
                echo "  $f"
            done
        else
            echo "  [INFO] $initdir — does not exist"
        fi
    done
    echo ""

    echo "--- .rc files with exec/service lines referencing /data ---"
    for initdir in /system/etc/init /vendor/etc/init; do
        if [ -d "$initdir" ]; then
            find "$initdir" -name "*.rc" 2>/dev/null | while read f; do
                matches=$(grep -n "exec.*/data\|service.*/data" "$f" 2>/dev/null)
                if [ -n "$matches" ]; then
                    echo "  [HIGH] $f"
                    echo "$matches" | sed 's/^/    /'
                fi
            done
        fi
    done
    echo ""

    # ──────────────────────────────────────────────────────────────
    # 6. PROPERTY_CONTEXTS WRITABLE ENTRIES
    # ──────────────────────────────────────────────────────────────
    echo "┌─────────────────────────────────────────────────────────────┐"
    echo "│ 6. PROPERTY_CONTEXTS — BROAD DOMAIN ENTRIES               │"
    echo "└─────────────────────────────────────────────────────────────┘"

    for pctx in /system/etc/selinux/plat_property_contexts \
                /vendor/etc/selinux/vendor_property_contexts; do
        if [ -f "$pctx" ]; then
            echo "--- $pctx ---"
            grep -E "u:object_r:shell_prop|u:object_r:everyone|shell:.*exact|shell:.*prefix" "$pctx" 2>/dev/null | while read line; do
                echo "  [HIGH] $line"
            done
            echo "  (Total entries: $(wc -l < "$pctx" 2>/dev/null))"
        else
            echo "  [INFO] $pctx — not found or not readable"
        fi
    done
    echo ""

    # ──────────────────────────────────────────────────────────────
    # 7. SERVICE_CONTEXTS BROAD DOMAINS
    # ──────────────────────────────────────────────────────────────
    echo "┌─────────────────────────────────────────────────────────────┐"
    echo "│ 7. SERVICE_CONTEXTS — BROAD DOMAIN ENTRIES                │"
    echo "└─────────────────────────────────────────────────────────────┘"

    for sctx in /system/etc/selinux/plat_service_contexts \
                /vendor/etc/selinux/vendor_service_contexts; do
        if [ -f "$sctx" ]; then
            echo "--- $sctx ---"
            grep -E "u:object_r:shell_service|u:object_r:su_service|:shell:|:su:" "$sctx" 2>/dev/null | while read line; do
                echo "  [HIGH] $line"
            done
            echo "  (Total entries: $(wc -l < "$sctx" 2>/dev/null))"
        else
            echo "  [INFO] $sctx — not found or not readable"
        fi
    done
    echo ""

    # ──────────────────────────────────────────────────────────────
    # 8. WRITABLE /DATA PATHS REACHABLE WITHOUT ROOT
    # ──────────────────────────────────────────────────────────────
    echo "┌─────────────────────────────────────────────────────────────┐"
    echo "│ 8. WRITABLE /DATA PATHS REACHABLE WITHOUT ROOT            │"
    echo "└─────────────────────────────────────────────────────────────┘"

    for datapath in /data/local/tmp /data/local /data/misc/wifi /data/misc/bluetooth; do
        if [ ! -e "$datapath" ]; then
            echo "  [INFO] $datapath — does not exist"
        elif [ -w "$datapath" ]; then
            case "$datapath" in
                /data/local/tmp)
                    echo "  [INFO] $datapath — writable (expected, but confirms code execution path)"
                    ls -ld "$datapath" 2>/dev/null | sed 's/^/    /'
                    ;;
                *)
                    echo "  [HIGH] $datapath — writable without root"
                    ls -ld "$datapath" 2>/dev/null | sed 's/^/    /'
                    ;;
            esac
        else
            echo "  [OK] $datapath — not writable"
            ls -ld "$datapath" 2>/dev/null | sed 's/^/    /'
        fi
    done
    echo ""

    # ──────────────────────────────────────────────────────────────
    # 9. SUMMARY
    # ──────────────────────────────────────────────────────────────
    echo "┌─────────────────────────────────────────────────────────────┐"
    echo "│ 9. SUMMARY                                                 │"
    echo "└─────────────────────────────────────────────────────────────┘"

    CRIT_COUNT=0
    HIGH_COUNT=0

    # Count writable PATH dirs
    OLD_IFS2="$IFS"
    IFS=":"
    for dir in $PATH; do
        IFS="$OLD_IFS2"
        if [ -d "${dir:-.}" ] && [ -w "${dir:-.}" ]; then
            CRIT_COUNT=$((CRIT_COUNT + 1))
        fi
        IFS=":"
    done
    IFS="$OLD_IFS2"

    # Count writable root-owned files
    for scandir in /system/bin /system/etc /vendor/bin /vendor/etc; do
        if [ -d "$scandir" ]; then
            n=$(find "$scandir" -maxdepth 2 -user root -perm -o+w 2>/dev/null | wc -l)
            CRIT_COUNT=$((CRIT_COUNT + n))
        fi
    done

    # Count SUID binaries
    for bindir in /system/bin /system/xbin /vendor/bin; do
        if [ -d "$bindir" ]; then
            n=$(find "$bindir" -maxdepth 1 -perm -4000 2>/dev/null | wc -l)
            CRIT_COUNT=$((CRIT_COUNT + n))
            n=$(find "$bindir" -maxdepth 1 -perm -2000 ! -perm -4000 2>/dev/null | wc -l)
            HIGH_COUNT=$((HIGH_COUNT + n))
        fi
    done

    # Count writable /data paths (excluding /data/local/tmp)
    for datapath in /data/local /data/misc/wifi /data/misc/bluetooth; do
        if [ -e "$datapath" ] && [ -w "$datapath" ]; then
            HIGH_COUNT=$((HIGH_COUNT + 1))
        fi
    done

    echo "  [CRITICAL] findings: $CRIT_COUNT"
    echo "  [HIGH]     findings: $HIGH_COUNT"
    echo ""
    echo "  See above sections for full details."
    echo ""
    echo "  Sections covered:"
    echo "    1. Writable PATH directories"
    echo "    2. Writable root-owned files (/system/bin, /system/etc, /vendor/bin, /vendor/etc)"
    echo "    3. SUID/SGID binaries in system/vendor bin directories"
    echo "    4. Linker namespace configs (ld.config.txt, linkerconfig)"
    echo "    5. Init .rc files with exec/service lines referencing /data"
    echo "    6. property_contexts entries with broad domain access"
    echo "    7. service_contexts entries with shell/su domain access"
    echo "    8. Writable /data paths accessible without root"
    echo ""

} > "${OUTPUT_FILE}" 2>&1

echo "[+] Privilege escalation surface audit saved to: ${OUTPUT_FILE}"
