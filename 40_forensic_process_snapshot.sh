#!/system/bin/sh
# 40_forensic_process_snapshot.sh — Comprehensive process security snapshot (deliverable-grade)
# Usage: sh 40_forensic_process_snapshot.sh [output_directory]
OUTPUT_DIR="${1:-.}"
OUTPUT_FILE="${OUTPUT_DIR}/forensic_process_snapshot.txt"

{
    echo "╔══════════════════════════════════════════════════════════════════╗"
    echo "║         FORENSIC PROCESS SECURITY SNAPSHOT — DELIVERABLE        ║"
    echo "╚══════════════════════════════════════════════════════════════════╝"
    echo ""

    # ─────────────────────────────────────────────────────────────────────
    # SECTION 1: SNAPSHOT METADATA
    # ─────────────────────────────────────────────────────────────────────
    echo "=== SECTION 1: SNAPSHOT METADATA ==="
    echo "Timestamp:      $(date)"
    echo "Device model:   $(getprop ro.product.model 2>/dev/null || echo n/a)"
    echo "Android:        $(getprop ro.build.version.release 2>/dev/null || echo n/a)"
    echo "Build:          $(getprop ro.build.display.id 2>/dev/null || echo n/a)"
    echo "Kernel:         $(uname -r 2>/dev/null || echo n/a)"
    echo "ADB shell UID:  $(id 2>/dev/null || echo n/a)"
    echo "SELinux mode:   $(getenforce 2>/dev/null || cat /sys/fs/selinux/enforce 2>/dev/null || echo n/a)"
    echo ""

    # ─────────────────────────────────────────────────────────────────────
    # SECTION 2: PROCESS COUNT SUMMARY
    # ─────────────────────────────────────────────────────────────────────
    echo "=== SECTION 2: PROCESS COUNT SUMMARY ==="
    total=$(ps -A 2>/dev/null | wc -l)
    root_count=$(ps -A 2>/dev/null | awk '$2=="root"' | wc -l)
    system_count=$(ps -A 2>/dev/null | awk '$2=="system"' | wc -l)
    shell_count=$(ps -A 2>/dev/null | awk '$2=="shell"' | wc -l)
    echo "[INFO] Total processes (ps -A lines):  $total"
    echo "[INFO] UID=0 (root) processes:         $root_count"
    echo "[INFO] UID=1000 (system) processes:    $system_count"
    echo "[INFO] UID=2000 (shell) processes:     $shell_count"
    echo ""

    # ─────────────────────────────────────────────────────────────────────
    # SECTION 3: FULL PROCESS TABLE
    # ─────────────────────────────────────────────────────────────────────
    echo "=== SECTION 3: FULL PROCESS TABLE (first 200 entries) ==="
    echo "[INFO] 'args' field is truncated by Android ps — expected"
    echo ""
    ps -A -o pid,ppid,user,group,name,args 2>/dev/null | head -200
    echo ""

    # ─────────────────────────────────────────────────────────────────────
    # SECTION 4: PER-PROCESS SECURITY PROFILE (UID=0 processes)
    # ─────────────────────────────────────────────────────────────────────
    echo "=== SECTION 4: PER-PROCESS SECURITY PROFILE (UID=root) ==="
    echo "[INFO] Iterating all root-owned processes from /proc"
    echo ""

    ps -A 2>/dev/null | awk '$2=="root" {print $1}' | while read pid; do
        [ -d "/proc/$pid" ] || continue
        name=$(cat /proc/$pid/comm 2>/dev/null || echo "unknown")
        cmdline=$(tr '\0' ' ' < /proc/$pid/cmdline 2>/dev/null | cut -c1-120 || echo "n/a")
        echo "========================================"
        echo "PID: $pid  NAME: $name"
        echo "CMDLINE: $cmdline"
        statusfile="/proc/$pid/status"
        if [ -r "$statusfile" ]; then
            grep -E "^(Uid|Gid|CapInh|CapPrm|CapEff|CapBnd|CapAmb|Seccomp|NoNewPrivs|NSpid|PPid|Threads):" "$statusfile" 2>/dev/null
        else
            echo "[INFO] /proc/$pid/status not readable"
        fi
        echo "SELinux:    $(cat /proc/$pid/attr/current 2>/dev/null | tr -d '\0' || echo n/a)"
        echo "FD_count:   $(ls /proc/$pid/fd 2>/dev/null | wc -l)"
        echo "Libraries:  $(grep '\.so' /proc/$pid/maps 2>/dev/null | awk '{print $6}' | sort -u | tr '\n' ' ' | cut -c1-200)"
        echo "NS_user:    $(readlink /proc/$pid/ns/user 2>/dev/null || echo n/a)"
        echo "NS_mnt:     $(readlink /proc/$pid/ns/mnt 2>/dev/null || echo n/a)"
        echo "NS_net:     $(readlink /proc/$pid/ns/net 2>/dev/null || echo n/a)"
        # Risk assessment
        capeff=$(grep "^CapEff:" /proc/$pid/status 2>/dev/null | awk '{print $2}')
        seccomp=$(grep "^Seccomp:" /proc/$pid/status 2>/dev/null | awk '{print $2}')
        nonewprivs=$(grep "^NoNewPrivs:" /proc/$pid/status 2>/dev/null | awk '{print $2}')
        if [ "$capeff" = "0000001fffffffff" ] || [ "$capeff" = "000001ffffffffff" ] || [ "$capeff" = "00000001ffffffff" ]; then
            echo "RISK: [CRITICAL] ALL capabilities set — full kernel privilege"
        elif [ -n "$capeff" ] && [ "$capeff" != "0000000000000000" ]; then
            echo "RISK: [HIGH] has non-zero capabilities: $capeff"
        fi
        if [ "$seccomp" = "0" ]; then
            echo "RISK: [CRITICAL] no seccomp filter"
        fi
        if [ "$nonewprivs" = "0" ] || [ -z "$nonewprivs" ]; then
            echo "RISK: [MEDIUM] NoNewPrivs not set (can gain privileges via exec)"
        fi
        echo ""
    done

    # ─────────────────────────────────────────────────────────────────────
    # SECTION 5: NAMESPACE DIVERSITY
    # ─────────────────────────────────────────────────────────────────────
    echo "=== SECTION 5: NAMESPACE DIVERSITY ==="
    echo "[INFO] Distinct namespace IDs across all /proc/*/ns/* — count > 1 means"
    echo "[INFO] container/sandbox boundary present (potential escape surface)"
    echo ""
    for ns in user mnt pid net ipc uts; do
        count=0
        seen=""
        for pid in $(ls /proc/ 2>/dev/null | grep '^[0-9]'); do
            link=$(readlink /proc/$pid/ns/$ns 2>/dev/null)
            if [ -n "$link" ]; then
                already=0
                for s in $seen; do
                    [ "$s" = "$link" ] && already=1
                done
                if [ "$already" = "0" ]; then
                    seen="$seen $link"
                    count=$((count + 1))
                fi
            fi
        done
        if [ "$count" -gt 1 ]; then
            echo "[HIGH] ${ns}_ns: $count distinct IDs — namespace isolation in use"
        else
            echo "[INFO] ${ns}_ns: $count distinct ID(s)"
        fi
    done
    echo ""

    # ─────────────────────────────────────────────────────────────────────
    # SECTION 6: FILE DESCRIPTOR ANALYSIS (TOP CONSUMERS, UID=0)
    # ─────────────────────────────────────────────────────────────────────
    echo "=== SECTION 6: FILE DESCRIPTOR ANALYSIS (UID=root, top 10 by FD count) ==="
    echo ""
    # Collect pid:name:fdcount for root processes, sort by fdcount desc
    tmpfd=""
    ps -A 2>/dev/null | awk '$2=="root" {print $1}' | while read pid; do
        [ -d "/proc/$pid/fd" ] || continue
        name=$(cat /proc/$pid/comm 2>/dev/null || echo unknown)
        fdcount=$(ls /proc/$pid/fd 2>/dev/null | wc -l)
        echo "$fdcount $pid $name"
    done | sort -rn | head -10 | while read fdcount pid name; do
        echo "PID $pid ($name): $fdcount open FDs"
        # FD type breakdown
        sockets=$(ls -la /proc/$pid/fd 2>/dev/null | grep -c "socket:")
        pipes=$(ls -la /proc/$pid/fd 2>/dev/null | grep -c "pipe:")
        devices=$(ls -la /proc/$pid/fd 2>/dev/null | grep -c "/dev/")
        files=$(ls -la /proc/$pid/fd 2>/dev/null | grep -v "socket:\|pipe:\|/dev/" | grep -c " -> /")
        echo "  sockets=$sockets  pipes=$pipes  devices=$devices  files=$files"
        # Notable device FDs
        notable=$(ls -la /proc/$pid/fd 2>/dev/null | grep "/dev/" | awk '{print $NF}' | sort -u | tr '\n' '  ' | cut -c1-160)
        [ -n "$notable" ] && echo "  dev_fds: $notable"
        echo ""
    done

    # ─────────────────────────────────────────────────────────────────────
    # SECTION 7: DANGEROUS PROCESS FLAGS SUMMARY TABLE
    # ─────────────────────────────────────────────────────────────────────
    echo "=== SECTION 7: DANGEROUS PROCESS FLAGS SUMMARY TABLE (UID=root) ==="
    echo ""
    printf "%-8s %-24s %-20s %-9s %-12s %s\n" "PID" "NAME" "CapEff" "Seccomp" "NoNewPrivs" "Risk"
    printf "%-8s %-24s %-20s %-9s %-12s %s\n" "--------" "------------------------" "--------------------" "---------" "------------" "----------"

    # Collect all root processes and emit: risk_sort|pid|name|capeff|seccomp|nonewprivs
    ps -A 2>/dev/null | awk '$2=="root" {print $1}' | while read pid; do
        [ -r "/proc/$pid/status" ] || continue
        name=$(cat /proc/$pid/comm 2>/dev/null || echo unknown)
        capeff=$(grep "^CapEff:" /proc/$pid/status 2>/dev/null | awk '{print $2}')
        seccomp=$(grep "^Seccomp:" /proc/$pid/status 2>/dev/null | awk '{print $2}')
        nonewprivs=$(grep "^NoNewPrivs:" /proc/$pid/status 2>/dev/null | awk '{print $2}')
        risk="[OK]"
        sort_key=3
        if [ "$capeff" = "0000001fffffffff" ] || [ "$capeff" = "000001ffffffffff" ] || [ "$capeff" = "00000001ffffffff" ]; then
            risk="[CRITICAL] all-caps"
            sort_key=0
        elif [ "$seccomp" = "0" ] && [ -n "$capeff" ] && [ "$capeff" != "0000000000000000" ]; then
            risk="[CRITICAL] caps+no-seccomp"
            sort_key=0
        elif [ "$seccomp" = "0" ]; then
            risk="[HIGH] no seccomp"
            sort_key=1
        elif [ -n "$capeff" ] && [ "$capeff" != "0000000000000000" ]; then
            risk="[MEDIUM] has caps"
            sort_key=2
        fi
        echo "${sort_key}|${pid}|${name}|${capeff:-n/a}|${seccomp:-n/a}|${nonewprivs:-n/a}|${risk}"
    done | sort | while IFS="|" read sk pid name capeff seccomp nnp risk; do
        printf "%-8s %-24s %-20s %-9s %-12s %s\n" "$pid" "$name" "$capeff" "$seccomp" "$nnp" "$risk"
    done
    echo ""

    # ─────────────────────────────────────────────────────────────────────
    # SECTION 8: PROCESS LINEAGE (INIT TREE)
    # ─────────────────────────────────────────────────────────────────────
    echo "=== SECTION 8: PROCESS LINEAGE (PID/PPID/NAME — first 100 entries) ==="
    echo "[INFO] Use PPID column to identify unexpected parent-child relationships"
    echo "[INFO] Processes with PPID=1 are direct children of init"
    echo "[INFO] Non-init parents for privileged processes may indicate injection"
    echo ""
    ps -A -o pid,ppid,user,name 2>/dev/null | head -100
    echo ""

    # ─────────────────────────────────────────────────────────────────────
    # SECTION 9: HIGH-INTEREST PROCESS SPOTLIGHT
    # ─────────────────────────────────────────────────────────────────────
    echo "=== SECTION 9: HIGH-INTEREST PROCESS SPOTLIGHT ==="
    echo "[INFO] Specific processes known to be high-value on Android"
    echo ""
    for target in tee_supplicant keystore2 gatekeeperd vold surfaceflinger system_server zygote64 zygote adbd; do
        pid=$(ps -A 2>/dev/null | grep -w "$target" | grep -v grep | awk '{print $1}' | head -1)
        if [ -n "$pid" ] && [ -d "/proc/$pid" ]; then
            echo "--- $target (PID $pid) ---"
            grep -E "^(Uid|Gid|CapEff|CapBnd|Seccomp|NoNewPrivs):" /proc/$pid/status 2>/dev/null
            echo "SELinux: $(cat /proc/$pid/attr/current 2>/dev/null | tr -d '\0' || echo n/a)"
            echo "FDs:     $(ls /proc/$pid/fd 2>/dev/null | wc -l)"
            echo ""
        else
            echo "--- $target: not running or PID not found ---"
            echo ""
        fi
    done

    # ─────────────────────────────────────────────────────────────────────
    # SECTION 10: RISK SUMMARY
    # ─────────────────────────────────────────────────────────────────────
    echo "=== SECTION 10: RISK SUMMARY ==="
    echo "[CRITICAL] Any root process with Seccomp=0 and full capabilities is a kernel attack vector"
    echo "[CRITICAL] tee_supplicant with all caps + no seccomp = direct path to TEE from root process"
    echo "[HIGH]     Root processes without NoNewPrivs set can acquire privileges via exec transitions"
    echo "[HIGH]     Multiple distinct mount namespaces may indicate exploitable container boundaries"
    echo "[MEDIUM]   High FD counts on privileged processes may expose sensitive file handles"
    echo "[INFO]     This snapshot covers shell-readable /proc entries only — root view differs"
    echo ""
    echo "Snapshot complete: $(date)"

} > "${OUTPUT_FILE}" 2>&1
