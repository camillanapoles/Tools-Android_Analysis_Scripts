#!/system/bin/sh
# 09_enum_privileged_processes.sh — Privileged process profiling (UID=0 and UID=1000)
# Usage: sh 09_enum_privileged_processes.sh [output_directory]
OUTPUT_DIR="${1:-.}"
OUTPUT_FILE="${OUTPUT_DIR}/enum_privileged_processes.txt"

{
    echo "============================================================"
    echo "  PRIVILEGED PROCESS PROFILER"
    echo "  Android Forensic & Security Audit Toolkit"
    echo "============================================================"
    echo ""

    # ----------------------------------------------------------------
    echo "=== SECTION 1: OVERVIEW ==="
    echo ""
    echo "All UID=root and UID=system processes:"
    ps -A -o pid,user,name 2>/dev/null | grep -E "^[[:space:]]*[0-9]+ (root|system)" | head -50
    echo ""

    ROOT_COUNT=$(ps -A -o pid,user,name 2>/dev/null | grep -E "^[[:space:]]*[0-9]+ root" | wc -l | tr -d ' ')
    SYS_COUNT=$(ps -A -o pid,user,name 2>/dev/null | grep -E "^[[:space:]]*[0-9]+ system" | wc -l | tr -d ' ')
    echo "[INFO] Total root (UID=0) processes: ${ROOT_COUNT}"
    echo "[INFO] Total system (UID=1000) processes: ${SYS_COUNT}"
    echo ""

    # ----------------------------------------------------------------
    echo "=== SECTION 2: PER-PROCESS PROFILE (UID=0 / root) ==="
    echo ""

    # Collect root PIDs — POSIX compatible, no arrays
    ROOT_PIDS=$(ps -A 2>/dev/null | awk '$2=="root" || $2=="0" {print $1}' | head -30)

    if [ -z "$ROOT_PIDS" ]; then
        echo "[INFO] No root processes found (may lack /proc access)"
    else
        for pid in $ROOT_PIDS; do
            # Verify /proc entry still exists (process may have exited)
            if [ ! -d "/proc/${pid}" ]; then
                continue
            fi

            # Read name from cmdline, fall back to comm
            PNAME=$(cat /proc/${pid}/cmdline 2>/dev/null | tr '\0' ' ' | cut -c1-60)
            if [ -z "$PNAME" ]; then
                PNAME=$(cat /proc/${pid}/comm 2>/dev/null)
            fi
            if [ -z "$PNAME" ]; then
                PNAME="(unknown)"
            fi

            echo "--- PID ${pid}: ${PNAME} ---"

            # UID/GID lines
            UID_LINE=$(grep "^Uid:" /proc/${pid}/status 2>/dev/null)
            GID_LINE=$(grep "^Gid:" /proc/${pid}/status 2>/dev/null)
            echo "UID/GID:    ${UID_LINE} | ${GID_LINE}"

            # Capabilities
            CAPEFF=$(grep "^CapEff:" /proc/${pid}/status 2>/dev/null | awk '{print $2}')
            if [ -z "$CAPEFF" ]; then
                echo "Caps:       (unavailable)"
            elif [ "$CAPEFF" = "0000000000000000" ]; then
                echo "Caps:       ${CAPEFF} [INFO] no effective capabilities"
            elif [ "$CAPEFF" = "0000001fffffffff" ] || [ "$CAPEFF" = "000001ffffffffff" ] || [ "$CAPEFF" = "0000003fffffffff" ]; then
                echo "Caps:       ${CAPEFF} [CRITICAL] has ALL capabilities"
            else
                echo "Caps:       ${CAPEFF} [HIGH] has capabilities: ${CAPEFF}"
            fi

            # Seccomp
            SECCOMP=$(grep "^Seccomp:" /proc/${pid}/status 2>/dev/null | awk '{print $2}')
            if [ -z "$SECCOMP" ]; then
                echo "Seccomp:    (unavailable)"
            elif [ "$SECCOMP" = "0" ]; then
                echo "Seccomp:    0 [CRITICAL] no seccomp filter"
            elif [ "$SECCOMP" = "1" ]; then
                echo "Seccomp:    1 (strict)"
            elif [ "$SECCOMP" = "2" ]; then
                echo "Seccomp:    2 (filter/BPF)"
            else
                echo "Seccomp:    ${SECCOMP}"
            fi

            # NoNewPrivs
            NNP=$(grep "^NoNewPrivs:" /proc/${pid}/status 2>/dev/null | awk '{print $2}')
            if [ -z "$NNP" ]; then
                echo "NoNewPrivs: (unavailable)"
            elif [ "$NNP" = "0" ]; then
                echo "NoNewPrivs: 0 (not set)"
            else
                echo "NoNewPrivs: ${NNP} (set)"
            fi

            # Compound risk: root + caps + no seccomp + no NoNewPrivs
            if [ -n "$CAPEFF" ] && [ -n "$SECCOMP" ] && [ -n "$NNP" ]; then
                if [ "$SECCOMP" = "0" ] && [ "$NNP" = "0" ] && [ "$CAPEFF" != "0000000000000000" ]; then
                    echo "[CRITICAL] Compound risk: root+caps, no seccomp, no NoNewPrivs — fully exploitable if reachable"
                fi
            fi

            # SELinux context
            SELINUX=$(cat /proc/${pid}/attr/current 2>/dev/null | tr -d '\0')
            if [ -z "$SELINUX" ]; then
                SELINUX="(unavailable)"
            fi
            echo "SELinux:    ${SELINUX}"

            # FD count
            FD_COUNT=$(ls /proc/${pid}/fd 2>/dev/null | wc -l | tr -d ' ')
            echo "FD count:   ${FD_COUNT}"

            # Mapped shared libraries (top 10 unique)
            echo "Maps (libs):"
            grep "\.so" /proc/${pid}/maps 2>/dev/null | awk '{print $6}' | sort -u | head -10 | while read lib; do
                echo "            ${lib}"
            done

            # Namespace IDs
            NS_USER=$(readlink /proc/${pid}/ns/user 2>/dev/null)
            NS_MNT=$(readlink /proc/${pid}/ns/mnt 2>/dev/null)
            if [ -z "$NS_USER" ]; then NS_USER="(unavailable)"; fi
            if [ -z "$NS_MNT" ]; then NS_MNT="(unavailable)"; fi
            echo "NS user:    ${NS_USER}"
            echo "NS mnt:     ${NS_MNT}"

            echo ""
        done
    fi

    # ----------------------------------------------------------------
    echo "=== SECTION 3: SYSTEM SERVER (UID=1000) BRIEF PROFILE ==="
    echo ""

    SS_PID=$(ps -A 2>/dev/null | grep system_server | awk '{print $1}' | head -1)

    if [ -z "$SS_PID" ]; then
        echo "[INFO] system_server not found"
    else
        echo "[INFO] system_server PID: ${SS_PID} (normal Android system_server)"
        SS_CAPEFF=$(grep "^CapEff:" /proc/${SS_PID}/status 2>/dev/null | awk '{print $2}')
        SS_SECCOMP=$(grep "^Seccomp:" /proc/${SS_PID}/status 2>/dev/null | awk '{print $2}')
        SS_FD=$(ls /proc/${SS_PID}/fd 2>/dev/null | wc -l | tr -d ' ')
        SS_LIBS=$(grep "\.so" /proc/${SS_PID}/maps 2>/dev/null | awk '{print $6}' | sort -u | wc -l | tr -d ' ')
        if [ -z "$SS_CAPEFF" ]; then SS_CAPEFF="(unavailable)"; fi
        if [ -z "$SS_SECCOMP" ]; then SS_SECCOMP="(unavailable)"; fi
        echo "CapEff:     ${SS_CAPEFF}"
        echo "Seccomp:    ${SS_SECCOMP}"
        echo "FD count:   ${SS_FD}"
        echo "Mapped libs: ${SS_LIBS} unique"
    fi
    echo ""

    # ----------------------------------------------------------------
    echo "=== SECTION 4: HIGHEST-RISK PROCESSES SUMMARY ==="
    echo "Processes with Seccomp=0 AND non-zero CapEff (most dangerous)"
    echo ""
    printf "%-8s %-40s %-20s %s\n" "PID" "NAME" "CapEff" "Risk"
    printf "%-8s %-40s %-20s %s\n" "-------" "---------------------------------------" "-------------------" "----"

    for pid in $ROOT_PIDS; do
        if [ ! -d "/proc/${pid}" ]; then
            continue
        fi
        CAPEFF=$(grep "^CapEff:" /proc/${pid}/status 2>/dev/null | awk '{print $2}')
        SECCOMP=$(grep "^Seccomp:" /proc/${pid}/status 2>/dev/null | awk '{print $2}')

        if [ -z "$CAPEFF" ] || [ -z "$SECCOMP" ]; then
            continue
        fi

        if [ "$SECCOMP" = "0" ] && [ "$CAPEFF" != "0000000000000000" ]; then
            PNAME=$(cat /proc/${pid}/comm 2>/dev/null | cut -c1-38)
            if [ -z "$PNAME" ]; then
                PNAME="(unknown)"
            fi
            if [ "$CAPEFF" = "0000001fffffffff" ] || [ "$CAPEFF" = "000001ffffffffff" ] || [ "$CAPEFF" = "0000003fffffffff" ]; then
                RISK="[CRITICAL] all caps + no seccomp"
            else
                RISK="[HIGH] caps + no seccomp"
            fi
            printf "%-8s %-40s %-20s %s\n" "$pid" "$PNAME" "$CAPEFF" "$RISK"
        fi
    done
    echo ""

    echo "============================================================"
    echo "  END OF REPORT"
    echo "============================================================"

} > "${OUTPUT_FILE}" 2>&1
