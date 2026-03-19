#!/system/bin/sh

# Android Privilege Jail Audit — Comprehensive security constraint analysis
# Audits capability restrictions, network gates, SELinux domain, seccomp, and escalation surface
# UID 0 may still be heavily restricted by layered jail mechanisms

OUTPUT_DIR="${1:-.}"
OUTPUT_FILE="${OUTPUT_DIR}/audit_android_jail.txt"

echo "[*] Auditing Android privilege jail and capability restrictions..."

{
    echo "╔══════════════════════════════════════════════════════════════════╗"
    echo "║          ANDROID PRIVILEGE JAIL & CAPABILITY AUDIT              ║"
    echo "║        Analyzing layered privilege restriction mechanisms       ║"
    echo "╚══════════════════════════════════════════════════════════════════╝"
    echo ""

    # =========================================================================
    # SECTION 1: CURRENT PROCESS IDENTITY
    # =========================================================================
    echo "┌─ SECTION 1: CURRENT PROCESS IDENTITY ─────────────────────────────┐"
    echo ""

    echo "=== id output ==="
    id 2>/dev/null || echo "[ERROR] id command failed"
    echo ""

    echo "=== /proc/self/status security fields ==="
    grep -E "^(Uid|Gid|Groups|CapInh|CapPrm|CapEff|CapBnd|CapAmb|Seccomp|NoNewPrivs):" \
        /proc/self/status 2>/dev/null || echo "[ERROR] Cannot read /proc/self/status"
    echo ""

    # Extract for later use
    CURRENT_UID=$(grep "^Uid:" /proc/self/status 2>/dev/null | awk '{print $2}')
    CURRENT_GID=$(grep "^Gid:" /proc/self/status 2>/dev/null | awk '{print $2}')
    CURRENT_GROUPS=$(grep "^Groups:" /proc/self/status 2>/dev/null | sed 's/Groups:\t//')

    echo "Parsed identity:"
    echo "  UID: ${CURRENT_UID:-unknown}"
    echo "  GID: ${CURRENT_GID:-unknown}"
    echo "  Supplementary groups: ${CURRENT_GROUPS:-none}"
    echo ""

    echo "└────────────────────────────────────────────────────────────────────┘"
    echo ""

    # =========================================================================
    # SECTION 2: CAPABILITY ANALYSIS
    # =========================================================================
    echo "┌─ SECTION 2: CAPABILITY ANALYSIS ──────────────────────────────────┐"
    echo ""

    # Helper function to decode capability hex bitmask to list of cap names
    decode_capabilities() {
        hex_value="$1"
        cap_name=""

        # Remove '0x' prefix if present and pad to 16 chars (64-bit)
        hex_value=$(printf "%s" "$hex_value" | sed 's/0x//' | sed 's/^0*//')
        hex_value=$(printf "%016s" "$hex_value" | tr ' ' '0')

        # POSIX shell: convert full hex string to decimal
        dec=$(printf '%d' "0x${hex_value}" 2>/dev/null || echo "0")

        caps_list=""

        # Check each bit (0-40)
        bit=0
        while [ $bit -le 40 ]; do
            if [ $((dec & (1 << bit))) -ne 0 ]; then
                # Bit is set — lookup cap name
                case "$bit" in
                    0) cap_name="CAP_CHOWN" ;;
                    1) cap_name="CAP_DAC_OVERRIDE" ;;
                    2) cap_name="CAP_DAC_READ_SEARCH" ;;
                    3) cap_name="CAP_FOWNER" ;;
                    4) cap_name="CAP_FSETID" ;;
                    5) cap_name="CAP_KILL" ;;
                    6) cap_name="CAP_SETGID" ;;
                    7) cap_name="CAP_SETUID" ;;
                    8) cap_name="CAP_SETPCAP" ;;
                    9) cap_name="CAP_LINUX_IMMUTABLE" ;;
                    10) cap_name="CAP_NET_BIND_SERVICE" ;;
                    11) cap_name="CAP_NET_BROADCAST" ;;
                    12) cap_name="CAP_NET_ADMIN" ;;
                    13) cap_name="CAP_NET_RAW" ;;
                    14) cap_name="CAP_IPC_LOCK" ;;
                    15) cap_name="CAP_IPC_OWNER" ;;
                    16) cap_name="CAP_SYS_MODULE" ;;
                    17) cap_name="CAP_SYS_RAWIO" ;;
                    18) cap_name="CAP_SYS_CHROOT" ;;
                    19) cap_name="CAP_SYS_PTRACE" ;;
                    20) cap_name="CAP_SYS_PACCT" ;;
                    21) cap_name="CAP_SYS_ADMIN" ;;
                    22) cap_name="CAP_SYS_BOOT" ;;
                    23) cap_name="CAP_SYS_NICE" ;;
                    24) cap_name="CAP_SYS_RESOURCE" ;;
                    25) cap_name="CAP_SYS_TIME" ;;
                    26) cap_name="CAP_SYS_TTY_CONFIG" ;;
                    27) cap_name="CAP_MKNOD" ;;
                    28) cap_name="CAP_LEASE" ;;
                    29) cap_name="CAP_AUDIT_WRITE" ;;
                    30) cap_name="CAP_AUDIT_CONTROL" ;;
                    31) cap_name="CAP_SETFCAP" ;;
                    32) cap_name="CAP_MAC_OVERRIDE" ;;
                    33) cap_name="CAP_MAC_ADMIN" ;;
                    34) cap_name="CAP_SYSLOG" ;;
                    35) cap_name="CAP_WAKE_ALARM" ;;
                    36) cap_name="CAP_BLOCK_SUSPEND" ;;
                    37) cap_name="CAP_AUDIT_READ" ;;
                    38) cap_name="CAP_PERFMON" ;;
                    39) cap_name="CAP_BPF" ;;
                    40) cap_name="CAP_CHECKPOINT_RESTORE" ;;
                    *) cap_name="" ;;
                esac
                if [ -n "$cap_name" ]; then
                    if [ -z "$caps_list" ]; then
                        caps_list="$cap_name"
                    else
                        caps_list="${caps_list}, ${cap_name}"
                    fi
                fi
            fi
            bit=$((bit + 1))
        done

        if [ -z "$caps_list" ]; then
            caps_list="(none — no capabilities)"
        fi

        echo "$caps_list"
    }

    # Read capability fields from /proc/self/status
    CAP_INH=$(grep "^CapInh:" /proc/self/status 2>/dev/null | awk '{print $2}' | tr a-z A-Z)
    CAP_PRM=$(grep "^CapPrm:" /proc/self/status 2>/dev/null | awk '{print $2}' | tr a-z A-Z)
    CAP_EFF=$(grep "^CapEff:" /proc/self/status 2>/dev/null | awk '{print $2}' | tr a-z A-Z)
    CAP_BND=$(grep "^CapBnd:" /proc/self/status 2>/dev/null | awk '{print $2}' | tr a-z A-Z)
    CAP_AMB=$(grep "^CapAmb:" /proc/self/status 2>/dev/null | awk '{print $2}' | tr a-z A-Z)

    echo "=== Raw Capability Values ==="
    echo "  CapInh (Inheritable): $CAP_INH"
    echo "  CapPrm (Permitted):   $CAP_PRM"
    echo "  CapEff (Effective):   $CAP_EFF"
    echo "  CapBnd (Bounding):    $CAP_BND"
    echo "  CapAmb (Ambient):     $CAP_AMB"
    echo ""

    echo "=== Decoded Capabilities ==="
    echo ""
    echo "Inheritable capabilities:"
    echo "  $(decode_capabilities "$CAP_INH")"
    echo ""

    echo "Permitted capabilities:"
    echo "  $(decode_capabilities "$CAP_PRM")"
    echo ""

    echo "EFFECTIVE capabilities (what's ACTUALLY USABLE now):"
    CAP_EFF_DECODED=$(decode_capabilities "$CAP_EFF")
    echo "  $CAP_EFF_DECODED"
    echo ""

    echo "Bounding set (maximum ceiling for any child):"
    CAP_BND_DECODED=$(decode_capabilities "$CAP_BND")
    echo "  $CAP_BND_DECODED"
    echo ""

    echo "Ambient capabilities:"
    echo "  $(decode_capabilities "$CAP_AMB")"
    echo ""

    echo "=== Capability Jail Interpretation ==="
    if [ "$CAP_EFF" = "0000000000000000" ] || [ "$CAP_EFF" = "0x0" ] || [ -z "$CAP_EFF" ]; then
        echo "  [CRITICAL] CapEff is ZERO: Even with UID 0, this process has NO capabilities."
        echo "             This is HARD jail: no file ops, no network, no privilege escalation possible."
    else
        echo "  [HIGH] CapEff is NON-ZERO: This process has active capabilities."
        echo "         Check the decoded list above for what operations are possible."
    fi
    echo ""

    # Check bounding set for dangerous capabilities
    echo "=== Bounding Set Risk Assessment ==="
    CAP_BND_DEC=$(printf '%d' "0x${CAP_BND##*0x}" 2>/dev/null || printf '%d' "0x${CAP_BND}" 2>/dev/null || echo "0")

    # Map of dangerous caps and their bit positions
    dangerous_caps=""
    [ $((CAP_BND_DEC & (1 << 21))) -ne 0 ] && dangerous_caps="${dangerous_caps}[CRITICAL] CAP_SYS_ADMIN "
    [ $((CAP_BND_DEC & (1 << 19))) -ne 0 ] && dangerous_caps="${dangerous_caps}[HIGH] CAP_SYS_PTRACE "
    [ $((CAP_BND_DEC & (1 << 16))) -ne 0 ] && dangerous_caps="${dangerous_caps}[CRITICAL] CAP_SYS_MODULE "
    [ $((CAP_BND_DEC & (1 << 13))) -ne 0 ] && dangerous_caps="${dangerous_caps}[HIGH] CAP_NET_RAW "
    [ $((CAP_BND_DEC & (1 << 2))) -ne 0 ] && dangerous_caps="${dangerous_caps}[HIGH] CAP_DAC_READ_SEARCH "
    [ $((CAP_BND_DEC & (1 << 1))) -ne 0 ] && dangerous_caps="${dangerous_caps}[HIGH] CAP_DAC_OVERRIDE "
    [ $((CAP_BND_DEC & (1 << 7))) -ne 0 ] && dangerous_caps="${dangerous_caps}[HIGH] CAP_SETUID "
    [ $((CAP_BND_DEC & (1 << 6))) -ne 0 ] && dangerous_caps="${dangerous_caps}[HIGH] CAP_SETGID "

    if [ -n "$dangerous_caps" ]; then
        echo "  Dangerous capabilities in bounding set:"
        echo "  $dangerous_caps"
    else
        echo "  [OK] No obviously dangerous caps in bounding set."
    fi
    echo ""

    echo "└────────────────────────────────────────────────────────────────────┘"
    echo ""

    # =========================================================================
    # SECTION 3: ANDROID PARANOID NETWORK GATES
    # =========================================================================
    echo "┌─ SECTION 3: ANDROID PARANOID NETWORK ──────────────────────────────┐"
    echo ""

    echo "=== Network Access via GID Gates ==="
    echo "Android paranoid_network requires GID membership for socket types:"
    echo ""

    # Function to check if we're in a group
    has_gid() {
        local gid="$1"
        echo "$CURRENT_GROUPS" | grep -qE "(^|[^0-9])${gid}([^0-9]|$)"
        return $?
    }

    # Check network critical GIDs
    echo "Critical network GIDs:"
    if has_gid "3003"; then
        echo "  [OK] GID 3003 (inet) — Can create AF_INET/AF_INET6 sockets (TCP/UDP)"
    else
        echo "  [CRITICAL] MISSING GID 3003 (inet) — Cannot create TCP/UDP sockets, even as root"
    fi

    if has_gid "3004"; then
        echo "  [OK] GID 3004 (net_raw) — Can use SOCK_RAW and packet sockets"
    else
        echo "  [HIGH] MISSING GID 3004 (net_raw) — No raw packet access"
    fi

    if has_gid "3005"; then
        echo "  [OK] GID 3005 (net_admin) — Can perform network administration"
    else
        echo "  [MEDIUM] MISSING GID 3005 (net_admin) — Limited network admin capabilities"
    fi

    if has_gid "3006"; then
        echo "  [INFO] GID 3006 (net_bw_acct) — Network bandwidth accounting available"
    else
        echo "  [INFO] MISSING GID 3006 (net_bw_acct)"
    fi

    if has_gid "3007"; then
        echo "  [INFO] GID 3007 (net_bw_stats) — Network bandwidth stats available"
    else
        echo "  [INFO] MISSING GID 3007 (net_bw_stats)"
    fi
    echo ""

    echo "Other relevant GIDs:"
    for gid_name in "1000:system" "1001:radio" "1002:bluetooth" "1003:graphics" "1004:input" "1005:audio" "1006:camera" "1007:log" "1009:mount" "1010:wifi" "1013:media" "2000:shell" "2001:cache" "3001:bt_net" "3002:inet_raw"; do
        gid=${gid_name%:*}
        name=${gid_name#*:}
        if has_gid "$gid"; then
            echo "  [INFO] GID $gid ($name) — member"
        fi
    done
    echo ""

    echo "└────────────────────────────────────────────────────────────────────┘"
    echo ""

    # =========================================================================
    # SECTION 4: SELINUX DOMAIN CONFINEMENT
    # =========================================================================
    echo "┌─ SECTION 4: SELINUX DOMAIN CONFINEMENT ────────────────────────────┐"
    echo ""

    SEL_CURRENT=$(cat /proc/self/attr/current 2>/dev/null)
    SEL_EXEC=$(cat /proc/self/attr/exec 2>/dev/null)
    SEL_FSCREATE=$(cat /proc/self/attr/fscreate 2>/dev/null)

    if [ -z "$SEL_CURRENT" ]; then
        echo "[INFO] SELinux not enabled or not accessible on this device"
    else
        echo "=== Current SELinux Context ==="
        echo "  Current:   $SEL_CURRENT"
        echo "  Exec:      $SEL_EXEC"
        echo "  FsCreate:  $SEL_FSCREATE"
        echo ""

        echo "=== Domain Analysis ==="
        case "$SEL_CURRENT" in
            *":shell:"*)
                echo "  [HIGH] Standard ADB shell domain — heavily confined"
                echo "         Limited file access, no raw capability usage" ;;
            *":su:"*)
                echo "  [CRITICAL] Rooted shell domain — significantly less confined"
                echo "             Higher risk profile, fewer restrictions" ;;
            *":init:"*)
                echo "  [CRITICAL] init domain — very powerful, system startup context" ;;
            *":kernel:"*)
                echo "  [CRITICAL] kernel domain — kernel-level access" ;;
            *)
                echo "  [INFO] Custom domain: $SEL_CURRENT"
                echo "         Domain severity depends on policy configuration" ;;
        esac
        echo ""
    fi

    # Try to check SELinux status
    if [ -d /sys/fs/selinux ]; then
        echo "=== SELinux Boolean Settings (sample) ==="
        ls /sys/fs/selinux/booleans/ 2>/dev/null | head -10 | while read bool; do
            if [ -f "/sys/fs/selinux/booleans/$bool" ]; then
                val=$(cat "/sys/fs/selinux/booleans/$bool" 2>/dev/null | head -1)
                echo "  $bool: $val"
            fi
        done
    fi
    echo ""

    echo "└────────────────────────────────────────────────────────────────────┘"
    echo ""

    # =========================================================================
    # SECTION 5: SECCOMP STATUS
    # =========================================================================
    echo "┌─ SECTION 5: SECCOMP FILTER STATUS ────────────────────────────────┐"
    echo ""

    SECCOMP=$(grep "^Seccomp:" /proc/self/status 2>/dev/null | awk '{print $2}')
    NONEWPRIVS=$(grep "^NoNewPrivs:" /proc/self/status 2>/dev/null | awk '{print $2}')

    echo "=== Seccomp Mode ==="
    case "$SECCOMP" in
        0)
            echo "  [OK] Seccomp disabled (mode 0)"
            echo "       All syscalls available" ;;
        1)
            echo "  [CRITICAL] Seccomp STRICT MODE (mode 1)"
            echo "             Only read/write/exit/_exit/sigreturn allowed"
            echo "             Heavy restriction on system capability" ;;
        2)
            echo "  [HIGH] Seccomp FILTER MODE (mode 2)"
            echo "         BPF-based custom syscall filter active"
            echo "         Depends on policy but significantly restrictive" ;;
        *)
            echo "  [INFO] Seccomp mode: $SECCOMP (unknown)" ;;
    esac
    echo ""

    echo "=== NoNewPrivs Flag ==="
    if [ "$NONEWPRIVS" = "1" ]; then
        echo "  [HIGH] NoNewPrivs is SET (1)"
        echo "         This process and all children can NEVER gain new privileges"
        echo "         Blocks many privilege escalation vectors"
    else
        echo "  [INFO] NoNewPrivs is not set: $NONEWPRIVS"
        echo "         Children may be able to gain new privileges"
    fi
    echo ""

    echo "└────────────────────────────────────────────────────────────────────┘"
    echo ""

    # =========================================================================
    # SECTION 6: PRIVILEGE ESCALATION SURFACE
    # =========================================================================
    echo "┌─ SECTION 6: PRIVILEGE ESCALATION SURFACE ─────────────────────────┐"
    echo ""

    echo "=== su Binary Availability ==="
    which su >/dev/null 2>&1 && echo "  [CRITICAL] su found in PATH" || echo "  [OK] su not in PATH"
    [ -f /system/bin/su ] && echo "  [CRITICAL] /system/bin/su exists and accessible"
    [ -f /system/xbin/su ] && echo "  [HIGH] /system/xbin/su exists and accessible"
    [ -f /sbin/su ] && echo "  [HIGH] /sbin/su exists and accessible"
    echo ""

    echo "=== SUID Executables in PATH ==="
    found_suid=0
    for dir in $(echo "$PATH" | tr ':' ' '); do
        if [ -d "$dir" ]; then
            suid_binaries=$(find "$dir" -type f -perm /4000 2>/dev/null | head -5)
            if [ -n "$suid_binaries" ]; then
                found_suid=1
                echo "  [HIGH] SUID binaries in $dir:"
                echo "$suid_binaries" | sed 's/^/    /'
            fi
        fi
    done
    [ $found_suid -eq 0 ] && echo "  [OK] No obvious SUID binaries found in PATH"
    echo ""

    echo "=== Writable Directories in PATH ==="
    found_writable=0
    for dir in $(echo "$PATH" | tr ':' ' '); do
        if [ -w "$dir" ] 2>/dev/null; then
            found_writable=1
            echo "  [CRITICAL] Writable PATH directory: $dir"
        fi
    done
    [ $found_writable -eq 0 ] && echo "  [OK] No writable directories in PATH"
    echo ""

    echo "=== Environment Risk Factors ==="
    echo "  PATH: ${PATH}"
    if [ -n "$LD_LIBRARY_PATH" ]; then
        echo "  [HIGH] LD_LIBRARY_PATH set: ${LD_LIBRARY_PATH}"
    fi
    if [ -n "$LD_PRELOAD" ]; then
        echo "  [CRITICAL] LD_PRELOAD set: ${LD_PRELOAD} — code injection vector"
    fi
    echo ""

    echo "=== ptrace Capability ==="
    if [ $((CAP_BND_DEC & (1 << 19))) -ne 0 ]; then
        echo "  [HIGH] CAP_SYS_PTRACE in bounding set — process attachment possible"
    else
        echo "  [OK] CAP_SYS_PTRACE not in bounding set"
    fi
    echo ""

    echo "└────────────────────────────────────────────────────────────────────┘"
    echo ""

    # =========================================================================
    # SECTION 7: PROCESSES WITH ELEVATED PRIVILEGES
    # =========================================================================
    echo "┌─ SECTION 7: PROCESSES WITH ELEVATED CAPABILITIES ─────────────────┐"
    echo ""

    echo "=== Scanning /proc for processes with non-zero CapEff ==="
    echo ""

    procs_with_caps=0
    for pid_dir in /proc/[0-9]*; do
        pid=$(basename "$pid_dir")
        status_file="$pid_dir/status"

        if [ -f "$status_file" ]; then
            cap_eff=$(grep "^CapEff:" "$status_file" 2>/dev/null | awk '{print $2}')

            if [ -n "$cap_eff" ] && [ "$cap_eff" != "0000000000000000" ] && [ "$cap_eff" != "0x0" ]; then
                name=$(grep "^Name:" "$status_file" 2>/dev/null | awk '{print $2}')
                uid=$(grep "^Uid:" "$status_file" 2>/dev/null | awk '{print $2}')
                procs_with_caps=$((procs_with_caps + 1))

                # Only show first 40 to avoid spam
                if [ $procs_with_caps -le 40 ]; then
                    echo "  PID $pid ($name) UID=$uid CapEff=$cap_eff"
                fi
            fi
        fi
    done 2>/dev/null

    echo ""
    echo "  [Total processes scanned with elevated caps: $procs_with_caps]"
    echo ""

    echo "└────────────────────────────────────────────────────────────────────┘"
    echo ""

    # =========================================================================
    # SECTION 8: ANDROID AID REFERENCE TABLE
    # =========================================================================
    echo "┌─ SECTION 8: ANDROID AID (APPLICATION ID) REFERENCE ────────────────┐"
    echo ""

    echo "=== Android AID Membership ==="
    echo ""
    echo "System AIDs (you may have access to):"

    # Function to check and report AID membership
    check_aid() {
        local aid=$1
        local name=$2
        local description=$3

        if has_gid "$aid"; then
            echo "  [OK] AID $aid ($name) — MEMBER"
        else
            echo "  [ ] AID $aid ($name) — not member"
        fi
    }

    check_aid "1000" "system" "System services"
    check_aid "1001" "radio" "Telephony/radio services"
    check_aid "1002" "bluetooth" "Bluetooth services"
    check_aid "1003" "graphics" "Graphics/DRM"
    check_aid "1004" "input" "Input devices"
    check_aid "1005" "audio" "Audio services"
    check_aid "1006" "camera" "Camera access"
    check_aid "1007" "log" "System logging"
    check_aid "1008" "compass" "Sensor access"
    check_aid "1009" "mount" "SD card mount"
    check_aid "1010" "wifi" "WiFi services"
    check_aid "1013" "media" "Media services"
    check_aid "1014" "dhcp" "DHCP client"
    check_aid "1017" "sdcard_rw" "SD card read/write"
    check_aid "1021" "gps" "GPS/location"
    check_aid "1023" "media_rw" "Media read/write"
    check_aid "1028" "sdcard_r" "SD card read"
    echo ""

    echo "Shell/tool AIDs:"
    check_aid "2000" "shell" "ADB shell"
    check_aid "2001" "cache" "Cache partition"
    check_aid "2002" "diag" "Diagnostics"
    echo ""

    echo "Network AIDs (already covered above):"
    check_aid "3001" "bt_net" "Bluetooth network"
    check_aid "3002" "inet_raw" "Raw IP sockets"
    check_aid "3003" "inet" "TCP/UDP sockets"
    check_aid "3004" "net_raw" "Raw sockets"
    check_aid "3005" "net_admin" "Network admin"
    echo ""

    echo "└────────────────────────────────────────────────────────────────────┘"
    echo ""

    # =========================================================================
    # SECTION 9: SUMMARY AND VERDICT
    # =========================================================================
    echo "╔══════════════════════════════════════════════════════════════════╗"
    echo "║                     JAIL STATE SUMMARY                          ║"
    echo "╚══════════════════════════════════════════════════════════════════╝"
    echo ""

    echo "=== Identity ==="
    echo "  UID: ${CURRENT_UID:-unknown}"
    echo "  GID: ${CURRENT_GID:-unknown}"
    echo ""

    echo "=== Capability Status ==="
    if [ "$CAP_EFF" = "0000000000000000" ] || [ -z "$CAP_EFF" ]; then
        echo "  Effective Caps: [CRITICAL] ZERO — Hard capability jail"
        jail_level="HARD"
    else
        echo "  Effective Caps: [HIGH] NON-ZERO — Process has active capabilities"
        jail_level="SOFT"
    fi
    echo "  Bounding Set: $CAP_BND_DECODED"
    echo ""

    echo "=== Network Access ==="
    if has_gid "3003"; then
        echo "  [OK] Can use TCP/UDP sockets"
    else
        echo "  [CRITICAL] BLOCKED from TCP/UDP sockets"
    fi
    echo ""

    echo "=== SELinux Domain ==="
    if [ -n "$SEL_CURRENT" ]; then
        echo "  Domain: $SEL_CURRENT"
        case "$SEL_CURRENT" in
            *":shell:"*) echo "  Level: Standard shell (highly confined)" ;;
            *":su:"*) echo "  Level: Rooted shell (less confined)" ;;
            *) echo "  Level: Custom domain (depends on policy)" ;;
        esac
    else
        echo "  [INFO] SELinux not enabled or not accessible"
    fi
    echo ""

    echo "=== Seccomp + NoNewPrivs ==="
    echo "  Seccomp: $SECCOMP ($([ "$SECCOMP" = "0" ] && echo "disabled" || echo "enabled"))"
    echo "  NoNewPrivs: $NONEWPRIVS ($([ "$NONEWPRIVS" = "1" ] && echo "set — prevents privilege gain" || echo "not set"))"
    echo ""

    echo "=== Privilege Escalation Risk ==="
    if [ "$CAP_EFF" = "0000000000000000" ] && [ "$NONEWPRIVS" = "1" ]; then
        echo "  [OK] Very low escalation risk"
        echo "       - No capabilities"
        echo "       - NoNewPrivs prevents privilege gain"
    elif [ "$NONEWPRIVS" = "1" ]; then
        echo "  [MEDIUM] Moderate escalation risk"
        echo "           - Has some capabilities"
        echo "           - NoNewPrivs prevents new privilege gain"
    else
        echo "  [HIGH] Escalation risk present"
        echo "         - Children may gain new privileges"
        echo "         - Check available SUID binaries and su availability above"
    fi
    echo ""

    echo "=== OVERALL VERDICT ==="
    if [ "$CURRENT_UID" = "0" ]; then
        echo "  [CRITICAL] Running as UID 0 (root)"
        echo ""
        if [ "$CAP_EFF" = "0000000000000000" ]; then
            echo "  Status: FULLY JAILED — Despite UID 0, this process is heavily restricted"
            echo "          Capabilities, network access, syscalls, and SELinux all enforce restrictions"
            echo "          This is the Android jail working as designed"
        else
            echo "  Status: PARTIALLY JAILED — UID 0 with capabilities"
            echo "          Jail is less restrictive; check specific capabilities above"
        fi
    else
        echo "  [INFO] Running as UID $CURRENT_UID (non-root)"
        echo ""
        if [ "$CAP_EFF" = "0000000000000000" ]; then
            echo "  Status: FULLY JAILED — Standard unprivileged process"
            echo "          Typical for app containers; jail is working as designed"
        else
            echo "  Status: CAPABILITIES PRESENT — Non-root with elevated privileges"
            echo "          Unusual configuration; check capabilities above"
        fi
    fi
    echo ""

    echo "=== Audit Complete ==="
    echo "  Timestamp: $(date 2>/dev/null || echo 'unknown')"
    echo ""

} > "${OUTPUT_FILE}" 2>&1

echo "[+] Android jail audit saved to: ${OUTPUT_FILE}"
