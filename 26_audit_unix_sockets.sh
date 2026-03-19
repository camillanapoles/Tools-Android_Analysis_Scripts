#!/system/bin/sh
# 26_audit_unix_sockets.sh — Audit Unix domain sockets for accessibility and privilege escalation vectors

OUTPUT_DIR="${1:-.}"
OUTPUT_FILE="${OUTPUT_DIR}/audit_unix_sockets.txt"

echo "[*] Auditing Unix domain sockets..."

{
    echo "╔════════════════════════════════════════════════════════════════╗"
    echo "║          UNIX DOMAIN SOCKET SECURITY AUDIT                     ║"
    echo "╚════════════════════════════════════════════════════════════════╝"
    echo ""
    echo "[*] Timestamp: $(date '+%Y-%m-%d %H:%M:%S')"
    echo ""

    # ─────────────────────────────────────────────────────────────────
    # SECTION: UNIX SOCKET OVERVIEW
    # ─────────────────────────────────────────────────────────────────
    echo "┌─ UNIX SOCKET OVERVIEW ─────────────────────────────────────────┐"
    echo ""

    SOCKET_COUNT=$(cat /proc/net/unix 2>/dev/null | wc -l)
    echo "[*] Total Unix domain sockets on system: $((SOCKET_COUNT - 1)) (header line excluded)"
    echo ""
    echo "    Context: Unix domain sockets are inter-process communication (IPC)"
    echo "    endpoints. World-readable or world-writable sockets allow any"
    echo "    process to communicate with privileged services. This is a common"
    echo "    privilege escalation vector if the socket handler does not validate"
    echo "    caller permissions."
    echo ""
    echo "└────────────────────────────────────────────────────────────────┘"
    echo ""

    # ─────────────────────────────────────────────────────────────────
    # SECTION: /dev/socket FILESYSTEM SOCKETS
    # ─────────────────────────────────────────────────────────────────
    echo "┌─ /dev/socket FILESYSTEM SOCKETS ──────────────────────────────┐"
    echo ""

    if [ -d /dev/socket ]; then
        SOCKET_FILES=$(ls -1 /dev/socket 2>/dev/null)
        SOCKET_FILES_COUNT=$(echo "$SOCKET_FILES" | wc -l)
        echo "[*] Found $SOCKET_FILES_COUNT socket files in /dev/socket/"
        echo ""

        WORLD_ACCESSIBLE=0
        HIGH_VALUE_ACCESSIBLE=""

        # Known high-value sockets to call out
        HIGH_VALUE="adbd vold netd installd zygote logd lmkd mdnsd property_service"

        for socket in $SOCKET_FILES; do
            SOCK_PATH="/dev/socket/$socket"
            # Try both SELinux context (ls -Z) and fallback (ls -la)
            if ls -Z "$SOCK_PATH" >/dev/null 2>&1; then
                SOCK_INFO=$(ls -laZ "$SOCK_PATH" 2>/dev/null)
            else
                SOCK_INFO=$(ls -la "$SOCK_PATH" 2>/dev/null)
            fi

            if [ -n "$SOCK_INFO" ]; then
                echo "$SOCK_INFO"

                # Check for world-accessible (other bits set for read or write)
                PERMS=$(echo "$SOCK_INFO" | awk '{print $1}')
                if echo "$PERMS" | grep -q '..w'; then
                    echo "    [HIGH] World-writable socket: $socket"
                    WORLD_ACCESSIBLE=$((WORLD_ACCESSIBLE + 1))
                fi
                if echo "$PERMS" | grep -q 'r..r'; then
                    echo "    [HIGH] World-readable socket: $socket"
                    WORLD_ACCESSIBLE=$((WORLD_ACCESSIBLE + 1))
                fi

                # Check if socket name is in high-value list
                for hv in $HIGH_VALUE; do
                    if [ "$socket" = "$hv" ]; then
                        echo "    [CRITICAL] High-value socket present: $socket"
                        HIGH_VALUE_ACCESSIBLE="$HIGH_VALUE_ACCESSIBLE $socket"
                    fi
                done
                echo ""
            fi
        done

        if [ $WORLD_ACCESSIBLE -gt 0 ]; then
            echo "[HIGH] Total world-accessible sockets: $WORLD_ACCESSIBLE"
            echo ""
        else
            echo "[OK] No world-accessible sockets detected in /dev/socket/"
            echo ""
        fi
    else
        echo "[INFO] /dev/socket directory not found or not accessible"
        echo ""
    fi

    echo "└────────────────────────────────────────────────────────────────┘"
    echo ""

    # ─────────────────────────────────────────────────────────────────
    # SECTION: ABSTRACT NAMESPACE SOCKETS
    # ─────────────────────────────────────────────────────────────────
    echo "┌─ ABSTRACT NAMESPACE SOCKETS (@) ──────────────────────────────┐"
    echo ""
    echo "    Context: Abstract sockets (@ prefix) are not filesystem-visible"
    echo "    but are accessible to any process that knows the name. They are"
    echo "    restricted by uid/gid/SELinux but not by filesystem permissions."
    echo ""

    ABSTRACT_SOCKETS=$(cat /proc/net/unix 2>/dev/null | awk '{print $NF}' | grep "^@" | sort -u | head -50)
    ABSTRACT_COUNT=$(echo "$ABSTRACT_SOCKETS" | grep "^@" | wc -l)

    if [ $ABSTRACT_COUNT -gt 0 ]; then
        echo "[*] Found $ABSTRACT_COUNT abstract namespace sockets:"
        echo ""
        echo "$ABSTRACT_SOCKETS" | while read -r sock; do
            if [ -n "$sock" ]; then
                echo "    $sock"

                # Flag sockets with privileged service names
                case "$sock" in
                    *zygote*|*system_server*|*property_service*|*vold*|*netd*|*installd*|*logd*)
                        echo "    [CRITICAL] Privileged service socket"
                        ;;
                esac
            fi
        done
        echo ""
    else
        echo "[INFO] No abstract namespace sockets found or unable to enumerate"
        echo ""
    fi

    echo "└────────────────────────────────────────────────────────────────┘"
    echo ""

    # ─────────────────────────────────────────────────────────────────
    # SECTION: FILESYSTEM-BOUND SOCKETS (non-/dev/socket)
    # ─────────────────────────────────────────────────────────────────
    echo "┌─ FILESYSTEM-BOUND SOCKETS (non-/dev/socket) ───────────────────┐"
    echo ""
    echo "    Context: Sockets with filesystem paths outside /dev/socket are"
    echo "    typically app-specific or special-purpose. Check for world-"
    echo "    accessible paths and unusual ownership."
    echo ""

    FS_SOCKETS=$(cat /proc/net/unix 2>/dev/null | awk '{print $NF}' | grep "^/" | grep -v "^/dev/socket" | sort -u)
    FS_COUNT=$(echo "$FS_SOCKETS" | grep "^/" | wc -l)

    if [ $FS_COUNT -gt 0 ]; then
        echo "[*] Found $FS_COUNT filesystem-bound sockets outside /dev/socket:"
        echo ""
        echo "$FS_SOCKETS" | while read -r sock; do
            if [ -n "$sock" ] && [ -e "$sock" ]; then
                SOCK_PERMS=$(ls -la "$sock" 2>/dev/null)
                echo "$SOCK_PERMS"

                PERMS=$(echo "$SOCK_PERMS" | awk '{print $1}')
                if echo "$PERMS" | grep -q '..w'; then
                    echo "    [HIGH] World-writable socket: $sock"
                fi
                if echo "$PERMS" | grep -q 'r..r'; then
                    echo "    [HIGH] World-readable socket: $sock"
                fi
                echo ""
            fi
        done
    else
        echo "[OK] No filesystem-bound sockets found outside /dev/socket"
        echo ""
    fi

    echo "└────────────────────────────────────────────────────────────────┘"
    echo ""

    # ─────────────────────────────────────────────────────────────────
    # SECTION: SOCKET ACCESSIBILITY TEST
    # ─────────────────────────────────────────────────────────────────
    echo "┌─ SOCKET ACCESSIBILITY TEST ───────────────────────────────────┐"
    echo ""
    echo "    Context: Test if current user/uid can actually read, write, or"
    echo "    stat socket files. This is a practical privilege check."
    echo ""

    if [ -d /dev/socket ]; then
        READABLE=0
        WRITABLE=0
        DENIED=0

        for sock in /dev/socket/*; do
            if [ -e "$sock" ]; then
                if [ -w "$sock" ]; then
                    echo "[WRITABLE] $sock"
                    WRITABLE=$((WRITABLE + 1))
                elif [ -r "$sock" ]; then
                    echo "[READABLE] $sock"
                    READABLE=$((READABLE + 1))
                else
                    DENIED=$((DENIED + 1))
                fi
            fi
        done 2>/dev/null

        echo ""
        echo "[*] Accessibility summary:"
        echo "    Writable sockets:  $WRITABLE"
        echo "    Readable sockets:  $READABLE"
        echo "    Denied sockets:    $DENIED"
        echo ""

        if [ $WRITABLE -gt 0 ]; then
            echo "[HIGH] User has write access to $WRITABLE sockets"
            echo ""
        fi
    else
        echo "[INFO] /dev/socket not accessible for permission testing"
        echo ""
    fi

    echo "└────────────────────────────────────────────────────────────────┘"
    echo ""

    # ─────────────────────────────────────────────────────────────────
    # SECTION: NETSTAT UNIX SOCKETS
    # ─────────────────────────────────────────────────────────────────
    echo "┌─ NETSTAT UNIX SOCKETS ────────────────────────────────────────┐"
    echo ""
    echo "    Context: Show listening and connected Unix sockets as seen by"
    echo "    netstat or ss. States include LISTENING, CONNECTED, etc."
    echo ""

    if command -v netstat >/dev/null 2>&1; then
        echo "[*] Using netstat -x (Unix sockets):"
        echo ""
        netstat -x 2>/dev/null | head -50 || echo "[INFO] netstat -x produced no output"
        echo ""
    elif command -v ss >/dev/null 2>&1; then
        echo "[*] Using ss -x (Unix sockets):"
        echo ""
        ss -x 2>/dev/null | head -50 || echo "[INFO] ss -x produced no output"
        echo ""
    else
        echo "[INFO] Neither netstat nor ss available for Unix socket enumeration"
        echo ""
    fi

    echo "└────────────────────────────────────────────────────────────────┘"
    echo ""

    # ─────────────────────────────────────────────────────────────────
    # SECTION: ZYGOTE SOCKET
    # ─────────────────────────────────────────────────────────────────
    echo "┌─ ZYGOTE SOCKET (APP SPAWNING) ────────────────────────────────┐"
    echo ""
    echo "    Context: Zygote sockets (/dev/socket/zygote, zygote_secondary)"
    echo "    are used by the Android runtime to spawn new app processes."
    echo "    Access to zygote is normally restricted to system_server."
    echo "    If accessible from unprivileged shell, this is a critical"
    echo "    privilege escalation vector enabling arbitrary app spawning."
    echo ""

    ZYGOTE_SOCKETS="zygote zygote_secondary"
    ZYGOTE_ACCESSIBLE=0

    for zyg in $ZYGOTE_SOCKETS; do
        ZYG_PATH="/dev/socket/$zyg"
        if [ -e "$ZYG_PATH" ]; then
            ZYG_INFO=$(ls -la "$ZYG_PATH" 2>/dev/null)
            echo "$ZYG_INFO"

            if [ -w "$ZYG_PATH" ]; then
                echo "    [CRITICAL] Zygote socket is WRITABLE by current user"
                ZYGOTE_ACCESSIBLE=$((ZYGOTE_ACCESSIBLE + 1))
            elif [ -r "$ZYG_PATH" ]; then
                echo "    [CRITICAL] Zygote socket is READABLE by current user"
                ZYGOTE_ACCESSIBLE=$((ZYGOTE_ACCESSIBLE + 1))
            else
                echo "    [OK] Zygote socket is not accessible to current user"
            fi
            echo ""
        else
            echo "[INFO] $zyg not found (expected on devices without secondary zygote)"
            echo ""
        fi
    done

    if [ $ZYGOTE_ACCESSIBLE -gt 0 ]; then
        echo "[CRITICAL] One or more zygote sockets are accessible — high privilege escalation risk"
        echo ""
    fi

    echo "└────────────────────────────────────────────────────────────────┘"
    echo ""

    # ─────────────────────────────────────────────────────────────────
    # SECTION: SUMMARY
    # ─────────────────────────────────────────────────────────────────
    echo "╔════════════════════════════════════════════════════════════════╗"
    echo "║                        AUDIT SUMMARY                           ║"
    echo "╚════════════════════════════════════════════════════════════════╝"
    echo ""
    echo "[*] Key Findings:"
    echo "    • Total Unix sockets: ~$((SOCKET_COUNT - 1))"
    echo "    • /dev/socket files: ~$SOCKET_FILES_COUNT (if enumerated)"
    echo "    • Abstract sockets (@): ~$ABSTRACT_COUNT"
    echo "    • Filesystem-bound (/): ~$FS_COUNT"
    echo ""
    echo "[*] Recommendations:"
    echo "    1. World-accessible sockets should be restricted to necessary service ports"
    echo "    2. Verify zygote and property_service are not accessible from shell"
    echo "    3. Check for custom app sockets in /data/local/tmp or /cache with weak perms"
    echo "    4. Use SELinux context to restrict socket access at policy level"
    echo "    5. Monitor socket creation/deletion for runtime security"
    echo ""
    echo "[*] Audit completed: $(date '+%Y-%m-%d %H:%M:%S')"
    echo ""

} > "${OUTPUT_FILE}" 2>&1

echo "[+] Unix socket audit saved to: ${OUTPUT_FILE}"
