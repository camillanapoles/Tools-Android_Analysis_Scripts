#!/system/bin/sh
# 17_audit_namespaces.sh - Investigate Linux namespace state and unprivileged namespace clone capability
# Purpose: Deep enumeration of namespace configuration and unshare permissions on Android 14

OUTPUT_DIR="${1:-.}"
OUTPUT_FILE="${OUTPUT_DIR}/probe_namespaces.txt"

{
    echo "=== Namespace Probe ==="
    echo "Timestamp: $(date)"
    echo ""

    echo "=== Shell's Own Namespace Links ==="
    ls -la /proc/self/ns/ 2>&1
    echo ""

    echo "=== Namespace Configuration Checks ==="

    echo "[CHECK] /proc/sys/kernel/unprivileged_userns_clone"
    if [ -f /proc/sys/kernel/unprivileged_userns_clone ]; then
        echo "[FOUND] $(cat /proc/sys/kernel/unprivileged_userns_clone)"
    else
        echo "[NOT FOUND] File does not exist"
    fi
    echo ""

    echo "[CHECK] /proc/sys/kernel/unprivileged_bpf_disabled"
    if [ -f /proc/sys/kernel/unprivileged_bpf_disabled ]; then
        echo "[FOUND] $(cat /proc/sys/kernel/unprivileged_bpf_disabled)"
    else
        echo "[NOT FOUND] File does not exist"
    fi
    echo ""

    echo "[CHECK] /proc/sys/user/max_user_namespaces"
    if [ -f /proc/sys/user/max_user_namespaces ]; then
        echo "[FOUND] $(cat /proc/sys/user/max_user_namespaces)"
    else
        echo "[NOT FOUND] File does not exist"
    fi
    echo ""

    echo "=== Process Namespace Enumeration ==="
    echo "[INFO] Scanning first 20 accessible processes for namespace differences..."
    for pid in $(ls /proc/ 2>/dev/null | grep -E '^[0-9]+$' | head -20); do
        if [ -d "/proc/$pid/ns" ]; then
            echo "--- PID $pid ---"
            ls -la "/proc/$pid/ns/" 2>/dev/null | tail -n +2
        fi
    done
    echo ""

    echo "=== Current Process Namespace Identifiers ==="
    echo "[CHECK] readlink /proc/self/ns/user:"
    readlink /proc/self/ns/user 2>&1
    echo ""

    echo "[CHECK] readlink /proc/self/ns/pid:"
    readlink /proc/self/ns/pid 2>&1
    echo ""

    echo "[CHECK] readlink /proc/self/ns/mount:"
    readlink /proc/self/ns/mount 2>&1
    echo ""

    echo "[CHECK] readlink /proc/self/ns/net:"
    readlink /proc/self/ns/net 2>&1
    echo ""

    echo "=== Process Status (Capabilities, Seccomp, NoNewPrivs) ==="
    if [ -f /proc/self/status ]; then
        grep -iE 'Cap|Seccomp|NoNew' /proc/self/status 2>&1
    else
        echo "[ERROR] /proc/self/status not accessible"
    fi
    echo ""

    echo "=== Namespace Comparison Summary ==="
    SELF_NS_USER=$(readlink /proc/self/ns/user 2>/dev/null)
    echo "Our user namespace: $SELF_NS_USER"

    DIFF_NS_COUNT=0
    for pid in $(ls /proc/ 2>/dev/null | grep -E '^[0-9]+$' | head -20); do
        if [ -r "/proc/$pid/ns/user" ]; then
            OTHER_NS=$(readlink "/proc/$pid/ns/user" 2>/dev/null)
            if [ "$OTHER_NS" != "$SELF_NS_USER" ] && [ -n "$OTHER_NS" ]; then
                echo "[FINDING] PID $pid runs in different user namespace: $OTHER_NS"
                DIFF_NS_COUNT=$((DIFF_NS_COUNT + 1))
            fi
        fi
    done

    if [ $DIFF_NS_COUNT -eq 0 ]; then
        echo "[INFO] All sampled processes share the same user namespace"
    else
        echo "[FINDING] Found $DIFF_NS_COUNT processes in different user namespaces"
    fi
    echo ""

    echo "=== Namespace Probe Complete ==="

} > "${OUTPUT_FILE}" 2>&1

echo "Output written to: ${OUTPUT_FILE}"
