#!/system/bin/sh
# 28_audit_tee.sh — TEE (Trusted Execution Environment) attack surface mapping
# Probes accessible TEE interfaces, devices, and services from unprivileged shell context

OUTPUT_DIR="${1:-.}"
OUTPUT_FILE="${OUTPUT_DIR}/probe_tee_surface.txt"

{
    echo "=== TEE Attack Surface Probe ==="
    echo ""

    echo "=== Section 1: TEE Device Nodes ==="
    echo "TEE device files (/dev/tee*):"
    ls -la /dev/tee* 2>/dev/null || echo "[N/A]"
    echo ""

    echo "TEE private device files (/dev/teepriv*):"
    ls -la /dev/teepriv* 2>/dev/null || echo "[N/A]"
    echo ""

    echo "Attempting to read /dev/tee0 (expect Permission denied from SELinux):"
    od -c /dev/tee0 2>&1 | head -3
    echo ""

    echo "SELinux label on /dev/tee0:"
    ls -Z /dev/tee0 2>/dev/null || echo "[N/A]"
    echo ""

    echo "=== Section 2: TEE Supplicant Process ==="
    echo "tee_supplicant process info:"
    TEE_PID=$(ps -A 2>/dev/null | grep -i tee_supplicant | awk '{print $1}' | head -1)

    if [ -n "$TEE_PID" ]; then
        ps -A 2>/dev/null | grep -i tee_supplicant
        echo ""
        echo "Open file descriptors for tee_supplicant (PID: $TEE_PID):"
        ls /proc/$TEE_PID/fd 2>/dev/null | head -20 || echo "[N/A]"
        echo ""
        echo "Process status (capabilities, UIDs, SELinux context):"
        cat /proc/$TEE_PID/status 2>/dev/null | grep -E 'Cap|Uid|Gid|SELinux' || echo "[N/A]"
    else
        echo "[N/A] tee_supplicant not running"
    fi
    echo ""

    echo "=== Section 3: TEE-Related Binder Services ==="
    echo "Querying android.security.apc:"
    service check android.security.apc 2>/dev/null || echo "[N/A]"
    echo ""

    echo "Querying android.security.authorization:"
    service check android.security.authorization 2>/dev/null || echo "[N/A]"
    echo ""

    echo "Querying android.hardware.security.keymint.IKeyMintDevice/default:"
    service check android.hardware.security.keymint.IKeyMintDevice/default 2>/dev/null || echo "[N/A]"
    echo ""

    echo "Querying android.system.keystore2.IKeystoreService/default:"
    service check android.system.keystore2.IKeystoreService/default 2>/dev/null || echo "[N/A]"
    echo ""

    echo "=== Section 4: KeyMint / Keystore Surface ==="
    echo "Keystore directory contents (/data/misc/keystore, max depth 2):"
    find /data/misc/keystore -maxdepth 2 2>/dev/null | head -20 || echo "[N/A]"
    echo ""

    echo "Keystore directory permissions:"
    ls -la /data/misc/keystore 2>/dev/null || echo "[N/A]"
    echo ""

    echo "User misc directory permissions:"
    ls -la /data/misc/user 2>/dev/null || echo "[N/A]"
    echo ""

    echo "=== Section 5: TEE Configuration and Libraries ==="
    echo "TEE init configuration file:"
    cat /vendor/etc/init/android.hardware.security.keymint@2.0-service-aw.rc 2>/dev/null || echo "[N/A]"
    echo ""

    echo "TEE-related libraries in /vendor/lib64:"
    ls -la /vendor/lib64/*tee* /vendor/lib64/*optee* /vendor/lib64/*keymint* 2>/dev/null | head -20 || echo "[N/A]"
    echo ""

    echo "Extracting strings from tee_supplicant binary (dev/ioctl/uuid/session patterns):"
    if [ -x /vendor/bin/tee_supplicant ]; then
        strings /vendor/bin/tee_supplicant 2>/dev/null | grep -E '/dev/|ioctl|uuid|session' | head -20
    else
        echo "[N/A] /vendor/bin/tee_supplicant not found or not executable"
    fi
    echo ""

    echo "=== Section 6: TEE Trusted Applications (TA) ==="
    echo "TA binary files in /vendor and /system:"
    find /vendor /system -name "*.ta" -o -name "*.TA" 2>/dev/null | head -20 || echo "[N/A]"
    echo ""

    echo "TA file details (first 10):"
    find /vendor /system -name "*.ta" 2>/dev/null | head -10 | while read f; do
        ls -la "$f"
    done || echo "[N/A]"
    echo ""

    echo "=== Section 7: TEE Daemon Ports and IPC ==="
    echo "Searching for tee-related listening sockets:"
    netstat -ln 2>/dev/null | grep -E 'tee|5558|5559|5560|5561' || echo "[N/A]"
    echo ""

    echo "Unix domain sockets in /dev/socket (may contain TEE-related IPC):"
    ls -la /dev/socket 2>/dev/null | grep -iE 'tee|keymint|keystore|hwbinder' || echo "[N/A] - none found"
    echo ""

    echo "=== Section 8: Risk Summary ==="
    echo "[CRITICAL] TEE devices are world-accessible if permissions allow (check Section 1)"
    echo "[HIGH] Binder IPC to KeyMint/Keystore may be exploitable via transaction forgery"
    echo "[HIGH] TA extraction and offline analysis may reveal TEE implementation flaws"
    echo "[MEDIUM] tee_supplicant fd enumeration may leak TEE internal state"
    echo ""

} > "${OUTPUT_FILE}" 2>&1
