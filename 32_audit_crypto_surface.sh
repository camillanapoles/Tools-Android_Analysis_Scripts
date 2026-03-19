#!/system/bin/sh
# 32_audit_crypto_surface.sh — Cryptographic surface audit (keys, keystore, TEE)
# Usage: sh 32_audit_crypto_surface.sh [output_directory]
OUTPUT_DIR="${1:-.}"
OUTPUT_FILE="${OUTPUT_DIR}/audit_crypto_surface.txt"
{
    echo "============================================================"
    echo "  39_audit_crypto_surface.sh — Cryptographic Surface Audit"
    echo "============================================================"
    echo ""

    # ----------------------------------------------------------------
    echo "=== SECTION 1: KERNEL KEYRING (/proc/keys) ==="
    echo ""
    if [ -r /proc/keys ]; then
        echo "[INFO] /proc/keys is readable — enumerating kernel keyring:"
        cat /proc/keys 2>/dev/null
        echo ""
        TOTAL_KEYS=$(cat /proc/keys 2>/dev/null | wc -l)
        echo "Total key entries: ${TOTAL_KEYS}"
        USER_KEYS=$(cat /proc/keys 2>/dev/null | grep -c "user\|logon" 2>/dev/null || echo 0)
        if [ "${USER_KEYS}" -gt 0 ] 2>/dev/null; then
            echo "[HIGH] ${USER_KEYS} user/logon key(s) visible in kernel keyring — key material may be accessible from shell"
        fi
        ASYM_KEYS=$(cat /proc/keys 2>/dev/null | grep -c "asymmetric" 2>/dev/null || echo 0)
        if [ "${ASYM_KEYS}" -gt 0 ] 2>/dev/null; then
            echo "[HIGH] ${ASYM_KEYS} asymmetric key(s) in kernel keyring"
        fi
        KEYRING_COUNT=$(cat /proc/keys 2>/dev/null | grep -c "keyring" 2>/dev/null || echo 0)
        echo "[INFO] Keyrings: ${KEYRING_COUNT}, Asymmetric: ${ASYM_KEYS}, User/logon: ${USER_KEYS}"
    else
        echo "[INFO] /proc/keys not accessible from shell (normal — requires CAP_READ_SYMMETRIC_KEYS or root)"
    fi
    echo ""

    # ----------------------------------------------------------------
    echo "=== SECTION 2: KEYSTORE2 KEY INVENTORY ==="
    echo ""
    echo "keystore2 process check:"
    ps -A 2>/dev/null | grep keystore || echo "[INFO] keystore2 not visible in ps output"
    echo ""
    echo "keystore2 service check:"
    service check android.security.keystore2 2>/dev/null || echo "[INFO] android.security.keystore2 not reachable via service check"
    echo ""
    echo "Attempting key list via cmd keystore2:"
    KS2_OUT=$(cmd keystore2 list 2>/dev/null)
    if [ -n "${KS2_OUT}" ]; then
        echo "${KS2_OUT}"
        KS2_COUNT=$(echo "${KS2_OUT}" | wc -l)
        echo "[HIGH] ${KS2_COUNT} keystore2 key entries visible without root — verify this is expected for shell UID"
    else
        echo "[INFO] cmd keystore2 list returned no output (normal for non-root)"
    fi
    echo ""
    echo "Attempting key list via keystore_cli_v2:"
    KS_CLI_OUT=$(keystore_cli_v2 list 2>/dev/null)
    if [ -n "${KS_CLI_OUT}" ]; then
        echo "${KS_CLI_OUT}"
        echo "[HIGH] keystore_cli_v2 returned key entries — key inventory accessible from shell"
    else
        echo "[INFO] keystore_cli_v2 list returned no output or binary not found"
    fi
    echo ""

    # ----------------------------------------------------------------
    echo "=== SECTION 3: /vendor/etc/ KEY MATERIAL SCAN ==="
    echo ""
    echo "Searching for certificate/key files in /vendor/etc/:"
    FOUND_KEYS=$(find /vendor/etc -name "*.pem" -o -name "*.key" -o -name "*.crt" -o -name "*.p12" -o -name "*.pfx" 2>/dev/null | head -30)
    if [ -n "${FOUND_KEYS}" ]; then
        echo "${FOUND_KEYS}" | while read KFILE; do
            ls -la "${KFILE}" 2>/dev/null
            # Check world-readability
            PERMS=$(ls -la "${KFILE}" 2>/dev/null | awk '{print $1}')
            case "${KFILE}" in
                *.key|*.p12|*.pfx)
                    # World-readable private key = CRITICAL
                    case "${PERMS}" in
                        *"r--"*|*"r-x"*)
                            echo "[CRITICAL] Private key file is world-readable: ${KFILE}"
                            ;;
                        *)
                            echo "[INFO] Private key file found (check permissions): ${KFILE}"
                            ;;
                    esac
                    ;;
                *.pem|*.crt)
                    case "${PERMS}" in
                        *"r--"*|*"r-x"*)
                            echo "[HIGH] Certificate file is world-readable: ${KFILE}"
                            ;;
                        *)
                            echo "[INFO] Certificate file (restricted): ${KFILE}"
                            ;;
                    esac
                    ;;
            esac
        done
    else
        echo "[INFO] No .pem/.key/.crt/.p12/.pfx files found in /vendor/etc/"
    fi
    echo ""
    echo "Broader search for private key headers in /vendor/etc/:"
    grep -rl "BEGIN.*PRIVATE KEY\|BEGIN RSA PRIVATE\|BEGIN EC PRIVATE" /vendor/etc/ 2>/dev/null | head -10 | while read F; do
        echo "[CRITICAL] File contains private key material: ${F}"
        ls -la "${F}" 2>/dev/null
    done
    echo ""

    # ----------------------------------------------------------------
    echo "=== SECTION 4: WIDEVINE STATE ==="
    echo ""
    echo "Widevine security level (getprop):"
    WV_LEVEL=$(getprop cts.widevine_security_level 2>/dev/null)
    if [ -n "${WV_LEVEL}" ]; then
        echo "cts.widevine_security_level = ${WV_LEVEL}"
        case "${WV_LEVEL}" in
            *L3*|*l3*)
                echo "[HIGH] Widevine L3 — software-only, no TEE protection; keys extractable via software attacks"
                ;;
            *L1*|*l1*)
                echo "[INFO] Widevine L1 — TEE-backed, hardware protected"
                ;;
            *)
                echo "[MEDIUM] Widevine level unrecognized: ${WV_LEVEL}"
                ;;
        esac
    else
        echo "[INFO] cts.widevine_security_level property not set"
    fi
    echo ""
    echo "Widevine-related properties:"
    getprop 2>/dev/null | grep -i "widevine\|drm\|mediadrm" | head -20
    echo ""
    echo "drm.drmManager service check:"
    service check drm.drmManager 2>/dev/null || echo "[INFO] drm.drmManager not reachable"
    echo ""
    echo "Widevine vendor credential files (/vendor/etc/drm/):"
    if [ -d /vendor/etc/drm ]; then
        ls -laR /vendor/etc/drm/ 2>/dev/null
    else
        echo "[INFO] /vendor/etc/drm/ does not exist"
    fi
    echo ""
    echo "Widevine blobs (/data/vendor/mediadrm/) — requires elevated access:"
    if [ -d /data/vendor/mediadrm ]; then
        ls -laR /data/vendor/mediadrm/ 2>/dev/null || echo "[INFO] /data/vendor/mediadrm/ not readable from shell (expected)"
    else
        echo "[INFO] /data/vendor/mediadrm/ does not exist or not accessible"
    fi
    echo ""

    # ----------------------------------------------------------------
    echo "=== SECTION 5: FACE BIOMETRIC MODEL FILES ==="
    echo ""
    echo "Searching known face model directories:"
    for FACEDIR in /vendor/etc/face /data/misc/face /data/vendor/face /data/misc/biometrics; do
        if [ -d "${FACEDIR}" ]; then
            echo "Contents of ${FACEDIR}:"
            ls -laR "${FACEDIR}" 2>/dev/null || echo "[INFO] Not readable"
        else
            echo "[INFO] ${FACEDIR} does not exist"
        fi
        echo ""
    done
    echo "Searching filesystem for face model files (depth-limited):"
    find / -maxdepth 8 \( -name "*.facemodel" -o -name "face_model*" -o -name "*.face" \) 2>/dev/null | head -10 | while read FM; do
        FMPERMS=$(ls -la "${FM}" 2>/dev/null)
        echo "${FMPERMS}"
        case "${FMPERMS}" in
            *"r--"*|*"r-x"*)
                echo "[HIGH] Face biometric model is world-readable: ${FM} — can be used for offline attack"
                ;;
            *)
                echo "[INFO] Face model file found: ${FM}"
                ;;
        esac
    done
    echo ""

    # ----------------------------------------------------------------
    echo "=== SECTION 6: HARDWARE-BACKED KEY EVIDENCE ==="
    echo ""
    echo "Keymaster/KeyMint/StrongBox properties:"
    getprop 2>/dev/null | grep -i "keymaster\|keymint\|strongbox\|hardware.security" | head -20
    echo ""
    echo "KeyMint HAL implementation files (/vendor/lib64/hw/):"
    if [ -d /vendor/lib64/hw ]; then
        ls -la /vendor/lib64/hw/ 2>/dev/null | grep -i "keymint\|keymaster" | head -10 \
            || echo "[INFO] No keymint/keymaster HAL libs found in /vendor/lib64/hw/"
    else
        echo "[INFO] /vendor/lib64/hw/ does not exist"
    fi
    echo ""
    echo "KeyMint HAL implementation files (/vendor/lib/hw/):"
    if [ -d /vendor/lib/hw ]; then
        ls -la /vendor/lib/hw/ 2>/dev/null | grep -i "keymint\|keymaster" | head -10 \
            || echo "[INFO] No keymint/keymaster HAL libs found in /vendor/lib/hw/"
    else
        echo "[INFO] /vendor/lib/hw/ does not exist"
    fi
    echo ""
    echo "hardware.keystore.xml (hardware-backed key declaration):"
    if [ -f /vendor/etc/hardware_keystore.xml ]; then
        cat /vendor/etc/hardware_keystore.xml 2>/dev/null
    elif [ -f /system/etc/hardware_keystore.xml ]; then
        cat /system/etc/hardware_keystore.xml 2>/dev/null
    else
        echo "[INFO] hardware_keystore.xml not found in expected locations"
    fi
    echo ""
    echo "Strongbox / SE attestation properties:"
    getprop 2>/dev/null | grep -i "strongbox\|secure_element\|se_service" | head -10
    echo ""
    KEYMINT_HW=$(getprop ro.hardware.keymint 2>/dev/null)
    if [ -n "${KEYMINT_HW}" ]; then
        echo "[INFO] ro.hardware.keymint = ${KEYMINT_HW} — hardware-backed keymint present (expected)"
    else
        KEYMASTER_HW=$(getprop ro.hardware.keymaster 2>/dev/null)
        if [ -n "${KEYMASTER_HW}" ]; then
            echo "[INFO] ro.hardware.keymaster = ${KEYMASTER_HW} — hardware-backed keymaster present"
        else
            echo "[HIGH] No hardware keymint/keymaster property set — may be software fallback only"
        fi
    fi
    echo ""

    # ----------------------------------------------------------------
    echo "=== SECTION 7: CERTIFICATE PINNING / TRUST ANCHORS ==="
    echo ""

    # --- System CA certificates ---
    echo "System CA store:"
    SYSTEM_CERT_DIRS="/system/etc/security/cacerts /apex/com.android.conscrypt/cacerts /etc/security/cacerts"
    SYSTEM_CERT_DIR_FOUND=""
    for _cdir in $SYSTEM_CERT_DIRS; do
        if [ -d "${_cdir}" ]; then
            SYSTEM_CERT_DIR_FOUND="${_cdir}"
            break
        fi
    done
    if [ -n "${SYSTEM_CERT_DIR_FOUND}" ]; then
        SYS_CA_COUNT=$(ls "${SYSTEM_CERT_DIR_FOUND}" 2>/dev/null | wc -l)
        echo "[INFO] ${SYS_CA_COUNT} system CA certificate(s) in ${SYSTEM_CERT_DIR_FOUND}"
        echo ""
        echo "Certificate subjects (first 30):"
        for _cert in "${SYSTEM_CERT_DIR_FOUND}"/*; do
            [ -f "${_cert}" ] || continue
            _subj=$(openssl x509 -in "${_cert}" -noout -subject 2>/dev/null | sed 's/subject=//')
            [ -z "${_subj}" ] && _subj=$(head -5 "${_cert}" 2>/dev/null | grep -E "CN=|O=" | head -1)
            _name=$(basename "${_cert}")
            # Flag debug/proxy CAs
            case "$(echo "${_subj}" | tr '[:upper:]' '[:lower:]')" in
                *mitmproxy*|*burp*|*charles*|*fiddler*|*zap*|*portswigger*|*debug*|*test*|*localhost*)
                    echo "[CRITICAL] ${_name}: ${_subj}" ;;
                *)
                    echo "  ${_name}: ${_subj}" ;;
            esac
        done 2>/dev/null | head -30
        echo ""
    else
        echo "[INFO] /system/etc/security/cacerts/ does not exist"
    fi
    echo ""

    # --- User-added CAs ---
    echo "User-added CAs (/data/misc/user/0/cacerts-added/):"
    if [ -d /data/misc/user/0/cacerts-added ]; then
        USER_CA_COUNT=$(ls /data/misc/user/0/cacerts-added/ 2>/dev/null | wc -l)
        if [ "${USER_CA_COUNT}" -gt 0 ] 2>/dev/null; then
            echo "[HIGH] ${USER_CA_COUNT} user-added CA certificate(s) found — MitM risk"
            ls -la /data/misc/user/0/cacerts-added/ 2>/dev/null
            echo ""
            echo "User CA details:"
            for _cert in /data/misc/user/0/cacerts-added/*; do
                [ -f "${_cert}" ] || continue
                _name=$(basename "${_cert}")
                _subj=$(openssl x509 -in "${_cert}" -noout -subject 2>/dev/null | sed 's/subject=//')
                _issuer=$(openssl x509 -in "${_cert}" -noout -issuer 2>/dev/null | sed 's/issuer=//')
                _dates=$(openssl x509 -in "${_cert}" -noout -dates 2>/dev/null)
                echo "  Certificate: ${_name}"
                echo "    Subject: ${_subj}"
                echo "    Issuer:  ${_issuer}"
                echo "    ${_dates}"
                echo ""
            done
        else
            echo "[INFO] No user-added CAs (0 files)"
        fi
    else
        echo "[INFO] /data/misc/user/0/cacerts-added/ does not exist"
    fi
    echo ""

    # --- Removed system CAs ---
    echo "Removed system CAs (/data/misc/user/0/cacerts-removed/):"
    if [ -d /data/misc/user/0/cacerts-removed ]; then
        REM_CA_COUNT=$(ls /data/misc/user/0/cacerts-removed/ 2>/dev/null | wc -l)
        if [ "${REM_CA_COUNT}" -gt 0 ] 2>/dev/null; then
            echo "[MEDIUM] ${REM_CA_COUNT} system CA(s) removed by user — trust chain modified"
            ls -la /data/misc/user/0/cacerts-removed/ 2>/dev/null
        else
            echo "[INFO] No system CAs removed"
        fi
    else
        echo "[INFO] /data/misc/user/0/cacerts-removed/ does not exist"
    fi
    echo ""

    # --- Network security config ---
    echo "Network security config (check for cleartext / custom pins):"
    find /data/app -name "network_security_config.xml" 2>/dev/null | head -10 | while read NSC; do
        echo "[INFO] Found: ${NSC}"
        cat "${NSC}" 2>/dev/null | head -30
        echo "---"
    done
    echo ""

    # ----------------------------------------------------------------
    echo "=== SECTION 8: SUMMARY ==="
    echo ""
    echo "Audit complete. Review [CRITICAL] and [HIGH] labels above for action items."
    echo "Key areas of concern:"
    echo "  - Kernel keyring visibility (Section 1)"
    echo "  - Keystore2 key exposure without root (Section 2)"
    echo "  - World-readable private key files in /vendor/etc/ (Section 3)"
    echo "  - Widevine L3 (software-only, no TEE) (Section 4)"
    echo "  - World-readable face biometric models (Section 5)"
    echo "  - Software-fallback key storage (Section 6)"
    echo "  - User-added CA certificates / debug proxy CAs / expired certs (Section 7)"
    echo ""
    echo "NOTE: This script enumerates only. No key material was decrypted or extracted."

} > "${OUTPUT_FILE}" 2>&1
