#!/system/bin/sh
# DROID FORENSIC - User and UID Enumeration
# Collects user details, UIDs, GIDs, and Android-specific identifiers
# Usage: sh 13_enum_users.sh [output_directory]

OUTPUT_DIR="${1:-.}"
OUTPUT_FILE="${OUTPUT_DIR}/users_uids.txt"

echo "[*] Enumerating users and UIDs..."

{
    echo "═══════════════════════════════════════════════════════════════"
    echo "  USER AND UID ENUMERATION"
    echo "  Timestamp: $(date)"
    echo "═══════════════════════════════════════════════════════════════"
    echo ""

    # Current process identity
    echo "┌─────────────────────────────────────────────────────────────┐"
    echo "│ CURRENT PROCESS IDENTITY                                   │"
    echo "└─────────────────────────────────────────────────────────────┘"
    echo "id output:"
    id 2>/dev/null
    echo ""
    echo "whoami: $(whoami 2>/dev/null || echo '[not available]')"
    echo ""
    echo "/proc/self/status identity fields:"
    cat /proc/self/status 2>/dev/null | grep -E "^(Uid|Gid|Groups|Cap)"
    echo ""

    # SELinux context
    echo "┌─────────────────────────────────────────────────────────────┐"
    echo "│ SELINUX CONTEXT                                            │"
    echo "└─────────────────────────────────────────────────────────────┘"
    echo "Enforce status: $(getenforce 2>/dev/null || echo '[getenforce not available]')"
    echo "Current context: $(id -Z 2>/dev/null || cat /proc/self/attr/current 2>/dev/null || echo '[not available]')"
    echo ""

    # /etc/passwd
    echo "┌─────────────────────────────────────────────────────────────┐"
    echo "│ /etc/passwd                                                │"
    echo "└─────────────────────────────────────────────────────────────┘"
    cat /etc/passwd 2>/dev/null || echo "[/etc/passwd not readable]"
    echo ""

    # /system/etc/passwd
    echo "┌─────────────────────────────────────────────────────────────┐"
    echo "│ /system/etc/passwd                                         │"
    echo "└─────────────────────────────────────────────────────────────┘"
    cat /system/etc/passwd 2>/dev/null || echo "[/system/etc/passwd not readable]"
    echo ""

    # /etc/group
    echo "┌─────────────────────────────────────────────────────────────┐"
    echo "│ /etc/group                                                 │"
    echo "└─────────────────────────────────────────────────────────────┘"
    cat /etc/group 2>/dev/null || echo "[/etc/group not readable]"
    echo ""

    # /system/etc/group
    echo "┌─────────────────────────────────────────────────────────────┐"
    echo "│ /system/etc/group                                          │"
    echo "└─────────────────────────────────────────────────────────────┘"
    cat /system/etc/group 2>/dev/null || echo "[/system/etc/group not readable]"
    echo ""

    # Android AIDs reference
    echo "┌─────────────────────────────────────────────────────────────┐"
    echo "│ ANDROID SYSTEM AIDs (well-known)                           │"
    echo "└─────────────────────────────────────────────────────────────┘"
    cat << 'EOF'
AID_ROOT            0      Root
AID_SYSTEM          1000   System server
AID_RADIO           1001   Telephony
AID_BLUETOOTH       1002   Bluetooth
AID_GRAPHICS        1003   Graphics
AID_INPUT           1004   Input
AID_AUDIO           1005   Audio
AID_CAMERA          1006   Camera
AID_LOG             1007   Logging
AID_COMPASS         1008   Compass
AID_MOUNT           1009   Mount
AID_WIFI            1010   WiFi
AID_ADB             1011   ADB
AID_INSTALL         1012   Install
AID_MEDIA           1013   Media
AID_DHCP            1014   DHCP
AID_SDCARD_RW       1015   SDCard R/W
AID_VPN             1016   VPN
AID_KEYSTORE        1017   Keystore
AID_USB             1018   USB
AID_DRM             1019   DRM
AID_MDNSR           1020   mDNS
AID_GPS             1021   GPS
AID_MEDIA_RW        1023   Media R/W
AID_MTP             1024   MTP
AID_NFC             1027   NFC
AID_SDCARD_R        1028   SDCard Read
AID_CLAT            1029   CLAT
AID_LOOP_RADIO      1030   Loop Radio
AID_SHELL           2000   Shell
AID_CACHE           2001   Cache
AID_DIAG            2002   Diagnostics
AID_NET_BT_ADMIN    3001   Bluetooth Admin
AID_NET_BT          3002   Bluetooth
AID_INET            3003   Internet
AID_NET_RAW         3004   Raw Sockets (PCAP)
AID_NET_ADMIN       3005   Network Admin
AID_NET_BW_STATS    3006   Bandwidth Stats
AID_NET_BW_ACCT     3007   Bandwidth Accounting
AID_EVERYBODY       9997   Everybody
AID_MISC            9998   Misc
AID_NOBODY          9999   Nobody
AID_APP_START       10000  First app UID
AID_ISOLATED_START  99000  First isolated UID
EOF
    echo ""

    # Android users (multi-user)
    echo "┌─────────────────────────────────────────────────────────────┐"
    echo "│ ANDROID USERS (pm list users)                              │"
    echo "└─────────────────────────────────────────────────────────────┘"
    pm list users 2>/dev/null || echo "[pm list users not available]"
    echo ""

    # Running processes with UIDs
    echo "┌─────────────────────────────────────────────────────────────┐"
    echo "│ RUNNING PROCESSES BY UID                                   │"
    echo "└─────────────────────────────────────────────────────────────┘"
    ps -A -o USER,UID,PID,PPID,NAME 2>/dev/null | head -100 || ps -A 2>/dev/null | head -100 || ps 2>/dev/null | head -100
    echo "[truncated to 100 entries]"
    echo ""

    # Unique UIDs in running processes
    echo "┌─────────────────────────────────────────────────────────────┐"
    echo "│ UNIQUE UIDs IN RUNNING PROCESSES                           │"
    echo "└─────────────────────────────────────────────────────────────┘"
    ps -A -o UID 2>/dev/null | sort -n | uniq -c | sort -rn | head -30
    echo ""

    # SUID binaries
    echo "┌─────────────────────────────────────────────────────────────┐"
    echo "│ SUID BINARIES                                              │"
    echo "└─────────────────────────────────────────────────────────────┘"
    echo "Searching /system..."
    find /system -perm -4000 -type f 2>/dev/null | while read f; do
        ls -la "$f"
    done
    echo ""
    echo "Searching /vendor..."
    find /vendor -perm -4000 -type f 2>/dev/null | while read f; do
        ls -la "$f"
    done
    echo ""
    echo "Searching /data..."
    find /data -perm -4000 -type f 2>/dev/null | while read f; do
        ls -la "$f"
    done
    echo ""

    # SGID binaries
    echo "┌─────────────────────────────────────────────────────────────┐"
    echo "│ SGID BINARIES                                              │"
    echo "└─────────────────────────────────────────────────────────────┘"
    echo "Searching /system..."
    find /system -perm -2000 -type f 2>/dev/null | while read f; do
        ls -la "$f"
    done
    echo ""
    echo "Searching /vendor..."
    find /vendor -perm -2000 -type f 2>/dev/null | while read f; do
        ls -la "$f"
    done
    echo ""

    # Files owned by root in unusual places
    echo "┌─────────────────────────────────────────────────────────────┐"
    echo "│ ROOT-OWNED FILES IN /data                                  │"
    echo "└─────────────────────────────────────────────────────────────┘"
    find /data -user 0 -type f 2>/dev/null | head -50
    echo "[truncated to 50 entries]"
    echo ""

    # Files owned by special UIDs (network capable)
    echo "┌─────────────────────────────────────────────────────────────┐"
    echo "│ FILES OWNED BY NET_RAW (3004) - PCAP CAPABLE               │"
    echo "└─────────────────────────────────────────────────────────────┘"
    find /system /vendor -user 3004 -type f 2>/dev/null | head -20
    find /system /vendor -group 3004 -type f 2>/dev/null | head -20
    echo ""

    # Android permissions from platform.xml
    echo "┌─────────────────────────────────────────────────────────────┐"
    echo "│ PERMISSION TO GID MAPPINGS (platform.xml)                  │"
    echo "└─────────────────────────────────────────────────────────────┘"
    cat /system/etc/permissions/platform.xml 2>/dev/null | grep -A2 "<permission" | head -100
    echo "[truncated]"
    echo ""

    # /data/system users
    echo "┌─────────────────────────────────────────────────────────────┐"
    echo "│ /data/system USER DATA                                     │"
    echo "└─────────────────────────────────────────────────────────────┘"
    ls -la /data/system/users/ 2>/dev/null || echo "[not accessible]"
    ls -la /data/user/ 2>/dev/null || echo "[not accessible]"
    echo ""

} > "${OUTPUT_FILE}" 2>&1

echo "[+] User and UID enumeration saved to: ${OUTPUT_FILE}"
