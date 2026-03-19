#!/system/bin/sh
# DROID FORENSIC - Netstat / Socket Enumeration
# Collects active network connections, listening ports, and socket information
# Usage: sh 22_enum_netstat.sh [output_directory]

OUTPUT_DIR="${1:-.}"
OUTPUT_FILE="${OUTPUT_DIR}/netstat.txt"

echo "[*] Collecting netstat and socket information..."

{
    echo "═══════════════════════════════════════════════════════════════"
    echo "  NETSTAT / SOCKET ENUMERATION"
    echo "  Timestamp: $(date)"
    echo "═══════════════════════════════════════════════════════════════"
    echo ""

    # netstat if available
    echo "┌─────────────────────────────────────────────────────────────┐"
    echo "│ NETSTAT -tulpn (Listening TCP/UDP with PIDs)               │"
    echo "└─────────────────────────────────────────────────────────────┘"
    netstat -tulpn 2>/dev/null || echo "[netstat not available]"
    echo ""

    echo "┌─────────────────────────────────────────────────────────────┐"
    echo "│ NETSTAT -an (All connections, numeric)                     │"
    echo "└─────────────────────────────────────────────────────────────┘"
    netstat -an 2>/dev/null || echo "[netstat not available]"
    echo ""

    # ss as alternative
    echo "┌─────────────────────────────────────────────────────────────┐"
    echo "│ SS -tulpn (Socket Statistics)                              │"
    echo "└─────────────────────────────────────────────────────────────┘"
    ss -tulpn 2>/dev/null || echo "[ss not available]"
    echo ""

    echo "┌─────────────────────────────────────────────────────────────┐"
    echo "│ SS -an (All sockets)                                       │"
    echo "└─────────────────────────────────────────────────────────────┘"
    ss -an 2>/dev/null || echo "[ss not available]"
    echo ""

    # /proc/net TCP connections
    echo "┌─────────────────────────────────────────────────────────────┐"
    echo "│ /proc/net/tcp (Raw TCP sockets - IPv4)                     │"
    echo "└─────────────────────────────────────────────────────────────┘"
    cat /proc/net/tcp 2>/dev/null || echo "[not available]"
    echo ""

    echo "┌─────────────────────────────────────────────────────────────┐"
    echo "│ /proc/net/tcp6 (Raw TCP sockets - IPv6)                    │"
    echo "└─────────────────────────────────────────────────────────────┘"
    cat /proc/net/tcp6 2>/dev/null || echo "[not available]"
    echo ""

    # /proc/net UDP
    echo "┌─────────────────────────────────────────────────────────────┐"
    echo "│ /proc/net/udp (Raw UDP sockets - IPv4)                     │"
    echo "└─────────────────────────────────────────────────────────────┘"
    cat /proc/net/udp 2>/dev/null || echo "[not available]"
    echo ""

    echo "┌─────────────────────────────────────────────────────────────┐"
    echo "│ /proc/net/udp6 (Raw UDP sockets - IPv6)                    │"
    echo "└─────────────────────────────────────────────────────────────┘"
    cat /proc/net/udp6 2>/dev/null || echo "[not available]"
    echo ""

    # Raw sockets
    echo "┌─────────────────────────────────────────────────────────────┐"
    echo "│ /proc/net/raw (Raw sockets)                                │"
    echo "└─────────────────────────────────────────────────────────────┘"
    cat /proc/net/raw 2>/dev/null || echo "[not available]"
    cat /proc/net/raw6 2>/dev/null
    echo ""

    # Unix domain sockets
    echo "┌─────────────────────────────────────────────────────────────┐"
    echo "│ /proc/net/unix (Unix Domain Sockets)                       │"
    echo "└─────────────────────────────────────────────────────────────┘"
    cat /proc/net/unix 2>/dev/null || echo "[not available]"
    echo ""

    # Netlink sockets
    echo "┌─────────────────────────────────────────────────────────────┐"
    echo "│ /proc/net/netlink (Netlink Sockets)                        │"
    echo "└─────────────────────────────────────────────────────────────┘"
    cat /proc/net/netlink 2>/dev/null || echo "[not available]"
    echo ""

    # Packet sockets (raw packet capture)
    echo "┌─────────────────────────────────────────────────────────────┐"
    echo "│ /proc/net/packet (Packet Sockets - pcap capable)           │"
    echo "└─────────────────────────────────────────────────────────────┘"
    cat /proc/net/packet 2>/dev/null || echo "[not available]"
    echo ""

    # Network statistics
    echo "┌─────────────────────────────────────────────────────────────┐"
    echo "│ /proc/net/snmp (Network Statistics)                        │"
    echo "└─────────────────────────────────────────────────────────────┘"
    cat /proc/net/snmp 2>/dev/null || echo "[not available]"
    echo ""

    # Socket memory usage
    echo "┌─────────────────────────────────────────────────────────────┐"
    echo "│ /proc/net/sockstat (Socket Memory Stats)                   │"
    echo "└─────────────────────────────────────────────────────────────┘"
    cat /proc/net/sockstat 2>/dev/null || echo "[not available]"
    cat /proc/net/sockstat6 2>/dev/null
    echo ""

    # Process to socket mapping attempt
    echo "┌─────────────────────────────────────────────────────────────┐"
    echo "│ PROCESS SOCKET MAPPINGS                                    │"
    echo "└─────────────────────────────────────────────────────────────┘"
    echo "Attempting to map sockets to processes..."
    for pid in /proc/[0-9]*; do
        pid_num=$(basename "$pid")
        fd_dir="$pid/fd"
        if [ -d "$fd_dir" ]; then
            cmdline=$(cat "$pid/cmdline" 2>/dev/null | tr '\0' ' ')
            for fd in "$fd_dir"/*; do
                link=$(readlink "$fd" 2>/dev/null)
                case "$link" in
                    socket:*|pipe:*)
                        echo "PID $pid_num ($cmdline): $link"
                        ;;
                esac
            done
        fi
    done 2>/dev/null | head -200
    echo ""
    echo "[truncated to 200 entries]"
    echo ""

} > "${OUTPUT_FILE}" 2>&1

echo "[+] Netstat enumeration saved to: ${OUTPUT_FILE}"
