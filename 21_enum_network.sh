#!/system/bin/sh
# DROID FORENSIC - Network Interface Enumeration
# Collects network interfaces, IP addresses, and related configuration
# Usage: sh 21_enum_network.sh [output_directory]

OUTPUT_DIR="${1:-.}"
OUTPUT_FILE="${OUTPUT_DIR}/network_interfaces.txt"

echo "[*] Enumerating network interfaces..."

{
    echo "═══════════════════════════════════════════════════════════════"
    echo "  NETWORK INTERFACE ENUMERATION"
    echo "  Timestamp: $(date)"
    echo "  Hostname: $(hostname 2>/dev/null || getprop net.hostname 2>/dev/null || echo 'unknown')"
    echo "═══════════════════════════════════════════════════════════════"
    echo ""

    # Basic interface listing
    echo "┌─────────────────────────────────────────────────────────────┐"
    echo "│ INTERFACE LIST (ip link)                                   │"
    echo "└─────────────────────────────────────────────────────────────┘"
    ip link 2>/dev/null || cat /proc/net/dev 2>/dev/null
    echo ""

    # IP addresses
    echo "┌─────────────────────────────────────────────────────────────┐"
    echo "│ IP ADDRESSES (ip addr)                                     │"
    echo "└─────────────────────────────────────────────────────────────┘"
    ip addr 2>/dev/null || ifconfig -a 2>/dev/null
    echo ""

    # IPv6 addresses
    echo "┌─────────────────────────────────────────────────────────────┐"
    echo "│ IPv6 ADDRESSES                                             │"
    echo "└─────────────────────────────────────────────────────────────┘"
    cat /proc/net/if_inet6 2>/dev/null || echo "[not available]"
    echo ""

    # Routing table
    echo "┌─────────────────────────────────────────────────────────────┐"
    echo "│ ROUTING TABLE                                              │"
    echo "└─────────────────────────────────────────────────────────────┘"
    ip route 2>/dev/null || cat /proc/net/route 2>/dev/null
    echo ""

    # IPv6 routes
    echo "┌─────────────────────────────────────────────────────────────┐"
    echo "│ IPv6 ROUTING TABLE                                         │"
    echo "└─────────────────────────────────────────────────────────────┘"
    ip -6 route 2>/dev/null || cat /proc/net/ipv6_route 2>/dev/null
    echo ""

    # ARP table
    echo "┌─────────────────────────────────────────────────────────────┐"
    echo "│ ARP TABLE                                                  │"
    echo "└─────────────────────────────────────────────────────────────┘"
    ip neigh 2>/dev/null || cat /proc/net/arp 2>/dev/null
    echo ""

    # DNS configuration
    echo "┌─────────────────────────────────────────────────────────────┐"
    echo "│ DNS CONFIGURATION                                          │"
    echo "└─────────────────────────────────────────────────────────────┘"
    echo "resolv.conf:"
    cat /etc/resolv.conf 2>/dev/null || echo "[not available]"
    echo ""
    echo "System DNS properties:"
    getprop | grep -i dns 2>/dev/null
    echo ""

    # WiFi information
    echo "┌─────────────────────────────────────────────────────────────┐"
    echo "│ WIFI INFORMATION                                           │"
    echo "└─────────────────────────────────────────────────────────────┘"
    getprop | grep -i wifi 2>/dev/null
    echo ""
    cat /proc/net/wireless 2>/dev/null || echo "[wireless stats not available]"
    echo ""

    # Network device statistics
    echo "┌─────────────────────────────────────────────────────────────┐"
    echo "│ INTERFACE STATISTICS (/proc/net/dev)                       │"
    echo "└─────────────────────────────────────────────────────────────┘"
    cat /proc/net/dev 2>/dev/null
    echo ""

    # Network namespace info
    echo "┌─────────────────────────────────────────────────────────────┐"
    echo "│ NETWORK NAMESPACES                                         │"
    echo "└─────────────────────────────────────────────────────────────┘"
    ip netns list 2>/dev/null || echo "[namespaces not available or empty]"
    echo ""

    # Android-specific network properties
    echo "┌─────────────────────────────────────────────────────────────┐"
    echo "│ ANDROID NETWORK PROPERTIES                                 │"
    echo "└─────────────────────────────────────────────────────────────┘"
    getprop | grep -E "^(\[net\.|dhcp\.|wifi\.)" 2>/dev/null
    echo ""

    # VPN information
    echo "┌─────────────────────────────────────────────────────────────┐"
    echo "│ VPN/TUNNEL INTERFACES                                      │"
    echo "└─────────────────────────────────────────────────────────────┘"
    ip tunnel show 2>/dev/null || echo "[tunnel info not available]"
    ls -la /dev/tun* 2>/dev/null || echo "[no tun devices]"
    echo ""

} > "${OUTPUT_FILE}" 2>&1

echo "[+] Network enumeration saved to: ${OUTPUT_FILE}"
