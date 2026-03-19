
#!/system/bin/sh
# 23_audit_network_deep.sh — Deep network configuration audit
# Usage: sh 23_audit_network_deep.sh [output_directory]
OUTPUT_DIR="${1:-.}"
OUTPUT_FILE="${OUTPUT_DIR}/audit_network_deep.txt"

{
    echo "╔══════════════════════════════════════════════════════════╗"
    echo "║         DEEP NETWORK CONFIGURATION AUDIT                ║"
    echo "╚══════════════════════════════════════════════════════════╝"
    echo ""
    echo "Timestamp: $(date)"
    echo ""

    # ──────────────────────────────────────────────
    # SECTION 1: IPTABLES / IP6TABLES RULES
    # ──────────────────────────────────────────────
    echo "═══════════════════════════════════════════════════════════"
    echo "SECTION 1: IPTABLES / IP6TABLES RULES"
    echo "═══════════════════════════════════════════════════════════"
    echo ""

    echo "--- iptables filter table ---"
    IPT_OUT=$(iptables -L -n -v 2>/dev/null | head -80)
    if [ -n "$IPT_OUT" ]; then
        echo "$IPT_OUT"
        # Count rules in INPUT chain
        INPUT_RULES=$(iptables -L INPUT -n -v 2>/dev/null | tail -n +3 | grep -c ".")
        FORWARD_RULES=$(iptables -L FORWARD -n -v 2>/dev/null | tail -n +3 | grep -c ".")
        INPUT_POLICY=$(iptables -L INPUT -n -v 2>/dev/null | head -2 | grep -o "policy [A-Z]*" | awk '{print $2}')
        FORWARD_POLICY=$(iptables -L FORWARD -n -v 2>/dev/null | head -2 | grep -o "policy [A-Z]*" | awk '{print $2}')
        echo ""
        echo "[INFO] INPUT chain: policy=${INPUT_POLICY}, rules=${INPUT_RULES}"
        echo "[INFO] FORWARD chain: policy=${FORWARD_POLICY}, rules=${FORWARD_RULES}"
        if [ "$INPUT_POLICY" = "ACCEPT" ] && [ "$INPUT_RULES" -le 1 ] 2>/dev/null; then
            echo "[HIGH] INPUT policy ACCEPT with no/minimal rules — firewall may be open"
        fi
        if [ "$FORWARD_POLICY" = "ACCEPT" ] && [ "$FORWARD_RULES" -le 1 ] 2>/dev/null; then
            echo "[HIGH] FORWARD policy ACCEPT with no/minimal rules — packet forwarding open"
        fi
    else
        echo "[INFO] iptables not accessible or no rules (may require elevated privileges)"
    fi
    echo ""

    echo "--- iptables NAT table ---"
    iptables -L -n -v -t nat 2>/dev/null | head -40 || echo "[INFO] NAT table not accessible"
    echo ""

    echo "--- ip6tables filter table ---"
    IP6T_OUT=$(ip6tables -L -n -v 2>/dev/null | head -40)
    if [ -n "$IP6T_OUT" ]; then
        echo "$IP6T_OUT"
        INPUT6_POLICY=$(ip6tables -L INPUT -n -v 2>/dev/null | head -2 | grep -o "policy [A-Z]*" | awk '{print $2}')
        INPUT6_RULES=$(ip6tables -L INPUT -n -v 2>/dev/null | tail -n +3 | grep -c ".")
        echo ""
        echo "[INFO] IPv6 INPUT chain: policy=${INPUT6_POLICY}, rules=${INPUT6_RULES}"
        if [ "$INPUT6_POLICY" = "ACCEPT" ] && [ "$INPUT6_RULES" -le 1 ] 2>/dev/null; then
            echo "[HIGH] IPv6 INPUT policy ACCEPT with no/minimal rules — IPv6 firewall open"
        fi
    else
        echo "[INFO] ip6tables not accessible or no rules"
    fi
    echo ""

    # ──────────────────────────────────────────────
    # SECTION 2: POLICY ROUTING TABLES
    # ──────────────────────────────────────────────
    echo "═══════════════════════════════════════════════════════════"
    echo "SECTION 2: POLICY ROUTING TABLES"
    echo "═══════════════════════════════════════════════════════════"
    echo ""

    echo "--- IP routing rules (policy rules) ---"
    ip rule list 2>/dev/null || ip rule show 2>/dev/null || echo "[INFO] ip rule not available"
    echo ""

    echo "--- Routing table (all) ---"
    RT_ALL=$(ip route show table all 2>/dev/null | head -40)
    if [ -n "$RT_ALL" ]; then
        echo "$RT_ALL"
        VPN_ROUTES=$(echo "$RT_ALL" | grep -c "tun\|vpn\|ppp")
        if [ "$VPN_ROUTES" -gt 0 ] 2>/dev/null; then
            echo "[INFO] $VPN_ROUTES route(s) reference VPN/tunnel interfaces — possible active VPN"
        fi
    else
        ip route show 2>/dev/null | head -40 || echo "[INFO] ip route not available"
    fi
    echo ""

    # ──────────────────────────────────────────────
    # SECTION 3: SOCKET → UID MAPPING
    # ──────────────────────────────────────────────
    echo "═══════════════════════════════════════════════════════════"
    echo "SECTION 3: SOCKET → UID MAPPING"
    echo "═══════════════════════════════════════════════════════════"
    echo ""
    echo "[INFO] /proc/net/tcp6 format: sl local_addr rem_addr st tx_rx tr retrns uid timeout inode"
    echo "[INFO] local_addr is hex-encoded: XXXXXXXX:PPPP (addr:port). UID is column 8 (0-indexed)."
    echo "[INFO] Address 00000000000000000000000001000000 = ::1 (loopback), 00000000 = 0.0.0.0"
    echo ""

    echo "--- /proc/net/tcp6 (IPv6+IPv4-mapped TCP sockets) ---"
    if [ -f /proc/net/tcp6 ]; then
        head -30 /proc/net/tcp6
        # Check for UID=0 listening sockets on non-loopback (state 0A = LISTEN)
        # Column layout: sl local rem st tx:rx tr retr uid to inode
        # Non-loopback listening: state=0A, local addr not pure loopback
        echo ""
        echo "[INFO] Scanning for UID=0 LISTEN sockets on non-loopback..."
        # st=0A is LISTEN; loopback IPv4-mapped = 0000000000000000FFFF000001000000 or 0100007F
        awk 'NR>1 && $4=="0A" {
            uid=$8
            local=$2
            # flag if uid=0
            if (uid == "0") print "[HIGH] UID=0 LISTEN socket: local=" local " uid=" uid
        }' /proc/net/tcp6 2>/dev/null
    elif [ -f /proc/net/tcp ]; then
        echo "[INFO] tcp6 not found, falling back to /proc/net/tcp (IPv4 only)"
        head -30 /proc/net/tcp
        awk 'NR>1 && $4=="0A" {
            uid=$8; local=$2
            if (uid == "0") print "[HIGH] UID=0 LISTEN socket: local=" local " uid=" uid
        }' /proc/net/tcp 2>/dev/null
    else
        echo "[INFO] No TCP socket table accessible"
    fi
    echo ""

    echo "--- /proc/net/udp6 (UDP sockets) ---"
    if [ -f /proc/net/udp6 ]; then
        head -20 /proc/net/udp6
        awk 'NR>1 {uid=$8; local=$2; if (uid=="0") print "[HIGH] UID=0 UDP socket: local=" local " uid=" uid}' /proc/net/udp6 2>/dev/null
    elif [ -f /proc/net/udp ]; then
        echo "[INFO] udp6 not found, falling back to /proc/net/udp"
        head -20 /proc/net/udp
        awk 'NR>1 {uid=$8; local=$2; if (uid=="0") print "[HIGH] UID=0 UDP socket: local=" local " uid=" uid}' /proc/net/udp 2>/dev/null
    else
        echo "[INFO] No UDP socket table accessible"
    fi
    echo ""

    # ──────────────────────────────────────────────
    # SECTION 4: ARP TABLE
    # ──────────────────────────────────────────────
    echo "═══════════════════════════════════════════════════════════"
    echo "SECTION 4: ARP TABLE"
    echo "═══════════════════════════════════════════════════════════"
    echo ""

    if [ -f /proc/net/arp ]; then
        cat /proc/net/arp
        ARP_TOTAL=$(tail -n +2 /proc/net/arp | wc -l | tr -d ' ')
        ARP_INCOMPLETE=$(tail -n +2 /proc/net/arp | awk '$3=="0x0"' | wc -l | tr -d ' ')
        echo ""
        echo "[INFO] ARP entries: total=${ARP_TOTAL}, incomplete=${ARP_INCOMPLETE}"
        if [ "$ARP_INCOMPLETE" -gt 0 ] 2>/dev/null; then
            echo "[INFO] Incomplete ARP entries may indicate unreachable hosts or ARP poisoning artifacts"
        fi
    else
        echo "[INFO] /proc/net/arp not accessible"
    fi
    echo ""

    # ──────────────────────────────────────────────
    # SECTION 5: MULTICAST GROUPS
    # ──────────────────────────────────────────────
    echo "═══════════════════════════════════════════════════════════"
    echo "SECTION 5: MULTICAST GROUPS"
    echo "═══════════════════════════════════════════════════════════"
    echo ""

    echo "--- IPv4 IGMP memberships (/proc/net/igmp) ---"
    if [ -f /proc/net/igmp ]; then
        head -20 /proc/net/igmp
        IGMP_COUNT=$(tail -n +2 /proc/net/igmp | wc -l | tr -d ' ')
        echo "[INFO] IGMPv4 group memberships: ${IGMP_COUNT}"
    else
        echo "[INFO] /proc/net/igmp not accessible"
    fi
    echo ""

    echo "--- IPv6 MLD memberships (/proc/net/igmp6) ---"
    if [ -f /proc/net/igmp6 ]; then
        head -20 /proc/net/igmp6
        IGMP6_COUNT=$(wc -l < /proc/net/igmp6 | tr -d ' ')
        echo "[INFO] IGMPv6/MLD group memberships: ${IGMP6_COUNT}"
        UNUSUAL_MC=$(grep -v "ff02::1\|ff02::2\|ff02::1:ff\|ff01::1" /proc/net/igmp6 2>/dev/null | wc -l | tr -d ' ')
        if [ "$UNUSUAL_MC" -gt 0 ] 2>/dev/null; then
            echo "[INFO] ${UNUSUAL_MC} non-standard multicast group(s) detected:"
            grep -v "ff02::1\|ff02::2\|ff02::1:ff\|ff01::1" /proc/net/igmp6 2>/dev/null | head -10
        fi
    else
        echo "[INFO] /proc/net/igmp6 not accessible"
    fi
    echo ""

    # ──────────────────────────────────────────────
    # SECTION 6: NETWORK INTERFACES (DEEP)
    # ──────────────────────────────────────────────
    echo "═══════════════════════════════════════════════════════════"
    echo "SECTION 6: NETWORK INTERFACES (DEEP)"
    echo "═══════════════════════════════════════════════════════════"
    echo ""

    echo "--- Interface list ---"
    ip link show 2>/dev/null || ifconfig -a 2>/dev/null || echo "[INFO] No interface enumeration tool available"
    echo ""

    echo "--- /proc/net/dev statistics ---"
    if [ -f /proc/net/dev ]; then
        cat /proc/net/dev
        echo ""
        # Check for tun/tap interfaces
        TUN_IFS=$(tail -n +3 /proc/net/dev | awk '{print $1}' | grep -c "^tun\|^tap\|^ppp\|^wg")
        if [ "$TUN_IFS" -gt 0 ] 2>/dev/null; then
            echo "[HIGH] ${TUN_IFS} tunnel/VPN interface(s) present in /proc/net/dev:"
            tail -n +3 /proc/net/dev | awk '{print $1}' | grep "^tun\|^tap\|^ppp\|^wg"
        fi
        # Check for unexpected virtual interfaces
        VIRT_IFS=$(tail -n +3 /proc/net/dev | awk '{print $1}' | grep -c "^docker\|^virbr\|^lxc\|^veth")
        if [ "$VIRT_IFS" -gt 0 ] 2>/dev/null; then
            echo "[MEDIUM] ${VIRT_IFS} container/virtualisation interface(s) detected"
        fi
    else
        echo "[INFO] /proc/net/dev not accessible"
    fi
    echo ""

    # ──────────────────────────────────────────────
    # SECTION 7: DNS CONFIGURATION
    # ──────────────────────────────────────────────
    echo "═══════════════════════════════════════════════════════════"
    echo "SECTION 7: DNS CONFIGURATION"
    echo "═══════════════════════════════════════════════════════════"
    echo ""

    echo "--- /etc/resolv.conf ---"
    if [ -f /etc/resolv.conf ]; then
        cat /etc/resolv.conf
    else
        echo "[INFO] /etc/resolv.conf not present (normal on Android — DNS via netd)"
    fi
    echo ""

    echo "--- System DNS properties ---"
    DNS1=$(getprop net.dns1 2>/dev/null)
    DNS2=$(getprop net.dns2 2>/dev/null)
    echo "net.dns1=${DNS1:-[not set]}"
    echo "net.dns2=${DNS2:-[not set]}"
    echo ""

    echo "--- DHCP/per-interface DNS properties ---"
    getprop 2>/dev/null | grep "\.dns" || echo "[INFO] No per-interface DNS properties found"
    echo ""

    # Flag non-standard resolvers (not Google 8.8.x, Cloudflare 1.1.x, or private RFC1918)
    for DNS_ADDR in "$DNS1" "$DNS2"; do
        if [ -n "$DNS_ADDR" ]; then
            case "$DNS_ADDR" in
                8.8.8.*|8.8.4.*|1.1.1.*|1.0.0.*|9.9.9.*) ;;
                192.168.*|10.*|172.16.*|172.17.*|172.18.*|172.19.*|172.20.*|172.21.*|172.22.*|172.23.*|172.24.*|172.25.*|172.26.*|172.27.*|172.28.*|172.29.*|172.30.*|172.31.*) ;;
                127.*|::1) ;;
                "") ;;
                *) echo "[HIGH] Non-standard DNS resolver configured: ${DNS_ADDR}" ;;
            esac
        fi
    done
    echo ""

    # ──────────────────────────────────────────────
    # SECTION 8: RAW PACKET SOCKETS (/proc/net/packet)
    # ──────────────────────────────────────────────
    echo "═══════════════════════════════════════════════════════════"
    echo "SECTION 8: RAW PACKET SOCKETS (/proc/net/packet)"
    echo "═══════════════════════════════════════════════════════════"
    echo ""
    echo "[INFO] Processes with AF_PACKET sockets require CAP_NET_RAW — non-root holders are notable"
    echo ""

    if [ -f /proc/net/packet ]; then
        cat /proc/net/packet
        RAW_COUNT=$(tail -n +2 /proc/net/packet | wc -l | tr -d ' ')
        echo ""
        echo "[INFO] Open AF_PACKET (raw) sockets: ${RAW_COUNT}"
        if [ "$RAW_COUNT" -gt 0 ] 2>/dev/null; then
            echo "[HIGH] ${RAW_COUNT} raw packet socket(s) open — verify holders have legitimate use (tcpdump, network monitor, or malicious sniffer)"
        fi
    else
        echo "[INFO] /proc/net/packet not accessible"
    fi
    echo ""

    # ──────────────────────────────────────────────
    # SECTION 9: SUMMARY
    # ──────────────────────────────────────────────
    echo "═══════════════════════════════════════════════════════════"
    echo "SECTION 9: SUMMARY"
    echo "═══════════════════════════════════════════════════════════"
    echo ""
    echo "Deep network audit complete."
    echo "Review [HIGH] findings above for: open firewall policies, UID=0 sockets on"
    echo "non-loopback addresses, active tunnel interfaces, non-standard DNS resolvers,"
    echo "and open raw packet sockets."
    echo ""
    echo "Timestamp: $(date)"

} > "${OUTPUT_FILE}" 2>&1
