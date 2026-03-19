#!/system/bin/sh
# DROID FORENSIC - Linux Capabilities Audit
# Identifies files with special Linux capabilities (alternative to SUID)
# Usage: sh 10_audit_capabilities.sh [output_directory]

OUTPUT_DIR="${1:-.}"
OUTPUT_FILE="${OUTPUT_DIR}/audit_capabilities.txt"

echo "[*] Auditing Linux capabilities..."

{
    echo "═══════════════════════════════════════════════════════════════"
    echo "  LINUX CAPABILITIES AUDIT"
    echo "  Timestamp: $(date)"
    echo "═══════════════════════════════════════════════════════════════"
    echo ""
    echo "Linux capabilities allow fine-grained privilege control"
    echo "Files with capabilities can perform privileged operations"
    echo "without full root access"
    echo ""

    # Check if getcap is available
    echo "┌─────────────────────────────────────────────────────────────┐"
    echo "│ CAPABILITY TOOLS AVAILABILITY                              │"
    echo "└─────────────────────────────────────────────────────────────┘"
    
    if command -v getcap >/dev/null 2>&1; then
        echo "[+] getcap: available"
        GETCAP_AVAILABLE=1
    else
        echo "[-] getcap: NOT available"
        GETCAP_AVAILABLE=0
    fi
    
    if command -v capsh >/dev/null 2>&1; then
        echo "[+] capsh: available"
    else
        echo "[-] capsh: NOT available"
    fi
    echo ""

    # Current process capabilities
    echo "┌─────────────────────────────────────────────────────────────┐"
    echo "│ CURRENT PROCESS CAPABILITIES                               │"
    echo "└─────────────────────────────────────────────────────────────┘"
    
    echo "/proc/self/status capability fields:"
    cat /proc/self/status 2>/dev/null | grep -i cap
    echo ""
    
    if command -v capsh >/dev/null 2>&1; then
        echo "Decoded capabilities:"
        CAP_EFF=$(cat /proc/self/status 2>/dev/null | grep CapEff | awk '{print $2}')
        if [ -n "$CAP_EFF" ]; then
            capsh --decode="$CAP_EFF" 2>/dev/null
        fi
    fi
    echo ""

    # Files with capabilities in system paths
    if [ "$GETCAP_AVAILABLE" -eq 1 ]; then
        echo "┌─────────────────────────────────────────────────────────────┐"
        echo "│ FILES WITH CAPABILITIES IN /system                         │"
        echo "└─────────────────────────────────────────────────────────────┘"
        
        getcap -r /system 2>/dev/null | while read line; do
            echo "[CAP] $line"
        done
        echo ""

        echo "┌─────────────────────────────────────────────────────────────┐"
        echo "│ FILES WITH CAPABILITIES IN /vendor                         │"
        echo "└─────────────────────────────────────────────────────────────┘"
        
        getcap -r /vendor 2>/dev/null | while read line; do
            echo "[CAP] $line"
        done
        echo ""

        echo "┌─────────────────────────────────────────────────────────────┐"
        echo "│ FILES WITH CAPABILITIES IN /sbin                           │"
        echo "└─────────────────────────────────────────────────────────────┘"
        
        getcap -r /sbin 2>/dev/null | while read line; do
            echo "[CAP] $line"
        done
        echo ""

        echo "┌─────────────────────────────────────────────────────────────┐"
        echo "│ FILES WITH CAPABILITIES IN /data                           │"
        echo "└─────────────────────────────────────────────────────────────┘"
        
        getcap -r /data 2>/dev/null | while read line; do
            echo "[SUSPICIOUS CAP] $line"
        done
        echo ""
    fi

    # Capability reference
    echo "┌─────────────────────────────────────────────────────────────┐"
    echo "│ LINUX CAPABILITIES REFERENCE                               │"
    echo "└─────────────────────────────────────────────────────────────┘"
    cat << 'EOF'
HIGH-RISK CAPABILITIES:
  cap_sys_admin     - Broad system admin (almost root)
  cap_sys_ptrace    - Trace/debug processes
  cap_sys_module    - Load/unload kernel modules
  cap_sys_rawio     - Raw I/O port access
  cap_dac_override  - Bypass file permission checks
  cap_dac_read_search - Bypass read permission checks
  cap_setuid        - Change UID
  cap_setgid        - Change GID
  cap_chown         - Change file ownership

NETWORK CAPABILITIES:
  cap_net_admin     - Network configuration
  cap_net_raw       - Raw sockets (packet capture)
  cap_net_bind_service - Bind to privileged ports (<1024)

OTHER NOTABLE:
  cap_sys_boot      - Reboot system
  cap_sys_time      - Change system time
  cap_mknod         - Create device nodes
  cap_kill          - Send signals to any process
  cap_audit_write   - Write to audit log
EOF
    echo ""

    # Specific capability searches
    echo "┌─────────────────────────────────────────────────────────────┐"
    echo "│ FILES WITH CAP_NET_RAW (Packet Capture)                    │"
    echo "└─────────────────────────────────────────────────────────────┘"
    
    if [ "$GETCAP_AVAILABLE" -eq 1 ]; then
        getcap -r /system /vendor /sbin 2>/dev/null | grep -i "net_raw" | while read line; do
            echo "[PCAP CAPABLE] $line"
        done
    else
        echo "[getcap not available - checking known locations]"
        for bin in tcpdump dumpcap tshark; do
            location=$(which "$bin" 2>/dev/null)
            if [ -n "$location" ]; then
                echo "Found: $location"
                ls -la "$location" 2>/dev/null
            fi
        done
    fi
    echo ""

    echo "┌─────────────────────────────────────────────────────────────┐"
    echo "│ FILES WITH CAP_SYS_ADMIN                                   │"
    echo "└─────────────────────────────────────────────────────────────┘"
    
    if [ "$GETCAP_AVAILABLE" -eq 1 ]; then
        getcap -r /system /vendor /sbin 2>/dev/null | grep -i "sys_admin" | while read line; do
            echo "[SYS_ADMIN] $line"
        done
    fi
    echo ""

    echo "┌─────────────────────────────────────────────────────────────┐"
    echo "│ FILES WITH CAP_SYS_PTRACE                                  │"
    echo "└─────────────────────────────────────────────────────────────┘"
    
    if [ "$GETCAP_AVAILABLE" -eq 1 ]; then
        getcap -r /system /vendor /sbin 2>/dev/null | grep -i "sys_ptrace" | while read line; do
            echo "[PTRACE] $line"
        done
    fi
    echo ""

    # Kernel capability support
    echo "┌─────────────────────────────────────────────────────────────┐"
    echo "│ KERNEL CAPABILITY INFORMATION                              │"
    echo "└─────────────────────────────────────────────────────────────┘"
    
    echo "Capability version:"
    cat /proc/sys/kernel/cap_last_cap 2>/dev/null
    echo ""
    
    echo "Kernel capability bounding set:"
    cat /proc/1/status 2>/dev/null | grep -i cap
    echo ""

    # Ambient capabilities
    echo "┌─────────────────────────────────────────────────────────────┐"
    echo "│ AMBIENT CAPABILITIES CHECK                                 │"
    echo "└─────────────────────────────────────────────────────────────┘"
    
    if [ -f /proc/sys/kernel/cap_last_cap ]; then
        echo "Ambient capabilities supported in kernel"
    else
        echo "Ambient capability info not available"
    fi
    echo ""

    # Summary
    echo "┌─────────────────────────────────────────────────────────────┐"
    echo "│ SUMMARY                                                    │"
    echo "└─────────────────────────────────────────────────────────────┘"
    
    if [ "$GETCAP_AVAILABLE" -eq 1 ]; then
        TOTAL_CAPS=$(getcap -r /system /vendor 2>/dev/null | wc -l)
        echo "Total files with capabilities: $TOTAL_CAPS"
    else
        echo "getcap not available - manual review required"
    fi
    echo ""

} > "${OUTPUT_FILE}" 2>&1

echo "[+] Capabilities audit saved to: ${OUTPUT_FILE}"
