#!/system/bin/sh
# DROID FORENSIC - Broadcast Receiver Enumeration & Security Audit
# Identifies broadcast receivers and tests for injection vulnerabilities
# Usage: sh 31_enum_broadcast_receivers.sh [output_directory]

OUTPUT_DIR="${1:-.}"
OUTPUT_FILE="${OUTPUT_DIR}/broadcast_receivers.txt"

echo "[*] Enumerating broadcast receivers..."

{
    echo "═══════════════════════════════════════════════════════════════"
    echo "  BROADCAST RECEIVER ENUMERATION & SECURITY AUDIT"
    echo "  Timestamp: $(date)"
    echo "═══════════════════════════════════════════════════════════════"
    echo ""
    echo "Broadcast receivers can be exploited via broadcast injection"
    echo "if not properly protected with permissions."
    echo ""
    echo "Attack vector: am broadcast -a <action> --es <key> <value>"
    echo ""

    # Get all packages
    PACKAGES=$(pm list packages 2>/dev/null | sed 's/package://')

    # System broadcast actions reference
    echo "┌─────────────────────────────────────────────────────────────┐"
    echo "│ PROTECTED SYSTEM BROADCAST ACTIONS                         │"
    echo "└─────────────────────────────────────────────────────────────┘"
    echo ""
    echo "These broadcasts can ONLY be sent by the system:"
    cat << 'EOF'
  android.intent.action.BOOT_COMPLETED
  android.intent.action.PACKAGE_ADDED
  android.intent.action.PACKAGE_REMOVED
  android.intent.action.BATTERY_LOW
  android.intent.action.BATTERY_OKAY
  android.intent.action.POWER_CONNECTED
  android.intent.action.POWER_DISCONNECTED
  android.intent.action.SCREEN_ON
  android.intent.action.SCREEN_OFF
  android.intent.action.USER_PRESENT
  android.provider.Telephony.SMS_RECEIVED
  android.provider.Telephony.WAP_PUSH_RECEIVED
  android.net.conn.CONNECTIVITY_CHANGE
  android.net.wifi.STATE_CHANGE
EOF
    echo ""

    # Enumerate registered receivers globally
    echo "┌─────────────────────────────────────────────────────────────┐"
    echo "│ REGISTERED BROADCAST RECEIVERS (Global)                    │"
    echo "└─────────────────────────────────────────────────────────────┘"
    echo ""
    
    echo "Top 50 most common broadcast actions registered:"
    dumpsys package 2>/dev/null | sed -n '/Receiver Resolver Table:/,/Service Resolver Table:\|Provider Resolver Table:\|^[A-Z]/p' | grep "Action:" | sed 's/.*Action: "/  /;s/".*//' | sort | uniq -c | sort -rn | head -50
    echo ""

    # Per-package receiver analysis
    echo "┌─────────────────────────────────────────────────────────────┐"
    echo "│ PER-PACKAGE BROADCAST RECEIVER ANALYSIS                    │"
    echo "└─────────────────────────────────────────────────────────────┘"
    echo ""

    TOTAL_RECEIVERS=0
    UNPROTECTED_RECEIVERS=0
    HIGH_RISK_APPS=""

    for pkg in $PACKAGES; do
        # Get receiver info
        RECEIVER_INFO=$(dumpsys package "$pkg" 2>/dev/null | sed -n '/Receivers:/,/Providers:\|^[A-Z]/p')
        
        # Count receivers
        RECV_COUNT=$(echo "$RECEIVER_INFO" | grep -c "exported=true" 2>/dev/null || echo "0")
        
        if [ "$RECV_COUNT" -gt 0 ]; then
            echo "════════════════════════════════════════════════════════════"
            echo "Package: $pkg"
            echo "════════════════════════════════════════════════════════════"
            echo "  Exported Receivers: $RECV_COUNT"
            echo ""
            
            TOTAL_RECEIVERS=$((TOTAL_RECEIVERS + RECV_COUNT))
            
            # List each receiver with details
            echo "  [RECEIVERS]"
            
            # Parse receiver details
            dumpsys package "$pkg" 2>/dev/null | sed -n '/Receivers:/,/Providers:\|Services:\|^[A-Z]/p' | grep -E "exported=true|permission=|Action:|Category:" | while read line; do
                if echo "$line" | grep -q "exported=true"; then
                    RECV_NAME=$(echo "$line" | grep -oE "[a-zA-Z0-9_.]+\.[A-Z][a-zA-Z0-9_]*" | tail -1)
                    PERM=$(echo "$line" | grep -oE "permission=[a-zA-Z0-9_.]*")
                    
                    if [ -n "$PERM" ]; then
                        echo "    Receiver: $RECV_NAME"
                        echo "      Protection: $PERM"
                    else
                        echo "    Receiver: $RECV_NAME"
                        echo "      Protection: [NONE - UNPROTECTED]"
                        UNPROTECTED_RECEIVERS=$((UNPROTECTED_RECEIVERS + 1))
                    fi
                elif echo "$line" | grep -q "Action:"; then
                    ACTION=$(echo "$line" | sed 's/.*Action: "//;s/".*//')
                    echo "      Intent Action: $ACTION"
                    
                    # Generate test command
                    echo "      Test: am broadcast -a $ACTION -n $pkg/$RECV_NAME"
                fi
            done
            echo ""
        fi
    done

    # Custom (non-system) broadcast actions
    echo "┌─────────────────────────────────────────────────────────────┐"
    echo "│ CUSTOM BROADCAST ACTIONS (Non-System)                      │"
    echo "└─────────────────────────────────────────────────────────────┘"
    echo ""
    echo "These custom actions may be injectable by malicious apps:"
    echo ""
    
    dumpsys package 2>/dev/null | sed -n '/Receiver Resolver Table:/,/Service Resolver Table:\|^[A-Z]/p' | grep "Action:" | sed 's/.*Action: "//;s/".*//' | grep -v "^android\." | sort -u | head -50 | while read action; do
        echo "  $action"
    done
    echo ""

    # Receivers listening for dangerous intents
    echo "┌─────────────────────────────────────────────────────────────┐"
    echo "│ HIGH-RISK BROADCAST PATTERNS                               │"
    echo "└─────────────────────────────────────────────────────────────┘"
    echo ""
    
    echo "[*] Receivers for SMS-related broadcasts:"
    dumpsys package 2>/dev/null | grep -B5 "SMS\|MMS\|WAP_PUSH" | grep "package:\|Receiver" | head -20
    echo ""
    
    echo "[*] Receivers for BOOT_COMPLETED (auto-start apps):"
    dumpsys package 2>/dev/null | sed -n '/Receiver Resolver Table:/,/Service Resolver Table:/p' | grep -B3 "BOOT_COMPLETED" | grep -E "[a-z]+\.[a-z]+" | head -20
    echo ""
    
    echo "[*] Receivers with custom actions (potential injection):"
    for pkg in $PACKAGES; do
        dumpsys package "$pkg" 2>/dev/null | sed -n '/Receivers:/,/Providers:\|^[A-Z]/p' | grep -E "exported=true" | grep -v "permission=" | while read line; do
            RECV=$(echo "$line" | grep -oE "[a-zA-Z0-9_.]+Receiver[a-zA-Z0-9_]*")
            if [ -n "$RECV" ]; then
                echo "  [UNPROTECTED] $pkg / $RECV"
            fi
        done
    done 2>/dev/null | head -30
    echo ""

    # Dynamic receivers (runtime registered)
    echo "┌─────────────────────────────────────────────────────────────┐"
    echo "│ DYNAMICALLY REGISTERED RECEIVERS                           │"
    echo "└─────────────────────────────────────────────────────────────┘"
    echo ""
    echo "Receivers registered at runtime (from activity manager):"
    echo ""
    
    dumpsys activity broadcasts 2>/dev/null | grep -E "Receiver|BroadcastFilter|action" | head -50
    echo ""

    # Sticky broadcasts
    echo "┌─────────────────────────────────────────────────────────────┐"
    echo "│ STICKY BROADCASTS (Persistent State)                       │"
    echo "└─────────────────────────────────────────────────────────────┘"
    echo ""
    echo "Sticky broadcasts persist and can be read by any app:"
    echo ""
    
    dumpsys activity broadcasts 2>/dev/null | sed -n '/Sticky broadcasts/,/^[A-Z]/p' | head -50
    echo ""

    # Ordered broadcast handlers
    echo "┌─────────────────────────────────────────────────────────────┐"
    echo "│ ORDERED BROADCAST PRIORITIES                               │"
    echo "└─────────────────────────────────────────────────────────────┘"
    echo ""
    echo "High-priority receivers can intercept/modify broadcasts:"
    echo ""
    
    dumpsys package 2>/dev/null | grep -E "priority=" | sort -t= -k2 -rn | head -30
    echo ""

    # Secret codes
    echo "┌─────────────────────────────────────────────────────────────┐"
    echo "│ SECRET DIALER CODES                                        │"
    echo "└─────────────────────────────────────────────────────────────┘"
    echo ""
    echo "Receivers for android.provider.Telephony.SECRET_CODE:"
    echo "Dial *#*#<code>#*#* to trigger these"
    echo ""
    
    dumpsys package 2>/dev/null | grep -B10 "SECRET_CODE" | grep -E "package:|host=" | while read line; do
        echo "  $line"
    done
    echo ""

    # Generate test commands
    echo "┌─────────────────────────────────────────────────────────────┐"
    echo "│ BROADCAST INJECTION TEST COMMANDS                          │"
    echo "└─────────────────────────────────────────────────────────────┘"
    echo ""
    echo "# Test unprotected receivers with these commands:"
    echo ""
    
    # Find and generate test commands for unprotected receivers
    for pkg in $PACKAGES; do
        dumpsys package "$pkg" 2>/dev/null | sed -n '/Receivers:/,/Providers:\|^[A-Z]/p' | grep -E "exported=true" | grep -v "permission=" | while read line; do
            RECV=$(echo "$line" | grep -oE "[a-zA-Z0-9_.]+\.[A-Z][a-zA-Z0-9_]*" | tail -1)
            if [ -n "$RECV" ]; then
                # Get associated action
                ACTION=$(dumpsys package "$pkg" 2>/dev/null | sed -n '/Receivers:/,/Providers:/p' | grep -A5 "$RECV" | grep "Action:" | head -1 | sed 's/.*Action: "//;s/".*//')
                if [ -n "$ACTION" ]; then
                    echo "am broadcast -a $ACTION -n $pkg/$RECV"
                else
                    echo "am broadcast -n $pkg/$RECV"
                fi
            fi
        done
    done 2>/dev/null | head -30
    echo ""

    # Summary
    echo "┌─────────────────────────────────────────────────────────────┐"
    echo "│ BROADCAST RECEIVER AUDIT SUMMARY                           │"
    echo "└─────────────────────────────────────────────────────────────┘"
    echo ""
    echo "Total Exported Receivers:    $TOTAL_RECEIVERS"
    echo "Unprotected Receivers:       $UNPROTECTED_RECEIVERS"
    echo ""
    
    if [ "$UNPROTECTED_RECEIVERS" -gt 0 ]; then
        echo "[WARNING] Unprotected broadcast receivers detected!"
        echo "  These can receive broadcasts from ANY application."
        echo "  Risk: Data injection, unauthorized actions, privilege escalation"
        echo ""
        echo "Recommendations:"
        echo "  1. Add permission requirements to exported receivers"
        echo "  2. Use LocalBroadcastManager for internal broadcasts"
        echo "  3. Validate all data received via broadcasts"
        echo "  4. Set android:exported='false' if external access not needed"
    else
        echo "[OK] All exported receivers appear to have permission protection"
    fi
    echo ""

} > "${OUTPUT_FILE}" 2>&1

echo "[+] Broadcast receiver enumeration saved to: ${OUTPUT_FILE}"
