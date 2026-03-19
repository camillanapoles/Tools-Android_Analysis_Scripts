#!/system/bin/sh
# 30_audit_app_attack_surface.sh — Application attack surface enumeration
# Enumerates app-layer security risks: allowBackup, debuggable APKs, overlay perms,
# accessibility services, device admin, deep links, implicit broadcast receivers.
# Usage: sh 30_audit_app_attack_surface.sh [output_directory]

OUTPUT_DIR="${1:-.}"
OUTPUT_FILE="${OUTPUT_DIR}/audit_app_attack_surface.txt"

{
    echo "========================================================"
    echo "  41 — Application Attack Surface Audit"
    echo "  $(date)"
    echo "========================================================"
    echo ""

    # -------------------------------------------------------
    # SECTION 1: ALLOWBACKUP APPS
    # -------------------------------------------------------
    echo "=== SECTION 1: ALLOWBACKUP APPS ==="
    echo "[INFO] Apps with allowBackup=true can have data extracted via 'adb backup' without root."
    echo ""

    BACKUP_COUNT=0
    dumpsys package packages 2>/dev/null | grep -B5 "allowBackup=true" | grep "Package\[" | head -30 | while read line; do
        pkg=$(echo "$line" | sed 's/.*Package\[//;s/\].*//')
        echo "[HIGH] allowBackup=true: $pkg"
        BACKUP_COUNT=$((BACKUP_COUNT + 1))
    done
    echo ""

    # -------------------------------------------------------
    # SECTION 2: DEBUGGABLE APKs
    # -------------------------------------------------------
    echo "=== SECTION 2: DEBUGGABLE APKs ==="
    echo "[INFO] Debuggable apps allow attaching a debugger, reading/writing memory, and extracting secrets."
    echo ""

    DEBUG_COUNT=0
    pm list packages 2>/dev/null | sed 's/package://' | while read pkg; do
        if dumpsys package "$pkg" 2>/dev/null | grep -q "DEBUGGABLE"; then
            echo "[CRITICAL] DEBUGGABLE: $pkg"
            DEBUG_COUNT=$((DEBUG_COUNT + 1))
        fi
    done | head -20
    echo ""

    # -------------------------------------------------------
    # SECTION 3: WEBVIEW REMOTE DEBUGGING
    # -------------------------------------------------------
    echo "=== SECTION 3: WEBVIEW REMOTE DEBUGGING ==="
    echo ""

    WEBVIEW_PROVIDER=$(getprop debug.webview.provider 2>/dev/null)
    WEBVIEW_PERSIST=$(getprop persist.webview.provider 2>/dev/null)
    echo "[INFO] debug.webview.provider: ${WEBVIEW_PROVIDER:-<not set>}"
    echo "[INFO] persist.webview.provider: ${WEBVIEW_PERSIST:-<not set>}"
    echo ""

    echo "[INFO] WebView/Chrome/Chromium processes currently running:"
    ps -A 2>/dev/null | grep -iE "webview|chrome|chromium" | head -10 || echo "  [N/A] No WebView processes found or ps unavailable"
    echo ""

    WEBVIEW_DEBUG=$(getprop ro.debuggable 2>/dev/null)
    if [ "$WEBVIEW_DEBUG" = "1" ]; then
        echo "[HIGH] ro.debuggable=1 — device-wide debug mode active; WebView DevTools potentially attachable"
    else
        echo "[INFO] ro.debuggable=${WEBVIEW_DEBUG:-<not set>} — not in global debug mode"
    fi
    echo ""

    # -------------------------------------------------------
    # SECTION 4: OVERLAY PERMISSIONS (SYSTEM_ALERT_WINDOW)
    # -------------------------------------------------------
    echo "=== SECTION 4: OVERLAY PERMISSIONS ==="
    echo "[INFO] SYSTEM_ALERT_WINDOW allows drawing over other apps — used by tapjacking/clickjacking attacks."
    echo ""

    echo "Apps granted SYSTEM_ALERT_WINDOW (appops):"
    cmd appops query-op SYSTEM_ALERT_WINDOW allow 2>/dev/null | head -30 | while read line; do
        case "$line" in
            *"com.android."*|*"android"*) echo "  [INFO] system: $line" ;;
            *) echo "  [HIGH] non-system overlay: $line" ;;
        esac
    done || echo "  [N/A] cmd appops unavailable"
    echo ""

    echo "Package flags referencing SYSTEM_ALERT_WINDOW:"
    dumpsys package packages 2>/dev/null | grep -E "SYSTEM_ALERT_WINDOW" | head -20 || echo "  [N/A]"
    echo ""

    # -------------------------------------------------------
    # SECTION 5: ACCESSIBILITY SERVICES
    # -------------------------------------------------------
    echo "=== SECTION 5: ACCESSIBILITY SERVICES ==="
    echo "[INFO] Enabled accessibility services can read screen content and inject input — keylogger risk."
    echo ""

    ACC_SERVICES=$(settings get secure enabled_accessibility_services 2>/dev/null)
    if [ -z "$ACC_SERVICES" ] || [ "$ACC_SERVICES" = "null" ]; then
        echo "[INFO] No accessibility services currently enabled."
    else
        echo "[INFO] Raw value: $ACC_SERVICES"
        echo ""
        # Colon-separated list — split with tr and process each
        echo "$ACC_SERVICES" | tr ':' '\n' | while read svc; do
            [ -z "$svc" ] && continue
            pkg=$(echo "$svc" | cut -d'/' -f1)
            case "$pkg" in
                com.android.*|com.google.*|android) echo "  [INFO] system: $svc" ;;
                *) echo "  [HIGH] third-party accessibility service: $svc" ;;
            esac
        done
    fi
    echo ""

    # -------------------------------------------------------
    # SECTION 6: DEVICE ADMIN APPS
    # -------------------------------------------------------
    echo "=== SECTION 6: DEVICE ADMIN APPS ==="
    echo "[INFO] Device admin apps can wipe device, enforce policies, lock screen — MDM/stalkerware risk."
    echo ""

    echo "Active device administrators:"
    dumpsys device_policy 2>/dev/null | grep -E "Active admin|Component:" | head -20 | while read line; do
        case "$line" in
            *"com.android."*|*"com.google."*) echo "  [INFO] system: $line" ;;
            *) echo "  [HIGH] non-system device admin: $line" ;;
        esac
    done || echo "  [N/A] device_policy service unavailable"
    echo ""

    # -------------------------------------------------------
    # SECTION 7: INSTALL FROM UNKNOWN SOURCES
    # -------------------------------------------------------
    echo "=== SECTION 7: INSTALL FROM UNKNOWN SOURCES ==="
    echo ""

    UNKNOWN_GLOBAL=$(settings get global install_non_market_apps 2>/dev/null)
    UNKNOWN_SECURE=$(settings get secure install_non_market_apps 2>/dev/null)
    echo "[INFO] global/install_non_market_apps: ${UNKNOWN_GLOBAL:-<not set>}"
    echo "[INFO] secure/install_non_market_apps: ${UNKNOWN_SECURE:-<not set>}"
    if [ "$UNKNOWN_GLOBAL" = "1" ] || [ "$UNKNOWN_SECURE" = "1" ]; then
        echo "[HIGH] Unknown sources enabled — sideloading permitted without Play Store"
    fi
    echo ""

    echo "[INFO] Total packages installed (user 0):"
    pm list packages --user 0 2>/dev/null | wc -l || pm list packages 2>/dev/null | wc -l
    echo ""

    # -------------------------------------------------------
    # SECTION 8: DEEP LINK HANDLERS (POTENTIAL CONFUSED DEPUTY)
    # -------------------------------------------------------
    echo "=== SECTION 8: DEEP LINK / INTENT HANDLERS ==="
    echo "[INFO] Apps handling http/https intents can intercept links — confused deputy / intent hijacking risk."
    echo ""

    echo "Packages handling android.intent.action.VIEW with http/https schemes:"
    dumpsys package 2>/dev/null | grep -A5 "android.intent.action.VIEW" | grep -E "scheme=http|scheme=https" | head -30 || echo "  [N/A]"
    echo ""

    echo "All http/https intent filter packages (via package manager):"
    pm query-activities --components -a android.intent.action.VIEW -d "http://x" 2>/dev/null | grep "  [a-z]" | while read pkg_cmp; do
        pkg=$(echo "$pkg_cmp" | cut -d'/' -f1 | sed 's/^  *//')
        case "$pkg" in
            com.android.*|com.google.*|android) echo "  [INFO] browser/system: $pkg_cmp" ;;
            *) echo "  [MEDIUM] non-system http handler: $pkg_cmp" ;;
        esac
    done | head -20
    echo ""

    # -------------------------------------------------------
    # SECTION 9: IMPLICIT BROADCAST RECEIVERS
    # -------------------------------------------------------
    echo "=== SECTION 9: IMPLICIT BROADCAST RECEIVERS ==="
    echo "[INFO] Apps receiving BOOT_COMPLETED/PACKAGE events get automatic execution and can persist stealthily."
    echo ""

    for ACTION in "android.intent.action.BOOT_COMPLETED" \
                  "android.intent.action.PACKAGE_INSTALLED" \
                  "android.intent.action.PACKAGE_REPLACED" \
                  "android.intent.action.MY_PACKAGE_REPLACED"; do
        echo "Receivers for $ACTION:"
        pm query-receivers --components -a "$ACTION" 2>/dev/null | grep "  [a-z]" | while read rcv; do
            pkg=$(echo "$rcv" | cut -d'/' -f1 | sed 's/^  *//')
            case "$pkg" in
                com.android.*|com.google.*|android) echo "  [INFO] system: $rcv" ;;
                *) echo "  [MEDIUM] non-system boot/install receiver: $rcv" ;;
            esac
        done | head -10
        echo ""
    done

    # -------------------------------------------------------
    # SECTION 10: PER-PACKAGE EXPORTED COMPONENT ANALYSIS
    # -------------------------------------------------------
    echo "=== SECTION 10: PER-PACKAGE EXPORTED COMPONENT ANALYSIS ==="
    echo "[INFO] Per-package count of exported Activities, Services, Receivers, and Providers."
    echo "[INFO] Exported components without permission protection are direct IPC attack targets."
    echo ""

    PACKAGES=$(pm list packages 2>/dev/null | sed 's/package://')
    TOTAL_PACKAGES=$(echo "$PACKAGES" | wc -l)
    echo "Total packages to scan: $TOTAL_PACKAGES"
    echo ""

    TOTAL_EXP_ACT=0
    TOTAL_EXP_SVC=0
    TOTAL_EXP_RCV=0
    TOTAL_EXP_PRV=0

    for pkg in $PACKAGES; do
        PKG_INFO=$(dumpsys package "$pkg" 2>/dev/null)
        [ -z "$PKG_INFO" ] && continue

        EXP_ACT=$(echo "$PKG_INFO" | sed -n '/Activities:/,/Services:\|Receivers:\|Providers:\|^$/p' | grep -c "exported=true" 2>/dev/null || echo 0)
        EXP_SVC=$(echo "$PKG_INFO" | sed -n '/Services:/,/Receivers:\|Providers:\|^$/p' | grep -c "exported=true" 2>/dev/null || echo 0)
        EXP_RCV=$(echo "$PKG_INFO" | sed -n '/Receivers:/,/Providers:\|^$/p' | grep -c "exported=true" 2>/dev/null || echo 0)
        EXP_PRV=$(echo "$PKG_INFO" | sed -n '/Providers:/,/^$/p' | grep -c "exported=true" 2>/dev/null || echo 0)

        if [ "$EXP_ACT" -gt 0 ] || [ "$EXP_SVC" -gt 0 ] || [ "$EXP_RCV" -gt 0 ] || [ "$EXP_PRV" -gt 0 ]; then
            UID_INFO=$(echo "$PKG_INFO" | grep -E "userId=|sharedUser=" | head -1)
            IS_DBG=$(echo "$PKG_INFO" | grep -c "DEBUGGABLE" 2>/dev/null || echo 0)
            LABEL="[INFO]"
            [ "$EXP_PRV" -gt 0 ] && LABEL="[HIGH]"
            [ "$IS_DBG" -gt 0 ] && LABEL="[HIGH]"
            echo "$LABEL $pkg — Act:$EXP_ACT Svc:$EXP_SVC Rcv:$EXP_RCV Prv:$EXP_PRV${UID_INFO:+  ($UID_INFO)}"
            TOTAL_EXP_ACT=$((TOTAL_EXP_ACT + EXP_ACT))
            TOTAL_EXP_SVC=$((TOTAL_EXP_SVC + EXP_SVC))
            TOTAL_EXP_RCV=$((TOTAL_EXP_RCV + EXP_RCV))
            TOTAL_EXP_PRV=$((TOTAL_EXP_PRV + EXP_PRV))
        fi
    done
    echo ""
    echo "Totals — Activities: $TOTAL_EXP_ACT  Services: $TOTAL_EXP_SVC  Receivers: $TOTAL_EXP_RCV  Providers: $TOTAL_EXP_PRV"
    TOTAL_EXPOSED=$((TOTAL_EXP_ACT + TOTAL_EXP_SVC + TOTAL_EXP_RCV + TOTAL_EXP_PRV))
    echo "Total exposed components: $TOTAL_EXPOSED"
    if [ "$TOTAL_EXP_PRV" -gt 0 ]; then
        echo "[HIGH] Exported Content Providers detected — test with: content query --uri content://<authority>"
    fi
    echo ""

    # -------------------------------------------------------
    # SECTION 11: UNPROTECTED EXPORTED COMPONENTS
    # -------------------------------------------------------
    echo "=== SECTION 11: UNPROTECTED EXPORTED COMPONENTS ==="
    echo "[INFO] Exported components with no permission= requirement — callable by any app on device."
    echo ""

    echo "--- Exported Activities without permission protection (top 30) ---"
    for pkg in $PACKAGES; do
        dumpsys package "$pkg" 2>/dev/null | grep -E "Activity.*exported=true" | grep -v "permission=" | while read line; do
            echo "  [HIGH] $pkg: $line"
        done
    done 2>/dev/null | head -30
    echo ""

    echo "--- Exported Services without permission protection (top 30) ---"
    for pkg in $PACKAGES; do
        dumpsys package "$pkg" 2>/dev/null | grep -E "Service.*exported=true" | grep -v "permission=" | while read line; do
            echo "  [HIGH] $pkg: $line"
        done
    done 2>/dev/null | head -30
    echo ""

    echo "--- Exported Receivers without permission protection (top 30) ---"
    for pkg in $PACKAGES; do
        dumpsys package "$pkg" 2>/dev/null | grep -E "Receiver.*exported=true" | grep -v "permission=" | while read line; do
            echo "  [HIGH] $pkg: $line"
        done
    done 2>/dev/null | head -30
    echo ""

    # -------------------------------------------------------
    # SECTION 12: SUMMARY
    # -------------------------------------------------------
    echo "========================================================"
    echo "  SUMMARY"
    echo "========================================================"
    echo ""
    echo "Counts from this run (grep on output file not available here — review above sections):"
    echo "[INFO] Review SECTION 1 for allowBackup [HIGH] entries."
    echo "[INFO] Review SECTION 2 for debuggable [CRITICAL] entries."
    echo "[INFO] Review SECTION 4 for overlay [HIGH] entries."
    echo "[INFO] Review SECTION 5 for third-party accessibility [HIGH] entries."
    echo "[INFO] Review SECTION 6 for non-system device admin [HIGH] entries."
    echo "[INFO] Review SECTION 7 for unknown sources [HIGH]."
    echo "[INFO] Review SECTION 8 for non-system http handlers [MEDIUM]."
    echo "[INFO] Review SECTION 9 for non-system boot receivers [MEDIUM]."
    echo "[INFO] Review SECTION 10 for per-package exported component counts [HIGH]."
    echo "[INFO] Review SECTION 11 for unprotected exported components [HIGH]."
    echo ""
    echo "Audit complete: $(date)"

} > "${OUTPUT_FILE}" 2>&1
