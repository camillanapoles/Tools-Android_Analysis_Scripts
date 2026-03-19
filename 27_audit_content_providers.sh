#!/system/bin/sh
# 27_audit_content_providers.sh — Audit Exported Content Providers and Data Exposure
# Android Forensic & Security Audit Toolkit
# Purpose: Test content:// URI accessibility and enumerate exposed data

OUTPUT_DIR="${1:-.}"
OUTPUT_FILE="${OUTPUT_DIR}/audit_content_providers.txt"

echo "[*] Auditing exported content providers..."

{
    echo "╔════════════════════════════════════════════════════════════════════════╗"
    echo "║           EXPORTED CONTENT PROVIDERS & DATA EXPOSURE AUDIT             ║"
    echo "╚════════════════════════════════════════════════════════════════════════╝"
    echo ""
    echo "=== SECTION: CONTENT PROVIDER OVERVIEW ==="
    echo ""
    echo "Content providers expose app data via content:// URIs. Exported providers"
    echo "without proper permissions expose sensitive data (contacts, SMS, call logs,"
    echo "settings, calendars, etc.) to any app with the URI authority."
    echo ""
    echo ""
    echo "=== SECTION: SYSTEM CONTENT PROVIDERS ==="
    echo ""
    echo "=== Content Provider: Settings (system) ==="
    content query --uri content://settings/system 2>/dev/null | head -20
    echo ""

    echo "=== Content Provider: Settings (global) ==="
    content query --uri content://settings/global 2>/dev/null | head -20
    echo ""

    echo "=== Content Provider: Settings (secure) ==="
    content query --uri content://settings/secure 2>/dev/null | head -20
    echo ""

    echo "=== Content Provider: Media (external images) ==="
    content query --uri content://media/external/images/media 2>/dev/null | head -10
    echo ""

    echo "=== Content Provider: Contacts (phones) ==="
    content query --uri content://contacts/phones 2>/dev/null | head -10
    echo ""

    echo "=== Content Provider: SMS ==="
    content query --uri content://sms 2>/dev/null | head -10
    echo ""

    echo "=== Content Provider: Call Log ==="
    content query --uri content://call_log/calls 2>/dev/null | head -10
    echo ""

    echo "=== SECTION: SENSITIVE SETTINGS QUERIES ==="
    echo ""
    echo "[HIGH] Checking accessible global settings..."
    echo ""

    echo "[CRITICAL] install_non_market_apps"
    content query --uri content://settings/global --where "name='install_non_market_apps'" 2>/dev/null
    echo ""

    echo "[CRITICAL] development_settings_enabled"
    content query --uri content://settings/global --where "name='development_settings_enabled'" 2>/dev/null
    echo ""

    echo "[CRITICAL] adb_enabled"
    content query --uri content://settings/global --where "name='adb_enabled'" 2>/dev/null
    echo ""

    echo "=== SECTION: THIRD-PARTY APPS WITH EXPORTED CONTENT PROVIDERS ==="
    echo ""
    echo "[INFO] Enumerating third-party apps with exported content providers..."
    echo ""
    pm list packages -3 2>/dev/null | while read pkg_line; do
        pname=$(echo "$pkg_line" | sed 's/package://')
        if [ -n "$pname" ]; then
            result=$(dumpsys package "$pname" 2>/dev/null | grep -A2 'Provider{')
            if [ -n "$result" ]; then
                echo "[MEDIUM] PACKAGE: $pname"
                echo "$result"
                echo ""
            fi
        fi
    done | head -200
    echo ""

    echo "=== SECTION: DATA EXPOSURE VIA FILE PERMISSIONS ==="
    echo ""
    echo "[HIGH] World-readable app data files (/data/data)"
    find /data/data -maxdepth 2 -perm -o+r 2>/dev/null | head -30
    echo ""

    echo "[CRITICAL] World-readable APK files (/data/app)"
    find /data/app -maxdepth 3 -name "*.apk" -perm -o+r 2>/dev/null | head -20
    echo ""

    echo "[MEDIUM] Group-readable app data directories (/data/data)"
    find /data/data -maxdepth 1 -type d -perm -g+r 2>/dev/null | head -20
    echo ""

    echo "[MEDIUM] World-writable shared storage (/sdcard)"
    find /sdcard -maxdepth 2 -type d -perm -o+w 2>/dev/null | head -20
    echo ""

    echo "=== SECTION: CONTENT PROVIDER AUTHORITY DISCOVERY ==="
    echo ""
    echo "[INFO] Enumerating available content:// URI authorities via package manifest"
    pm list packages 2>/dev/null | while read pkg_line; do
        pname=$(echo "$pkg_line" | sed 's/package://')
        if [ -n "$pname" ]; then
            dumpsys package "$pname" 2>/dev/null | grep -E 'Provider{|authority=' | head -5
        fi
    done | head -100
    echo ""

    echo "╔════════════════════════════════════════════════════════════════════════╗"
    echo "║                         AUDIT SUMMARY                                  ║"
    echo "╚════════════════════════════════════════════════════════════════════════╝"
    echo ""
    echo "Content Provider Audit Complete"
    echo ""
    echo "Risk Assessment:"
    echo "  - Cross-reference exported providers with installed apps"
    echo "  - Test each discovered content:// URI with content query"
    echo "  - Verify sensitive data (contacts, SMS, call logs) is protected"
    echo "  - Check world-readable files and APKs for sensitive content"
    echo "  - Review file permissions on /data/data and /data/app directories"
    echo ""

} > "${OUTPUT_FILE}" 2>&1

echo "[+] Content provider audit saved to: ${OUTPUT_FILE}"
