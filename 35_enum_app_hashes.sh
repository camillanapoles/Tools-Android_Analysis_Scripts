#!/system/bin/sh
# DROID FORENSIC - Application Hash Enumeration
# Collects installed application hashes, filenames, and metadata
# Usage: sh 35_enum_app_hashes.sh [output_directory]

OUTPUT_DIR="${1:-.}"
OUTPUT_FILE="${OUTPUT_DIR}/application_hashes.txt"

echo "[*] Enumerating application hashes and metadata..."

{
    echo "═══════════════════════════════════════════════════════════════"
    echo "  APPLICATION HASH ENUMERATION"
    echo "  Timestamp: $(date)"
    echo "═══════════════════════════════════════════════════════════════"
    echo ""

    # List all packages
    echo "┌─────────────────────────────────────────────────────────────┐"
    echo "│ INSTALLED PACKAGES (pm list packages -f)                   │"
    echo "└─────────────────────────────────────────────────────────────┘"
    pm list packages -f 2>/dev/null || echo "[pm not available]"
    echo ""

    # System packages
    echo "┌─────────────────────────────────────────────────────────────┐"
    echo "│ SYSTEM PACKAGES                                            │"
    echo "└─────────────────────────────────────────────────────────────┘"
    pm list packages -f -s 2>/dev/null || echo "[pm not available]"
    echo ""

    # Third-party packages
    echo "┌─────────────────────────────────────────────────────────────┐"
    echo "│ THIRD-PARTY PACKAGES                                       │"
    echo "└─────────────────────────────────────────────────────────────┘"
    pm list packages -f -3 2>/dev/null || echo "[pm not available]"
    echo ""

    # Disabled packages
    echo "┌─────────────────────────────────────────────────────────────┐"
    echo "│ DISABLED PACKAGES                                          │"
    echo "└─────────────────────────────────────────────────────────────┘"
    pm list packages -d 2>/dev/null || echo "[pm not available]"
    echo ""

    # Package UIDs
    echo "┌─────────────────────────────────────────────────────────────┐"
    echo "│ PACKAGE UIDs (pm list packages -U)                         │"
    echo "└─────────────────────────────────────────────────────────────┘"
    pm list packages -U 2>/dev/null || echo "[pm not available]"
    echo ""

    # APK hashes from /system/app
    echo "┌─────────────────────────────────────────────────────────────┐"
    echo "│ SYSTEM APP HASHES (/system/app)                            │"
    echo "└─────────────────────────────────────────────────────────────┘"
    if command -v sha256sum >/dev/null 2>&1; then
        HASH_CMD="sha256sum"
    elif command -v md5sum >/dev/null 2>&1; then
        HASH_CMD="md5sum"
        echo "[WARNING: Using MD5 - SHA256 not available]"
    else
        HASH_CMD=""
        echo "[WARNING: No hash utility available]"
    fi

    if [ -n "$HASH_CMD" ]; then
        find /system/app -name "*.apk" -type f 2>/dev/null | while read apk; do
            echo "File: $apk"
            $HASH_CMD "$apk" 2>/dev/null
            ls -la "$apk" 2>/dev/null
            echo ""
        done
    fi
    echo ""

    # APK hashes from /system/priv-app
    echo "┌─────────────────────────────────────────────────────────────┐"
    echo "│ PRIVILEGED APP HASHES (/system/priv-app)                   │"
    echo "└─────────────────────────────────────────────────────────────┘"
    if [ -n "$HASH_CMD" ]; then
        find /system/priv-app -name "*.apk" -type f 2>/dev/null | while read apk; do
            echo "File: $apk"
            $HASH_CMD "$apk" 2>/dev/null
            ls -la "$apk" 2>/dev/null
            echo ""
        done
    fi
    echo ""

    # APK hashes from /vendor/app
    echo "┌─────────────────────────────────────────────────────────────┐"
    echo "│ VENDOR APP HASHES (/vendor/app)                            │"
    echo "└─────────────────────────────────────────────────────────────┘"
    if [ -n "$HASH_CMD" ]; then
        find /vendor/app -name "*.apk" -type f 2>/dev/null | while read apk; do
            echo "File: $apk"
            $HASH_CMD "$apk" 2>/dev/null
            ls -la "$apk" 2>/dev/null
            echo ""
        done
    fi
    echo ""

    # APK hashes from /data/app (user installed)
    echo "┌─────────────────────────────────────────────────────────────┐"
    echo "│ USER APP HASHES (/data/app)                                │"
    echo "└─────────────────────────────────────────────────────────────┘"
    if [ -n "$HASH_CMD" ]; then
        find /data/app -name "*.apk" -type f 2>/dev/null | while read apk; do
            echo "File: $apk"
            $HASH_CMD "$apk" 2>/dev/null
            ls -la "$apk" 2>/dev/null
            echo ""
        done
    fi
    echo ""

    # Product and ODM apps
    echo "┌─────────────────────────────────────────────────────────────┐"
    echo "│ PRODUCT/ODM APP HASHES                                     │"
    echo "└─────────────────────────────────────────────────────────────┘"
    if [ -n "$HASH_CMD" ]; then
        for dir in /product/app /product/priv-app /odm/app /odm/priv-app; do
            if [ -d "$dir" ]; then
                echo "--- $dir ---"
                find "$dir" -name "*.apk" -type f 2>/dev/null | while read apk; do
                    echo "File: $apk"
                    $HASH_CMD "$apk" 2>/dev/null
                    ls -la "$apk" 2>/dev/null
                    echo ""
                done
            fi
        done
    fi
    echo ""

    # Dumpsys package info for detailed metadata
    echo "┌─────────────────────────────────────────────────────────────┐"
    echo "│ PACKAGE DATABASE SUMMARY                                   │"
    echo "└─────────────────────────────────────────────────────────────┘"
    dumpsys package packages 2>/dev/null | head -500 || echo "[dumpsys not available]"
    echo ""
    echo "[truncated to 500 lines - use 'dumpsys package' for full output]"
    echo ""

    # Shared libraries
    echo "┌─────────────────────────────────────────────────────────────┐"
    echo "│ SHARED LIBRARIES                                           │"
    echo "└─────────────────────────────────────────────────────────────┘"
    pm list libraries 2>/dev/null || echo "[pm not available]"
    echo ""

    # Features
    echo "┌─────────────────────────────────────────────────────────────┐"
    echo "│ SYSTEM FEATURES                                            │"
    echo "└─────────────────────────────────────────────────────────────┘"
    pm list features 2>/dev/null || echo "[pm not available]"
    echo ""

} > "${OUTPUT_FILE}" 2>&1

echo "[+] Application hash enumeration saved to: ${OUTPUT_FILE}"
