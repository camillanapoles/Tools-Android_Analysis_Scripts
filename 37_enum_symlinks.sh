#!/system/bin/sh
# DROID FORENSIC - Symlinks Enumeration
# Collects symbolic links across the filesystem
# Usage: sh 37_enum_symlinks.sh [output_directory]

OUTPUT_DIR="${1:-.}"
OUTPUT_FILE="${OUTPUT_DIR}/symlinks.txt"

echo "[*] Enumerating symbolic links..."

{
    echo "═══════════════════════════════════════════════════════════════"
    echo "  SYMBOLIC LINKS ENUMERATION"
    echo "  Timestamp: $(date)"
    echo "═══════════════════════════════════════════════════════════════"
    echo ""

    # Critical system symlinks
    echo "┌─────────────────────────────────────────────────────────────┐"
    echo "│ CRITICAL SYSTEM SYMLINKS                                   │"
    echo "└─────────────────────────────────────────────────────────────┘"
    
    CRITICAL_PATHS="/init /system/bin/sh /system/bin/app_process /system/bin/app_process32 /system/bin/app_process64 /system/xbin/su /sbin/su /system/bin/su /data/local/tmp/su"
    
    for path in $CRITICAL_PATHS; do
        if [ -e "$path" ] || [ -L "$path" ]; then
            echo "Path: $path"
            ls -la "$path" 2>/dev/null
            target=$(readlink -f "$path" 2>/dev/null)
            if [ -n "$target" ] && [ "$target" != "$path" ]; then
                echo "  -> Resolves to: $target"
                ls -la "$target" 2>/dev/null | sed 's/^/     /'
            fi
            echo ""
        fi
    done
    echo ""

    # /system/bin symlinks
    echo "┌─────────────────────────────────────────────────────────────┐"
    echo "│ SYMLINKS IN /system/bin                                    │"
    echo "└─────────────────────────────────────────────────────────────┘"
    find /system/bin -type l 2>/dev/null | while read link; do
        target=$(readlink "$link" 2>/dev/null)
        echo "$link -> $target"
    done
    echo ""
    echo "Count: $(find /system/bin -type l 2>/dev/null | wc -l) symlinks"
    echo ""

    # /system/xbin symlinks
    echo "┌─────────────────────────────────────────────────────────────┐"
    echo "│ SYMLINKS IN /system/xbin                                   │"
    echo "└─────────────────────────────────────────────────────────────┘"
    find /system/xbin -type l 2>/dev/null | while read link; do
        target=$(readlink "$link" 2>/dev/null)
        echo "$link -> $target"
    done
    echo ""

    # /vendor/bin symlinks
    echo "┌─────────────────────────────────────────────────────────────┐"
    echo "│ SYMLINKS IN /vendor/bin                                    │"
    echo "└─────────────────────────────────────────────────────────────┘"
    find /vendor/bin -type l 2>/dev/null | while read link; do
        target=$(readlink "$link" 2>/dev/null)
        echo "$link -> $target"
    done
    echo ""

    # /system/lib and /system/lib64 symlinks
    echo "┌─────────────────────────────────────────────────────────────┐"
    echo "│ SYMLINKS IN /system/lib*                                   │"
    echo "└─────────────────────────────────────────────────────────────┘"
    for libdir in /system/lib /system/lib64; do
        if [ -d "$libdir" ]; then
            echo "--- $libdir ---"
            find "$libdir" -type l 2>/dev/null | head -50 | while read link; do
                target=$(readlink "$link" 2>/dev/null)
                echo "$link -> $target"
            done
            echo "[showing first 50]"
            echo ""
        fi
    done
    echo ""

    # /vendor/lib symlinks
    echo "┌─────────────────────────────────────────────────────────────┐"
    echo "│ SYMLINKS IN /vendor/lib*                                   │"
    echo "└─────────────────────────────────────────────────────────────┘"
    for libdir in /vendor/lib /vendor/lib64; do
        if [ -d "$libdir" ]; then
            echo "--- $libdir ---"
            find "$libdir" -type l 2>/dev/null | head -50 | while read link; do
                target=$(readlink "$link" 2>/dev/null)
                echo "$link -> $target"
            done
            echo "[showing first 50]"
            echo ""
        fi
    done
    echo ""

    # /dev symlinks
    echo "┌─────────────────────────────────────────────────────────────┐"
    echo "│ SYMLINKS IN /dev                                           │"
    echo "└─────────────────────────────────────────────────────────────┘"
    find /dev -type l 2>/dev/null | while read link; do
        target=$(readlink "$link" 2>/dev/null)
        echo "$link -> $target"
    done
    echo ""

    # /etc symlinks (often points to /system/etc)
    echo "┌─────────────────────────────────────────────────────────────┐"
    echo "│ ROOT LEVEL SYMLINKS                                        │"
    echo "└─────────────────────────────────────────────────────────────┘"
    for item in /etc /bin /sbin /lib /lib64 /vendor /product /odm /system_ext; do
        if [ -L "$item" ]; then
            target=$(readlink "$item" 2>/dev/null)
            echo "$item -> $target"
        elif [ -d "$item" ]; then
            echo "$item [directory]"
        fi
    done
    echo ""

    # Broken symlinks in system paths
    echo "┌─────────────────────────────────────────────────────────────┐"
    echo "│ BROKEN SYMLINKS (targets don't exist)                      │"
    echo "└─────────────────────────────────────────────────────────────┘"
    for dir in /system/bin /system/xbin /vendor/bin /system/lib /system/lib64; do
        if [ -d "$dir" ]; then
            find "$dir" -type l 2>/dev/null | while read link; do
                if [ ! -e "$link" ]; then
                    target=$(readlink "$link" 2>/dev/null)
                    echo "[BROKEN] $link -> $target"
                fi
            done
        fi
    done
    echo ""

    # APEX symlinks
    echo "┌─────────────────────────────────────────────────────────────┐"
    echo "│ APEX MODULE SYMLINKS                                       │"
    echo "└─────────────────────────────────────────────────────────────┘"
    find /apex -maxdepth 2 -type l 2>/dev/null | while read link; do
        target=$(readlink "$link" 2>/dev/null)
        echo "$link -> $target"
    done
    echo ""

    # /data symlinks (may need elevated privileges)
    echo "┌─────────────────────────────────────────────────────────────┐"
    echo "│ SYMLINKS IN /data/local                                    │"
    echo "└─────────────────────────────────────────────────────────────┘"
    find /data/local -type l 2>/dev/null | while read link; do
        target=$(readlink "$link" 2>/dev/null)
        echo "$link -> $target"
    done
    echo ""

    # Symlinks pointing outside their parent directory (potential traversal)
    echo "┌─────────────────────────────────────────────────────────────┐"
    echo "│ SYMLINKS POINTING TO ABSOLUTE PATHS                        │"
    echo "└─────────────────────────────────────────────────────────────┘"
    echo "Symlinks in /system pointing to /data or other sensitive areas:"
    find /system -type l 2>/dev/null | while read link; do
        target=$(readlink "$link" 2>/dev/null)
        case "$target" in
            /data/*|/sdcard/*|/mnt/*)
                echo "[CROSS-BOUNDARY] $link -> $target"
                ;;
        esac
    done
    echo ""

} > "${OUTPUT_FILE}" 2>&1

echo "[+] Symlinks enumeration saved to: ${OUTPUT_FILE}"
