#!/system/bin/sh
# DROID FORENSIC - Shell Commands Enumeration
# Collects available shell commands, binaries, and their permissions
# Usage: sh 36_enum_shell_commands.sh [output_directory]

OUTPUT_DIR="${1:-.}"
OUTPUT_FILE="${OUTPUT_DIR}/shell_commands.txt"

echo "[*] Enumerating available shell commands..."

{
    echo "═══════════════════════════════════════════════════════════════"
    echo "  SHELL COMMANDS ENUMERATION"
    echo "  Timestamp: $(date)"
    echo "═══════════════════════════════════════════════════════════════"
    echo ""

    # Environment
    echo "┌─────────────────────────────────────────────────────────────┐"
    echo "│ ENVIRONMENT VARIABLES                                      │"
    echo "└─────────────────────────────────────────────────────────────┘"
    env 2>/dev/null || printenv 2>/dev/null
    echo ""

    # PATH
    echo "┌─────────────────────────────────────────────────────────────┐"
    echo "│ PATH VARIABLE                                              │"
    echo "└─────────────────────────────────────────────────────────────┘"
    echo "PATH=$PATH"
    echo ""
    echo "Parsed PATH directories:"
    echo "$PATH" | tr ':' '\n' | while read dir; do
        if [ -d "$dir" ]; then
            count=$(ls -1 "$dir" 2>/dev/null | wc -l)
            echo "  [EXISTS] $dir ($count files)"
        else
            echo "  [MISSING] $dir"
        fi
    done
    echo ""

    # /system/bin
    echo "┌─────────────────────────────────────────────────────────────┐"
    echo "│ /system/bin CONTENTS                                       │"
    echo "└─────────────────────────────────────────────────────────────┘"
    ls -la /system/bin/ 2>/dev/null
    echo ""
    echo "Count: $(ls -1 /system/bin/ 2>/dev/null | wc -l) files"
    echo ""

    # /system/xbin
    echo "┌─────────────────────────────────────────────────────────────┐"
    echo "│ /system/xbin CONTENTS                                      │"
    echo "└─────────────────────────────────────────────────────────────┘"
    ls -la /system/xbin/ 2>/dev/null || echo "[/system/xbin not present]"
    echo ""

    # /vendor/bin
    echo "┌─────────────────────────────────────────────────────────────┐"
    echo "│ /vendor/bin CONTENTS                                       │"
    echo "└─────────────────────────────────────────────────────────────┘"
    ls -la /vendor/bin/ 2>/dev/null || echo "[/vendor/bin not present]"
    echo ""

    # /sbin
    echo "┌─────────────────────────────────────────────────────────────┐"
    echo "│ /sbin CONTENTS                                             │"
    echo "└─────────────────────────────────────────────────────────────┘"
    ls -la /sbin/ 2>/dev/null || echo "[/sbin not accessible]"
    echo ""

    # /product/bin
    echo "┌─────────────────────────────────────────────────────────────┐"
    echo "│ /product/bin CONTENTS                                      │"
    echo "└─────────────────────────────────────────────────────────────┘"
    ls -la /product/bin/ 2>/dev/null || echo "[/product/bin not present]"
    echo ""

    # /apex binaries
    echo "┌─────────────────────────────────────────────────────────────┐"
    echo "│ APEX BINARIES (/apex/*/bin)                                │"
    echo "└─────────────────────────────────────────────────────────────┘"
    for apex_bin in /apex/*/bin; do
        if [ -d "$apex_bin" ]; then
            echo "--- $apex_bin ---"
            ls -la "$apex_bin" 2>/dev/null | head -20
            echo ""
        fi
    done
    echo ""

    # Toybox applets
    echo "┌─────────────────────────────────────────────────────────────┐"
    echo "│ TOYBOX APPLETS                                             │"
    echo "└─────────────────────────────────────────────────────────────┘"
    toybox 2>/dev/null || echo "[toybox not available]"
    echo ""
    echo "Toybox location and info:"
    which toybox 2>/dev/null
    ls -la $(which toybox 2>/dev/null) 2>/dev/null
    echo ""

    # Busybox applets (if present)
    echo "┌─────────────────────────────────────────────────────────────┐"
    echo "│ BUSYBOX APPLETS (if installed)                             │"
    echo "└─────────────────────────────────────────────────────────────┘"
    busybox --list 2>/dev/null || busybox 2>/dev/null || echo "[busybox not available]"
    echo ""
    echo "Busybox locations:"
    which busybox 2>/dev/null
    ls -la /system/xbin/busybox /system/bin/busybox /data/local/tmp/busybox 2>/dev/null
    echo ""

    # Shell type
    echo "┌─────────────────────────────────────────────────────────────┐"
    echo "│ SHELL INFORMATION                                          │"
    echo "└─────────────────────────────────────────────────────────────┘"
    echo "SHELL=$SHELL"
    echo "Current shell: $(readlink /proc/$$/exe 2>/dev/null)"
    echo ""
    ls -la /system/bin/sh /bin/sh 2>/dev/null
    echo ""
    file /system/bin/sh 2>/dev/null || echo "[file command not available]"
    echo ""

    # Security-sensitive commands
    echo "┌─────────────────────────────────────────────────────────────┐"
    echo "│ SECURITY-SENSITIVE COMMANDS                                │"
    echo "└─────────────────────────────────────────────────────────────┘"
    
    SENSITIVE_CMDS="su sudo dmesg logcat strace ltrace gdb ptrace tcpdump nc ncat netcat socat curl wget nmap"
    
    for cmd in $SENSITIVE_CMDS; do
        location=$(which "$cmd" 2>/dev/null)
        if [ -n "$location" ]; then
            echo "[FOUND] $cmd: $location"
            ls -la "$location" 2>/dev/null | sed 's/^/  /'
        else
            echo "[NOT FOUND] $cmd"
        fi
    done
    echo ""

    # Package manager commands
    echo "┌─────────────────────────────────────────────────────────────┐"
    echo "│ ANDROID PACKAGE MANAGER COMMANDS                           │"
    echo "└─────────────────────────────────────────────────────────────┘"
    
    ANDROID_CMDS="pm cmd am dumpsys settings content service app_process dalvikvm"
    
    for cmd in $ANDROID_CMDS; do
        location=$(which "$cmd" 2>/dev/null)
        if [ -n "$location" ]; then
            echo "[FOUND] $cmd: $location"
            ls -la "$location" 2>/dev/null | sed 's/^/  /'
        else
            echo "[NOT FOUND] $cmd"
        fi
    done
    echo ""

    # Debug/development commands
    echo "┌─────────────────────────────────────────────────────────────┐"
    echo "│ DEBUG/DEVELOPMENT COMMANDS                                 │"
    echo "└─────────────────────────────────────────────────────────────┘"
    
    DEBUG_CMDS="debuggerd crash_dump tombstoned perfetto simpleperf atrace"
    
    for cmd in $DEBUG_CMDS; do
        location=$(which "$cmd" 2>/dev/null)
        if [ -n "$location" ]; then
            echo "[FOUND] $cmd: $location"
            ls -la "$location" 2>/dev/null | sed 's/^/  /'
        fi
    done
    echo ""

    # Commands with SUID bit
    echo "┌─────────────────────────────────────────────────────────────┐"
    echo "│ SUID COMMANDS IN PATH                                      │"
    echo "└─────────────────────────────────────────────────────────────┘"
    echo "$PATH" | tr ':' '\n' | while read dir; do
        if [ -d "$dir" ]; then
            find "$dir" -perm -4000 -type f 2>/dev/null | while read f; do
                ls -la "$f"
            done
        fi
    done
    echo ""

} > "${OUTPUT_FILE}" 2>&1

echo "[+] Shell commands enumeration saved to: ${OUTPUT_FILE}"
