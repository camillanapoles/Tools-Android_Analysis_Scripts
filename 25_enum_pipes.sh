#!/system/bin/sh
# DROID FORENSIC - Pipes and IPC Enumeration
# Collects named pipes, unix sockets, binder, and other IPC mechanisms
# Usage: sh 25_enum_pipes.sh [output_directory]

OUTPUT_DIR="${1:-.}"
OUTPUT_FILE="${OUTPUT_DIR}/pipes_ipc.txt"

echo "[*] Enumerating pipes and IPC mechanisms..."

{
    echo "═══════════════════════════════════════════════════════════════"
    echo "  PIPES AND IPC ENUMERATION"
    echo "  Timestamp: $(date)"
    echo "═══════════════════════════════════════════════════════════════"
    echo ""

    # Named pipes (FIFOs)
    echo "┌─────────────────────────────────────────────────────────────┐"
    echo "│ NAMED PIPES (FIFOs)                                        │"
    echo "└─────────────────────────────────────────────────────────────┘"
    echo "Searching common locations for named pipes..."
    
    for dir in /dev /data/local/tmp /tmp /var/run /run /dev/socket /data/misc; do
        if [ -d "$dir" ]; then
            echo ""
            echo "--- $dir ---"
            find "$dir" -type p 2>/dev/null | while read pipe; do
                ls -la "$pipe" 2>/dev/null
            done
        fi
    done
    echo ""

    # Unix domain sockets
    echo "┌─────────────────────────────────────────────────────────────┐"
    echo "│ UNIX DOMAIN SOCKETS                                        │"
    echo "└─────────────────────────────────────────────────────────────┘"
    echo "Searching for socket files..."
    
    for dir in /dev /dev/socket /data/misc /var/run /run /tmp; do
        if [ -d "$dir" ]; then
            echo ""
            echo "--- $dir ---"
            find "$dir" -type s 2>/dev/null | while read sock; do
                ls -la "$sock" 2>/dev/null
            done
        fi
    done
    echo ""

    # /dev/socket (Android-specific)
    echo "┌─────────────────────────────────────────────────────────────┐"
    echo "│ ANDROID SOCKETS (/dev/socket)                              │"
    echo "└─────────────────────────────────────────────────────────────┘"
    ls -la /dev/socket/ 2>/dev/null || echo "[/dev/socket not accessible]"
    echo ""

    # Abstract unix sockets (from /proc/net/unix)
    echo "┌─────────────────────────────────────────────────────────────┐"
    echo "│ ABSTRACT UNIX SOCKETS (from /proc/net/unix)                │"
    echo "└─────────────────────────────────────────────────────────────┘"
    echo "Abstract sockets start with @ in the path column"
    cat /proc/net/unix 2>/dev/null | grep -E "^[0-9]" | awk '{print $NF}' | grep "^@" | sort -u
    echo ""

    # All unix sockets with full details
    echo "┌─────────────────────────────────────────────────────────────┐"
    echo "│ ALL UNIX SOCKETS (Full /proc/net/unix)                     │"
    echo "└─────────────────────────────────────────────────────────────┘"
    cat /proc/net/unix 2>/dev/null
    echo ""

    # Binder devices
    echo "┌─────────────────────────────────────────────────────────────┐"
    echo "│ BINDER DEVICES                                             │"
    echo "└─────────────────────────────────────────────────────────────┘"
    ls -la /dev/binder /dev/hwbinder /dev/vndbinder 2>/dev/null
    ls -la /dev/*binder* 2>/dev/null
    echo ""

    # Binder state (requires root)
    echo "┌─────────────────────────────────────────────────────────────┐"
    echo "│ BINDER STATE (requires elevated privileges)                │"
    echo "└─────────────────────────────────────────────────────────────┘"
    cat /sys/kernel/debug/binder/state 2>/dev/null | head -100 || echo "[binder debug not accessible]"
    echo "[truncated to 100 lines]"
    echo ""

    # Binder transactions
    echo "┌─────────────────────────────────────────────────────────────┐"
    echo "│ BINDER TRANSACTIONS                                        │"
    echo "└─────────────────────────────────────────────────────────────┘"
    cat /sys/kernel/debug/binder/transactions 2>/dev/null | head -50 || echo "[not accessible]"
    echo ""

    # Service manager (binder services)
    echo "┌─────────────────────────────────────────────────────────────┐"
    echo "│ BINDER SERVICES (service list)                             │"
    echo "└─────────────────────────────────────────────────────────────┘"
    service list 2>/dev/null | head -100 || echo "[service list not available]"
    echo "[truncated to 100 entries]"
    echo ""

    # AIDL interfaces
    echo "┌─────────────────────────────────────────────────────────────┐"
    echo "│ HARDWARE SERVICES (HIDL/AIDL)                              │"
    echo "└─────────────────────────────────────────────────────────────┘"
    lshal 2>/dev/null | head -100 || echo "[lshal not available]"
    echo "[truncated to 100 entries]"
    echo ""

    # Message queues
    echo "┌─────────────────────────────────────────────────────────────┐"
    echo "│ MESSAGE QUEUES (ipcs -q)                                   │"
    echo "└─────────────────────────────────────────────────────────────┘"
    ipcs -q 2>/dev/null || echo "[ipcs not available]"
    echo ""

    # Shared memory
    echo "┌─────────────────────────────────────────────────────────────┐"
    echo "│ SHARED MEMORY (ipcs -m)                                    │"
    echo "└─────────────────────────────────────────────────────────────┘"
    ipcs -m 2>/dev/null || echo "[ipcs not available]"
    echo ""

    # Semaphores
    echo "┌─────────────────────────────────────────────────────────────┐"
    echo "│ SEMAPHORES (ipcs -s)                                       │"
    echo "└─────────────────────────────────────────────────────────────┘"
    ipcs -s 2>/dev/null || echo "[ipcs not available]"
    echo ""

    # /dev/ashmem (Android shared memory)
    echo "┌─────────────────────────────────────────────────────────────┐"
    echo "│ ANDROID SHARED MEMORY                                      │"
    echo "└─────────────────────────────────────────────────────────────┘"
    ls -la /dev/ashmem* 2>/dev/null || echo "[ashmem devices not found]"
    echo ""

    # Ion memory allocator
    echo "┌─────────────────────────────────────────────────────────────┐"
    echo "│ ION MEMORY ALLOCATOR                                       │"
    echo "└─────────────────────────────────────────────────────────────┘"
    ls -la /dev/ion 2>/dev/null || echo "[ion device not found]"
    cat /sys/kernel/debug/ion/heaps/* 2>/dev/null | head -50
    echo ""

    # Process pipe/socket FDs
    echo "┌─────────────────────────────────────────────────────────────┐"
    echo "│ PROCESS PIPE FILE DESCRIPTORS                              │"
    echo "└─────────────────────────────────────────────────────────────┘"
    for pid in /proc/[0-9]*; do
        pid_num=$(basename "$pid")
        fd_dir="$pid/fd"
        if [ -d "$fd_dir" ]; then
            for fd in "$fd_dir"/*; do
                link=$(readlink "$fd" 2>/dev/null)
                case "$link" in
                    pipe:*)
                        cmdline=$(cat "$pid/cmdline" 2>/dev/null | tr '\0' ' ' | cut -c1-50)
                        echo "PID $pid_num: $link ($cmdline)"
                        ;;
                esac
            done
        fi
    done 2>/dev/null | head -100
    echo "[truncated to 100 entries]"
    echo ""

} > "${OUTPUT_FILE}" 2>&1

echo "[+] Pipes and IPC enumeration saved to: ${OUTPUT_FILE}"
