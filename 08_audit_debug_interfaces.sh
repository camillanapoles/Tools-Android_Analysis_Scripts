#!/system/bin/sh
# DROID FORENSIC - Debug Interfaces Audit
# Enumerates debug capabilities: ptrace, debugfs, tracefs, perf, kprobes
# Usage: sh 08_audit_debug_interfaces.sh [output_directory]

OUTPUT_DIR="${1:-.}"
OUTPUT_FILE="${OUTPUT_DIR}/audit_debug_interfaces.txt"

echo "[*] Auditing debug interfaces and capabilities..."

{
    echo "═══════════════════════════════════════════════════════════════"
    echo "  DEBUG INTERFACES AUDIT"
    echo "  Timestamp: $(date)"
    echo "═══════════════════════════════════════════════════════════════"
    echo ""
    echo "Debug interfaces can be exploited for privilege escalation,"
    echo "process injection, and kernel-level attacks if not restricted."
    echo ""

    # =========================================================================
    # SECTION 1: ptrace Status
    # =========================================================================
    
    echo "┌─────────────────────────────────────────────────────────────┐"
    echo "│ PTRACE DEBUGGING INTERFACE                                 │"
    echo "└─────────────────────────────────────────────────────────────┘"
    echo ""
    echo "ptrace allows process debugging and memory inspection."
    echo ""

    echo "=== ptrace_scope (Yama LSM) ==="
    PTRACE_SCOPE=$(cat /proc/sys/kernel/yama/ptrace_scope 2>/dev/null)
    echo "kernel.yama.ptrace_scope: ${PTRACE_SCOPE:-not available}"
    
    case "$PTRACE_SCOPE" in
        0)
            echo "  ██ [WARNING] Classic ptrace - any process can ptrace any other"
            echo "  Risk: Process injection, memory dumping, debugging attacks"
            ;;
        1)
            echo "  [OK] Restricted ptrace - only parent can ptrace children"
            ;;
        2)
            echo "  [OK] Admin-only ptrace - requires CAP_SYS_PTRACE"
            ;;
        3)
            echo "  [OK] No ptrace - completely disabled"
            ;;
        *)
            echo "  [INFO] Yama LSM may not be enabled"
            ;;
    esac
    echo ""

    # Check if we can ptrace
    echo "=== ptrace Capability Test ==="
    if [ -f /proc/self/status ]; then
        CAP_EFFECTIVE=$(grep "CapEff" /proc/self/status 2>/dev/null | awk '{print $2}')
        echo "Current process CapEff: $CAP_EFFECTIVE"
        
        # Check for CAP_SYS_PTRACE (bit 19)
        if [ -n "$CAP_EFFECTIVE" ]; then
            # Convert hex to check bit 19
            CAP_DEC=$(printf "%d" "0x$CAP_EFFECTIVE" 2>/dev/null || echo "0")
            PTRACE_CAP=$((CAP_DEC & (1 << 19)))
            if [ "$PTRACE_CAP" -gt 0 ]; then
                echo "  [INFO] CAP_SYS_PTRACE is available"
            else
                echo "  [OK] CAP_SYS_PTRACE not available to this process"
            fi
        fi
    fi
    echo ""

    # Check for debuggable processes
    echo "=== Debuggable Processes ==="
    echo "Processes that may be debuggable:"
    ps -A 2>/dev/null | head -1
    for pid in $(ls /proc 2>/dev/null | grep -E "^[0-9]+$" | head -50); do
        if [ -r "/proc/$pid/status" ]; then
            TRACER=$(grep "TracerPid" /proc/$pid/status 2>/dev/null | awk '{print $2}')
            if [ -n "$TRACER" ] && [ "$TRACER" != "0" ]; then
                NAME=$(cat /proc/$pid/comm 2>/dev/null)
                echo "  PID $pid ($NAME) is being traced by PID $TRACER"
            fi
        fi
    done
    echo ""

    # =========================================================================
    # SECTION 2: debugfs Status
    # =========================================================================
    
    echo "┌─────────────────────────────────────────────────────────────┐"
    echo "│ DEBUGFS FILESYSTEM                                         │"
    echo "└─────────────────────────────────────────────────────────────┘"
    echo ""
    echo "debugfs exposes kernel debugging information."
    echo ""

    echo "=== debugfs Mount Status ==="
    DEBUGFS_MOUNT=$(mount 2>/dev/null | grep debugfs)
    if [ -n "$DEBUGFS_MOUNT" ]; then
        echo "██ [WARNING] debugfs is MOUNTED:"
        echo "  $DEBUGFS_MOUNT"
        echo ""
        
        echo "=== debugfs Contents ==="
        if [ -d /sys/kernel/debug ]; then
            echo "Top-level entries in /sys/kernel/debug:"
            ls -la /sys/kernel/debug/ 2>/dev/null | head -30
            echo ""
            
            # Check for sensitive debug interfaces
            echo "=== Sensitive debugfs Entries ==="
            
            # Binder debug
            if [ -d /sys/kernel/debug/binder ]; then
                echo "[FOUND] Binder debugging: /sys/kernel/debug/binder"
                ls /sys/kernel/debug/binder/ 2>/dev/null | sed 's/^/  /'
            fi
            
            # GPU debug
            if [ -d /sys/kernel/debug/dri ] || [ -d /sys/kernel/debug/gpu ]; then
                echo "[FOUND] GPU debugging interfaces"
            fi
            
            # USB debug
            if [ -d /sys/kernel/debug/usb ]; then
                echo "[FOUND] USB debugging: /sys/kernel/debug/usb"
            fi
            
            # Clocks
            if [ -f /sys/kernel/debug/clk/clk_summary ]; then
                echo "[FOUND] Clock debugging available"
            fi
            
            # Regulators
            if [ -d /sys/kernel/debug/regulator ]; then
                echo "[FOUND] Regulator debugging available"
            fi
            
            # Tracing
            if [ -d /sys/kernel/debug/tracing ]; then
                echo "[FOUND] Kernel tracing: /sys/kernel/debug/tracing"
            fi
            
            # Kprobes
            if [ -d /sys/kernel/debug/kprobes ]; then
                echo "[FOUND] Kprobes debugging: /sys/kernel/debug/kprobes"
            fi
            
            # ion memory allocator
            if [ -d /sys/kernel/debug/ion ]; then
                echo "[FOUND] ION memory debugging"
            fi
            echo ""
        fi
    else
        echo "[OK] debugfs is NOT mounted"
    fi
    echo ""

    # =========================================================================
    # SECTION 3: tracefs Status
    # =========================================================================
    
    echo "┌─────────────────────────────────────────────────────────────┐"
    echo "│ TRACEFS FILESYSTEM (Kernel Tracing)                        │"
    echo "└─────────────────────────────────────────────────────────────┘"
    echo ""

    echo "=== tracefs Mount Status ==="
    TRACEFS_MOUNT=$(mount 2>/dev/null | grep tracefs)
    if [ -n "$TRACEFS_MOUNT" ]; then
        echo "[INFO] tracefs is mounted:"
        echo "  $TRACEFS_MOUNT"
        echo ""
        
        # Check tracing status
        TRACING_PATH="/sys/kernel/debug/tracing"
        [ -d "/sys/kernel/tracing" ] && TRACING_PATH="/sys/kernel/tracing"
        
        if [ -d "$TRACING_PATH" ]; then
            echo "=== Tracing Configuration ==="
            
            # Current tracer
            CURRENT_TRACER=$(cat "$TRACING_PATH/current_tracer" 2>/dev/null)
            echo "Current tracer: ${CURRENT_TRACER:-none}"
            
            # Available tracers
            echo "Available tracers:"
            cat "$TRACING_PATH/available_tracers" 2>/dev/null | sed 's/^/  /'
            
            # Tracing enabled
            TRACING_ON=$(cat "$TRACING_PATH/tracing_on" 2>/dev/null)
            echo "Tracing enabled: ${TRACING_ON:-unknown}"
            
            # Buffer size
            BUFFER_SIZE=$(cat "$TRACING_PATH/buffer_size_kb" 2>/dev/null)
            echo "Buffer size: ${BUFFER_SIZE:-unknown} KB"
            echo ""
            
            # Active events
            echo "=== Active Trace Events ==="
            if [ -f "$TRACING_PATH/set_event" ]; then
                EVENTS=$(cat "$TRACING_PATH/set_event" 2>/dev/null)
                if [ -n "$EVENTS" ]; then
                    echo "Active events:"
                    echo "$EVENTS" | head -20 | sed 's/^/  /'
                else
                    echo "No active trace events"
                fi
            fi
            echo ""
        fi
    else
        echo "[OK] tracefs is NOT mounted (or combined with debugfs)"
    fi
    echo ""

    # =========================================================================
    # SECTION 4: perf_event Interface
    # =========================================================================
    
    echo "┌─────────────────────────────────────────────────────────────┐"
    echo "│ PERF_EVENT INTERFACE                                       │"
    echo "└─────────────────────────────────────────────────────────────┘"
    echo ""
    echo "perf_event allows hardware performance monitoring."
    echo ""

    echo "=== perf_event_paranoid Setting ==="
    PERF_PARANOID=$(cat /proc/sys/kernel/perf_event_paranoid 2>/dev/null)
    echo "kernel.perf_event_paranoid: ${PERF_PARANOID:-not available}"
    
    case "$PERF_PARANOID" in
        -1)
            echo "  ██ [CRITICAL] No restrictions - full perf access for all users"
            ;;
        0)
            echo "  ██ [WARNING] Reduced restrictions - broad perf access"
            ;;
        1)
            echo "  [WARNING] Default - kernel profiling restricted to root"
            ;;
        2)
            echo "  [OK] Paranoid - user process profiling only"
            ;;
        3)
            echo "  [OK] Very paranoid - all perf access restricted to root"
            ;;
        *)
            echo "  [INFO] Non-standard value"
            ;;
    esac
    echo ""

    # Check perf tool availability
    echo "=== perf Tool Availability ==="
    if command -v perf >/dev/null 2>&1; then
        echo "██ [INFO] perf command is available"
        perf --version 2>/dev/null
    else
        echo "[OK] perf command not found"
    fi
    echo ""

    # Check for simpleperf (Android's perf)
    echo "=== simpleperf Availability ==="
    if command -v simpleperf >/dev/null 2>&1; then
        echo "[INFO] simpleperf is available"
        simpleperf --version 2>/dev/null
    elif [ -f /system/bin/simpleperf ]; then
        echo "[INFO] simpleperf found at /system/bin/simpleperf"
    else
        echo "[OK] simpleperf not found"
    fi
    echo ""

    # =========================================================================
    # SECTION 5: kprobes Interface
    # =========================================================================
    
    echo "┌─────────────────────────────────────────────────────────────┐"
    echo "│ KPROBES INTERFACE                                          │"
    echo "└─────────────────────────────────────────────────────────────┘"
    echo ""
    echo "kprobes allows dynamic kernel instrumentation."
    echo ""

    echo "=== kprobes Availability ==="
    if [ -d /sys/kernel/debug/kprobes ]; then
        echo "██ [WARNING] kprobes interface is available"
        
        # Check if enabled
        KPROBES_ENABLED=$(cat /sys/kernel/debug/kprobes/enabled 2>/dev/null)
        echo "kprobes enabled: ${KPROBES_ENABLED:-unknown}"
        
        # List active kprobes
        echo ""
        echo "Active kprobes:"
        cat /sys/kernel/debug/kprobes/list 2>/dev/null | head -20 | sed 's/^/  /'
        
        # Blacklist
        echo ""
        echo "kprobes blacklist (first 10):"
        cat /sys/kernel/debug/kprobes/blacklist 2>/dev/null | head -10 | sed 's/^/  /'
    else
        echo "[OK] kprobes interface not accessible"
    fi
    echo ""

    # Check kernel config for kprobes
    if [ -f /proc/config.gz ]; then
        echo "=== Kernel kprobes Configuration ==="
        zcat /proc/config.gz 2>/dev/null | grep -E "CONFIG_KPROBES|CONFIG_KRETPROBES|CONFIG_HAVE_KPROBES"
    fi
    echo ""

    # =========================================================================
    # SECTION 6: /proc Debug Interfaces
    # =========================================================================
    
    echo "┌─────────────────────────────────────────────────────────────┐"
    echo "│ /proc DEBUG INTERFACES                                     │"
    echo "└─────────────────────────────────────────────────────────────┘"
    echo ""

    echo "=== Kernel Pointer Exposure ==="
    KPTR_RESTRICT=$(cat /proc/sys/kernel/kptr_restrict 2>/dev/null)
    echo "kernel.kptr_restrict: ${KPTR_RESTRICT:-not available}"
    case "$KPTR_RESTRICT" in
        0)
            echo "  ██ [WARNING] Kernel pointers exposed to all users"
            ;;
        1)
            echo "  [OK] Kernel pointers hidden from unprivileged users"
            ;;
        2)
            echo "  [OK] Kernel pointers always hidden"
            ;;
    esac
    echo ""

    echo "=== dmesg Access ==="
    DMESG_RESTRICT=$(cat /proc/sys/kernel/dmesg_restrict 2>/dev/null)
    echo "kernel.dmesg_restrict: ${DMESG_RESTRICT:-not available}"
    if [ "$DMESG_RESTRICT" = "0" ]; then
        echo "  ██ [WARNING] dmesg accessible to unprivileged users"
    else
        echo "  [OK] dmesg restricted"
    fi
    echo ""

    echo "=== kallsyms Access ==="
    if [ -f /proc/kallsyms ]; then
        KALLSYMS_SAMPLE=$(head -1 /proc/kallsyms 2>/dev/null)
        if echo "$KALLSYMS_SAMPLE" | grep -q "^0000000000000000"; then
            echo "[OK] kallsyms addresses are zeroed (restricted)"
        else
            echo "██ [WARNING] kallsyms addresses may be visible"
            echo "  Sample: $KALLSYMS_SAMPLE"
        fi
    else
        echo "[OK] kallsyms not accessible"
    fi
    echo ""

    echo "=== /proc/<pid>/mem Access ==="
    if [ -r /proc/self/mem ]; then
        echo "[INFO] /proc/self/mem is readable"
    else
        echo "[OK] /proc/self/mem is not directly readable"
    fi
    echo ""

    echo "=== /proc/<pid>/maps Access ==="
    MAPS_SAMPLE=$(cat /proc/self/maps 2>/dev/null | head -3)
    if [ -n "$MAPS_SAMPLE" ]; then
        echo "[INFO] Process maps are readable:"
        echo "$MAPS_SAMPLE" | sed 's/^/  /'
    fi
    echo ""

    # =========================================================================
    # SECTION 7: Android Debug Properties
    # =========================================================================
    
    echo "┌─────────────────────────────────────────────────────────────┐"
    echo "│ ANDROID DEBUG PROPERTIES                                   │"
    echo "└─────────────────────────────────────────────────────────────┘"
    echo ""

    echo "=== Debug-Related System Properties ==="
    getprop 2>/dev/null | grep -iE "debug|dbg" | sort | while read line; do
        # Highlight potentially dangerous settings
        if echo "$line" | grep -qiE "=1\]$|=true\]$|=enabled\]$"; then
            echo "██ $line"
        else
            echo "  $line"
        fi
    done
    echo ""

    echo "=== Developer/Engineering Properties ==="
    getprop 2>/dev/null | grep -iE "ro\.debuggable|ro\.secure|persist\.sys\.usb|ro\.build\.type" | while read line; do
        echo "  $line"
    done
    echo ""

    # =========================================================================
    # SECTION 8: JTAG/Hardware Debug
    # =========================================================================
    
    echo "┌─────────────────────────────────────────────────────────────┐"
    echo "│ HARDWARE DEBUG INDICATORS                                  │"
    echo "└─────────────────────────────────────────────────────────────┘"
    echo ""

    echo "=== JTAG/SWD Properties ==="
    getprop 2>/dev/null | grep -iE "jtag|swd|debug_fuse|fuse" | head -10
    echo ""

    echo "=== Secure Boot Fuses ==="
    getprop 2>/dev/null | grep -iE "fuse|efuse|secboot|secure_boot" | head -10
    echo ""

    # Check for debug device nodes
    echo "=== Debug Device Nodes ==="
    ls -la /dev/*debug* /dev/*jtag* /dev/*diag* 2>/dev/null | head -10
    echo ""

    # =========================================================================
    # SECTION 9: Memory Debugging
    # =========================================================================
    
    echo "┌─────────────────────────────────────────────────────────────┐"
    echo "│ MEMORY DEBUGGING FEATURES                                  │"
    echo "└─────────────────────────────────────────────────────────────┘"
    echo ""

    echo "=== KASAN (Kernel Address Sanitizer) ==="
    if [ -f /proc/config.gz ]; then
        if zcat /proc/config.gz 2>/dev/null | grep -q "CONFIG_KASAN=y"; then
            echo "[INFO] KASAN is enabled (debug build)"
        else
            echo "[OK] KASAN not enabled"
        fi
    fi
    echo ""

    echo "=== UBSAN (Undefined Behavior Sanitizer) ==="
    if [ -f /proc/config.gz ]; then
        if zcat /proc/config.gz 2>/dev/null | grep -q "CONFIG_UBSAN=y"; then
            echo "[INFO] UBSAN is enabled (debug build)"
        else
            echo "[OK] UBSAN not enabled"
        fi
    fi
    echo ""

    echo "=== slub_debug Status ==="
    CMDLINE=$(cat /proc/cmdline 2>/dev/null)
    if echo "$CMDLINE" | grep -q "slub_debug"; then
        echo "██ [INFO] slub_debug is enabled via cmdline"
        echo "$CMDLINE" | tr ' ' '\n' | grep slub_debug
    else
        echo "[OK] slub_debug not in cmdline"
    fi
    echo ""

    # =========================================================================
    # SECTION 10: Debugging Tools Available
    # =========================================================================
    
    echo "┌─────────────────────────────────────────────────────────────┐"
    echo "│ DEBUGGING TOOLS AVAILABLE                                  │"
    echo "└─────────────────────────────────────────────────────────────┘"
    echo ""

    DEBUG_TOOLS="gdb gdbserver lldb strace ltrace ptrace perf simpleperf crash debuggerd tombstoned"
    
    echo "Checking for debugging tools:"
    for tool in $DEBUG_TOOLS; do
        TOOL_PATH=$(which "$tool" 2>/dev/null)
        if [ -n "$TOOL_PATH" ]; then
            echo "  [FOUND] $tool: $TOOL_PATH"
        fi
    done
    echo ""

    # Check for gdbserver specifically
    echo "=== gdbserver Check ==="
    find /system /vendor /data -name "gdbserver*" -type f 2>/dev/null | while read f; do
        echo "  ██ [FOUND] $f"
    done
    echo ""

    # =========================================================================
    # SECTION 11: Core Dump Configuration
    # =========================================================================
    
    echo "┌─────────────────────────────────────────────────────────────┐"
    echo "│ CORE DUMP CONFIGURATION                                    │"
    echo "└─────────────────────────────────────────────────────────────┘"
    echo ""

    echo "=== Core Pattern ==="
    CORE_PATTERN=$(cat /proc/sys/kernel/core_pattern 2>/dev/null)
    echo "kernel.core_pattern: ${CORE_PATTERN:-not available}"
    
    if echo "$CORE_PATTERN" | grep -q "|"; then
        echo "  [INFO] Core dumps piped to external program"
    fi
    echo ""

    echo "=== Core File Limits ==="
    ulimit -c 2>/dev/null
    echo ""

    echo "=== Tombstone Directory ==="
    if [ -d /data/tombstones ]; then
        echo "Tombstones present:"
        ls -la /data/tombstones/ 2>/dev/null | tail -10
    fi
    echo ""

    # =========================================================================
    # SECTION 12: Summary
    # =========================================================================
    
    echo "┌─────────────────────────────────────────────────────────────┐"
    echo "│ DEBUG INTERFACES SUMMARY                                   │"
    echo "└─────────────────────────────────────────────────────────────┘"
    echo ""

    RISK_COUNT=0
    
    # Tally risks
    [ "$PTRACE_SCOPE" = "0" ] && RISK_COUNT=$((RISK_COUNT + 1))
    [ -n "$DEBUGFS_MOUNT" ] && RISK_COUNT=$((RISK_COUNT + 1))
    [ "$PERF_PARANOID" = "-1" ] || [ "$PERF_PARANOID" = "0" ] && RISK_COUNT=$((RISK_COUNT + 1))
    [ "$KPTR_RESTRICT" = "0" ] && RISK_COUNT=$((RISK_COUNT + 1))
    [ "$DMESG_RESTRICT" = "0" ] && RISK_COUNT=$((RISK_COUNT + 1))
    [ -d /sys/kernel/debug/kprobes ] && RISK_COUNT=$((RISK_COUNT + 1))

    echo "Debug Interface Status:"
    echo "  ptrace_scope:         ${PTRACE_SCOPE:-N/A}"
    echo "  debugfs mounted:      $([ -n "$DEBUGFS_MOUNT" ] && echo "YES" || echo "NO")"
    echo "  tracefs mounted:      $([ -n "$TRACEFS_MOUNT" ] && echo "YES" || echo "NO")"
    echo "  perf_event_paranoid:  ${PERF_PARANOID:-N/A}"
    echo "  kptr_restrict:        ${KPTR_RESTRICT:-N/A}"
    echo "  dmesg_restrict:       ${DMESG_RESTRICT:-N/A}"
    echo ""
    echo "Risk Indicators Found: $RISK_COUNT"
    echo ""

    if [ "$RISK_COUNT" -gt 2 ]; then
        echo "████████████████████████████████████████████████████████████"
        echo "██ MULTIPLE DEBUG INTERFACES EXPOSED ██"
        echo "████████████████████████████████████████████████████████████"
        echo ""
        echo "This device has multiple debug interfaces accessible."
        echo "Likely an engineering/debug build - not suitable for production."
    elif [ "$RISK_COUNT" -gt 0 ]; then
        echo "[WARNING] Some debug interfaces are exposed"
        echo "Review findings above for specific concerns."
    else
        echo "[OK] Debug interfaces appear properly restricted"
    fi
    echo ""

    echo "Recommendations:"
    echo "  1. Set ptrace_scope >= 1 (restrict ptrace)"
    echo "  2. Unmount debugfs in production builds"
    echo "  3. Set perf_event_paranoid >= 2"
    echo "  4. Enable kptr_restrict and dmesg_restrict"
    echo "  5. Remove gdbserver and debug tools from production"
    echo "  6. Verify this is not an engineering/debug build"
    echo ""

    # =========================================================================
    # SECTION 13: tracefs Write-Permission Audit
    # =========================================================================

    echo "┌─────────────────────────────────────────────────────────────┐"
    echo "│ TRACEFS WRITE-PERMISSION AUDIT                             │"
    echo "└─────────────────────────────────────────────────────────────┘"
    echo ""
    echo "Checking DAC write access to tracefs control files from this shell."
    echo "(No actual writes are performed — permission bits tested only.)"
    echo ""

    echo "=== tracefs Control File Write Access ==="
    if [ -e /sys/kernel/tracing/tracing_on ]; then
        if [ -w /sys/kernel/tracing/tracing_on ]; then
            echo "  [CRITICAL] /sys/kernel/tracing/tracing_on — WRITABLE (unprivileged tracing enable)"
        else
            echo "  [OK] /sys/kernel/tracing/tracing_on — not writable"
        fi
    else
        echo "  [INFO] /sys/kernel/tracing/tracing_on — not present"
    fi

    if [ -e /sys/kernel/tracing/current_tracer ]; then
        if [ -w /sys/kernel/tracing/current_tracer ]; then
            echo "  [CRITICAL] /sys/kernel/tracing/current_tracer — WRITABLE (tracer selection possible)"
        else
            echo "  [OK] /sys/kernel/tracing/current_tracer — not writable"
        fi
    else
        echo "  [INFO] /sys/kernel/tracing/current_tracer — not present"
    fi

    if [ -e /sys/kernel/tracing/events/syscalls/enable ]; then
        if [ -w /sys/kernel/tracing/events/syscalls/enable ]; then
            echo "  [CRITICAL] /sys/kernel/tracing/events/syscalls/enable — WRITABLE (syscall tracing enable)"
        else
            echo "  [OK] /sys/kernel/tracing/events/syscalls/enable — not writable"
        fi
    else
        echo "  [INFO] /sys/kernel/tracing/events/syscalls/enable — not present"
    fi

    if [ -e /sys/kernel/tracing/kprobe_events ]; then
        if [ -w /sys/kernel/tracing/kprobe_events ]; then
            echo "  [CRITICAL] /sys/kernel/tracing/kprobe_events — WRITABLE (custom kprobe injection possible)"
        else
            echo "  [OK] /sys/kernel/tracing/kprobe_events — not writable"
        fi
    else
        echo "  [INFO] /sys/kernel/tracing/kprobe_events — not present"
    fi
    echo ""

    # =========================================================================
    # SECTION 14: tracefs Read-Only Sections
    # =========================================================================

    echo "┌─────────────────────────────────────────────────────────────┐"
    echo "│ TRACEFS READABLE PATHS                                     │"
    echo "└─────────────────────────────────────────────────────────────┘"
    echo ""
    echo "Paths readable from unprivileged shell — information disclosure surface:"
    echo ""

    echo "=== tracefs Read Access ==="
    if [ -e /sys/kernel/tracing/trace ]; then
        if [ -r /sys/kernel/tracing/trace ]; then
            echo "  [HIGH] /sys/kernel/tracing/trace — READABLE (live kernel trace buffer)"
            echo "  Sample (first 5 lines):"
            cat /sys/kernel/tracing/trace 2>/dev/null | head -5 | sed 's/^/    /'
        else
            echo "  [OK] /sys/kernel/tracing/trace — not readable"
        fi
    else
        echo "  [INFO] /sys/kernel/tracing/trace — not present"
    fi

    if [ -e /sys/kernel/tracing/trace_pipe ]; then
        if [ -r /sys/kernel/tracing/trace_pipe ]; then
            echo "  [HIGH] /sys/kernel/tracing/trace_pipe — READABLE (streaming trace events)"
        else
            echo "  [OK] /sys/kernel/tracing/trace_pipe — not readable"
        fi
    else
        echo "  [INFO] /sys/kernel/tracing/trace_pipe — not present"
    fi

    if [ -e /sys/kernel/tracing/available_tracers ]; then
        if [ -r /sys/kernel/tracing/available_tracers ]; then
            echo "  [INFO] /sys/kernel/tracing/available_tracers — readable"
            AVAIL_TRACERS=$(cat /sys/kernel/tracing/available_tracers 2>/dev/null)
            echo "    Tracers: ${AVAIL_TRACERS:-none}"
        else
            echo "  [OK] /sys/kernel/tracing/available_tracers — not readable"
        fi
    else
        echo "  [INFO] /sys/kernel/tracing/available_tracers — not present"
    fi

    if [ -e /sys/kernel/tracing/available_events ]; then
        if [ -r /sys/kernel/tracing/available_events ]; then
            EVENT_COUNT=$(cat /sys/kernel/tracing/available_events 2>/dev/null | wc -l)
            echo "  [INFO] /sys/kernel/tracing/available_events — readable ($EVENT_COUNT events)"
        else
            echo "  [OK] /sys/kernel/tracing/available_events — not readable"
        fi
    else
        echo "  [INFO] /sys/kernel/tracing/available_events — not present"
    fi
    echo ""

    # =========================================================================
    # SECTION 15: eBPF Surface
    # =========================================================================

    echo "┌─────────────────────────────────────────────────────────────┐"
    echo "│ EBPF ATTACK SURFACE                                        │"
    echo "└─────────────────────────────────────────────────────────────┘"
    echo ""
    echo "eBPF programs can be used for kernel instrumentation and privilege escalation."
    echo ""

    echo "=== Unprivileged BPF ==="
    if [ -s /proc/sys/kernel/unprivileged_bpf_disabled ]; then
        UNPRIVILEGED_BPF=$(cat /proc/sys/kernel/unprivileged_bpf_disabled 2>/dev/null)
        echo "kernel.unprivileged_bpf_disabled: ${UNPRIVILEGED_BPF:-unreadable}"
        case "$UNPRIVILEGED_BPF" in
            0)
                echo "  [CRITICAL] Unprivileged eBPF is ENABLED — any process can load BPF programs"
                echo "  Risk: kernel memory reads, syscall interception, privilege escalation via BPF"
                ;;
            1)
                echo "  [INFO] Unprivileged BPF is disabled (requires CAP_BPF or CAP_SYS_ADMIN)"
                ;;
            2)
                echo "  [INFO] Unprivileged BPF disabled and locked (cannot be re-enabled at runtime)"
                ;;
            *)
                echo "  [INFO] Non-standard value"
                ;;
        esac
    else
        echo "  [INFO] /proc/sys/kernel/unprivileged_bpf_disabled — not present (kernel may lack BPF)"
    fi
    echo ""

    echo "=== BPF JIT Compiler ==="
    if [ -s /proc/sys/net/core/bpf_jit_enable ]; then
        BPF_JIT=$(cat /proc/sys/net/core/bpf_jit_enable 2>/dev/null)
        echo "net.core.bpf_jit_enable: ${BPF_JIT:-unreadable}"
        case "$BPF_JIT" in
            0)
                echo "  [INFO] BPF JIT disabled (interpreter mode only)"
                ;;
            1)
                echo "  [MEDIUM] BPF JIT enabled — compiled BPF may be vulnerable to side-channel attacks"
                ;;
            2)
                echo "  [MEDIUM] BPF JIT enabled with debugging — JIT output may be readable"
                ;;
        esac
    else
        echo "  [INFO] /proc/sys/net/core/bpf_jit_enable — not present"
    fi
    echo ""

    echo "=== BPF Filesystem ==="
    if [ -d /sys/fs/bpf ]; then
        echo "  [INFO] /sys/fs/bpf/ is mounted (BPF object pinning enabled)"
        BPF_PERMS=$(ls -ld /sys/fs/bpf/ 2>/dev/null)
        echo "  Permissions: ${BPF_PERMS:-unavailable}"
        if [ -w /sys/fs/bpf ]; then
            echo "  [HIGH] /sys/fs/bpf/ is WRITABLE — BPF objects can be pinned by this process"
        else
            echo "  [OK] /sys/fs/bpf/ is not writable from this process"
        fi
        echo "  Contents:"
        ls /sys/fs/bpf/ 2>/dev/null | head -10 | sed 's/^/    /'
    else
        echo "  [INFO] /sys/fs/bpf/ not mounted"
    fi
    echo ""

} > "${OUTPUT_FILE}" 2>&1

echo "[+] Debug interfaces audit saved to: ${OUTPUT_FILE}"
