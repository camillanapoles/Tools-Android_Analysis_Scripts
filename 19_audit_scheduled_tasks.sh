#!/system/bin/sh
# DROID FORENSIC - Scheduled Tasks Audit
# Enumerates JobScheduler, AlarmManager, WorkManager jobs and persistence mechanisms
# Usage: sh 19_audit_scheduled_tasks.sh [output_directory]

OUTPUT_DIR="${1:-.}"
OUTPUT_FILE="${OUTPUT_DIR}/audit_scheduled_tasks.txt"

echo "[*] Auditing scheduled tasks and persistence mechanisms..."

{
    echo "═══════════════════════════════════════════════════════════════"
    echo "  SCHEDULED TASKS & PERSISTENCE AUDIT"
    echo "  Timestamp: $(date)"
    echo "═══════════════════════════════════════════════════════════════"
    echo ""
    echo "Scheduled tasks can be used for persistence by malware or"
    echo "may reveal sensitive background operations."
    echo ""

    # =========================================================================
    # SECTION 1: JobScheduler Jobs
    # =========================================================================
    
    echo "┌─────────────────────────────────────────────────────────────┐"
    echo "│ JOBSCHEDULER JOBS                                          │"
    echo "└─────────────────────────────────────────────────────────────┘"
    echo ""
    echo "JobScheduler is the modern Android task scheduling API."
    echo ""

    echo "=== All Scheduled Jobs (dumpsys jobscheduler) ==="
    JOBSCHEDULER_OUTPUT=$(dumpsys jobscheduler 2>/dev/null)
    
    if [ -n "$JOBSCHEDULER_OUTPUT" ]; then
        # Count total jobs
        JOB_COUNT=$(echo "$JOBSCHEDULER_OUTPUT" | grep -c "JOB\|JobStatus")
        echo "Total scheduled jobs found: ~$JOB_COUNT"
        echo ""
        
        # Show registered jobs section
        echo "--- Registered Jobs ---"
        echo "$JOBSCHEDULER_OUTPUT" | sed -n '/Registered.*jobs/,/^[A-Z]/p' | head -100
        echo ""
        
        # Show pending jobs
        echo "--- Pending Jobs ---"
        echo "$JOBSCHEDULER_OUTPUT" | sed -n '/Pending.*jobs\|Ready.*jobs/,/^[A-Z]/p' | head -50
        echo ""
        
        # Show active jobs
        echo "--- Active Jobs ---"
        echo "$JOBSCHEDULER_OUTPUT" | sed -n '/Active.*jobs\|Currently.*running/,/^[A-Z]/p' | head -30
        echo ""
        
    else
        echo "[INFO] JobScheduler information not available"
    fi

    # Per-package job analysis
    echo "=== Jobs by Package ==="
    echo "$JOBSCHEDULER_OUTPUT" | grep -E "^\s+JOB|u0a[0-9]+:" | head -50
    echo ""

    # Check for suspicious job patterns
    echo "=== Suspicious Job Detection ==="
    SUSPICIOUS_JOBS=$(echo "$JOBSCHEDULER_OUTPUT" | grep -iE "persist|boot|background|hidden|stealth|spy|monitor|track|keylog|record")
    if [ -n "$SUSPICIOUS_JOBS" ]; then
        echo "██ [WARNING] Potentially suspicious job names/patterns:"
        echo "$SUSPICIOUS_JOBS" | head -20
    else
        echo "[OK] No obviously suspicious job patterns detected"
    fi
    echo ""

    # =========================================================================
    # SECTION 2: AlarmManager Alarms
    # =========================================================================
    
    echo "┌─────────────────────────────────────────────────────────────┐"
    echo "│ ALARMMANAGER ALARMS                                        │"
    echo "└─────────────────────────────────────────────────────────────┘"
    echo ""
    echo "AlarmManager schedules time-based tasks and wake-ups."
    echo ""

    echo "=== All Alarms (dumpsys alarm) ==="
    ALARM_OUTPUT=$(dumpsys alarm 2>/dev/null)
    
    if [ -n "$ALARM_OUTPUT" ]; then
        # Get alarm statistics
        echo "--- Alarm Statistics ---"
        echo "$ALARM_OUTPUT" | sed -n '/Alarm Stats/,/^[A-Z]/p' | head -30
        echo ""
        
        # Pending alarms
        echo "--- Pending Alarms ---"
        echo "$ALARM_OUTPUT" | sed -n '/Pending alarm batches/,/^[A-Z]/p' | head -50
        echo ""
        
        # Batch alarms
        echo "--- Alarm Batches ---"
        echo "$ALARM_OUTPUT" | grep -E "Batch|ELAPSED|RTC" | head -30
        echo ""
        
        # Wake-up alarms (high priority - can wake device)
        echo "--- Wake-up Alarms ---"
        echo "$ALARM_OUTPUT" | grep -iE "WAKEUP|wake" | head -30
        echo ""
        
        # Top alarm users
        echo "--- Top Alarm Users ---"
        echo "$ALARM_OUTPUT" | sed -n '/Top Alarms/,/^[A-Z]/p' | head -30
        echo ""
        
    else
        echo "[INFO] AlarmManager information not available"
    fi

    # Check for repeating alarms (persistence indicator)
    echo "=== Repeating Alarms (Persistence Indicator) ==="
    echo "$ALARM_OUTPUT" | grep -iE "repeat|interval|period" | head -20
    echo ""

    # =========================================================================
    # SECTION 3: WorkManager Jobs (AndroidX)
    # =========================================================================
    
    echo "┌─────────────────────────────────────────────────────────────┐"
    echo "│ WORKMANAGER JOBS                                           │"
    echo "└─────────────────────────────────────────────────────────────┘"
    echo ""
    echo "WorkManager is AndroidX's recommended task scheduler."
    echo ""

    # WorkManager uses JobScheduler/AlarmManager under the hood
    # but stores its own state in app databases
    
    echo "=== WorkManager Databases ==="
    find /data/data -name "androidx.work.workdb*" -o -name "work_database*" 2>/dev/null | while read db; do
        echo "Found: $db"
        APP_PKG=$(echo "$db" | sed 's|/data/data/||;s|/.*||')
        echo "  Package: $APP_PKG"
        
        # Try to read work entries
        if [ -f "$db" ]; then
            echo "  Tables:"
            sqlite3 "$db" ".tables" 2>/dev/null | sed 's/^/    /'
            
            echo "  Pending work:"
            sqlite3 "$db" "SELECT id, worker_class_name, state FROM workspec LIMIT 10;" 2>/dev/null | sed 's/^/    /'
        fi
        echo ""
    done
    echo ""

    # =========================================================================
    # SECTION 4: Boot-Completed Receivers (Auto-Start)
    # =========================================================================
    
    echo "┌─────────────────────────────────────────────────────────────┐"
    echo "│ BOOT-COMPLETED RECEIVERS (Auto-Start Apps)                 │"
    echo "└─────────────────────────────────────────────────────────────┘"
    echo ""
    echo "Apps registered for BOOT_COMPLETED start automatically on boot."
    echo ""

    echo "=== BOOT_COMPLETED Receivers ==="
    dumpsys package 2>/dev/null | sed -n '/Receiver Resolver Table/,/Service Resolver Table/p' | grep -B5 "BOOT_COMPLETED" | grep -E "^\s+[a-z]" | sort -u | head -30
    echo ""

    # Also check for QUICKBOOT and similar
    echo "=== Other Boot-Related Receivers ==="
    dumpsys package 2>/dev/null | sed -n '/Receiver Resolver Table/,/Service Resolver Table/p' | grep -iE "BOOT|QUICKBOOT|LOCKED_BOOT|USER_UNLOCKED" | head -20
    echo ""

    # =========================================================================
    # SECTION 5: Sync Adapters
    # =========================================================================
    
    echo "┌─────────────────────────────────────────────────────────────┐"
    echo "│ SYNC ADAPTERS                                              │"
    echo "└─────────────────────────────────────────────────────────────┘"
    echo ""
    echo "Sync adapters run periodically to sync data."
    echo ""

    echo "=== Registered Sync Adapters ==="
    dumpsys content 2>/dev/null | sed -n '/SyncAdapters/,/^[A-Z]/p' | head -50
    echo ""

    echo "=== Sync Status ==="
    dumpsys content 2>/dev/null | sed -n '/SyncManager/,/^[A-Z]/p' | head -30
    echo ""

    # =========================================================================
    # SECTION 6: Device Idle (Doze) Whitelist
    # =========================================================================
    
    echo "┌─────────────────────────────────────────────────────────────┐"
    echo "│ DOZE MODE WHITELIST                                        │"
    echo "└─────────────────────────────────────────────────────────────┘"
    echo ""
    echo "Apps whitelisted from Doze can run unrestricted in background."
    echo ""

    echo "=== Device Idle Whitelist ==="
    dumpsys deviceidle 2>/dev/null | sed -n '/Whitelist/,/^[A-Z]/p' | head -50
    echo ""

    echo "=== System Whitelist ==="
    dumpsys deviceidle whitelist 2>/dev/null | head -30
    echo ""

    # =========================================================================
    # SECTION 7: Background Restrictions
    # =========================================================================
    
    echo "┌─────────────────────────────────────────────────────────────┐"
    echo "│ BACKGROUND RESTRICTIONS                                    │"
    echo "└─────────────────────────────────────────────────────────────┘"
    echo ""

    echo "=== App Standby Buckets ==="
    dumpsys usagestats 2>/dev/null | grep -iE "bucket|standby" | head -30
    echo ""

    echo "=== Battery Optimization Exemptions ==="
    dumpsys deviceidle 2>/dev/null | grep -iE "exempt|whitelist" | head -20
    echo ""

    # =========================================================================
    # SECTION 8: Foreground Services
    # =========================================================================
    
    echo "┌─────────────────────────────────────────────────────────────┐"
    echo "│ FOREGROUND SERVICES                                        │"
    echo "└─────────────────────────────────────────────────────────────┘"
    echo ""
    echo "Foreground services run persistently with user notification."
    echo ""

    echo "=== Active Foreground Services ==="
    dumpsys activity services 2>/dev/null | grep -iE "foreground|isForeground=true" | head -30
    echo ""

    echo "=== Services by Type ==="
    dumpsys activity services 2>/dev/null | grep -E "ServiceRecord|ProcessRecord" | head -30
    echo ""

    # =========================================================================
    # SECTION 9: Scheduled Downloads
    # =========================================================================
    
    echo "┌─────────────────────────────────────────────────────────────┐"
    echo "│ DOWNLOAD MANAGER QUEUE                                     │"
    echo "└─────────────────────────────────────────────────────────────┘"
    echo ""

    echo "=== Pending Downloads ==="
    dumpsys download 2>/dev/null | head -50
    echo ""

    # =========================================================================
    # SECTION 10: Firebase/GCM Push Registration
    # =========================================================================
    
    echo "┌─────────────────────────────────────────────────────────────┐"
    echo "│ PUSH NOTIFICATION SERVICES                                 │"
    echo "└─────────────────────────────────────────────────────────────┘"
    echo ""

    echo "=== GCM/FCM Registration ==="
    dumpsys activity services 2>/dev/null | grep -iE "gcm|fcm|firebase|messaging" | head -20
    echo ""

    # Check for Firebase databases
    echo "=== Firebase Persistence ==="
    find /data/data -name "*firebase*" -type f 2>/dev/null | head -20
    echo ""

    # =========================================================================
    # SECTION 11: Cron-like Tasks (if rooted/custom ROM)
    # =========================================================================
    
    echo "┌─────────────────────────────────────────────────────────────┐"
    echo "│ CRON/INIT SCHEDULED TASKS                                  │"
    echo "└─────────────────────────────────────────────────────────────┘"
    echo ""

    echo "=== Crontabs (if available) ==="
    for cron_path in /etc/crontab /var/spool/cron/* /data/crontab /system/etc/crontab; do
        if [ -f "$cron_path" ]; then
            echo "Found: $cron_path"
            cat "$cron_path" 2>/dev/null | sed 's/^/  /'
            echo ""
        fi
    done
    echo ""

    echo "=== Init.d Scripts ==="
    for initd_path in /system/etc/init.d /data/adb/service.d /data/adb/post-fs-data.d; do
        if [ -d "$initd_path" ]; then
            echo "Directory: $initd_path"
            ls -la "$initd_path" 2>/dev/null | sed 's/^/  /'
            echo ""
        fi
    done
    echo ""

    # =========================================================================
    # SECTION 12: Task Statistics
    # =========================================================================
    
    echo "┌─────────────────────────────────────────────────────────────┐"
    echo "│ TASK EXECUTION STATISTICS                                  │"
    echo "└─────────────────────────────────────────────────────────────┘"
    echo ""

    echo "=== Job Execution History ==="
    echo "$JOBSCHEDULER_OUTPUT" | sed -n '/Job history/,/^[A-Z]/p' | head -40
    echo ""

    echo "=== Recent Alarm Deliveries ==="
    echo "$ALARM_OUTPUT" | sed -n '/Recent.*delivery/,/^[A-Z]/p' | head -30
    echo ""

    # =========================================================================
    # SECTION 13: Persistence Analysis
    # =========================================================================
    
    echo "┌─────────────────────────────────────────────────────────────┐"
    echo "│ PERSISTENCE MECHANISM ANALYSIS                             │"
    echo "└─────────────────────────────────────────────────────────────┘"
    echo ""

    echo "=== Apps with Multiple Persistence Mechanisms ==="
    echo ""
    
    # Get unique packages from various sources
    BOOT_APPS=$(dumpsys package 2>/dev/null | sed -n '/Receiver Resolver Table/,/Service Resolver Table/p' | grep -B5 "BOOT_COMPLETED" | grep -oE "com\.[a-z0-9._]+" | sort -u)
    JOB_APPS=$(echo "$JOBSCHEDULER_OUTPUT" | grep -oE "com\.[a-z0-9._]+" | sort -u)
    ALARM_APPS=$(echo "$ALARM_OUTPUT" | grep -oE "com\.[a-z0-9._]+" | sort -u)
    WHITELIST_APPS=$(dumpsys deviceidle whitelist 2>/dev/null | grep -oE "com\.[a-z0-9._]+" | sort -u)

    # Find apps appearing in multiple lists
    echo "$BOOT_APPS" | while read app; do
        PERSISTENCE_COUNT=1
        MECHANISMS="BOOT_COMPLETED"
        
        if echo "$JOB_APPS" | grep -q "^${app}$"; then
            PERSISTENCE_COUNT=$((PERSISTENCE_COUNT + 1))
            MECHANISMS="$MECHANISMS, JobScheduler"
        fi
        if echo "$ALARM_APPS" | grep -q "^${app}$"; then
            PERSISTENCE_COUNT=$((PERSISTENCE_COUNT + 1))
            MECHANISMS="$MECHANISMS, AlarmManager"
        fi
        if echo "$WHITELIST_APPS" | grep -q "^${app}$"; then
            PERSISTENCE_COUNT=$((PERSISTENCE_COUNT + 1))
            MECHANISMS="$MECHANISMS, Doze-Exempt"
        fi
        
        if [ "$PERSISTENCE_COUNT" -ge 2 ]; then
            echo "  $app"
            echo "    Mechanisms ($PERSISTENCE_COUNT): $MECHANISMS"
        fi
    done | head -40
    echo ""

    # =========================================================================
    # SECTION 14: Summary
    # =========================================================================
    
    echo "┌─────────────────────────────────────────────────────────────┐"
    echo "│ SCHEDULED TASKS SUMMARY                                    │"
    echo "└─────────────────────────────────────────────────────────────┘"
    echo ""

    # Count various task types
    JOB_TOTAL=$(echo "$JOBSCHEDULER_OUTPUT" | grep -c "JOB\|JobStatus" 2>/dev/null || echo "0")
    ALARM_TOTAL=$(echo "$ALARM_OUTPUT" | grep -c "Alarm\|ELAPSED\|RTC" 2>/dev/null || echo "0")
    BOOT_TOTAL=$(dumpsys package 2>/dev/null | sed -n '/Receiver Resolver Table/,/Service Resolver Table/p' | grep -c "BOOT_COMPLETED" 2>/dev/null || echo "0")
    WHITELIST_TOTAL=$(dumpsys deviceidle whitelist 2>/dev/null | wc -l 2>/dev/null || echo "0")

    echo "Task Statistics:"
    echo "  JobScheduler Jobs:      ~$JOB_TOTAL"
    echo "  AlarmManager Alarms:    ~$ALARM_TOTAL"
    echo "  BOOT_COMPLETED Apps:    ~$BOOT_TOTAL"
    echo "  Doze Whitelist Apps:    ~$WHITELIST_TOTAL"
    echo ""

    echo "Security Implications:"
    echo "  - BOOT_COMPLETED receivers auto-start on boot (persistence)"
    echo "  - Doze-exempt apps can run unrestricted in background"
    echo "  - Repeating alarms may indicate persistent monitoring"
    echo "  - Multiple persistence mechanisms suggest intentional persistence"
    echo ""

    echo "Recommendations:"
    echo "  1. Review apps with multiple persistence mechanisms"
    echo "  2. Audit BOOT_COMPLETED receivers for unknown apps"
    echo "  3. Check Doze whitelist for unnecessary entries"
    echo "  4. Monitor JobScheduler for suspicious recurring jobs"
    echo ""

} > "${OUTPUT_FILE}" 2>&1

echo "[+] Scheduled tasks audit saved to: ${OUTPUT_FILE}"
