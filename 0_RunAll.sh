#!/system/bin/sh
# DROID FORENSIC - 0_RunAll Script
# Executes all forensic collection scripts in this directory
# Usage: sh 0_RunAll.sh [output_directory]

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
OUTPUT_BASE="${1:-/sdcard/DroidForensic/output}"
TIMESTAMP="$(date +%Y%m%d_%H%M%S)"
OUTPUT_DIR="${OUTPUT_BASE}/forensic_${TIMESTAMP}"

echo "╔══════════════════════════════════════════════════════════╗"
echo "║           DROID FORENSIC - Master Collector              ║"
echo "╚══════════════════════════════════════════════════════════╝"
echo ""
echo "[*] Script Directory: ${SCRIPT_DIR}"
echo "[*] Output Directory: ${OUTPUT_DIR}"
echo "[*] Timestamp: ${TIMESTAMP}"
echo ""

# Create output directory
mkdir -p "${OUTPUT_DIR}"
if [ $? -ne 0 ]; then
    echo "[!] ERROR: Failed to create output directory"
    exit 1
fi

# Log file for this run
LOG_FILE="${OUTPUT_DIR}/master.log"
echo "Forensic collection started: $(date)" > "${LOG_FILE}"
echo "Output directory: ${OUTPUT_DIR}" >> "${LOG_FILE}"
echo "" >> "${LOG_FILE}"

# Forensic context declaration
echo "╔══════════════════════════════════════════════════════════╗"
echo "║              FORENSIC CONTEXT DECLARATION                ║"
echo "╚══════════════════════════════════════════════════════════╝"
echo ""
echo "Was ADB enabled on this device BEFORE you connected it?"
echo "  1) YES - ADB was enabled when device was received"
echo "  2) NO  - I enabled ADB to run this toolkit"
echo "  3) UNKNOWN"
echo ""
printf "Enter choice [1/2/3]: "
read ADB_CONTEXT_CHOICE

case "$ADB_CONTEXT_CHOICE" in
    1) ADB_CONTEXT="ENABLED_AT_RECEIPT" ;;
    2) ADB_CONTEXT="ENABLED_BY_ANALYST" ;;
    *) ADB_CONTEXT="UNKNOWN" ;;
esac

# Write context file
CONTEXT_FILE="${OUTPUT_DIR}/forensic_context.txt"
{
    echo "=== FORENSIC COLLECTION CONTEXT ==="
    echo "Timestamp:   $(date)"
    echo "Collector:   $(id)"
    echo "Device:      $(getprop ro.product.model 2>/dev/null) / $(getprop ro.serialno 2>/dev/null)"
    echo "Android:     $(getprop ro.build.version.release 2>/dev/null)"
    echo "Build:       $(getprop ro.build.display.id 2>/dev/null)"
    echo ""
    echo "ADB_CONTEXT: $ADB_CONTEXT"
    case "$ADB_CONTEXT" in
        ENABLED_AT_RECEIPT)
            echo "NOTE: ADB was pre-enabled on this device. ADB-related findings reflect"
            echo "      the device's shipped/received state and carry full evidential weight."
            ;;
        ENABLED_BY_ANALYST)
            echo "NOTE: ADB was enabled by the analyst for this collection. ADB-enabled"
            echo "      findings (adb_enabled=1, etc.) do NOT reflect the device's received"
            echo "      state and should be excluded from ADB-exposure findings."
            ;;
        UNKNOWN)
            echo "NOTE: ADB context unknown. Review ADB-related findings manually."
            ;;
    esac
} > "$CONTEXT_FILE"
echo "[*] Context saved: $CONTEXT_FILE"
echo "[*] ADB context: $ADB_CONTEXT"
echo ""

# Log ADB context to master.log
echo "ADB context: $ADB_CONTEXT" >> "${LOG_FILE}"
echo "" >> "${LOG_FILE}"

# Counter for scripts
TOTAL=0
SUCCESS=0
FAILED=0

# Execute all .sh scripts in directory except 0_RunAll.sh and 99_Zip_Reports.sh
for script in "${SCRIPT_DIR}"/*.sh; do
    script_name="$(basename "$script")"

    # Skip 0_RunAll.sh itself and 99_Zip_Reports.sh (runs last)
    if [ "$script_name" = "0_RunAll.sh" ] || [ "$script_name" = "99_Zip_Reports.sh" ]; then
        continue
    fi

    # Skip if not a regular file
    if [ ! -f "$script" ]; then
        continue
    fi

    TOTAL=$((TOTAL + 1))
    echo "[*] Executing: ${script_name}"
    echo "----------------------------------------" >> "${LOG_FILE}"
    echo "Script: ${script_name}" >> "${LOG_FILE}"
    echo "Start: $(date)" >> "${LOG_FILE}"

    # Execute script with output directory as argument
    sh "$script" "${OUTPUT_DIR}" >> "${LOG_FILE}" 2>&1
    EXIT_CODE=$?

    if [ $EXIT_CODE -eq 0 ]; then
        echo "    [+] Success"
        echo "Status: SUCCESS" >> "${LOG_FILE}"
        SUCCESS=$((SUCCESS + 1))
    else
        echo "    [-] Failed (exit code: ${EXIT_CODE})"
        echo "Status: FAILED (exit code: ${EXIT_CODE})" >> "${LOG_FILE}"
        FAILED=$((FAILED + 1))
    fi

    echo "End: $(date)" >> "${LOG_FILE}"
    echo "" >> "${LOG_FILE}"
done

echo ""
echo "════════════════════════════════════════════════════════════"
echo "[*] Collection Complete"
echo "    Total Scripts: ${TOTAL}"
echo "    Successful:    ${SUCCESS}"
echo "    Failed:        ${FAILED}"
echo "    Output:        ${OUTPUT_DIR}"
echo "════════════════════════════════════════════════════════════"

# Summary to log
echo "════════════════════════════════════════" >> "${LOG_FILE}"
echo "Collection completed: $(date)" >> "${LOG_FILE}"
echo "Total: ${TOTAL}, Success: ${SUCCESS}, Failed: ${FAILED}" >> "${LOG_FILE}"

# Generate manifest of output files
echo ""
echo "[*] Generating file manifest..."
find "${OUTPUT_DIR}" -type f -exec ls -la {} \; > "${OUTPUT_DIR}/manifest.txt" 2>/dev/null

echo "[*] Done."

# Run zip as final step
echo ""
sh "${SCRIPT_DIR}/99_Zip_Reports.sh" "${OUTPUT_DIR}"
