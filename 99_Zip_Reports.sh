#!/system/bin/sh
# 99_Zip_Reports.sh — Archive forensic output for transfer
# Attempts zip, then tar+gz, then tar — exits gracefully if no tool available
# Usage: sh 99_Zip_Reports.sh <output_directory>

OUTPUT_DIR="${1:-.}"
PARENT_DIR="$(dirname "${OUTPUT_DIR}")"
DIRNAME="$(basename "${OUTPUT_DIR}")"
ARCHIVE_BASE="${PARENT_DIR}/${DIRNAME}"

echo "[*] 99_Zip_Reports: Attempting to archive ${OUTPUT_DIR}..."

# Probe for available archive tools
_zip_tool=""
_zip_ext=""

if command -v zip >/dev/null 2>&1; then
    _zip_tool="zip"
    _zip_ext="zip"
elif busybox zip --help >/dev/null 2>&1; then
    _zip_tool="busybox zip"
    _zip_ext="zip"
elif command -v tar >/dev/null 2>&1 && tar --help 2>&1 | grep -q "gzip\|z"; then
    _zip_tool="tar_gz"
    _zip_ext="tar.gz"
elif busybox tar --help >/dev/null 2>&1 && busybox tar --help 2>&1 | grep -q "gzip\|z"; then
    _zip_tool="busybox_tar_gz"
    _zip_ext="tar.gz"
elif command -v tar >/dev/null 2>&1; then
    _zip_tool="tar"
    _zip_ext="tar"
elif busybox tar --help >/dev/null 2>&1; then
    _zip_tool="busybox_tar"
    _zip_ext="tar"
fi

if [ -z "${_zip_tool}" ]; then
    echo "[INFO] 99_Zip_Reports: No supported archive tool found (zip/tar/busybox)."
    echo "[INFO] Reports remain unarchived at: ${OUTPUT_DIR}"
    echo "[INFO] Transfer the directory manually."
    exit 0
fi

ARCHIVE="${ARCHIVE_BASE}.${_zip_ext}"

case "${_zip_tool}" in
    zip)
        zip -r "${ARCHIVE}" "${OUTPUT_DIR}" >/dev/null 2>&1
        ;;
    "busybox zip")
        busybox zip -r "${ARCHIVE}" "${OUTPUT_DIR}" >/dev/null 2>&1
        ;;
    tar_gz)
        tar -czf "${ARCHIVE}" -C "${PARENT_DIR}" "${DIRNAME}" 2>/dev/null
        ;;
    busybox_tar_gz)
        busybox tar -czf "${ARCHIVE}" -C "${PARENT_DIR}" "${DIRNAME}" 2>/dev/null
        ;;
    tar)
        tar -cf "${ARCHIVE}" -C "${PARENT_DIR}" "${DIRNAME}" 2>/dev/null
        ;;
    busybox_tar)
        busybox tar -cf "${ARCHIVE}" -C "${PARENT_DIR}" "${DIRNAME}" 2>/dev/null
        ;;
esac

if [ $? -eq 0 ] && [ -f "${ARCHIVE}" ]; then
    ARCHIVE_SIZE=$(ls -la "${ARCHIVE}" 2>/dev/null | awk '{print $5}')
    echo "[+] Archive created: ${ARCHIVE} (${ARCHIVE_SIZE} bytes)"
    echo "[INFO] Transfer this file: ${ARCHIVE}"
else
    echo "[INFO] 99_Zip_Reports: Archive creation failed or produced empty file."
    echo "[INFO] Tool attempted: ${_zip_tool}"
    echo "[INFO] Reports remain at: ${OUTPUT_DIR}"
fi

exit 0
