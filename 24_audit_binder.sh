#!/system/bin/sh
# 24_audit_binder.sh — Audit Binder IPC Services and Accessibility
# Android Forensic & Security Audit Toolkit

OUTPUT_DIR="${1:-.}"
OUTPUT_FILE="${OUTPUT_DIR}/audit_binder.txt"

echo "[*] Auditing Binder IPC services..."

{
	echo "╔════════════════════════════════════════════════════════════════════════╗"
	echo "║              BINDER IPC SERVICES & ACCESSIBILITY AUDIT                 ║"
	echo "╚════════════════════════════════════════════════════════════════════════╝"
	echo ""
	echo "=== SECTION: BINDER OVERVIEW ==="
	echo ""
	echo "Binder is Android's primary IPC mechanism. Services registered with"
	echo "servicemanager are accessible to callers with appropriate SELinux"
	echo "permissions. Vendor services often have weaker access controls."
	echo ""
	echo "--- Binder Device Permissions ---"
	ls -la /dev/binder /dev/hwbinder /dev/vndbinder 2>/dev/null || echo "[!] Binder devices not accessible"
	echo ""
	echo "--- SELinux Context (Binder Devices) ---"
	ls -lZ /dev/binder 2>/dev/null | grep -o 'u:object_r:[^ ]*' || echo "[!] Unable to read SELinux context"
	ls -lZ /dev/hwbinder 2>/dev/null | grep -o 'u:object_r:[^ ]*' || echo "[!] /dev/hwbinder SELinux context unavailable"
	ls -lZ /dev/vndbinder 2>/dev/null | grep -o 'u:object_r:[^ ]*' || echo "[!] /dev/vndbinder SELinux context unavailable"
	echo ""
	echo ""
	echo "=== SECTION: ALL REGISTERED SERVICES ==="
	echo ""
	service_count=$(service list 2>/dev/null | wc -l)
	echo "Total registered services: ${service_count}"
	echo ""
	echo "--- Full Service List ---"
	service list 2>/dev/null || echo "[!] service list command unavailable"
	echo ""
	echo ""
	echo "=== SECTION: HIGH-VALUE SERVICE TARGETS ==="
	echo ""
	echo "Checking for critical system services..."
	echo ""

	# Define high-value service targets
	targets="activity package permission user device_policy backup dropbox appops clipboard input window power batterystats"

	for target in ${targets}; do
		result=$(service check "${target}" 2>/dev/null)
		if [ -n "${result}" ]; then
			echo "[+] ${target}: ${result}"
		else
			echo "[-] ${target}: NOT FOUND or INACCESSIBLE"
		fi
	done

	echo ""
	echo "--- Additional Dumpsys Accessible Services ---"
	dumpsys 2>/dev/null | grep -E '^\w+:$' | head -20 || echo "[!] dumpsys service list unavailable"
	echo ""
	echo ""
	echo "=== SECTION: VENDOR SERVICES [HIGH PRIORITY] ==="
	echo ""
	echo "Filtering for vendor-specific services (vendor.*, hal.*, hw.* prefixes)..."
	echo ""
	vendor_count=$(service list 2>/dev/null | grep -E 'vendor\.|hal\.|hw\.' | wc -l)
	echo "Vendor services found: ${vendor_count}"
	echo ""

	if [ "${vendor_count}" -gt 0 ]; then
		echo "--- Vendor Service List ---"
		service list 2>/dev/null | grep -E 'vendor\.|hal\.|hw\.'
		echo ""
		echo "[CRITICAL] Vendor services detected. These often lack strict SELinux controls."
	else
		echo "[-] No vendor services detected in this enumeration."
	fi
	echo ""
	echo ""
	echo "=== SECTION: HARDWARE ABSTRACTION LAYER (HAL) SERVICES ==="
	echo ""
	echo "Searching for HAL service interfaces..."
	echo ""
	dumpsys 2>/dev/null | grep -i 'hal\|hardware' | head -30 || echo "[!] HAL enumeration failed"
	echo ""
	echo "--- /dev/hwbinder Accessibility ---"
	test -r /dev/hwbinder 2>/dev/null && echo "[+] /dev/hwbinder is readable" || echo "[-] /dev/hwbinder not readable"
	test -w /dev/hwbinder 2>/dev/null && echo "[CRITICAL] /dev/hwbinder is WRITABLE" || echo "[OK] /dev/hwbinder not writable"
	echo ""
	echo ""
	echo "=== SECTION: ACCESSIBLE DUMPSYS OUTPUTS ==="
	echo ""
	echo "Testing dumpsys accessibility for key services..."
	echo ""

	echo "--- Activity Manager ---"
	if dumpsys activity 2>/dev/null | head -1 | grep -q .; then
		echo "[+] Activity output accessible (first 20 lines):"
		dumpsys activity 2>/dev/null | head -20
	else
		echo "[-] Activity Manager not accessible"
	fi
	echo ""

	echo "--- Package Manager ---"
	if dumpsys package 2>/dev/null | head -1 | grep -q .; then
		echo "[+] Package output accessible (first 5 lines):"
		dumpsys package 2>/dev/null | head -5
	else
		echo "[-] Package Manager not accessible"
	fi
	echo ""

	echo "--- Battery Stats ---"
	if dumpsys batterystats 2>/dev/null | head -1 | grep -q .; then
		echo "[+] BatteryStats output accessible (first 10 lines):"
		dumpsys batterystats 2>/dev/null | head -10
	else
		echo "[-] BatteryStats not accessible"
	fi
	echo ""

	echo "--- Clipboard Service [HIGH RISK] ---"
	if dumpsys clipboard 2>/dev/null | head -1 | grep -q .; then
		echo "[HIGH] Clipboard output accessible (first 10 lines):"
		dumpsys clipboard 2>/dev/null | head -10
	else
		echo "[OK] Clipboard not accessible"
	fi
	echo ""

	echo "--- Dropbox (Crash/Event Logs) [HIGH RISK] ---"
	if dumpsys dropbox 2>/dev/null | head -1 | grep -q .; then
		echo "[HIGH] Dropbox output accessible (first 20 lines):"
		dumpsys dropbox 2>/dev/null | head -20
	else
		echo "[OK] Dropbox not accessible"
	fi
	echo ""
	echo ""
	echo "=== SECTION: /proc/binder STATISTICS ==="
	echo ""

	if [ -d /proc/binder ]; then
		echo "[+] /proc/binder directory exists"
		echo ""
		echo "--- /proc/binder Contents ---"
		ls /proc/binder/ 2>/dev/null || echo "[!] Unable to list /proc/binder"
		echo ""

		echo "--- Binder Statistics ---"
		if [ -f /proc/binder/stats ]; then
			echo "[+] /proc/binder/stats (first 30 lines):"
			cat /proc/binder/stats 2>/dev/null | head -30
		else
			echo "[-] /proc/binder/stats not readable"
		fi
		echo ""

		echo "--- Binder State ---"
		if [ -f /proc/binder/state ]; then
			echo "[+] /proc/binder/state (first 50 lines):"
			cat /proc/binder/state 2>/dev/null | head -50
		else
			echo "[-] /proc/binder/state not readable"
		fi
	else
		echo "[-] /proc/binder directory not found"
	fi
	echo ""
	echo ""
	echo ""
	echo "=== SECTION: HIDL/LSHAL ENUMERATION ==="
	echo ""
	echo "Hardware Abstraction Layer (HAL) services registered via hwservicemanager."
	echo ""
	if command -v lshal >/dev/null 2>&1; then
		lshal_out=$(lshal 2>/dev/null)
		hal_count=$(echo "${lshal_out}" | grep -c "@" 2>/dev/null || echo 0)
		echo "Total HAL interfaces: ${hal_count}"
		echo ""
		echo "--- Full lshal Output (first 80 lines) ---"
		echo "${lshal_out}" | head -80
		echo ""
		echo "--- Security HALs ---"
		echo "${lshal_out}" | grep -iE "keymaster|keymint|gatekeeper|weaver|oemlock|secureclock|identity|confirmationui"
		echo ""
		echo "--- Biometric HALs [HIGH] ---"
		bio_hals=$(echo "${lshal_out}" | grep -iE "biometric|fingerprint|face|iris")
		if [ -n "${bio_hals}" ]; then
			echo "[HIGH] Biometric HALs present:"
			echo "${bio_hals}"
		else
			echo "[-] No biometric HALs found"
		fi
		echo ""
		echo "--- DRM / Content Protection HALs [HIGH] ---"
		drm_hals=$(echo "${lshal_out}" | grep -iE "drm|clearkey|widevine|playready|hdcp")
		if [ -n "${drm_hals}" ]; then
			echo "[HIGH] DRM/content-protection HALs present — key material may be accessible:"
			echo "${drm_hals}"
		else
			echo "[-] No DRM HALs found"
		fi
		echo ""
		echo "--- Connectivity HALs ---"
		echo "${lshal_out}" | grep -iE "wifi|bluetooth|nfc|radio|ril|gnss|gps"
		echo ""
		echo "--- Vendor-Specific HALs ---"
		echo "${lshal_out}" | grep -iE "vendor\\.|oem\\." | head -20
		echo ""
		passthrough_count=$(echo "${lshal_out}" | grep -ic "passthrough" 2>/dev/null || echo 0)
		binderized_count=$(echo "${lshal_out}" | grep -icE "hwbinder|binderized" 2>/dev/null || echo 0)
		echo "HAL implementation types — passthrough: ${passthrough_count}  binderized: ${binderized_count}"
		echo "[INFO] Passthrough HALs run in the client process and bypass some SELinux boundaries."
	else
		echo "[INFO] lshal not available — falling back to hwservicemanager dumpsys"
		dumpsys hwservicemanager 2>/dev/null | head -50 || echo "[!] hwservicemanager not accessible"
	fi
	echo ""
	echo ""
	echo "=== SECTION: AIDL SERVICES (SENSITIVE) ==="
	echo ""
	echo "AIDL services registered with servicemanager. Cross-referencing known"
	echo "security-sensitive service names."
	echo ""
	echo "--- All Services from service list ---"
	service list 2>/dev/null | head -100 || echo "[!] service list unavailable"
	echo ""
	sensitive_services="android.system.keystore2 android.hardware.keymaster android.hardware.keymint android.hardware.gatekeeper android.hardware.biometrics.fingerprint android.hardware.biometrics.face android.hardware.biometrics android.security.keystore android.service.gatekeeper"
	echo "--- Cross-reference: Known Sensitive AIDL Services ---"
	for ss in ${sensitive_services}; do
		hit=$(service list 2>/dev/null | grep "${ss}")
		if [ -n "${hit}" ]; then
			echo "[HIGH] FOUND: ${hit}"
		fi
	done
	echo ""
	echo "--- Debug/Factory/Test Services [HIGH] ---"
	debug_svcs=$(service list 2>/dev/null | grep -iE "debug|test|diag|eng|factory")
	if [ -n "${debug_svcs}" ]; then
		echo "[HIGH] Debug/factory services detected:"
		echo "${debug_svcs}"
	else
		echo "[OK] No debug/factory services found"
	fi
	echo ""
	echo ""
	echo "=== SECTION: SERVICE-TO-PROCESS MAPPING ==="
	echo ""
	echo "Mapping key security services to their hosting PID and UID."
	echo ""
	echo "--- system_server (hosts most AIDL services) ---"
	ps -A 2>/dev/null | grep system_server || echo "[!] system_server not found in ps output"
	echo ""
	echo "--- servicemanager / hwservicemanager / vndservicemanager ---"
	ps -A 2>/dev/null | grep -E "servicemanager" || echo "[!] servicemanager processes not found"
	echo ""
	echo "--- android.system.keystore2 process ---"
	ps -A 2>/dev/null | grep -iE "keystore|keystored" | head -5 || echo "[-] keystore process not visible"
	echo ""
	echo "--- android.hardware.gatekeeper ---"
	ps -A 2>/dev/null | grep -iE "gatekeeper" | head -5 || echo "[-] gatekeeper process not visible"
	echo ""
	echo "--- android.hardware.biometrics.* ---"
	ps -A 2>/dev/null | grep -iE "biometric|fingerprint|face" | head -10 || echo "[-] biometric processes not visible"
	echo ""
	echo "--- DRM HAL processes ---"
	ps -A 2>/dev/null | grep -iE "drmserver|drm\\." | head -5 || echo "[-] DRM server process not visible"
	echo ""
	echo "--- Allwinner / vendor TEE processes ---"
	ps -A 2>/dev/null | grep -iE "tee|supplicant|keymint|keymaster" | head -10 || echo "[-] No TEE/keymint processes visible"
	echo ""
	echo ""
	echo "=== SECTION: SELINUX BINDER SERVICE CONTEXTS ==="
	echo ""
	echo "SELinux maps service names to security domains via service_contexts files."
	echo "Services in overly broad domains (e.g. system_server, vendor_init, init)"
	echo "may allow privilege escalation via Binder."
	echo ""
	for ctx_file in /system/etc/selinux/plat_service_contexts /vendor/etc/selinux/vndservice_contexts /vendor/etc/selinux/vendor_service_contexts; do
		if [ -f "${ctx_file}" ]; then
			echo "--- ${ctx_file} ---"
			cat "${ctx_file}" 2>/dev/null | head -80
			echo ""
			echo "  Overly broad domains in ${ctx_file}:"
			grep -E "u:object_r:(system_server|vendor_init|init|su|shell)_service" "${ctx_file}" 2>/dev/null \
				| while IFS= read -r line; do echo "  [HIGH] ${line}"; done
			echo ""
		else
			echo "[-] ${ctx_file} not found"
		fi
	done
	echo ""
	echo ""
	echo "=== SECTION: DETAILED DUMPSYS — HIGH-VALUE SERVICES ==="
	echo ""
	echo "Collecting dumpsys output for high-value services not covered above."
	echo "These services expose sensitive system state and are common audit targets."
	echo ""

	echo "--- Permission Manager [HIGH] ---"
	if dumpsys permission 2>/dev/null | head -1 | grep -q .; then
		echo "[HIGH] permission service accessible (first 30 lines):"
		dumpsys permission 2>/dev/null | head -30
	else
		echo "[OK] permission service not accessible from shell"
	fi
	echo ""

	echo "--- User Manager [HIGH] ---"
	if dumpsys user 2>/dev/null | head -1 | grep -q .; then
		echo "[HIGH] user service accessible (first 20 lines):"
		dumpsys user 2>/dev/null | head -20
	else
		echo "[OK] user service not accessible from shell"
	fi
	echo ""

	echo "--- Device Policy Manager [CRITICAL] ---"
	if dumpsys device_policy 2>/dev/null | head -1 | grep -q .; then
		echo "[CRITICAL] device_policy service accessible (first 30 lines):"
		dumpsys device_policy 2>/dev/null | head -30
	else
		echo "[OK] device_policy service not accessible from shell"
	fi
	echo ""

	echo "--- Backup Manager [HIGH] ---"
	if dumpsys backup 2>/dev/null | head -1 | grep -q .; then
		echo "[HIGH] backup service accessible (first 20 lines):"
		dumpsys backup 2>/dev/null | head -20
	else
		echo "[OK] backup service not accessible from shell"
	fi
	echo ""

	echo "--- App Ops [HIGH] ---"
	if dumpsys appops 2>/dev/null | head -1 | grep -q .; then
		echo "[HIGH] appops service accessible (first 30 lines):"
		dumpsys appops 2>/dev/null | head -30
	else
		echo "[OK] appops service not accessible from shell"
	fi
	echo ""

	echo "--- Input Manager [MEDIUM] ---"
	if dumpsys input 2>/dev/null | head -1 | grep -q .; then
		echo "[MEDIUM] input service accessible (first 20 lines):"
		dumpsys input 2>/dev/null | head -20
	else
		echo "[OK] input service not accessible from shell"
	fi
	echo ""

	echo "--- Window Manager [MEDIUM] ---"
	if dumpsys window 2>/dev/null | head -1 | grep -q .; then
		echo "[MEDIUM] window service accessible (first 20 lines):"
		dumpsys window 2>/dev/null | head -20
	else
		echo "[OK] window service not accessible from shell"
	fi
	echo ""

	echo "--- Power Manager [MEDIUM] ---"
	if dumpsys power 2>/dev/null | head -1 | grep -q .; then
		echo "[MEDIUM] power service accessible (first 20 lines):"
		dumpsys power 2>/dev/null | head -20
	else
		echo "[OK] power service not accessible from shell"
	fi
	echo ""
	echo ""
	echo "=== SECTION: SUSPICIOUS SERVICE NAMES ==="
	echo ""
	echo "Scanning service list for names associated with factory, diagnostic,"
	echo "root-access, or injection functionality."
	echo ""

	echo "--- Services with Exploit/Injection Keywords [CRITICAL] ---"
	suspicious_svcs=$(service list 2>/dev/null | grep -iE "backdoor|root|su|shell|exec|inject|hook|patch")
	if [ -n "${suspicious_svcs}" ]; then
		echo "[CRITICAL] Suspicious service names detected:"
		echo "${suspicious_svcs}"
	else
		echo "[OK] No services with exploit/injection keywords found"
	fi
	echo ""

	echo "--- Services with Vendor/OEM Prefixes (format-filtered) [HIGH] ---"
	vendor_prefix_svcs=$(service list 2>/dev/null | grep -iE "^[0-9]+[[:space:]]+(vendor\.|oem\.|qcom\.|qti\.|mtk\.|sec\.|samsung\.|huawei\.|xiaomi\.)")
	if [ -n "${vendor_prefix_svcs}" ]; then
		echo "[HIGH] Services with OEM-format vendor prefixes:"
		echo "${vendor_prefix_svcs}"
	else
		echo "[-] No OEM-format vendor-prefixed services found"
	fi
	echo ""
	echo ""
	echo "=== SECTION: SERVICE CALL ACCESSIBILITY TEST ==="
	echo ""
	echo "Attempting 'service call <name> 1' on registered services to identify"
	echo "which Binder interfaces are callable from the shell context (UID=2000)."
	echo "Services that respond without permission/security errors are flagged."
	echo ""
	echo "[INFO] Testing first 50 registered services..."
	echo ""

	svc_list=$(service list 2>/dev/null | head -50 | awk -F: '{print $1}' | awk '{print $2}')
	found_accessible=0
	for svc in ${svc_list}; do
		if [ -n "${svc}" ]; then
			call_result=$(service call "${svc}" 1 2>&1)
			if ! echo "${call_result}" | grep -qiE "permission|security|denied|exception|error"; then
				echo "[HIGH] ACCESSIBLE: ${svc}"
				found_accessible=1
			fi
		fi
	done
	if [ "${found_accessible}" -eq 0 ]; then
		echo "[OK] No services responded without permission errors"
	fi
	echo ""
	echo ""
		echo "╔════════════════════════════════════════════════════════════════════════╗"
	echo "║                         AUDIT SUMMARY                                  ║"
	echo "╚════════════════════════════════════════════════════════════════════════╝"
	echo ""
	echo "Total services registered:  ${service_count}"
	echo "Vendor services detected:   ${vendor_count}"
	echo ""
	echo "Risk Assessment:"
	echo "  - Review vendor services for weak SELinux enforcement"
	echo "  - Monitor access to high-value services (activity, package, device_policy)"
	echo "  - Check /proc/binder/stats for transaction volume anomalies"
	echo "  - Verify binder device permissions are restrictive (typically 0660)"
	echo "  - Investigate any services flagged as accessible via 'service call' test"
	echo "  - Escalate any services found with exploit/injection keywords"
	echo ""
	echo "For detailed Binder transaction analysis, use: adb shell dumpsys activity"
	echo ""

} > "${OUTPUT_FILE}" 2>&1

echo "[+] Binder audit saved to: ${OUTPUT_FILE}"
