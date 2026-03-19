#!/system/bin/sh
# 07_audit_kernel.sh - Kernel security audit and hardening assessment
# Android forensic & security audit toolkit
# POSIX sh only, no bashisms

OUTPUT_DIR="${1:-.}"
OUTPUT_FILE="${OUTPUT_DIR}/audit_kernel.txt"

echo "[*] Auditing kernel security..."

{
	echo "╔════════════════════════════════════════════════════════════╗"
	echo "║         KERNEL SECURITY AUDIT AND HARDENING CHECK          ║"
	echo "╚════════════════════════════════════════════════════════════╝"
	echo ""
	echo "═══════════════════════════════════════════════════════════════"
	echo "SECTION: KERNEL VERSION"
	echo "═══════════════════════════════════════════════════════════════"
	echo ""
	echo "[*] Full kernel version info:"
	uname -a 2>/dev/null || echo "[ERROR] uname failed"
	echo ""
	echo "[*] /proc/version:"
	cat /proc/version 2>/dev/null || echo "[ERROR] /proc/version not accessible"
	echo ""

	# Parse kernel version number
	kernel_version=$(uname -r 2>/dev/null | cut -d. -f1,2)
	if [ -n "$kernel_version" ]; then
		echo "[*] Parsed kernel version: $kernel_version"
		# Check for kernel older than 5.10 on Android 14+
		major=$(uname -r 2>/dev/null | cut -d. -f1)
		minor=$(uname -r 2>/dev/null | cut -d. -f2)
		if [ "$major" -lt 5 ] || ([ "$major" -eq 5 ] && [ "$minor" -lt 10 ]); then
			echo "[MEDIUM] Kernel version $major.$minor is older than 5.10 LTS — EOL risk, consider updating"
		fi
	fi
	echo ""

	echo "═══════════════════════════════════════════════════════════════"
	echo "SECTION: KERNEL CONFIGURATION EXPOSURE"
	echo "═══════════════════════════════════════════════════════════════"
	echo ""
	if [ -r /proc/config.gz ]; then
		echo "[HIGH] /proc/config.gz is readable — attacker can extract full kernel config"
		echo ""
		echo "[*] Security-relevant kernel config options:"
		zcat /proc/config.gz 2>/dev/null | grep -E "CONFIG_SECURITY|CONFIG_MODULES|CONFIG_KALLSYMS|CONFIG_DEVMEM|CONFIG_STRICT_DEVMEM|CONFIG_ANDROID_PARANOID_NETWORK|CONFIG_HAVE_ARCH_SECCOMP|CONFIG_SECCOMP" | head -30 || echo "[ERROR] Failed to extract config"
	elif [ -f /proc/config.gz ]; then
		echo "[HIGH] /proc/config.gz exists but not readable (permission denied)"
	else
		echo "[OK] /proc/config.gz not readable or not present"
	fi
	echo ""

	echo "═══════════════════════════════════════════════════════════════"
	echo "SECTION: KASLR / SYMBOL EXPOSURE"
	echo "═══════════════════════════════════════════════════════════════"
	echo ""
	echo "[*] First 5 entries in /proc/kallsyms:"
	head -5 /proc/kallsyms 2>/dev/null || echo "[ERROR] /proc/kallsyms not accessible"
	echo ""

	# Check if KASLR is effective by examining if addresses are non-zero
	kallsyms_sample=$(head -1 /proc/kallsyms 2>/dev/null | awk '{print $1}')
	if [ -n "$kallsyms_sample" ]; then
		if [ "$kallsyms_sample" = "0000000000000000" ]; then
			echo "[OK] Kernel symbols are zero-masked — kptr_restrict is working (KASLR protected)"
		else
			echo "[HIGH] Kernel symbols visible in /proc/kallsyms — KASLR is ineffective for this user"
		fi
	fi
	echo ""

	echo "[*] /proc/kcore accessibility:"
	if [ -r /proc/kcore ]; then
		echo "[HIGH] /proc/kcore is readable — kernel memory can be accessed"
	else
		echo "[OK] /proc/kcore is not readable"
	fi
	echo ""

	echo "═══════════════════════════════════════════════════════════════"
	echo "SECTION: KERNEL HARDENING SETTINGS"
	echo "═══════════════════════════════════════════════════════════════"
	echo ""

	# kptr_restrict
	echo "[*] /proc/sys/kernel/kptr_restrict:"
	kptr=$(cat /proc/sys/kernel/kptr_restrict 2>/dev/null)
	echo "    Value: $kptr"
	case "$kptr" in
		0) echo "    [CRITICAL] kptr_restrict=0 — kernel pointers are exposed (exploitable)" ;;
		1) echo "    [MEDIUM] kptr_restrict=1 — kernel pointers hidden from unprivileged users" ;;
		2) echo "    [OK] kptr_restrict=2 — kernel pointers hidden from all non-root" ;;
		*) echo "    [INFO] Unknown or unset" ;;
	esac
	echo ""

	# dmesg_restrict
	echo "[*] /proc/sys/kernel/dmesg_restrict:"
	dmesg_restrict=$(cat /proc/sys/kernel/dmesg_restrict 2>/dev/null)
	echo "    Value: $dmesg_restrict"
	case "$dmesg_restrict" in
		0) echo "    [MEDIUM] dmesg_restrict=0 — anyone can read kernel ring buffer" ;;
		1) echo "    [OK] dmesg_restrict=1 — only root can read dmesg" ;;
		*) echo "    [INFO] Unknown or unset" ;;
	esac
	echo ""

	# perf_event_paranoid
	echo "[*] /proc/sys/kernel/perf_event_paranoid:"
	perf=$(cat /proc/sys/kernel/perf_event_paranoid 2>/dev/null)
	echo "    Value: $perf"
	case "$perf" in
		-1) echo "    [HIGH] perf_event_paranoid=-1 — unrestricted performance monitoring (unprivileged)" ;;
		0) echo "    [MEDIUM] perf_event_paranoid=0 — basic access to performance monitoring" ;;
		1) echo "    [INFO] perf_event_paranoid=1 — restricted to own processes" ;;
		2) echo "    [OK] perf_event_paranoid=2 — restricted to kernel and admin" ;;
		3) echo "    [OK] perf_event_paranoid=3 — admin-only" ;;
		*) echo "    [INFO] Unknown or unset" ;;
	esac
	echo ""

	# randomize_va_space (ASLR)
	echo "[*] /proc/sys/kernel/randomize_va_space (ASLR):"
	aslr=$(cat /proc/sys/kernel/randomize_va_space 2>/dev/null)
	echo "    Value: $aslr"
	case "$aslr" in
		0) echo "    [CRITICAL] randomize_va_space=0 — ASLR disabled (highly exploitable)" ;;
		1) echo "    [MEDIUM] randomize_va_space=1 — conservative randomization" ;;
		2) echo "    [OK] randomize_va_space=2 — full ASLR enabled" ;;
		*) echo "    [INFO] Unknown or unset" ;;
	esac
	echo ""

	# yama/ptrace_scope (if exists)
	echo "[*] /proc/sys/kernel/yama/ptrace_scope:"
	if [ -r /proc/sys/kernel/yama/ptrace_scope ]; then
		ptrace=$(cat /proc/sys/kernel/yama/ptrace_scope 2>/dev/null)
		echo "    Value: $ptrace"
		case "$ptrace" in
			0) echo "    [HIGH] ptrace_scope=0 — any process can ptrace any other (unrestricted)" ;;
			1) echo "    [OK] ptrace_scope=1 — can only ptrace children" ;;
			2) echo "    [HIGH] ptrace_scope=2 — ptrace restricted to admin" ;;
			3) echo "    [OK] ptrace_scope=3 — ptrace completely disabled" ;;
			*) echo "    [INFO] Unknown value" ;;
		esac
	else
		echo "    [INFO] yama ptrace_scope not available (not built in kernel)"
	fi
	echo ""

	# unprivileged_bpf_disabled (if exists)
	echo "[*] /proc/sys/kernel/unprivileged_bpf_disabled:"
	if [ -r /proc/sys/kernel/unprivileged_bpf_disabled ]; then
		bpf=$(cat /proc/sys/kernel/unprivileged_bpf_disabled 2>/dev/null)
		echo "    Value: $bpf"
		if [ "$bpf" = "1" ]; then
			echo "    [OK] Unprivileged eBPF disabled"
		else
			echo "    [MEDIUM] Unprivileged eBPF may be enabled (potential exploit vector)"
		fi
	else
		echo "    [INFO] unprivileged_bpf_disabled not available"
	fi
	echo ""

	# sysrq
	echo "[*] /proc/sys/kernel/sysrq:"
	sysrq=$(cat /proc/sys/kernel/sysrq 2>/dev/null)
	echo "    Value: $sysrq"
	if [ "$sysrq" = "0" ]; then
		echo "    [OK] SysRq disabled"
	elif [ -z "$sysrq" ]; then
		echo "    [INFO] Not accessible"
	else
		echo "    [MEDIUM] SysRq enabled (value: $sysrq) — allows direct kernel manipulation from console"
	fi
	echo ""

	echo "═══════════════════════════════════════════════════════════════"
	echo "SECTION: MEMORY PROTECTIONS"
	echo "═══════════════════════════════════════════════════════════════"
	echo ""

	# mmap_min_addr
	echo "[*] /proc/sys/vm/mmap_min_addr (NULL pointer dereference protection):"
	mmap_min=$(cat /proc/sys/vm/mmap_min_addr 2>/dev/null)
	echo "    Value: $mmap_min"
	if [ "$mmap_min" = "0" ]; then
		echo "    [CRITICAL] mmap_min_addr=0 — NULL pointer dereference exploitable"
	elif [ -n "$mmap_min" ]; then
		echo "    [OK] mmap_min_addr=$mmap_min — NULL dereference protection enabled"
	else
		echo "    [INFO] Not accessible"
	fi
	echo ""

	# mmap_rnd_bits
	echo "[*] /proc/sys/vm/mmap_rnd_bits (ASLR bits for memory mapping):"
	if [ -r /proc/sys/vm/mmap_rnd_bits ]; then
		mmap_rnd=$(cat /proc/sys/vm/mmap_rnd_bits 2>/dev/null)
		echo "    Value: $mmap_rnd bits"
		if [ "$mmap_rnd" -ge 16 ]; then
			echo "    [OK] Strong ASLR entropy ($mmap_rnd bits)"
		else
			echo "    [MEDIUM] Weak ASLR entropy ($mmap_rnd bits)"
		fi
	else
		echo "    [INFO] Not available"
	fi
	echo ""

	# mmap_rnd_compat_bits
	echo "[*] /proc/sys/vm/mmap_rnd_compat_bits (32-bit ASLR):"
	if [ -r /proc/sys/vm/mmap_rnd_compat_bits ]; then
		mmap_compat=$(cat /proc/sys/vm/mmap_rnd_compat_bits 2>/dev/null)
		echo "    Value: $mmap_compat bits"
	else
		echo "    [INFO] Not available (64-bit system or not supported)"
	fi
	echo ""

	# exec-shield
	echo "[*] /proc/sys/kernel/exec-shield (if present):"
	if [ -r /proc/sys/kernel/exec-shield ]; then
		exec_shield=$(cat /proc/sys/kernel/exec-shield 2>/dev/null)
		echo "    Value: $exec_shield"
		if [ "$exec_shield" = "1" ]; then
			echo "    [OK] Exec-shield enabled (DEP/NX protection)"
		fi
	else
		echo "    [INFO] Not available (likely ARM64 without x86 compatibility)"
	fi
	echo ""

	echo "═══════════════════════════════════════════════════════════════"
	echo "SECTION: LOADED KERNEL MODULES"
	echo "═══════════════════════════════════════════════════════════════"
	echo ""

	if [ -r /proc/modules ]; then
		module_count=$(wc -l < /proc/modules 2>/dev/null)
		echo "[*] Total kernel modules loaded: $module_count"
		echo ""
		echo "[*] Module list (name, size, count, dependencies, state):"
		cat /proc/modules 2>/dev/null || echo "[ERROR] Failed to read /proc/modules"
		echo ""

		# Check for non-Live modules
		non_live=$(grep -v " Live" /proc/modules 2>/dev/null | wc -l)
		if [ "$non_live" -gt 0 ]; then
			echo "[MEDIUM] Found $non_live module(s) not in Live state (may be unloading or in error)"
		fi

		echo ""
		echo "[*] Suspicious module name scan (rootkit/hook/inject indicators):"
		suspicious_mods=$(grep -iE "rootkit|hide|hook|inject|backdoor|keylog" /proc/modules 2>/dev/null)
		if [ -n "$suspicious_mods" ]; then
			echo "[CRITICAL] Suspicious module names detected:"
			echo "$suspicious_mods"
		else
			echo "[OK] No obviously suspicious module names detected"
		fi
		echo ""

		echo "[*] Root/jailbreak-related modules (magisk/ksu/supersu/su):"
		root_mods=$(grep -iE "\bsu\b|magisk|supersu|ksu|kernelsu" /proc/modules 2>/dev/null)
		if [ -n "$root_mods" ]; then
			echo "[HIGH] Root-related modules found:"
			echo "$root_mods"
		else
			echo "[OK] No root-related module names detected"
		fi
	else
		echo "[INFO] /proc/modules not readable (kernel modules may not be enabled, or permission denied)"
	fi
	echo ""

	echo "═══════════════════════════════════════════════════════════════"
	echo "SECTION: KERNEL TAINT FLAGS"
	echo "═══════════════════════════════════════════════════════════════"
	echo ""

	tainted=$(cat /proc/sys/kernel/tainted 2>/dev/null)
	echo "[*] Kernel taint value: $tainted"
	echo ""

	if [ "$tainted" = "0" ] || [ -z "$tainted" ]; then
		echo "[OK] Kernel is not tainted"
	else
		echo "[*] Kernel taint flags set:"
		# Decode taint bits
		taint_num=$tainted
		taint_list=""

		test $((taint_num & 1)) -ne 0 && taint_list="$taint_list[1=proprietary module]"
		test $((taint_num & 2)) -ne 0 && taint_list="$taint_list[2=forced module]"
		test $((taint_num & 4)) -ne 0 && taint_list="$taint_list[4=SMP unsafe]"
		test $((taint_num & 8)) -ne 0 && taint_list="$taint_list[8=forced rmmod]"
		test $((taint_num & 16)) -ne 0 && taint_list="$taint_list[16=machine check]"
		test $((taint_num & 32)) -ne 0 && taint_list="$taint_list[32=bad page]"
		test $((taint_num & 64)) -ne 0 && taint_list="$taint_list[64=user taint]"
		test $((taint_num & 128)) -ne 0 && taint_list="$taint_list[128=die]"
		test $((taint_num & 256)) -ne 0 && taint_list="$taint_list[256=ACPI override]"
		test $((taint_num & 512)) -ne 0 && taint_list="$taint_list[512=warned]"
		test $((taint_num & 1024)) -ne 0 && taint_list="$taint_list[1024=STAGING driver]"
		test $((taint_num & 2048)) -ne 0 && taint_list="$taint_list[2048=firmware workaround]"
		test $((taint_num & 4096)) -ne 0 && taint_list="$taint_list[4096=out-of-tree module]"

		if [ -n "$taint_list" ]; then
			echo "$taint_list" | tr '[' '\n' | grep -v "^$"
		fi
	fi
	echo ""

	echo "═══════════════════════════════════════════════════════════════"
	echo "SECTION: DMESG ACCESS"
	echo "═══════════════════════════════════════════════════════════════"
	echo ""

	if dmesg 2>/dev/null | head -1 | grep -q . 2>/dev/null; then
		echo "[MEDIUM] dmesg is readable by this user — kernel ring buffer accessible"
		echo "[MEDIUM] May contain sensitive info: crypto keys, memory addresses, exploit details"
		echo ""
		echo "[*] Last 20 lines of kernel log:"
		dmesg 2>/dev/null | tail -20 || echo "[ERROR] dmesg read failed"
	else
		echo "[OK] dmesg not readable (permission denied or empty)"
	fi
	echo ""

	echo "═══════════════════════════════════════════════════════════════"
	echo "SECTION: ARM64 SECURITY FEATURES"
	echo "═══════════════════════════════════════════════════════════════"
	echo ""

	echo "[*] CPU features and architecture:"
	if [ -r /proc/cpuinfo ]; then
		cat /proc/cpuinfo 2>/dev/null | grep -iE "Features|CPU implementer|CPU architecture|CPU variant|CPU part|processor" || echo "[ERROR] Failed to read /proc/cpuinfo"
		echo ""

		# Check for ARM64 security features
		if grep -qi "pauth" /proc/cpuinfo 2>/dev/null; then
			echo "[OK] Pointer Authentication (PAUTH) supported — prevents code reuse attacks"
		else
			echo "[INFO] Pointer Authentication not advertised"
		fi

		if grep -qi "bti" /proc/cpuinfo 2>/dev/null; then
			echo "[OK] Branch Target Identification (BTI) supported — prevents branch hijacking"
		else
			echo "[INFO] BTI not advertised"
		fi

		if grep -qi "mte" /proc/cpuinfo 2>/dev/null; then
			echo "[OK] Memory Tagging Extension (MTE) supported — prevents memory corruption"
		else
			echo "[INFO] Memory Tagging Extension not advertised"
		fi
	else
		echo "[ERROR] /proc/cpuinfo not accessible"
	fi
	echo ""

	echo "═══════════════════════════════════════════════════════════════"
	echo "SECTION: SIMPLEPERF AVAILABILITY"
	echo "═══════════════════════════════════════════════════════════════"
	echo ""
	simpleperf_found=""
	for sp_path in /system/bin/simpleperf /system/xbin/simpleperf /vendor/bin/simpleperf; do
		if [ -x "$sp_path" ]; then
			simpleperf_found="$sp_path"
			break
		fi
	done
	if [ -n "$simpleperf_found" ]; then
		echo "[HIGH] simpleperf found at: $simpleperf_found — perf profiling accessible from shell (unprivileged)"
	else
		echo "[INFO] simpleperf not found in standard locations (/system/bin, /system/xbin, /vendor/bin)"
	fi
	echo ""

	echo "═══════════════════════════════════════════════════════════════"
	echo "SECTION: KERNEL SYMBOL LOOKUPS (commit_creds / prepare_kernel_cred)"
	echo "═══════════════════════════════════════════════════════════════"
	echo ""
	if [ -r /proc/kallsyms ]; then
		for ksym in commit_creds prepare_kernel_cred; do
			ksym_line=$(grep " ${ksym}$" /proc/kallsyms 2>/dev/null | head -1)
			if [ -n "$ksym_line" ]; then
				ksym_addr=$(echo "$ksym_line" | awk '{print $1}')
				if [ "$ksym_addr" = "0000000000000000" ]; then
					echo "[OK] $ksym found but address is zeroed — KASLR protecting this symbol"
				else
					echo "[CRITICAL] $ksym address visible: $ksym_addr — KASLR ineffective for this symbol"
				fi
			else
				echo "[INFO] $ksym not found in /proc/kallsyms"
			fi
		done
	else
		echo "[INFO] /proc/kallsyms not accessible"
	fi
	echo ""

	echo "═══════════════════════════════════════════════════════════════"
	echo "SECTION: /proc/iomem (PHYSICAL MEMORY MAP)"
	echo "═══════════════════════════════════════════════════════════════"
	echo ""
	if [ -r /proc/iomem ]; then
		echo "[HIGH] /proc/iomem is readable — physical memory layout exposed to this user"
		echo ""
		echo "[*] First 30 lines of /proc/iomem:"
		head -30 /proc/iomem 2>/dev/null
	else
		echo "[INFO] /proc/iomem not readable (permission denied or not present)"
	fi
	echo ""

	echo "═══════════════════════════════════════════════════════════════"
	echo "SECTION: /proc/vmallocinfo (VIRTUAL MEMORY ALLOCATIONS)"
	echo "═══════════════════════════════════════════════════════════════"
	echo ""
	if [ -r /proc/vmallocinfo ]; then
		echo "[INFO] /proc/vmallocinfo readable — first 20 lines:"
		head -20 /proc/vmallocinfo 2>/dev/null
	else
		echo "[INFO] /proc/vmallocinfo not readable (permission denied or not present)"
	fi
	echo ""

	echo "═══════════════════════════════════════════════════════════════"
	echo "SECTION: CPU VULNERABILITY MITIGATIONS"
	echo "═══════════════════════════════════════════════════════════════"
	echo ""
	if [ -d /sys/devices/system/cpu/vulnerabilities ]; then
		echo "[*] CPU vulnerability mitigation status:"
		for vuln_file in /sys/devices/system/cpu/vulnerabilities/*; do
			[ -f "$vuln_file" ] || continue
			vuln_name=$(basename "$vuln_file")
			vuln_status=$(cat "$vuln_file" 2>/dev/null)
			if echo "$vuln_status" | grep -q "Vulnerable"; then
				echo "    [HIGH] $vuln_name: $vuln_status"
			else
				echo "    [OK] $vuln_name: $vuln_status"
			fi
		done
	else
		echo "[INFO] /sys/devices/system/cpu/vulnerabilities not available on this kernel"
	fi
	echo ""

	echo "═══════════════════════════════════════════════════════════════"
	echo "SECTION: KERNEL CMDLINE SECURITY ANALYSIS"
	echo "═══════════════════════════════════════════════════════════════"
	echo ""
	cmdline=$(cat /proc/cmdline 2>/dev/null)
	if [ -n "$cmdline" ]; then
		echo "[*] Full kernel cmdline:"
		echo "$cmdline"
		echo ""
		echo "[*] Security-relevant boot parameters:"
		echo "$cmdline" | grep -o 'androidboot\.[^ ]*' | sort | while read param; do
			echo "    $param"
		done
		echo ""
		echo "$cmdline" | grep -q "androidboot.verifiedbootstate=orange" && echo "[HIGH] androidboot.verifiedbootstate=orange — device may not be fully verified"
		echo "$cmdline" | grep -q "androidboot.vbmeta.device_state=unlocked" && echo "[HIGH] androidboot.vbmeta.device_state=unlocked — verified boot disabled"
		echo "$cmdline" | grep -q "ro.oem_unlock_supported=1" && echo "[HIGH] ro.oem_unlock_supported=1 — OEM unlock supported"
		echo "$cmdline" | grep -q "selinux=0" && echo "[CRITICAL] selinux=0 in cmdline — SELinux disabled at boot"
		echo "$cmdline" | grep -q "enforcing=0" && echo "[CRITICAL] enforcing=0 in cmdline — SELinux set to permissive at boot"
	else
		echo "[INFO] /proc/cmdline not accessible or empty"
	fi
	echo ""

	echo "═══════════════════════════════════════════════════════════════"
	echo "SECTION: IMA INTEGRITY MEASUREMENT CHECKS"
	echo "═══════════════════════════════════════════════════════════════"
	echo ""
	if [ -f /sys/kernel/security/ima/policy ]; then
		if [ -r /sys/kernel/security/ima/policy ]; then
			echo "[INFO] IMA policy is readable — first 10 lines:"
			head -10 /sys/kernel/security/ima/policy 2>/dev/null
		else
			echo "[INFO] IMA policy file exists but is not readable (permission denied)"
		fi
	else
		echo "[INFO] IMA policy not present (/sys/kernel/security/ima/policy not found)"
	fi
	echo ""
	if [ -r /proc/keys ]; then
		ima_keys=$(grep -i "\.ima" /proc/keys 2>/dev/null)
		if [ -n "$ima_keys" ]; then
			echo "[INFO] IMA keyring entries visible in /proc/keys:"
			echo "$ima_keys"
		else
			echo "[INFO] No IMA keyring entries visible in /proc/keys"
		fi
	else
		echo "[INFO] /proc/keys not accessible"
	fi
	echo ""
	if [ -f /sys/kernel/security/ima/ascii_runtime_measurements ]; then
		echo "[INFO] IMA runtime measurements file exists: /sys/kernel/security/ima/ascii_runtime_measurements"
	fi
	echo ""

	echo "═══════════════════════════════════════════════════════════════"
	echo "SECTION: SYSCTL SECURITY PARAMETER SWEEP"
	echo "═══════════════════════════════════════════════════════════════"
	echo ""

	echo "[*] Additional kernel security sysctls (catch-all for non-standard values):"
	sysctl -a 2>/dev/null | grep -E "^kernel\." | grep -iE "random|restrict|protect|secure|yama|modules|sysrq|core_pattern|kptr" | sort
	echo ""

	echo "[*] Network security parameters:"
	sysctl -a 2>/dev/null | grep -E "^net\." | grep -iE "accept_redirects|accept_source_route|rp_filter|tcp_syncookies|icmp_echo_ignore|forwarding" | sort
	# Risk-label key values
	rp_filter=$(sysctl -n net.ipv4.conf.all.rp_filter 2>/dev/null)
	if [ -n "$rp_filter" ]; then
		if [ "$rp_filter" = "0" ]; then
			echo "[HIGH] net.ipv4.conf.all.rp_filter=0 — reverse path filtering disabled (spoofing risk)"
		else
			echo "[OK] net.ipv4.conf.all.rp_filter=$rp_filter — reverse path filtering active"
		fi
	fi
	syncookies=$(sysctl -n net.ipv4.tcp_syncookies 2>/dev/null)
	if [ -n "$syncookies" ]; then
		if [ "$syncookies" = "0" ]; then
			echo "[HIGH] net.ipv4.tcp_syncookies=0 — SYN cookie protection disabled (SYN flood risk)"
		else
			echo "[OK] net.ipv4.tcp_syncookies=$syncookies — SYN flood protection active"
		fi
	fi
	echo ""

	echo "[*] Memory security parameters:"
	sysctl -a 2>/dev/null | grep -E "^vm\." | grep -iE "mmap_min_addr|overcommit|swappiness" | sort
	echo ""

	echo "═══════════════════════════════════════════════════════════════"
	echo "SECTION: SUMMARY"
	echo "═══════════════════════════════════════════════════════════════"
	echo ""

	kernel_version=$(uname -r 2>/dev/null)
	tainted=$(cat /proc/sys/kernel/tainted 2>/dev/null)
	aslr=$(cat /proc/sys/kernel/randomize_va_space 2>/dev/null)

	echo "[*] Kernel: $kernel_version"
	echo "[*] Taint status: $tainted"

	# Count issues by severity
	critical_count=0
	high_count=0
	medium_count=0

	# Rough estimates based on what we checked
	kptr=$(cat /proc/sys/kernel/kptr_restrict 2>/dev/null)
	[ "$kptr" = "0" ] && critical_count=$((critical_count + 1))

	aslr=$(cat /proc/sys/kernel/randomize_va_space 2>/dev/null)
	[ "$aslr" = "0" ] && critical_count=$((critical_count + 1))

	mmap_min=$(cat /proc/sys/vm/mmap_min_addr 2>/dev/null)
	[ "$mmap_min" = "0" ] && critical_count=$((critical_count + 1))

	[ -r /proc/config.gz ] && high_count=$((high_count + 1))
	[ -r /proc/kcore ] && high_count=$((high_count + 1))

	perf=$(cat /proc/sys/kernel/perf_event_paranoid 2>/dev/null)
	[ "$perf" = "-1" ] && high_count=$((high_count + 1))

	ptrace=$(cat /proc/sys/kernel/yama/ptrace_scope 2>/dev/null)
	[ "$ptrace" = "0" ] && high_count=$((high_count + 1))

	# Suspicious/root modules
	grep -qiE "rootkit|hide|hook|inject|backdoor|keylog" /proc/modules 2>/dev/null && critical_count=$((critical_count + 1))
	grep -qiE "\bsu\b|magisk|supersu|ksu|kernelsu" /proc/modules 2>/dev/null && high_count=$((high_count + 1))

	# Network hardening
	rp_filter=$(sysctl -n net.ipv4.conf.all.rp_filter 2>/dev/null)
	[ "$rp_filter" = "0" ] && high_count=$((high_count + 1))
	syncookies=$(sysctl -n net.ipv4.tcp_syncookies 2>/dev/null)
	[ "$syncookies" = "0" ] && high_count=$((high_count + 1))

	echo ""
	echo "[*] Sections covered: kernel version, config exposure, KASLR/symbols, hardening"
	echo "    settings, memory protections, loaded modules (suspicious/root scan),"
	echo "    taint flags, dmesg access, ARM64 features, simpleperf, iomem/vmallocinfo,"
	echo "    CPU mitigations, cmdline, IMA, sysctl security sweep"
	echo ""
	echo "[*] Security issues found:"
	echo "    CRITICAL: $critical_count"
	echo "    HIGH:     $high_count"
	echo "    MEDIUM:   (see details above)"
	echo ""
	echo "AUDIT COMPLETE"

} > "${OUTPUT_FILE}" 2>&1

echo "[+] Kernel audit saved to: ${OUTPUT_FILE}"
