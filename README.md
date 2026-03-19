# Android Analysis Scripts

A collection of 41 POSIX shell scripts for forensic data collection and security auditing on Android devices. Scripts run directly on-device via ADB shell or a terminal emulator — no build step, no dependencies beyond standard Android utilities.

> **Legal Notice:** Use only on devices you own or have explicit written authorization to test. Unauthorized use may violate computer fraud laws.

---

## Requirements

- Android device or emulator (API 26 / Android 8.0+)
- ADB (Android Debug Bridge) for host-based execution
- Root access optional — scripts degrade gracefully and log permission denials

---

## Quick Start

### From host via ADB
```sh
adb push Toolchain/ /data/local/tmp/android-audit/
adb shell "cd /data/local/tmp/android-audit && sh 0_RunAll.sh /sdcard/forensic_output"
```

### On-device (terminal emulator)
```sh
sh 0_RunAll.sh /sdcard/forensic_output
```

### With root
```sh
adb shell su -c "sh 0_RunAll.sh /data/local/tmp/forensic_output"
```

### Single script
```sh
sh 01_audit_usb_adb.sh [output_directory]
```

All scripts accept an optional output directory as the first argument (defaults to current directory).

---

## Output

`0_RunAll.sh` creates a timestamped directory: `forensic_YYYYMMDD_HHMMSS/`

```
forensic_20260128_145213/
├── master.log
├── manifest.txt
├── audit_usb_adb.txt
├── audit_properties.txt
├── audit_partitions.txt
├── root_indicators.txt
├── audit_android_jail.txt
├── audit_selinux.txt
├── audit_kernel.txt
├── audit_debug_interfaces.txt
├── enum_privileged_processes.txt
├── audit_capabilities.txt
├── audit_setuid.txt
├── audit_privesc_surface.txt
├── users_uids.txt
├── device_nodes.txt
├── audit_writable_system.txt
├── audit_special_perms.txt
├── probe_namespaces.txt
├── audit_boot.txt
├── audit_scheduled_tasks.txt
├── vendor_customizations.txt
├── network_interfaces.txt
├── netstat.txt
├── audit_network_deep.txt
├── audit_binder.txt
├── pipes_ipc.txt
├── audit_unix_sockets.txt
├── audit_content_providers.txt
├── probe_tee_surface.txt
├── audit_hardware_interfaces.txt
├── audit_app_attack_surface.txt
├── broadcast_receivers.txt
├── audit_crypto_surface.txt
├── scan_certificate_files.txt
├── scan_hardcoded_secrets.txt
├── application_hashes.txt
├── shell_commands.txt
├── symlinks.txt
├── input_devices.txt
├── forensic_logs.txt
├── forensic_process_snapshot.txt
└── forensic_storage_sensitive.txt
```

> **Security:** Output files contain sensitive device data (credentials, keys, device identifiers). Treat as confidential, store encrypted, and delete after analysis.

---

## Risk Levels

Findings in output files are tagged:

| Tag | Meaning |
|-----|---------|
| `[CRITICAL]` | Immediate exploitation risk (exposed private keys, SUID root, world-writable system files) |
| `[HIGH]` | Significant attack surface (exported unprotected components, writable shell scripts) |
| `[MEDIUM]` | Notable configuration weakness (user CAs, permissive SELinux domains) |
| `[INFO]` | Informational — no direct risk, useful for baseline |

---

## Script Reference

### USB, ADB & Boot

| Script | Output File | Description |
|--------|-------------|-------------|
| `01_audit_usb_adb.sh` | `audit_usb_adb.txt` | ADB debugging status, authorization keys, USB configuration and functions, developer options, bootloader status, USB security properties, ADB shell capabilities |
| `18_audit_boot.sh` | `audit_boot.txt` | Init RC files, services defined in RC files, services running as root/system, Zygote configuration |

### System Properties & Partitions

| Script | Output File | Description |
|--------|-------------|-------------|
| `02_audit_properties.sh` | `audit_properties.txt` | Critical security flags (ro.debuggable, ro.secure, ro.adb.secure), build and signing type, SELinux properties, encryption state, persistent/mutable tamper indicators, root/hooking framework detection (Magisk/Xposed/Frida), Keymaster/Keymint properties, full property dump |
| `03_audit_partitions.sh` | `audit_partitions.txt` | Bootloader lock state, A/B partition scheme, partition layout, dm-verity status, Android Verified Boot (AVB), mount points, fstab configuration, Factory Reset Protection (FRP), partition integrity hashes |

### Root & Privilege Analysis

| Script | Output File | Description |
|--------|-------------|-------------|
| `04_enum_root_indicators.sh` | `root_indicators.txt` | SU binary detection, Magisk/KernelSU/APatch/SuperSU framework detection, Busybox indicators, modified system properties, suspicious overlayfs/bind mounts, /data/adb audit |
| `05_audit_android_jail.sh` | `audit_android_jail.txt` | Current process identity and decoded capabilities, Android paranoid network gate membership (GIDs), SELinux domain confinement, seccomp filter and NoNewPrivs status, privilege escalation surface, Android AID reference table |
| `09_enum_privileged_processes.sh` | `enum_privileged_processes.txt` | Per-process security profile for all UID=0 processes: capabilities, seccomp, NoNewPrivs, SELinux context, FD count, mapped libraries; system server brief profile; highest-risk process summary |
| `10_audit_capabilities.sh` | `audit_capabilities.txt` | getcap/capsh tool availability, current process capabilities, all files with Linux capabilities in /system, /vendor, /sbin, /data |
| `11_audit_setuid.sh` | `audit_setuid.txt` | `[CRITICAL]` SUID root binaries, all SUID binaries, all SGID binaries, binaries with both SUID and SGID set |
| `12_audit_privesc_surface.sh` | `audit_privesc_surface.txt` | Writable PATH directories, writable root-owned files, SUID/SGID enumeration as escalation vectors |
| `13_enum_users.sh` | `users_uids.txt` | Current process identity, SELinux context, /etc/passwd and /etc/group (system and Android equivalents), Android system AID reference table |

### SELinux & Kernel Security

| Script | Output File | Description |
|--------|-------------|-------------|
| `06_audit_selinux.sh` | `audit_selinux.txt` | Enforcement status, policy version, permissive and unconfined domains, process domain distribution, file/property/service contexts, recent AVC denials, app data contexts, seapp_contexts, SELinux booleans, MLS/MCS status |
| `07_audit_kernel.sh` | `audit_kernel.txt` | Kernel version, config exposure (/proc/config.gz), KASLR/symbol exposure, hardening settings (kptr_restrict/dmesg_restrict/perf_event_paranoid/ptrace_scope), loaded modules, taint flags, ARM64 features (PAC/BTI/MTE), CPU vulnerability mitigations, kernel cmdline analysis, IMA checks, sysctl security sweep |
| `08_audit_debug_interfaces.sh` | `audit_debug_interfaces.txt` | ptrace status, debugfs/tracefs mount state and contents, perf_event paranoid setting, kprobes, /proc debug interfaces, hardware debug (JTAG/SWD), memory debugging features, tracefs write permissions, eBPF attack surface |

### Namespaces & Scheduled Tasks

| Script | Output File | Description |
|--------|-------------|-------------|
| `17_audit_namespaces.sh` | `probe_namespaces.txt` | Shell namespace links, unprivileged namespace clone capability, user namespace configuration, per-process namespace identifiers, process status (capabilities/seccomp/NoNewPrivs) |
| `19_audit_scheduled_tasks.sh` | `audit_scheduled_tasks.txt` | JobScheduler jobs, AlarmManager alarms, WorkManager tasks, persistence mechanisms |

### File System & Permissions

| Script | Output File | Description |
|--------|-------------|-------------|
| `14_audit_device_nodes.sh` | `device_nodes.txt` | /dev overview and counts, `[CRITICAL]` world-writable device nodes, world-readable sensitive devices |
| `15_audit_writable_system.sh` | `audit_writable_system.txt` | Mount options (read-only enforcement), files/directories writable in /system and /vendor, writable shell scripts and RC/init files |
| `16_audit_special_perms.sh` | `audit_special_perms.txt` | `[CRITICAL]` world-writable files in system paths, `[HIGH]` world-writable directories, `[MEDIUM]` group-writable files, `[HIGH]` files owned by network-capable UIDs |
| `37_enum_symlinks.sh` | `symlinks.txt` | Symbolic links across critical system paths, APEX module symlinks, broken symlinks, cross-boundary links |
| `41_forensic_storage_sensitive.sh` | `forensic_storage_sensitive.txt` | World-readable files in /data, accessible SQLite databases, world-readable app private files |

### Network & IPC

| Script | Output File | Description |
|--------|-------------|-------------|
| `21_enum_network.sh` | `network_interfaces.txt` | Network interfaces, IP/IPv6 addresses, routing tables, ARP cache, DNS, WiFi and VPN/tunnel properties |
| `22_enum_netstat.sh` | `netstat.txt` | Listening TCP/UDP ports, active connections, /proc/net/tcp, Unix domain sockets, socket statistics |
| `23_audit_network_deep.sh` | `audit_network_deep.txt` | iptables/ip6tables rules, NAT table, deep network configuration audit |
| `24_audit_binder.sh` | `audit_binder.txt` | All registered Binder services, Binder device permissions, high-value service targets, vendor-prefix services |
| `25_enum_pipes.sh` | `pipes_ipc.txt` | Named pipes (FIFOs), Unix domain sockets |
| `26_audit_unix_sockets.sh` | `audit_unix_sockets.txt` | Unix socket accessibility audit, /dev/socket filesystem sockets, privilege escalation vectors |
| `27_audit_content_providers.sh` | `audit_content_providers.txt` | Exported content providers, queryable system URIs (Settings, Media, Contacts, SMS, Call Log), data exposure testing |

### Hardware & TEE

| Script | Output File | Description |
|--------|-------------|-------------|
| `28_audit_tee.sh` | `probe_tee_surface.txt` | TEE device nodes and permissions, tee_supplicant process profile, TEE-related Binder services, TA enumeration surface |
| `29_audit_hardware_interfaces.sh` | `audit_hardware_interfaces.txt` | hwbinder device node permissions, ION memory allocator and DMA-BUF heaps, kernel config exposure, GPIO/SPI/I2C sysfs interfaces, physical memory map |
| `38_enum_input_devices.sh` | `input_devices.txt` | /dev/input device enumeration, kernel input events (getevent), key layout and character map files, keylogging/injection surface |

### Application Security

| Script | Output File | Description |
|--------|-------------|-------------|
| `20_enum_vendor_customizations.sh` | `vendor_customizations.txt` | OEM-specific system properties, vendor custom services and apps, hidden/diagnostic functionality |
| `30_audit_app_attack_surface.sh` | `audit_app_attack_surface.txt` | Apps with allowBackup enabled, debuggable APKs, WebView remote debugging, overlay permissions, accessibility service abuse surface |
| `31_enum_broadcast_receivers.sh` | `broadcast_receivers.txt` | All registered broadcast receivers, unprotected receivers (injection risk), high-risk actions (SMS/BOOT_COMPLETED), sticky broadcasts |
| `35_enum_app_hashes.sh` | `application_hashes.txt` | Installed packages with APK paths, SHA256/MD5 hashes, system vs third-party, disabled packages, package UIDs |
| `36_enum_shell_commands.sh` | `shell_commands.txt` | Environment variables, PATH, /system/bin and /vendor/bin contents, Toybox/Busybox applets, security-sensitive binaries (su, tcpdump, strace) |

### Cryptography, Certificates & Secrets

| Script | Output File | Description |
|--------|-------------|-------------|
| `32_audit_crypto_surface.sh` | `audit_crypto_surface.txt` | Kernel keyring (/proc/keys), Keystore2 key inventory, hardware-backed key detection |
| `33_scan_certificate_files.sh` | `scan_certificate_files.txt` | `[CRITICAL]` private key files (PEM/DER/PKCS#12 by extension and content), APK-embedded certificates, world-readable cert files |
| `34_scan_hardcoded_secrets.sh` | `scan_hardcoded_secrets.txt` | SSH private keys, cloud credentials (AWS/GCP/Azure), API keys (Google/Firebase/Stripe/Twilio), JWT tokens, SharedPreferences credentials, APK-embedded secrets |

### Forensic Collection

| Script | Output File | Description |
|--------|-------------|-------------|
| `39_collect_logs.sh` | `forensic_logs.txt` | System logcat, kernel dmesg, tombstone crash logs, ANR traces, dropbox entries, SELinux denial log entries |
| `40_forensic_process_snapshot.sh` | `forensic_process_snapshot.txt` | Deliverable-grade process snapshot: full process table, per-UID=0 process security profile (capabilities, SELinux, seccomp), process count summary |

---

## Directory Structure

```
Toolchain/
├── 0_RunAll.sh                        # Orchestrator — runs scripts 01–41 in sequence
├── 99_Zip_Reports.sh                  # Archives output (zip → tar.gz → tar fallback)
├── 01_audit_usb_adb.sh
├── 02_audit_properties.sh
├── 03_audit_partitions.sh
├── 04_enum_root_indicators.sh
├── 05_audit_android_jail.sh
├── 06_audit_selinux.sh
├── 07_audit_kernel.sh
├── 08_audit_debug_interfaces.sh
├── 09_enum_privileged_processes.sh
├── 10_audit_capabilities.sh
├── 11_audit_setuid.sh
├── 12_audit_privesc_surface.sh
├── 13_enum_users.sh
├── 14_audit_device_nodes.sh
├── 15_audit_writable_system.sh
├── 16_audit_special_perms.sh
├── 17_audit_namespaces.sh
├── 18_audit_boot.sh
├── 19_audit_scheduled_tasks.sh
├── 20_enum_vendor_customizations.sh
├── 21_enum_network.sh
├── 22_enum_netstat.sh
├── 23_audit_network_deep.sh
├── 24_audit_binder.sh
├── 25_enum_pipes.sh
├── 26_audit_unix_sockets.sh
├── 27_audit_content_providers.sh
├── 28_audit_tee.sh
├── 29_audit_hardware_interfaces.sh
├── 30_audit_app_attack_surface.sh
├── 31_enum_broadcast_receivers.sh
├── 32_audit_crypto_surface.sh
├── 33_scan_certificate_files.sh
├── 34_scan_hardcoded_secrets.sh
├── 35_enum_app_hashes.sh
├── 36_enum_shell_commands.sh
├── 37_enum_symlinks.sh
├── 38_enum_input_devices.sh
├── 39_collect_logs.sh
├── 40_forensic_process_snapshot.sh
└── 41_forensic_storage_sensitive.sh
```

---

## Adding Scripts

Each script follows this template:

```sh
#!/system/bin/sh
OUTPUT_DIR="${1:-.}"
OUTPUT_FILE="${OUTPUT_DIR}/output_name.txt"
{
    echo "=== SECTION HEADER ==="
    echo "Timestamp: $(date)"
    # collection commands here
} > "${OUTPUT_FILE}" 2>&1
```

Key rules:
- Shebang must be `#!/system/bin/sh` — no bashisms, no arrays, no `[[ ]]`, no `local`
- Accept output directory as `$1`, default to `.`
- Redirect all stderr into the output file (`2>&1`)
- Tag findings with `[CRITICAL]`, `[HIGH]`, `[MEDIUM]`, or `[INFO]`
