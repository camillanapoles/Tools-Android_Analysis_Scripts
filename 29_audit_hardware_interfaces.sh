#!/system/bin/sh
# 29_audit_hardware_interfaces.sh — Hardware interface security audit
# Enumerates /dev nodes, ION/DMA-BUF heaps, kernel config, GPIO/SPI/I2C sysfs,
# and physical memory map for security exposure. Read-only — no writes to hardware.
# Usage: sh 29_audit_hardware_interfaces.sh [output_directory]

OUTPUT_DIR="${1:-.}"
OUTPUT_FILE="${OUTPUT_DIR}/audit_hardware_interfaces.txt"

VENDOR=$(getprop ro.hardware 2>/dev/null | tr '[:upper:]' '[:lower:]')
case "$VENDOR" in
    sun*) VENDOR_CLASS="allwinner" ;;
    kona|lahaina|taro|*msm*|*qcom*) VENDOR_CLASS="qualcomm" ;;
    *exynos*|*s5e*) VENDOR_CLASS="samsung" ;;
    *) VENDOR_CLASS="generic" ;;
esac

{
    echo "================================================================"
    echo " Hardware Interface Security Audit"
    echo "================================================================"
    echo "Vendor class: $VENDOR_CLASS (ro.hardware=$VENDOR)"
    echo ""

    CRITICAL_COUNT=0
    HIGH_COUNT=0

    # ----------------------------------------------------------------
    echo "=== Section 1: hwbinder Device Node ==="
    if [ -e /dev/hwbinder ]; then
        HWB_PERMS=$(ls -la /dev/hwbinder 2>/dev/null)
        echo "$HWB_PERMS"
        # Check world-writable (others write bit)
        WW=$(ls -la /dev/hwbinder 2>/dev/null | awk '{print $1}' | cut -c8)
        if [ "$WW" = "w" ]; then
            echo "[CRITICAL] /dev/hwbinder is world-writable — direct HAL Binder injection possible without servicemanager"
            CRITICAL_COUNT=$((CRITICAL_COUNT + 1))
        else
            GW=$(ls -la /dev/hwbinder 2>/dev/null | awk '{print $1}' | cut -c5)
            if [ "$GW" = "w" ]; then
                echo "[HIGH] /dev/hwbinder is group-writable — check if current user's groups include owner group"
                HIGH_COUNT=$((HIGH_COUNT + 1))
            else
                echo "[INFO] /dev/hwbinder exists but is not world- or group-writable"
            fi
        fi
        echo "Read access test: $(dd if=/dev/hwbinder bs=1 count=1 2>&1 | head -1)"
    else
        echo "[INFO] /dev/hwbinder not present"
    fi
    echo ""

    # ----------------------------------------------------------------
    echo "=== Section 2: binder and vndbinder Device Nodes ==="
    for NODE in /dev/binder /dev/vndbinder; do
        if [ -e "$NODE" ]; then
            echo "$(ls -la $NODE 2>/dev/null)"
            WW=$(ls -la $NODE 2>/dev/null | awk '{print $1}' | cut -c8)
            GW=$(ls -la $NODE 2>/dev/null | awk '{print $1}' | cut -c5)
            if [ "$WW" = "w" ]; then
                echo "[CRITICAL] $NODE is world-writable"
                CRITICAL_COUNT=$((CRITICAL_COUNT + 1))
            elif [ "$GW" = "w" ]; then
                echo "[HIGH] $NODE is group-writable"
                HIGH_COUNT=$((HIGH_COUNT + 1))
            else
                echo "[INFO] $NODE permissions appear normal"
            fi
        else
            echo "[INFO] $NODE not present"
        fi
    done
    echo ""

    # ----------------------------------------------------------------
    echo "=== Section 3: ION / DMA-BUF Heaps ==="
    if [ -e /dev/ion ]; then
        echo "Legacy ION device:"
        ls -la /dev/ion 2>/dev/null
        WW=$(ls -la /dev/ion 2>/dev/null | awk '{print $1}' | cut -c8)
        if [ "$WW" = "w" ]; then
            echo "[HIGH] /dev/ion is world-writable"
            HIGH_COUNT=$((HIGH_COUNT + 1))
        else
            echo "[INFO] /dev/ion exists (legacy ION allocator)"
        fi
    else
        echo "[INFO] /dev/ion not present (legacy ION not exposed)"
    fi
    echo ""

    if [ -d /dev/dma_heap ]; then
        echo "DMA-BUF heaps (/dev/dma_heap/):"
        ls -la /dev/dma_heap/ 2>/dev/null
        for HEAP in /dev/dma_heap/*; do
            [ -e "$HEAP" ] || continue
            WW=$(ls -la "$HEAP" 2>/dev/null | awk '{print $1}' | cut -c8)
            if [ "$WW" = "w" ]; then
                echo "[HIGH] $HEAP is world-writable"
                HIGH_COUNT=$((HIGH_COUNT + 1))
            fi
        done
    else
        echo "[INFO] /dev/dma_heap/ directory not present"
    fi
    echo ""

    # ----------------------------------------------------------------
    if [ "$VENDOR_CLASS" = "allwinner" ]; then
        echo "=== Section 4: Allwinner-Specific Device Nodes ==="
        echo "(VENDOR_CLASS=allwinner — running Allwinner-specific checks)"
        echo ""

        # sunxi_smc — SMC/TEE interface — highest risk
        if [ -e /dev/sunxi_smc ]; then
            echo "$(ls -la /dev/sunxi_smc 2>/dev/null)"
            echo "[CRITICAL] /dev/sunxi_smc exists — direct SMC/TEE interface accessible; enumerate sysfs for ioctl surface"
            CRITICAL_COUNT=$((CRITICAL_COUNT + 1))
            echo "Read access test: $(dd if=/dev/sunxi_smc bs=1 count=1 2>&1 | head -1)"
        else
            echo "[INFO] /dev/sunxi_smc not present"
        fi
        echo ""

        # tee0 / teepriv0 — OP-TEE nodes
        for NODE in /dev/tee0 /dev/teepriv0; do
            if [ -e "$NODE" ]; then
                echo "$(ls -la $NODE 2>/dev/null)"
                WW=$(ls -la $NODE 2>/dev/null | awk '{print $1}' | cut -c8)
                if [ "$WW" = "w" ]; then
                    echo "[CRITICAL] $NODE is world-writable — direct OP-TEE access possible"
                    CRITICAL_COUNT=$((CRITICAL_COUNT + 1))
                else
                    echo "[HIGH] $NODE exists — check SELinux label for shell access"
                    HIGH_COUNT=$((HIGH_COUNT + 1))
                fi
                echo "SELinux label: $(ls -Z $NODE 2>/dev/null || echo '[N/A]')"
            else
                echo "[INFO] $NODE not present"
            fi
            echo ""
        done

        # cedar_dev — video codec DMA
        if [ -e /dev/cedar_dev ]; then
            echo "$(ls -la /dev/cedar_dev 2>/dev/null)"
            WW=$(ls -la /dev/cedar_dev 2>/dev/null | awk '{print $1}' | cut -c8)
            if [ "$WW" = "w" ]; then
                echo "[HIGH] /dev/cedar_dev is world-writable — Allwinner VE DMA accessible"
                HIGH_COUNT=$((HIGH_COUNT + 1))
            else
                echo "[INFO] /dev/cedar_dev present (Allwinner video engine)"
            fi
            echo "Read test: $(dd if=/dev/cedar_dev bs=1 count=1 2>&1 | head -1)"
        else
            echo "[INFO] /dev/cedar_dev not present"
        fi
        echo ""

        # mali GPU
        for NODE in /dev/mali0 /dev/mali; do
            if [ -e "$NODE" ]; then
                echo "$(ls -la $NODE 2>/dev/null)"
                WW=$(ls -la $NODE 2>/dev/null | awk '{print $1}' | cut -c8)
                if [ "$WW" = "w" ]; then
                    echo "[HIGH] $NODE is world-writable — GPU DMA buffer access possible"
                    HIGH_COUNT=$((HIGH_COUNT + 1))
                else
                    echo "[INFO] $NODE present (Mali GPU)"
                fi
            else
                echo "[INFO] $NODE not present"
            fi
        done
        echo ""

        # g2d — 2D graphics engine
        if [ -e /dev/g2d ]; then
            echo "$(ls -la /dev/g2d 2>/dev/null)"
            WW=$(ls -la /dev/g2d 2>/dev/null | awk '{print $1}' | cut -c8)
            if [ "$WW" = "w" ]; then
                echo "[HIGH] /dev/g2d is world-writable — Allwinner G2D DMA accessible"
                HIGH_COUNT=$((HIGH_COUNT + 1))
            else
                echo "[INFO] /dev/g2d present (Allwinner 2D engine)"
            fi
        else
            echo "[INFO] /dev/g2d not present"
        fi
        echo ""

        # ump — ARM Unified Memory Provider
        if [ -e /dev/ump ]; then
            echo "$(ls -la /dev/ump 2>/dev/null)"
            WW=$(ls -la /dev/ump 2>/dev/null | awk '{print $1}' | cut -c8)
            if [ "$WW" = "w" ]; then
                echo "[HIGH] /dev/ump is world-writable — ARM UMP shared memory accessible"
                HIGH_COUNT=$((HIGH_COUNT + 1))
            else
                echo "[INFO] /dev/ump present (ARM Unified Memory Provider)"
            fi
        else
            echo "[INFO] /dev/ump not present"
        fi
        echo ""

        # Allwinner sysfs nodes
        echo "Allwinner sysfs nodes:"
        for SYSDIR in /sys/class/sunxi_info /sys/devices/platform/soc/soc:smc /sys/module/sunxi_smc; do
            if [ -e "$SYSDIR" ]; then
                echo "[HIGH] $SYSDIR exists — Allwinner-specific sysfs interface"
                ls -la "$SYSDIR" 2>/dev/null | head -10
                HIGH_COUNT=$((HIGH_COUNT + 1))
            fi
        done
        echo ""
    else
        echo "=== Section 4: Allwinner-Specific Nodes ==="
        echo "[INFO] Skipped — VENDOR_CLASS=$VENDOR_CLASS (not allwinner)"
        echo ""
    fi

    # ----------------------------------------------------------------
    echo "=== Section 5: Generic GPU / Media Nodes ==="
    for NODE in /dev/video0 /dev/video1; do
        if [ -e "$NODE" ]; then
            echo "$(ls -la $NODE 2>/dev/null)"
            WW=$(ls -la $NODE 2>/dev/null | awk '{print $1}' | cut -c8)
            [ "$WW" = "w" ] && echo "[HIGH] $NODE is world-writable" && HIGH_COUNT=$((HIGH_COUNT + 1)) || echo "[INFO] $NODE present (V4L2)"
        fi
    done

    if [ -d /dev/dri ]; then
        echo "DRM GPU nodes (/dev/dri/):"
        ls -la /dev/dri/ 2>/dev/null
        for DRI in /dev/dri/*; do
            [ -e "$DRI" ] || continue
            WW=$(ls -la "$DRI" 2>/dev/null | awk '{print $1}' | cut -c8)
            [ "$WW" = "w" ] && echo "[HIGH] $DRI is world-writable" && HIGH_COUNT=$((HIGH_COUNT + 1))
        done
    else
        echo "[INFO] /dev/dri/ not present"
    fi

    if [ "$VENDOR_CLASS" = "qualcomm" ] && [ -e /dev/kgsl-3d0 ]; then
        echo "$(ls -la /dev/kgsl-3d0 2>/dev/null)"
        WW=$(ls -la /dev/kgsl-3d0 2>/dev/null | awk '{print $1}' | cut -c8)
        [ "$WW" = "w" ] && echo "[HIGH] /dev/kgsl-3d0 is world-writable" && HIGH_COUNT=$((HIGH_COUNT + 1)) || echo "[INFO] /dev/kgsl-3d0 present (Qualcomm GPU)"
    fi
    echo ""

    # ----------------------------------------------------------------
    echo "=== Section 6: /proc/iomem — Physical Memory Map ==="
    if [ -r /proc/iomem ]; then
        echo "[HIGH] /proc/iomem is readable — physical memory map exposed"
        HIGH_COUNT=$((HIGH_COUNT + 1))
        echo "--- First 40 lines ---"
        head -40 /proc/iomem 2>/dev/null
        echo ""
        echo "--- TEE/TrustZone regions ---"
        TEE_REGIONS=$(grep -i "tee\|trust\|secure\|trustzone" /proc/iomem 2>/dev/null)
        if [ -n "$TEE_REGIONS" ]; then
            echo "[CRITICAL] TEE/TrustZone memory region addresses visible in /proc/iomem:"
            echo "$TEE_REGIONS"
            CRITICAL_COUNT=$((CRITICAL_COUNT + 1))
        else
            echo "[INFO] No TEE/TrustZone labels found in /proc/iomem"
        fi
    else
        echo "[INFO] /proc/iomem not readable"
    fi
    echo ""

    # ----------------------------------------------------------------
    echo "=== Section 7: /proc/config.gz — Kernel Configuration ==="
    if [ -r /proc/config.gz ]; then
        echo "[INFO] /proc/config.gz is readable — extracting security-relevant options"
        echo ""
        KCONFIG=$(gunzip -c /proc/config.gz 2>/dev/null | grep -E "CONFIG_(MODULES|DEVMEM|STRICT_DEVMEM|IO_STRICT_DEVMEM|DEVKMEM|KALLSYMS|KALLSYMS_ALL|KPROBES|FTRACE|PERF_EVENTS|SECCOMP|SECCOMP_FILTER|SECURITY_SELINUX|ANDROID_PARANOID_NETWORK)=" | head -30)
        echo "$KCONFIG"
        echo ""

        # DEVKMEM=y is critical — direct kernel memory access
        if echo "$KCONFIG" | grep -q "CONFIG_DEVKMEM=y"; then
            echo "[CRITICAL] CONFIG_DEVKMEM=y — /dev/kmem kernel memory device may be present"
            CRITICAL_COUNT=$((CRITICAL_COUNT + 1))
        fi

        # DEVMEM without STRICT_DEVMEM
        if echo "$KCONFIG" | grep -q "CONFIG_DEVMEM=y"; then
            if echo "$KCONFIG" | grep -q "CONFIG_STRICT_DEVMEM=y"; then
                echo "[INFO] CONFIG_DEVMEM=y but STRICT_DEVMEM=y — restricted /dev/mem"
            else
                echo "[HIGH] CONFIG_DEVMEM=y without CONFIG_STRICT_DEVMEM — /dev/mem may expose full physical memory"
                HIGH_COUNT=$((HIGH_COUNT + 1))
            fi
        fi

        # KALLSYMS_ALL exposes all symbol addresses
        if echo "$KCONFIG" | grep -q "CONFIG_KALLSYMS_ALL=y"; then
            echo "[HIGH] CONFIG_KALLSYMS_ALL=y — all kernel symbol addresses exposed (kASLR weakened)"
            HIGH_COUNT=$((HIGH_COUNT + 1))
        fi

        # No SECCOMP is a high risk
        if echo "$KCONFIG" | grep -q "CONFIG_SECCOMP=y"; then
            echo "[INFO] CONFIG_SECCOMP=y — seccomp syscall filtering available"
        else
            echo "[HIGH] CONFIG_SECCOMP not set — no kernel-level syscall filtering"
            HIGH_COUNT=$((HIGH_COUNT + 1))
        fi
    else
        echo "[INFO] /proc/config.gz not readable"
    fi
    echo ""

    # ----------------------------------------------------------------
    echo "=== Section 8: GPIO / SPI / I2C Sysfs Enumeration ==="

    echo "--- GPIO exported pins ---"
    if [ -d /sys/class/gpio ]; then
        GPIO_FOUND=0
        for GDIR in /sys/class/gpio/gpio*; do
            [ -d "$GDIR" ] || continue
            GPIO_FOUND=1
            GNAME=$(basename "$GDIR")
            DIRECTION=$(cat "$GDIR/direction" 2>/dev/null || echo "N/A")
            VALUE=$(cat "$GDIR/value" 2>/dev/null || echo "N/A")
            LABEL=$(cat "$GDIR/label" 2>/dev/null || echo "N/A")
            echo "[INFO] $GNAME: direction=$DIRECTION value=$VALUE label=$LABEL"
            # Check if value file is writable
            if [ -w "$GDIR/value" ]; then
                echo "[HIGH] $GNAME/value is writable by current user — GPIO output control possible"
                HIGH_COUNT=$((HIGH_COUNT + 1))
            fi
        done
        [ "$GPIO_FOUND" = "0" ] && echo "[INFO] No exported GPIOs found in /sys/class/gpio/"
    else
        echo "[INFO] /sys/class/gpio not present"
    fi
    echo ""

    echo "--- SPI devices ---"
    if [ -d /sys/bus/spi/devices ]; then
        SPI_LIST=$(ls /sys/bus/spi/devices/ 2>/dev/null)
        if [ -n "$SPI_LIST" ]; then
            echo "[INFO] SPI devices found:"
            for DEV in $SPI_LIST; do
                MODALIAS=$(cat /sys/bus/spi/devices/$DEV/modalias 2>/dev/null || echo "N/A")
                echo "  $DEV  modalias=$MODALIAS"
            done
        else
            echo "[INFO] No SPI devices found"
        fi
    else
        echo "[INFO] /sys/bus/spi/devices not present"
    fi
    echo ""

    echo "--- I2C devices ---"
    if [ -d /sys/bus/i2c/devices ]; then
        I2C_LIST=$(ls /sys/bus/i2c/devices/ 2>/dev/null)
        if [ -n "$I2C_LIST" ]; then
            echo "[INFO] I2C devices found:"
            for DEV in $I2C_LIST; do
                NAME=$(cat /sys/bus/i2c/devices/$DEV/name 2>/dev/null || echo "N/A")
                echo "  $DEV  name=$NAME"
            done
        else
            echo "[INFO] No I2C devices found"
        fi
    else
        echo "[INFO] /sys/bus/i2c/devices not present"
    fi
    echo ""

    # ----------------------------------------------------------------
    echo "================================================================"
    echo " SUMMARY"
    echo "================================================================"
    echo "[CRITICAL] findings: $CRITICAL_COUNT"
    echo "[HIGH]     findings: $HIGH_COUNT"
    echo ""
    if [ "$CRITICAL_COUNT" -gt 0 ]; then
        echo "OVERALL RISK: CRITICAL — immediate manual review required"
    elif [ "$HIGH_COUNT" -gt 0 ]; then
        echo "OVERALL RISK: HIGH — hardware interfaces expose attack surface"
    else
        echo "OVERALL RISK: LOW — no world-accessible high-risk hardware interfaces detected"
    fi
    echo "================================================================"

} > "${OUTPUT_FILE}" 2>&1
