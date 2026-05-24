#!/bin/bash
# =============================================================================
# SimpleHomeLog SIEM - Hardware Health Monitor
# =============================================================================
#
# Author:       Klaus Baumdick
# Date:         2026-05-24
# Version:      1.0.0
#
# Description:  Comprehensive hardware health monitoring for server infrastructure.
#
# =============================================================================
# LICENSE
# =============================================================================
# MIT License
#
# Copyright (c) 2026 Klaus Baumdick
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
# =============================================================================

# =============================================================================
# CONFIGURATION
# =============================================================================

TAG="hardware_monitor"
PID=$$

# Temperature thresholds in Celsius
TEMP_DISK_WARN=55
TEMP_DISK_CRITICAL=65
TEMP_CPU_WARN=75
TEMP_CPU_CRITICAL=85

# Fan speed threshold in RPM
FAN_SPEED_WARN=1000

# CPU throttling threshold (percentage of max frequency)
CPU_THROTTLE_WARN=50

# Disk devices to check
DISK_PATTERNS="/dev/sd[a-z] /dev/nvme[0-9]n[0-9] /dev/vd[a-z]"

# =============================================================================
# FUNCTIONS
# =============================================================================

log_to_syslog() {
    local severity="$1"
    local message="$2"

    case "$severity" in
        "CRITICAL") logger -p user.crit -t "${TAG}[${PID}]" "SimpleHomeLog: CRITICAL: $message" ;;
        "HIGH")     logger -p user.err -t "${TAG}[${PID}]" "SimpleHomeLog: HIGH: $message" ;;
        "MEDIUM")   logger -p user.warning -t "${TAG}[${PID}]" "SimpleHomeLog: MEDIUM: $message" ;;
        "LOW")      logger -p user.notice -t "${TAG}[${PID}]" "SimpleHomeLog: LOW: $message" ;;
        *)          logger -p user.info -t "${TAG}[${PID}]" "SimpleHomeLog: INFO: $message" ;;
    esac
}

command_exists() {
    command -v "$1" >/dev/null 2>&1
}

is_numeric() {
    [[ "$1" =~ ^[0-9]+$ ]]
}

# =============================================================================
# SECTION 1: Disk S.M.A.R.T. Monitoring
# =============================================================================

monitor_smart() {
    log_to_syslog "INFO" "=== Disk S.M.A.R.T. health monitoring ==="

    if ! command_exists smartctl; then
        log_to_syslog "INFO" "smartctl not installed - S.M.A.R.T. monitoring disabled"
        return 1
    fi

    local disk_found=0

    for disk in $DISK_PATTERNS; do
        for dev in $disk; do
            if [ -b "$dev" ]; then
                disk_found=1

                local smart_status=$(smartctl -H "$dev" 2>/dev/null | grep -i "SMART overall-health" | cut -d: -f2 | tr -d ' ')

                if [ -z "$smart_status" ]; then
                    continue
                fi

                if [ "$smart_status" = "PASSED" ]; then
                    log_to_syslog "INFO" "S.M.A.R.T. for ${dev}: PASSED"
                elif [ "$smart_status" = "FAILED" ]; then
                    log_to_syslog "CRITICAL" "S.M.A.R.T. for ${dev}: FAILED - Disk failure imminent!"
                fi

                # Check reallocated sectors
                local reallocated=$(smartctl -A "$dev" 2>/dev/null | grep -i "Reallocated_Sector" | awk '{print $10}')
                if [ -n "$reallocated" ] && [ "$reallocated" -gt 0 ] 2>/dev/null; then
                    log_to_syslog "HIGH" "Disk ${dev} has ${reallocated} reallocated sectors"
                fi

                # Check temperature
                local temp=$(smartctl -A "$dev" 2>/dev/null | grep -i "Temperature_Celsius" | awk '{print $10}')
                if [ -n "$temp" ] && is_numeric "$temp"; then
                    if [ "$temp" -gt "$TEMP_DISK_CRITICAL" ] 2>/dev/null; then
                        log_to_syslog "CRITICAL" "Disk ${dev} temperature: ${temp}°C"
                    elif [ "$temp" -gt "$TEMP_DISK_WARN" ] 2>/dev/null; then
                        log_to_syslog "HIGH" "Disk ${dev} temperature: ${temp}°C"
                    else
                        log_to_syslog "INFO" "Disk ${dev} temperature: ${temp}°C"
                    fi
                fi
            fi
        done
    done

    if [ $disk_found -eq 0 ]; then
        log_to_syslog "INFO" "No disk devices found for S.M.A.R.T. monitoring"
    fi
}

# =============================================================================
# SECTION 2: CPU and System Sensors
# =============================================================================

monitor_sensors() {
    log_to_syslog "INFO" "=== System sensor monitoring ==="

    if ! command_exists sensors; then
        log_to_syslog "INFO" "sensors not installed"
        return 1
    fi

    local sensor_data=$(sensors -u 2>/dev/null)

    if [ -z "$sensor_data" ]; then
        return 1
    fi

    # Monitor temperatures
    echo "$sensor_data" | grep -E "temp[0-9]+_input" | while read line; do
        local sensor_name=$(echo "$line" | cut -d_ -f1)
        local temp=$(echo "$line" | awk '{print $2}' | cut -d. -f1)

        if [ -n "$temp" ] && is_numeric "$temp"; then
            if [ "$temp" -gt "$TEMP_CPU_CRITICAL" ] 2>/dev/null; then
                log_to_syslog "CRITICAL" "Temperature ${sensor_name}: ${temp}°C"
            elif [ "$temp" -gt "$TEMP_CPU_WARN" ] 2>/dev/null; then
                log_to_syslog "HIGH" "Temperature ${sensor_name}: ${temp}°C"
            else
                log_to_syslog "INFO" "Temperature ${sensor_name}: ${temp}°C"
            fi
        fi
    done

    # Monitor fans
    echo "$sensor_data" | grep -E "fan[0-9]+_input" | while read line; do
        local fan_name=$(echo "$line" | cut -d_ -f1)
        local rpm=$(echo "$line" | awk '{print $2}' | cut -d. -f1)

        if [ -n "$rpm" ] && is_numeric "$rpm"; then
            if [ "$rpm" -lt "$FAN_SPEED_WARN" ] && [ "$rpm" -gt 0 ] 2>/dev/null; then
                log_to_syslog "LOW" "Fan ${fan_name}: ${rpm} RPM (low)"
            elif [ "$rpm" -eq 0 ] 2>/dev/null; then
                log_to_syslog "HIGH" "Fan ${fan_name}: NOT RUNNING"
            else
                log_to_syslog "INFO" "Fan ${fan_name}: ${rpm} RPM"
            fi
        fi
    done
}

# =============================================================================
# SECTION 3: CPU Information
# =============================================================================

monitor_cpu() {
    log_to_syslog "INFO" "=== CPU information ==="

    if [ -f /proc/cpuinfo ]; then
        local cpu_model=$(grep "model name" /proc/cpuinfo | head -1 | cut -d: -f2 | xargs)
        local cpu_cores=$(grep -c "^processor" /proc/cpuinfo)

        if [ -n "$cpu_model" ]; then
            log_to_syslog "INFO" "CPU: ${cpu_model} (${cpu_cores} cores)"
        fi

        # Check for CPU throttling
        if [ -f /sys/devices/system/cpu/cpu0/cpufreq/scaling_cur_freq ] && \
           [ -f /sys/devices/system/cpu/cpu0/cpufreq/scaling_max_freq ]; then

            local current_freq=$(cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_cur_freq 2>/dev/null)
            local max_freq=$(cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_max_freq 2>/dev/null)

            if [ -n "$current_freq" ] && [ -n "$max_freq" ] && [ "$max_freq" -gt 0 ]; then
                local freq_percent=$((current_freq * 100 / max_freq))

                if [ "$freq_percent" -lt "$CPU_THROTTLE_WARN" ]; then
                    log_to_syslog "MEDIUM" "CPU throttling: ${freq_percent}% of max frequency"
                else
                    log_to_syslog "INFO" "CPU frequency: ${freq_percent}% of max"
                fi
            fi
        fi
    fi
}

# =============================================================================
# SECTION 4: Software RAID Monitoring
# =============================================================================

monitor_software_raid() {
    log_to_syslog "INFO" "=== Software RAID monitoring ==="

    if [ ! -f /proc/mdstat ]; then
        log_to_syslog "INFO" "No software RAID detected"
        return 1
    fi

    local raid_detected=0

    while read line; do
        if echo "$line" | grep -qE "^md[0-9]"; then
            raid_detected=1
            local raid_device=$(echo "$line" | awk '{print $1}')
            local raid_status=$(echo "$line" | grep -oE "\[[U_]+\]")

            if echo "$line" | grep -q "\[.*_.*\]"; then
                log_to_syslog "CRITICAL" "RAID ${raid_device} DEGRADED: ${raid_status}"
            elif echo "$line" | grep -q "resync\|recovery"; then
                local progress=$(echo "$line" | grep -oE "[0-9]+\.[0-9]+%")
                log_to_syslog "INFO" "RAID ${raid_device} rebuilding: ${progress}"
            else
                log_to_syslog "INFO" "RAID ${raid_device}: ${raid_status}"
            fi
        fi
    done < /proc/mdstat

    if [ $raid_detected -eq 0 ]; then
        log_to_syslog "INFO" "No RAID arrays configured"
    fi
}

# =============================================================================
# SECTION 5: Hardware RAID Controllers
# =============================================================================

monitor_hardware_raid() {
    if command_exists megacli; then
        log_to_syslog "INFO" "=== MegaRAID status ==="
        local raid_info=$(megacli -LDInfo -Lall -aAll 2>/dev/null)
        if [ -n "$raid_info" ]; then
            echo "$raid_info" | grep -E "Virtual Drive|State|Size" | while read line; do
                if echo "$line" | grep -qi "State.*Degraded\|State.*Offline"; then
                    log_to_syslog "CRITICAL" "  ${line}"
                else
                    log_to_syslog "INFO" "  ${line}"
                fi
            done
        fi
    fi

    if command_exists hpssacli; then
        log_to_syslog "INFO" "=== HP SmartArray status ==="
        local raid_info=$(hpssacli controller all show config 2>/dev/null)
        if [ -n "$raid_info" ]; then
            echo "$raid_info" | grep -E "Logical Drive|Status" | while read line; do
                if echo "$line" | grep -qi "Status: Failed\|Status: Degraded"; then
                    log_to_syslog "CRITICAL" "  ${line}"
                else
                    log_to_syslog "INFO" "  ${line}"
                fi
            done
        fi
    fi
}

# =============================================================================
# SECTION 6: ECC Memory Error Detection
# =============================================================================

monitor_ecc_memory() {
    log_to_syslog "INFO" "=== ECC memory monitoring ==="

    if command_exists mcelog && [ -f /var/log/mcelog ]; then
        local ecc_errors=$(grep -i "ECC\|corrected\|uncorrected" /var/log/mcelog 2>/dev/null | tail -10)

        if [ -n "$ecc_errors" ]; then
            if echo "$ecc_errors" | grep -qi "uncorrected"; then
                log_to_syslog "CRITICAL" "Uncorrected ECC memory errors!"
            else
                log_to_syslog "HIGH" "Corrected ECC memory errors detected"
            fi
        else
            log_to_syslog "INFO" "No ECC memory errors detected"
        fi
    fi

    # Check EDAC interface
    if [ -d /sys/devices/system/edac ]; then
        local ue_count=$(cat /sys/devices/system/edac/mc/mc0/ue_count 2>/dev/null)
        local ce_count=$(cat /sys/devices/system/edac/mc/mc0/ce_count 2>/dev/null)

        if [ -n "$ue_count" ] && [ "$ue_count" -gt 0 ]; then
            log_to_syslog "CRITICAL" "EDAC: ${ue_count} uncorrected errors"
        fi
        if [ -n "$ce_count" ] && [ "$ce_count" -gt 0 ]; then
            log_to_syslog "HIGH" "EDAC: ${ce_count} corrected errors"
        fi
    fi
}

# =============================================================================
# SECTION 7: Syslog Hardware Error Parsing (KORRIGIERT)
# =============================================================================

monitor_syslog_errors() {
    log_to_syslog "INFO" "=== System log hardware error analysis ==="

    local syslog_file="/var/log/syslog"

    if [ ! -f "$syslog_file" ] && [ -f "/var/log/messages" ]; then
        syslog_file="/var/log/messages"
    fi

    if [ -f "$syslog_file" ]; then
        # Search for hardware errors, EXCLUDING our own script's logs
        # Pattern matches: words that start with 'hardware error' or similar
        # But excludes lines containing 'hardware_monitor'
        local hw_errors=$(grep -E "(hardware error|machine check|EDAC|PCIe error|AER:|MCE)" "$syslog_file" 2>/dev/null | grep -v "hardware_monitor" | tail -10)

        if [ -n "$hw_errors" ]; then
            log_to_syslog "HIGH" "Hardware errors detected in system logs"
            echo "$hw_errors" | while read line; do
                # Truncate long lines and escape special characters
                local clean_line=$(echo "$line" | cut -c1-200 | sed 's/"/\\"/g')
                log_to_syslog "HIGH" "  ${clean_line}"
            done
        else
            log_to_syslog "INFO" "No hardware errors found in system logs (last 24h)"
        fi
    else
        log_to_syslog "INFO" "System log file not found"
    fi
}

# =============================================================================
# SECTION 8: Power Supply Monitoring
# =============================================================================

monitor_power_supply() {
    log_to_syslog "INFO" "=== Power supply status ==="

    if [ ! -d /sys/class/power_supply ]; then
        log_to_syslog "INFO" "No power supply information available"
        return 1
    fi

    local psu_detected=0

    for psu in /sys/class/power_supply/*; do
        if [ -d "$psu" ]; then
            local psu_name=$(basename "$psu")

            if [ -f "$psu/online" ]; then
                psu_detected=1
                local psu_online=$(cat "$psu/online" 2>/dev/null)

                if [ "$psu_online" = "1" ]; then
                    log_to_syslog "INFO" "Power supply ${psu_name}: ONLINE"
                else
                    log_to_syslog "CRITICAL" "Power supply ${psu_name}: OFFLINE/FAILED"
                fi
            fi
        fi
    done

    if [ $psu_detected -eq 0 ]; then
        log_to_syslog "INFO" "No power supply monitoring data available"
    fi
}

# =============================================================================
# MAIN EXECUTION
# =============================================================================

main() {
    local start_time=$(date +%s%3N)

    log_to_syslog "INFO" "Hardware health monitoring started"

    monitor_smart
    monitor_sensors
    monitor_cpu
    monitor_software_raid
    monitor_hardware_raid
    monitor_ecc_memory
    monitor_syslog_errors
    monitor_power_supply

    local end_time=$(date +%s%3N)
    local duration=$((end_time - start_time))

    log_to_syslog "INFO" "Hardware health monitoring completed (duration: ${duration}ms)"
}

main

exit 0
