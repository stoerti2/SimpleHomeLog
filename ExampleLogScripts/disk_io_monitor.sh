#!/bin/bash
# =============================================================================
# SimpleHomeLog SIEM - Disk I/O Performance Monitor
# =============================================================================
#
# Author:       Klaus Baumdick
# Date:         2026-05-24
# Version:      1.0.0
#
# Description:  Comprehensive disk I/O performance monitoring for SIEM.
#               Tracks I/O wait, disk throughput, latency, and inode usage.
#               Detects performance bottlenecks and potential disk failures.
#
# Features:     - CPU I/O wait percentage monitoring (system-wide)
#               - Per-disk I/O statistics (TPS, read/write speed)
#               - Disk latency measurement with alerting
#               - Inode usage monitoring (often forgotten but critical!)
#               - Support for multiple disk types (SATA, SAS, NVMe)
#               - Fallback to /proc/stat when iostat not available
#               - Severity-based alerting for SIEM integration
#               - PID in syslog tag for Perl collector compatibility
#
# Thresholds:   - I/O Wait: WARN >10%, CRITICAL >25%
#               - Disk Latency: WARN >100ms
#               - Inode Usage: WARN >75%, CRITICAL >90%
#
# Severity Levels:
#   - CRITICAL: I/O wait >25%, inode usage >90%
#   - HIGH:     I/O wait >10%, disk latency >100ms, inode usage >75%
#   - MEDIUM:   Elevated values (reserved)
#   - LOW:      Minor issues (reserved)
#   - INFO:     Normal operation, routine statistics
#
# Dependencies: iostat (sysstat package), mpstat (sysstat package)
#               Fallback: /proc/stat (always available)
#
# Installation: Debian/Ubuntu: apt install sysstat
#               RHEL/CentOS: yum install sysstat
#               Enable iostat collection: systemctl enable sysstat
#
# Usage:        ./disk_io_monitor.sh
# Check:        tail -f /var/log/syslog | grep disk_io_monitor
# Crontab:      */10 * * * * /path/to/disk_io_monitor.sh
#
# Notes:        - First run of iostat may show zeros (needs sample interval)
#               - Some virtualization platforms may not expose all disk metrics
#               - NVMe drives use different device naming (nvme0n1, etc.)
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

# Syslog tag with PID placeholder for Perl SIEM collector compatibility
TAG="disk_io_monitor"

# Get current process ID for syslog tag
PID=$$

# Thresholds for I/O wait percentage (CPU time spent waiting for I/O)
IO_WAIT_WARN=10        # Warning at 10% I/O wait
IO_WAIT_CRIT=25        # Critical at 25% I/O wait

# Threshold for disk latency in milliseconds
# High latency indicates slow disk responses or overloaded storage
LATENCY_WARN=100       # Warning when disk latency exceeds 100ms

# Thresholds for inode usage percentage
# Inodes are file system metadata slots - running out prevents new files
INODE_WARN=75          # Warning when inode usage exceeds 75%
INODE_CRIT=90          # Critical when inode usage exceeds 90%

# Filesystem types to ignore in inode monitoring
# These are pseudo-filesystems that don't have real inode limits
IGNORE_FS_TYPES="tmpfs|devtmpfs|squashfs|overlay|fuse|udev|proc|sysfs|cgroup"

# Disk device patterns to monitor
# Adjust based on your storage hardware
DISK_PATTERNS="^sd[a-z]$|^hd[a-z]$|^vd[a-z]$|^nvme[0-9]n[0-9]$|^xvd[a-z]$"

# Whether to show detailed per-disk statistics
SHOW_DETAILED_STATS=1

# =============================================================================
# FUNCTIONS
# =============================================================================

# Log message to syslog with PID in tag (for Perl SIEM collector compatibility)
# Arguments:
#   $1 - Severity level (CRITICAL, HIGH, MEDIUM, LOW, INFO)
#   $2 - Message to log
# Returns: None
# =============================================================================
log_to_syslog() {
    local severity="$1"
    local message="$2"

    # Map severity to syslog priority and log with PID in tag
    case "$severity" in
        "CRITICAL")
            logger -p user.crit -t "${TAG}[${PID}]" "SimpleHomeLog: CRITICAL: $message"
            ;;
        "HIGH")
            logger -p user.err -t "${TAG}[${PID}]" "SimpleHomeLog: HIGH: $message"
            ;;
        "MEDIUM")
            logger -p user.warning -t "${TAG}[${PID}]" "SimpleHomeLog: MEDIUM: $message"
            ;;
        "LOW")
            logger -p user.notice -t "${TAG}[${PID}]" "SimpleHomeLog: LOW: $message"
            ;;
        *)
            logger -p user.info -t "${TAG}[${PID}]" "SimpleHomeLog: INFO: $message"
            ;;
    esac
}

# Check if a command exists and is executable
# Arguments:
#   $1 - Command name to check
# Returns: 0 if exists, 1 otherwise
# =============================================================================
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Check if a value is numeric
# Arguments:
#   $1 - Value to check
# Returns: 0 if numeric, 1 otherwise
# =============================================================================
is_numeric() {
    [[ "$1" =~ ^[0-9]+(\.[0-9]+)?$ ]]
}

# =============================================================================
# SECTION 1: I/O Wait Monitoring
# =============================================================================

monitor_iowait() {
    log_to_syslog "INFO" "=== I/O Wait Monitoring ==="

    local iowait=""

    # Try mpstat first (part of sysstat package)
    if command_exists mpstat; then
        # mpstat 1 1: Sample for 1 second, 1 interval
        local mpstat_output=$(mpstat 1 1 2>/dev/null)

        if [ -n "$mpstat_output" ]; then
            # Get the last line (average) and extract iowait column
            # Column 12 is %iowait in mpstat output
            iowait=$(echo "$mpstat_output" | tail -1 | awk '{print $12}' | cut -d. -f1)

            # Validate iowait is numeric
            if is_numeric "$iowait"; then
                if [ "$iowait" -ge "$IO_WAIT_CRIT" ] 2>/dev/null; then
                    log_to_syslog "CRITICAL" "System I/O wait: ${iowait}% (threshold: ${IO_WAIT_CRIT}%)"
                elif [ "$iowait" -ge "$IO_WAIT_WARN" ] 2>/dev/null; then
                    log_to_syslog "HIGH" "System I/O wait: ${iowait}% (threshold: ${IO_WAIT_WARN}%)"
                else
                    log_to_syslog "INFO" "System I/O wait: ${iowait}%"
                fi
                return 0
            fi
        fi
    fi

    # Fallback: Use /proc/stat for I/O wait ticks (raw counters)
    if [ -f /proc/stat ]; then
        # Get CPU statistics line
        local cpu_line=$(grep "^cpu " /proc/stat 2>/dev/null)

        if [ -n "$cpu_line" ]; then
            # Fields: user nice system idle iowait irq softirq steal guest guest_nice
            local iowait_ticks=$(echo "$cpu_line" | awk '{print $6}')
            local total_ticks=$(echo "$cpu_line" | awk '{sum=0; for(i=2;i<=NF;i++) sum+=$i; print sum}')

            if [ -n "$iowait_ticks" ] && [ -n "$total_ticks" ] && [ "$total_ticks" -gt 0 ]; then
                local iowait_percent=$((iowait_ticks * 100 / total_ticks))

                log_to_syslog "INFO" "I/O wait ticks: ${iowait_ticks} (${iowait_percent}% of CPU time)"

                if [ "$iowait_percent" -ge "$IO_WAIT_CRIT" ] 2>/dev/null; then
                    log_to_syslog "CRITICAL" "System I/O wait (estimated): ${iowait_percent}%"
                elif [ "$iowait_percent" -ge "$IO_WAIT_WARN" ] 2>/dev/null; then
                    log_to_syslog "HIGH" "System I/O wait (estimated): ${iowait_percent}%"
                fi
            else
                log_to_syslog "INFO" "Could not calculate I/O wait percentage from /proc/stat"
            fi
        else
            log_to_syslog "INFO" "No I/O wait data available (mpstat not installed, /proc/stat not readable)"
        fi
    else
        log_to_syslog "INFO" "No I/O wait data available - install sysstat package for detailed metrics"
    fi
}

# =============================================================================
# SECTION 2: Disk I/O Statistics (iostat)
# =============================================================================

monitor_disk_io() {
    if [ "$SHOW_DETAILED_STATS" != "1" ]; then
        return 0
    fi

    log_to_syslog "INFO" "=== Disk I/O Statistics ==="

    if ! command_exists iostat; then
        log_to_syslog "INFO" "iostat not installed - install sysstat package for disk I/O stats"
        return 1
    fi

    # Run iostat twice: first sample may be from boot (invalid), second is current
    # We use 2 intervals and take the second one
    local iostat_output=$(iostat -x 1 2 2>/dev/null)

    if [ -z "$iostat_output" ]; then
        log_to_syslog "INFO" "No iostat output available"
        return 1
    fi

    # Skip header lines and process device lines from the second sample
    local device_section=0
    local device_count=0

    while read line; do
        # Skip empty lines
        [ -z "$line" ] && continue

        # Detect start of device statistics (after header)
        if echo "$line" | grep -q "Device:"; then
            device_section=1
            continue
        fi

        # Only process device lines
        if [ $device_section -eq 1 ]; then
            # Get device name (first column)
            local device=$(echo "$line" | awk '{print $1}')

            # Check if this is a real disk device (not a partition or loop)
            if [[ "$device" =~ $DISK_PATTERNS ]]; then
                device_count=$((device_count + 1))

                # Extract I/O statistics
                # Column meanings for iostat -x:
                # 1: Device, 2: rrqm/s, 3: wrqm/s, 4: r/s, 5: w/s, 6: rMB/s, 7: wMB/s,
                # 8: avgrq-sz, 9: avgqu-sz, 10: await, 11: r_await, 12: w_await, 13: svctm, 14: %util
                local tps=$(echo "$line" | awk '{print $4 + $5}')  # r/s + w/s
                local read_mb=$(echo "$line" | awk '{print $6}')
                local write_mb=$(echo "$line" | awk '{print $7}')
                local await=$(echo "$line" | awk '{print $10}' | cut -d. -f1)
                local util=$(echo "$line" | awk '{print $14}' | cut -d. -f1)

                # Default values if empty
                [ -z "$tps" ] && tps="0"
                [ -z "$read_mb" ] && read_mb="0"
                [ -z "$write_mb" ] && write_mb="0"
                [ -z "$await" ] && await="0"
                [ -z "$util" ] && util="0"

                # Check for high latency
                if is_numeric "$await" && [ "${await%.*}" -ge "$LATENCY_WARN" ] 2>/dev/null; then
                    log_to_syslog "HIGH" "High disk latency on ${device}: ${await}ms"
                fi

                # Check for high utilization
                if is_numeric "$util" && [ "${util%.*}" -gt 90 ] 2>/dev/null; then
                    log_to_syslog "HIGH" "Disk ${device} utilization: ${util}%"
                fi

                # Log detailed stats
                log_to_syslog "INFO" "${device}: TPS=${tps}, Read=${read_mb}MB/s, Write=${write_mb}MB/s, Latency=${await}ms, Util=${util}%"
            fi
        fi
    done <<< "$iostat_output"

    if [ $device_count -eq 0 ]; then
        log_to_syslog "INFO" "No disk devices found matching patterns"
    fi
}

# =============================================================================
# SECTION 3: Inode Usage Monitoring
# =============================================================================

monitor_inode_usage() {
    log_to_syslog "INFO" "=== Inode Usage Monitoring ==="

    # Get inode usage for all mounted filesystems
    local df_output=$(df -i 2>/dev/null | grep -vE "$IGNORE_FS_TYPES")

    if [ -z "$df_output" ]; then
        log_to_syslog "INFO" "No filesystems found for inode monitoring"
        return 1
    fi

    # Skip header line and process each filesystem
    local critical_fs=""
    local warning_fs=""
    local fs_count=0

    echo "$df_output" | tail -n +2 | while read line; do
        [ -z "$line" ] && continue

        local inodes_used=$(echo "$line" | awk '{print $5}' | sed 's/%//')
        local mount=$(echo "$line" | awk '{print $6}')
        local filesystem=$(echo "$line" | awk '{print $1}')
        local inodes_total=$(echo "$line" | awk '{print $2}')

        # Skip if inodes_used is not numeric
        if ! is_numeric "$inodes_used"; then
            continue
        fi

        fs_count=$((fs_count + 1))

        # Check thresholds
        if [ "$inodes_used" -ge "$INODE_CRIT" ] 2>/dev/null; then
            log_to_syslog "CRITICAL" "Inode usage CRITICAL on ${mount} (${filesystem}): ${inodes_used}% (${inodes_total} inodes total)"
            critical_fs="${critical_fs} ${mount}"
        elif [ "$inodes_used" -ge "$INODE_WARN" ] 2>/dev/null; then
            log_to_syslog "HIGH" "Inode usage HIGH on ${mount} (${filesystem}): ${inodes_used}%"
            warning_fs="${warning_fs} ${mount}"
        else
            log_to_syslog "INFO" "Inode usage on ${mount}: ${inodes_used}% (${inodes_total} inodes)"
        fi
    done

    if [ $fs_count -eq 0 ]; then
        log_to_syslog "INFO" "No filesystems found for inode monitoring"
    fi
}

# =============================================================================
# SECTION 4: Disk Health Summary
# =============================================================================

monitor_disk_summary() {
    log_to_syslog "INFO" "=== Disk Health Summary ==="

    # Get disk usage summary
    local disk_usage=$(df -h 2>/dev/null | grep -vE "$IGNORE_FS_TYPES" | tail -n +2)

    if [ -n "$disk_usage" ]; then
        echo "$disk_usage" | while read line; do
            local usage=$(echo "$line" | awk '{print $5}' | sed 's/%//')
            local mount=$(echo "$line" | awk '{print $6}')
            local size=$(echo "$line" | awk '{print $2}')
            local used=$(echo "$line" | awk '{print $3}')
            local avail=$(echo "$line" | awk '{print $4}')

            if is_numeric "$usage"; then
                if [ "$usage" -ge 95 ] 2>/dev/null; then
                    log_to_syslog "CRITICAL" "Disk usage CRITICAL on ${mount}: ${usage}% (${used}/${size}, free: ${avail})"
                elif [ "$usage" -ge 90 ] 2>/dev/null; then
                    log_to_syslog "HIGH" "Disk usage HIGH on ${mount}: ${usage}% (${used}/${size})"
                else
                    log_to_syslog "INFO" "Disk usage on ${mount}: ${usage}% (${used}/${size})"
                fi
            fi
        done
    fi
}

# =============================================================================
# MAIN EXECUTION
# =============================================================================

main() {
    # Record start time for performance monitoring
    local start_time=$(date +%s%3N)

    # Log monitoring session start
    log_to_syslog "INFO" "Disk I/O performance monitoring started"
    log_to_syslog "INFO" "Host: $(hostname)"

    # Execute all monitoring modules
    monitor_iowait
    monitor_disk_io
    monitor_inode_usage
    monitor_disk_summary

    # Calculate and log duration
    local end_time=$(date +%s%3N)
    local duration=$((end_time - start_time))

    # Log monitoring session completion
    log_to_syslog "INFO" "Disk I/O performance monitoring completed (duration: ${duration}ms)"
}

# Run main function
main

exit 0

# =============================================================================
# CRONTAB ENTRIES
# =============================================================================
# Run every 10 minutes for regular disk I/O monitoring (recommended):
# */10 * * * * /usr/local/bin/disk_io_monitor.sh
#
# Run every 5 minutes for high-performance/critical systems:
# */5 * * * * /usr/local/bin/disk_io_monitor.sh
#
# Run every 30 minutes for basic monitoring:
# */30 * * * * /usr/local/bin/disk_io_monitor.sh
#
# With logging to dedicated file:
# */10 * * * * /usr/local/bin/disk_io_monitor.sh >> /var/log/disk_io_monitor.log 2>&1
#
# For root user (required for /proc/stat access):
# sudo crontab -e
#
# =============================================================================
