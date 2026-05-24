#!/bin/bash
# =============================================================================
# SimpleHomeLog SIEM - Process Monitor
# =============================================================================
#
# Author:       Klaus Baumdick
# Date:         2026-05-24
# Version:      1.0.0
#
# Description:  This script monitors system processes, tracks resource usage,
#               detects anomalies (zombie processes, high CPU/memory), and
#               sends structured logs to syslog for SIEM collection.
#
# Features:     - Top CPU and memory consuming process monitoring
#               - Zombie process detection with alerting
#               - Total process count tracking
#               - Process state anomaly detection
#               - Severity-based syslog logging with PID in tag
#               - Cron-friendly operation with summary statistics
#               - Threshold-based alerting (CPU, memory, zombies, count)
#
# Thresholds:   - CPU_THRESHOLD=80%: Alert when single process exceeds 80% CPU
#               - MEM_THRESHOLD=70%: Alert when single process exceeds 70% RAM
#               - ZOMBIE_THRESHOLD=5: Alert when more than 5 zombie processes
#               - PROCESS_COUNT_WARN=500: Warn when total processes >500
#
# Severity Levels (mapped to syslog priorities):
#   - CRITICAL: High zombie process count (>5 zombies)
#   - HIGH:     Single process >80% CPU or >70% memory
#   - MEDIUM:   Total process count >500
#   - LOW:      Elevated but sub-threshold values
#   - INFO:     Normal operation, routine statistics
#
# Dependencies: ps (procps), logger (util-linux), standard Bash utilities
#               Most systems have these pre-installed
#
# Usage:        ./process_monitor.sh
# Check:        tail -f /var/log/syslog | grep process_monitor
# Crontab:      */5 * * * * /path/to/process_monitor.sh
#
# Installation: 1. Copy script to /usr/local/bin/process_monitor.sh
#               2. chmod +x /usr/local/bin/process_monitor.sh
#               3. Add to crontab: crontab -e
#
# Output:       Logs to syslog with format:
#               process_monitor[PID]: SimpleHomeLog: SEVERITY: message
#
# Notes:        - The PID in the tag allows the Perl SIEM collector to parse
#                 logs with the pattern prozess[PID]: message
#               - Empty lines and header lines are filtered from ps output
#               - Numeric comparisons handle missing values gracefully
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
# Format: process_monitor[PID] - allows Perl script to parse with prozess[PID] regex
TAG="process_monitor"

# Get current process ID for syslog tag
PID=$$

# Resource usage thresholds (adjust based on your environment)
CPU_THRESHOLD=80          # Alert if single process uses >80% CPU
MEM_THRESHOLD=70          # Alert if single process uses >70% memory
ZOMBIE_THRESHOLD=5        # Alert if more than 5 zombie processes
PROCESS_COUNT_WARN=500    # Warn if total processes exceed 500

# Number of top processes to report (default: 5)
TOP_PROCESSES=5

# Whether to show command arguments (set to 0 to show only basename)
SHOW_FULL_COMMAND=1

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

# Check if a value is numeric (integer or float)
# Arguments:
#   $1 - Value to check
# Returns: 0 if numeric, 1 otherwise
# =============================================================================
is_numeric() {
    [[ "$1" =~ ^[0-9]+(\.[0-9]+)?$ ]]
}

# Get CPU usage percentage from ps output
# Handles both integer and float values gracefully
# =============================================================================
get_cpu_value() {
    local value="$1"
    # Remove decimal part if present for comparison
    echo "$value" | cut -d. -f1
}

# Get memory usage percentage from ps output
# =============================================================================
get_mem_value() {
    local value="$1"
    echo "$value" | cut -d. -f1
}

# Truncate command string to reasonable length
# =============================================================================
truncate_command() {
    local cmd="$1"
    local max_len="${2:-100}"
    if [ ${#cmd} -gt "$max_len" ]; then
        echo "${cmd:0:$max_len}..."
    else
        echo "$cmd"
    fi
}

# Get command string from ps output (handles arguments based on config)
# =============================================================================
get_command_string() {
    local line="$1"

    if [ "$SHOW_FULL_COMMAND" -eq 1 ]; then
        # Show command with arguments (fields 11+)
        echo "$line" | awk '{for(i=11;i<=NF;i++) printf "%s ", $i; print ""}' | sed 's/[[:space:]]*$//' | cut -c1-100
    else
        # Show only command name (field 11 only)
        echo "$line" | awk '{print $11}' | xargs basename 2>/dev/null | cut -c1-50
    fi
}

# =============================================================================
# MAIN EXECUTION
# =============================================================================

# Record start time for performance monitoring
START_TIME=$(date +%s%3N)

# Log monitoring session start
log_to_syslog "INFO" "Process monitoring started"

# =============================================================================
# SECTION 1: Top CPU Consumers
# =============================================================================
log_to_syslog "INFO" "=== Top ${TOP_PROCESSES} CPU consuming processes ==="

# Get top CPU processes, skip header, limit to TOP_PROCESSES
ps aux --sort=-%cpu 2>/dev/null | head -$((TOP_PROCESSES + 1)) | tail -$TOP_PROCESSES | while read line; do
    # Skip empty lines
    [ -z "$line" ] && continue

    # Extract process information
    cpu_raw=$(echo "$line" | awk '{print $3}')
    cpu=$(get_cpu_value "$cpu_raw")
    pid=$(echo "$line" | awk '{print $2}')
    cmd=$(get_command_string "$line")

    # Validate CPU value is numeric
    if is_numeric "$cpu"; then
        if [ "$cpu" -gt "$CPU_THRESHOLD" ] 2>/dev/null; then
            log_to_syslog "HIGH" "High CPU usage: ${cpu}% - PID:${pid} - ${cmd}"
        else
            log_to_syslog "INFO" "CPU: ${cpu}% - PID:${pid} - ${cmd}"
        fi
    else
        log_to_syslog "INFO" "CPU: N/A - PID:${pid} - ${cmd}"
    fi
done

# =============================================================================
# SECTION 2: Top Memory Consumers
# =============================================================================
log_to_syslog "INFO" "=== Top ${TOP_PROCESSES} memory consuming processes ==="

# Get top memory processes, skip header, limit to TOP_PROCESSES
ps aux --sort=-%mem 2>/dev/null | head -$((TOP_PROCESSES + 1)) | tail -$TOP_PROCESSES | while read line; do
    # Skip empty lines
    [ -z "$line" ] && continue

    # Extract process information
    mem_raw=$(echo "$line" | awk '{print $4}')
    mem=$(get_mem_value "$mem_raw")
    pid=$(echo "$line" | awk '{print $2}')
    cmd=$(get_command_string "$line")

    # Validate memory value is numeric
    if is_numeric "$mem"; then
        if [ "$mem" -gt "$MEM_THRESHOLD" ] 2>/dev/null; then
            log_to_syslog "HIGH" "High memory usage: ${mem}% - PID:${pid} - ${cmd}"
        else
            log_to_syslog "INFO" "MEM: ${mem}% - PID:${pid} - ${cmd}"
        fi
    else
        log_to_syslog "INFO" "MEM: N/A - PID:${pid} - ${cmd}"
    fi
done

# =============================================================================
# SECTION 3: Zombie Process Detection
# =============================================================================
log_to_syslog "INFO" "=== Zombie process detection ==="

# Count zombie processes (state 'Z')
zombie_count=$(ps aux 2>/dev/null | awk '$8=="Z"' | grep -v "grep" | wc -l)
zombie_count=$(echo "$zombie_count" | tr -d ' ')

if is_numeric "$zombie_count"; then
    if [ "$zombie_count" -gt "$ZOMBIE_THRESHOLD" ] 2>/dev/null; then
        log_to_syslog "CRITICAL" "High zombie process count: ${zombie_count}"

        # Log details of each zombie process
        ps aux 2>/dev/null | awk '$8=="Z"' | grep -v "grep" | while read line; do
            [ -z "$line" ] && continue
            pid=$(echo "$line" | awk '{print $2}')
            cmd=$(get_command_string "$line")
            log_to_syslog "CRITICAL" "Zombie process - PID:${pid} - ${cmd}"
        done
    else
        log_to_syslog "INFO" "Zombie processes: ${zombie_count}"
    fi
else
    log_to_syslog "WARNING" "Could not determine zombie process count"
fi

# =============================================================================
# SECTION 4: Total Process Count
# =============================================================================
log_to_syslog "INFO" "=== Total process statistics ==="

# Count total processes (including all states)
proc_count=$(ps aux 2>/dev/null | wc -l)
proc_count=$(echo "$proc_count" | tr -d ' ')

if is_numeric "$proc_count"; then
    if [ "$proc_count" -gt "$PROCESS_COUNT_WARN" ] 2>/dev/null; then
        log_to_syslog "MEDIUM" "High process count: ${proc_count} processes running"
    else
        log_to_syslog "INFO" "Total processes: ${proc_count}"
    fi
else
    log_to_syslog "WARNING" "Could not determine total process count"
fi

# =============================================================================
# SECTION 5: Process State Summary
# =============================================================================
log_to_syslog "INFO" "=== Process state summary ==="

# Count processes by state (R=running, S=sleeping, D=uninterruptible, etc.)
if [ -f /proc/stat ] || [ -d /proc ]; then
    running=$(ps aux 2>/dev/null | awk '$8 ~ /^R/' | grep -v "grep" | wc -l)
    sleeping=$(ps aux 2>/dev/null | awk '$8 ~ /^S/' | grep -v "grep" | wc -l)
    stopped=$(ps aux 2>/dev/null | awk '$8 ~ /^T/' | grep -v "grep" | wc -l)

    running=$(echo "$running" | tr -d ' ')
    sleeping=$(echo "$sleeping" | tr -d ' ')
    stopped=$(echo "$stopped" | tr -d ' ')

    log_to_syslog "INFO" "Process states - Running: ${running}, Sleeping: ${sleeping}, Stopped: ${stopped}"
fi

# =============================================================================
# SECTION 6: Process Monitoring Summary
# =============================================================================

# Calculate monitoring duration
END_TIME=$(date +%s%3N)
DURATION=$((END_TIME - START_TIME))

# Log completion with duration
log_to_syslog "INFO" "Process monitoring completed (duration: ${DURATION}ms)"

# Exit with success
exit 0

# =============================================================================
# CRONTAB ENTRY
# =============================================================================
# Run every 5 minutes for timely process monitoring
# */5 * * * * /usr/local/bin/process_monitor.sh
#
# For less frequent monitoring (every 15 minutes):
# */15 * * * * /usr/local/bin/process_monitor.sh
#
# With logging to dedicated file:
# */5 * * * * /path/to/process_monitor.sh >> /var/log/process_monitor.log 2>&1
#
# For root user (recommended for full process visibility):
# sudo crontab -e
#
# =============================================================================
