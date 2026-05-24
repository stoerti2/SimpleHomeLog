#!/bin/bash
# =============================================================================
# SimpleHomeLog SIEM - Load Average Monitor
# =============================================================================
#
# Author:       Klaus Baumdick
# Date:         2026-05-24
# Version:      1.0.0
#
# Description:  This script checks the system load average and sends alerts to syslog
#               Format: load_monitor[PID]
#
# Thresholds:   LOW: > 1.0, MEDIUM: > 2.0, HIGH: > 4.0, CRITICAL: > 8.0
#
# Usage: ./load_check.sh
# Check: tail -n 20 /var/log/syslog | grep load_monitor
# Crontab: */5 * * * * /path/to/load_check.sh (all 5 minutes)
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
# KONFIGURATION
# =============================================================================
TAG="load_monitor"
WARNING_LOW=1.0
WARNING_MEDIUM=2.0
WARNING_HIGH=4.0
WARNING_CRITICAL=8.0

# Anzahl der CPU-Kerne für normalisierte Load-Average (optional)
# 0 = deaktiviert, sonst wird load durch CPU-Kerne geteilt
NORMALIZE_BY_CPU=0

# =============================================================================
# FUNKTIONEN
# =============================================================================

# Log-Funktion mit PID im Tag (für Perl Parser Kompatibilität)
log_to_syslog() {
    local pid=$$

    case "$1" in
        "CRITICAL") logger -p user.crit -t "${TAG}[${pid}]" "SimpleHomeLog: $1: $2" ;;
        "HIGH")     logger -p user.err -t "${TAG}[${pid}]" "SimpleHomeLog: $1: $2" ;;
        "MEDIUM")   logger -p user.warning -t "${TAG}[${pid}]" "SimpleHomeLog: $1: $2" ;;
        "LOW")      logger -p user.notice -t "${TAG}[${pid}]" "SimpleHomeLog: $1: $2" ;;
        *)          logger -p user.info -t "${TAG}[${pid}]" "SimpleHomeLog: $1: $2" ;;
    esac
}

# Severity basierend auf Load-Average bestimmen
get_severity() {
    local load=$1

    if (( $(echo "$load >= $WARNING_CRITICAL" | bc -l) )); then
        echo "CRITICAL"
    elif (( $(echo "$load >= $WARNING_HIGH" | bc -l) )); then
        echo "HIGH"
    elif (( $(echo "$load >= $WARNING_MEDIUM" | bc -l) )); then
        echo "MEDIUM"
    elif (( $(echo "$load >= $WARNING_LOW" | bc -l) )); then
        echo "LOW"
    else
        echo "INFO"
    fi
}

# Anzahl der CPU-Kerne ermitteln
get_cpu_cores() {
    if [ -f /proc/cpuinfo ]; then
        grep -c ^processor /proc/cpuinfo
    else
        echo 1
    fi
}

# Load-Average normalisieren (durch CPU-Kerne teilen)
normalize_load() {
    local load=$1
    local cores=$2

    if [ $NORMALIZE_BY_CPU -eq 1 ] && [ $cores -gt 0 ]; then
        echo "scale=2; $load / $cores" | bc
    else
        echo $load
    fi
}

# =============================================================================
# HAUPT PROGRAMM
# =============================================================================

# CPU-Kerne ermitteln
CPU_CORES=$(get_cpu_cores)
log_to_syslog "INFO" "Load average check started (CPU cores: $CPU_CORES)"

# Load-Average aus /proc/loadavg holen
if [ -f /proc/loadavg ]; then
    read load1 load5 load15 rest < /proc/loadavg

    # Optional: Load normalisieren
    if [ $NORMALIZE_BY_CPU -eq 1 ]; then
        load1_norm=$(normalize_load $load1 $CPU_CORES)
        load5_norm=$(normalize_load $load5 $CPU_CORES)
        load15_norm=$(normalize_load $load15 $CPU_CORES)
        log_msg="1min: ${load1_norm} (norm), 5min: ${load5_norm} (norm), 15min: ${load15_norm} (norm) | raw: ${load1}, ${load5}, ${load15}"
    else
        log_msg="1min: ${load1}, 5min: ${load5}, 15min: ${load15}"
    fi

    # Severity basierend auf 1-Minuten Load
    severity=$(get_severity $load1)

    # Log mit Severity
    log_to_syslog "$severity" "$log_msg"

    # Zusätzliche CRITICAL Warnung
    if [ "$severity" = "CRITICAL" ]; then
        logger -p user.emerg -t "${TAG}[$$]" "SimpleHomeLog: CRITICAL: System load is ${load1} (15min: ${load15}) on ${CPU_CORES} CPU cores!"

        # Zusätzliche Details für kritische Last
        if command -v top >/dev/null 2>&1; then
            top -b -n 1 -o %CPU | head -n 20 | while read line; do
                logger -p user.err -t "${TAG}[$$]" "SimpleHomeLog: CRITICAL-DETAIL: $line"
            done
        fi
    fi

    # HIGH Warnung mit mehr Details
    if [ "$severity" = "HIGH" ]; then
        logger -p user.warning -t "${TAG}[$$]" "SimpleHomeLog: HIGH: High system load detected (${load1})"

        # Top 5 Prozesse anzeigen
        if command -v ps >/dev/null 2>&1; then
            ps aux --sort=-%cpu | head -n 6 | tail -n 5 | while read line; do
                logger -p user.warning -t "${TAG}[$$]" "SimpleHomeLog: HIGH-TOP5: $line"
            done
        fi
    fi

else
    log_to_syslog "ERROR" "Cannot read /proc/loadavg - load average check failed"
fi

log_to_syslog "INFO" "Load average check completed"

# =============================================================================
# ZUSATZ: Speicher-Informationen (optional)
# =============================================================================

# Speichernutzung auch loggen (optional)
if [ -f /proc/meminfo ]; then
    MEM_TOTAL=$(grep MemTotal /proc/meminfo | awk '{print $2}')
    MEM_AVAILABLE=$(grep MemAvailable /proc/meminfo | awk '{print $2}')
    MEM_PERCENT=$(( (MEM_TOTAL - MEM_AVAILABLE) * 100 / MEM_TOTAL ))

    if [ $MEM_PERCENT -gt 90 ]; then
        log_to_syslog "HIGH" "Memory usage: ${MEM_PERCENT}% (${MEM_AVAILABLE}KB available of ${MEM_TOTAL}KB total)"
    elif [ $MEM_PERCENT -gt 75 ]; then
        log_to_syslog "MEDIUM" "Memory usage: ${MEM_PERCENT}% (${MEM_AVAILABLE}KB available of ${MEM_TOTAL}KB total)"
    else
        log_to_syslog "INFO" "Memory usage: ${MEM_PERCENT}% (${MEM_AVAILABLE}KB available of ${MEM_TOTAL}KB total)"
    fi
fi
