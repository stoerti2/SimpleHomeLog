#!/bin/bash
# =============================================================================
# SimpleHomeLog SIEM - Filesystem Monitor
# =============================================================================
#
# Author:       Klaus Baumdick
# Date:         2026-05-23
# Version:      1.0.0
#
# Description:  This script checks the local filesystems and sends the info to the local syslog
#
# Usage: ./fs_check.sh
# Check: tail -n 20 /var/log/syslog | grep fs_monitor
# Crontab: */15 * * * * /path/to/fs_check.sh
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

WARNING_LOW=75
WARNING_MEDIUM=85
WARNING_HIGH=90
WARNING_CRITICAL=95
IGNORE_FS="tmpfs|devtmpfs|squashfs|overlay|fuse|udev|proc|sysfs|cgroup"
TAG="fs_monitor"

log_to_syslog() {
    case "$1" in
        "CRITICAL") logger -p user.crit -t "$TAG" "SimpleHomeLog: $1: $2" ;;
        "HIGH")     logger -p user.err -t "$TAG" "SimpleHomeLog: $1: $2" ;;
        "MEDIUM")   logger -p user.warning -t "$TAG" "SimpleHomeLog: $1: $2" ;;
        "LOW")      logger -p user.notice -t "$TAG" "SimpleHomeLog: $1: $2" ;;
        *)          logger -p user.info -t "$TAG" "SimpleHomeLog: $1: $2" ;;
    esac
}

get_severity() {
    if [ $1 -ge 95 ]; then echo "CRITICAL"
    elif [ $1 -ge 90 ]; then echo "HIGH"
    elif [ $1 -ge 85 ]; then echo "MEDIUM"
    elif [ $1 -ge 75 ]; then echo "LOW"
    else echo "INFO"; fi
}

log_to_syslog "INFO" "Filesystem check started"

df -hP 2>/dev/null | grep -vE "$IGNORE_FS" | tail -n +2 | while read line; do
    use_percent=$(echo $line | awk '{print $5}' | sed 's/%//')
    mountpoint=$(echo $line | awk '{print $6}')
    size=$(echo $line | awk '{print $2}')
    used=$(echo $line | awk '{print $3}')
    available=$(echo $line | awk '{print $4}')

    if [[ "$use_percent" =~ ^[0-9]+$ ]]; then
        severity=$(get_severity $use_percent)
        log_to_syslog "$severity" "$mountpoint - ${use_percent}% ($used of $size), free: $available"
        if [ "$severity" = "CRITICAL" ]; then
            logger -p user.emerg -t "$TAG" "SimpleHomeLog: CRITICAL: $mountpoint is ${use_percent}% full!"
        fi
    fi
done

log_to_syslog "INFO" "Filesystem check completed"
