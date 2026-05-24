#!/bin/bash
# =============================================================================
# SimpleHomeLog SIEM - Web Server Log Aggregator (Apache Version)
# =============================================================================
#
# Author:       Klaus Baumdick
# Date:         2026-05-24
# Version:      1.0.0
#
# Description:  Aggregates Apache web server access logs and sends summary
#               statistics to syslog for SIEM collection.
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

TAG="webserver_logs"
PID=$$

# Log file to analyze (your actual log file)
LOG_FILE="/var/log/apache2/other_vhosts_access.log"

# Alternative if the above is empty
if [ ! -s "$LOG_FILE" ]; then
    LOG_FILE="/var/log/apache2/access.log"
fi

# Time range to analyze (in minutes)
TIME_RANGE_MINUTES=60

# Thresholds
MAX_REQUESTS_PER_IP=500
ERROR_RATE_4XX_WARN=10
ERROR_RATE_4XX_CRIT=20
ERROR_RATE_5XX_WARN=5
ERROR_RATE_5XX_CRIT=10

TOP_IPS_COUNT=10
TOP_URLS_COUNT=10

# =============================================================================
# FUNCTIONS
# =============================================================================

log_to_syslog() {
    local severity="$1"
    local message="$2"

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

# Extract timestamp from log line and check if within range
is_recent_log() {
    local line="$1"
    local current_hour=$(date +%H)
    local current_min=$(date +%M)

    # Extract timestamp from format: [24/May/2026:00:00:46 +0200]
    if [[ "$line" =~ \[([0-9]{2})/([A-Za-z]{3})/([0-9]{4}):([0-9]{2}):([0-9]{2}):([0-9]{2}) ]]; then
        local hour="${BASH_REMATCH[4]}"
        local min="${BASH_REMATCH[5]}"

        # For simplicity, check if within last hour
        # Compare hour (handle day boundary would be complex, so we check last hour only)
        if [ "$hour" -eq "$current_hour" ]; then
            return 0
        elif [ "$hour" -eq $((current_hour - 1)) ] && [ "${current_min#0}" -lt 60 ]; then
            return 0
        elif [ "$hour" -eq 23 ] && [ "$current_hour" -eq 0 ]; then
            return 0
        fi
    fi

    # If no timestamp found or outside range, include anyway (fallback)
    return 0
}

# Extract IP address from line (handles "127.0.1.1:80" format)
extract_ip() {
    local line="$1"
    # Extract IP before colon if present, or just the first field
    local ip=$(echo "$line" | awk '{print $1}' | cut -d: -f1)
    echo "$ip"
}

# Extract status code
extract_status() {
    local line="$1"
    # Status is the 8th field in your log format
    local status=$(echo "$line" | awk '{print $9}')
    # Handle cases where status might be missing
    if [[ ! "$status" =~ ^[0-9]{3}$ ]]; then
        status="000"
    fi
    echo "$status"
}

# Extract URL (method and path)
extract_url() {
    local line="$1"
    # Extract from quotes: "GET /path HTTP/1.1"
    if [[ "$line" =~ \"(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH)\ ([^\ ]+) ]]; then
        echo "${BASH_REMATCH[2]}"
    else
        echo "unknown"
    fi
}

# Extract response size
extract_size() {
    local line="$1"
    # Size is the 10th field
    local size=$(echo "$line" | awk '{print $10}')
    echo "$size"
}

# =============================================================================
# MAIN
# =============================================================================

log_to_syslog "INFO" "Webserver log aggregation started (last ${TIME_RANGE_MINUTES} minutes)"

# Check if log file exists
if [ ! -f "$LOG_FILE" ]; then
    log_to_syslog "ERROR" "Log file not found: ${LOG_FILE}"
    exit 1
fi

log_to_syslog "INFO" "Using log file: ${LOG_FILE}"

# Get recent logs
TEMP_FILE=$(mktemp)
trap "rm -f $TEMP_FILE" EXIT

# Read recent logs and filter by time
while IFS= read -r line; do
    if [ -n "$line" ]; then
        echo "$line" >> "$TEMP_FILE"
    fi
done < <(tail -n 5000 "$LOG_FILE" 2>/dev/null)

total_requests=$(wc -l < "$TEMP_FILE")

if [ "$total_requests" -eq 0 ]; then
    log_to_syslog "INFO" "No web server log entries found"
    exit 0
fi

log_to_syslog "INFO" "Analyzing ${total_requests} requests"

# =============================================================================
# STATUS CODE DISTRIBUTION
# =============================================================================

log_to_syslog "INFO" "=== HTTP Status Code Distribution ==="

status_2xx=0
status_3xx=0
status_4xx=0
status_5xx=0

while IFS= read -r line; do
    status=$(extract_status "$line")
    case "$status" in
        2??) status_2xx=$((status_2xx + 1)) ;;
        3??) status_3xx=$((status_3xx + 1)) ;;
        4??) status_4xx=$((status_4xx + 1)) ;;
        5??) status_5xx=$((status_5xx + 1)) ;;
    esac
done < "$TEMP_FILE"

if [ "$total_requests" -gt 0 ]; then
    pct_2xx=$((status_2xx * 100 / total_requests))
    pct_3xx=$((status_3xx * 100 / total_requests))
    pct_4xx=$((status_4xx * 100 / total_requests))
    pct_5xx=$((status_5xx * 100 / total_requests))

    log_to_syslog "INFO" "2xx Success: ${status_2xx} (${pct_2xx}%)"
    log_to_syslog "INFO" "3xx Redirect: ${status_3xx} (${pct_3xx}%)"
    log_to_syslog "INFO" "4xx Client Error: ${status_4xx} (${pct_4xx}%)"
    log_to_syslog "INFO" "5xx Server Error: ${status_5xx} (${pct_5xx}%)"

    # Alerts
    if [ "$pct_5xx" -ge "$ERROR_RATE_5XX_CRIT" ]; then
        log_to_syslog "CRITICAL" "High 5xx error rate: ${pct_5xx}%"
    elif [ "$pct_5xx" -ge "$ERROR_RATE_5XX_WARN" ]; then
        log_to_syslog "HIGH" "Elevated 5xx error rate: ${pct_5xx}%"
    fi

    if [ "$pct_4xx" -ge "$ERROR_RATE_4XX_CRIT" ]; then
        log_to_syslog "CRITICAL" "High 4xx error rate: ${pct_4xx}%"
    elif [ "$pct_4xx" -ge "$ERROR_RATE_4XX_WARN" ]; then
        log_to_syslog "HIGH" "Elevated 4xx error rate: ${pct_4xx}%"
    fi
fi

# =============================================================================
# TOP IP ADDRESSES
# =============================================================================

log_to_syslog "INFO" "=== Top ${TOP_IPS_COUNT} IP Addresses ==="

while IFS= read -r line; do
    extract_ip "$line"
done < "$TEMP_FILE" | sort | uniq -c | sort -rn | head -"$TOP_IPS_COUNT" | while read count ip; do
    log_to_syslog "INFO" "  ${count} requests from ${ip}"

    if [ "$count" -gt "$MAX_REQUESTS_PER_IP" ]; then
        log_to_syslog "HIGH" "High request volume from IP ${ip}: ${count} requests"
    fi
done

# =============================================================================
# TOP URLS
# =============================================================================

log_to_syslog "INFO" "=== Top ${TOP_URLS_COUNT} Requested URLs ==="

while IFS= read -r line; do
    extract_url "$line"
done < "$TEMP_FILE" | sort | uniq -c | sort -rn | head -"$TOP_URLS_COUNT" | while read count url; do
    short_url=$(echo "$url" | cut -c1-80)
    log_to_syslog "INFO" "  ${count} requests to ${short_url}"
done

# =============================================================================
# SPECIFIC ERROR CODES
# =============================================================================

log_to_syslog "INFO" "=== Specific Error Code Summary ==="

for code in 403 404 500 502 503 408; do
    count=0
    while IFS= read -r line; do
        status=$(extract_status "$line")
        if [ "$status" = "$code" ]; then
            count=$((count + 1))
        fi
    done < "$TEMP_FILE"

    if [ "$count" -gt 0 ]; then
        if [ "$code" = "404" ] && [ "$count" -gt 50 ]; then
            log_to_syslog "MEDIUM" "HTTP 404 (Not Found): ${count} requests"
        elif [ "$code" = "408" ]; then
            log_to_syslog "INFO" "HTTP 408 (Timeout): ${count} requests"
        elif [ "$code" -ge 500 ] && [ "$count" -gt 10 ]; then
            log_to_syslog "HIGH" "HTTP ${code} (Server Error): ${count} requests"
        else
            log_to_syslog "INFO" "HTTP ${code}: ${count} requests"
        fi
    fi
done

# =============================================================================
# ATTACK PATTERN DETECTION
# =============================================================================

log_to_syslog "INFO" "=== Attack Pattern Detection ==="

# SQL injection patterns
sql_injection=$(grep -ciE "select.+from|union.+select|insert.+into|drop.+table|' OR '1'='1" "$TEMP_FILE" 2>/dev/null)
if [ "$sql_injection" -gt 0 ]; then
    log_to_syslog "HIGH" "SQL injection patterns detected: ${sql_injection} requests"
fi

# XSS patterns
xss=$(grep -ciE "<script|alert\(|onerror=|javascript:" "$TEMP_FILE" 2>/dev/null)
if [ "$xss" -gt 0 ]; then
    log_to_syslog "HIGH" "XSS attack patterns detected: ${xss} requests"
fi

# Path traversal
path_traversal=$(grep -ciE "\.\./|\.\.\\\\|/etc/passwd" "$TEMP_FILE" 2>/dev/null)
if [ "$path_traversal" -gt 0 ]; then
    log_to_syslog "HIGH" "Path traversal attempts detected: ${path_traversal} requests"
fi

if [ "$sql_injection" -eq 0 ] && [ "$xss" -eq 0 ] && [ "$path_traversal" -eq 0 ]; then
    log_to_syslog "INFO" "No attack patterns detected"
fi

# =============================================================================
# SUSPICIOUS USER-AGENTS
# =============================================================================

log_to_syslog "INFO" "=== Suspicious User-Agents ==="

# Scanner bots
scanner_count=$(grep -ciE "sqlmap|nikto|nmap|nessus|wpscan|dirb|gobuster|burp" "$TEMP_FILE" 2>/dev/null)
if [ "$scanner_count" -gt 0 ]; then
    log_to_syslog "MEDIUM" "Security scanner user-agents detected: ${scanner_count} requests"
fi

# Generic crawlers
crawler_count=$(grep -ciE "curl|wget|python-requests|Go-http-client|Java" "$TEMP_FILE" 2>/dev/null)
if [ "$crawler_count" -gt 0 ]; then
    log_to_syslog "INFO" "Automated tool user-agents detected: ${crawler_count} requests"
fi

if [ "$scanner_count" -eq 0 ] && [ "$crawler_count" -eq 0 ]; then
    log_to_syslog "INFO" "No suspicious user-agents detected"
fi

# =============================================================================
# TRAFFIC SUMMARY
# =============================================================================

log_to_syslog "INFO" "=== Traffic Summary ==="

# Total data transferred
total_bytes=0
while IFS= read -r line; do
    size=$(extract_size "$line")
    if [[ "$size" =~ ^[0-9]+$ ]]; then
        total_bytes=$((total_bytes + size))
    fi
done < "$TEMP_FILE"

if [ "$total_bytes" -gt 0 ]; then
    total_mb=$((total_bytes / 1024 / 1024))
    avg_bytes=$((total_bytes / total_requests))
    log_to_syslog "INFO" "Total data transferred: ${total_mb} MB"
    log_to_syslog "INFO" "Average response size: ${avg_bytes} bytes"
fi

# Requests per minute estimate
rpm=$((total_requests / TIME_RANGE_MINUTES))
log_to_syslog "INFO" "Estimated requests per minute: ${rpm}"

# =============================================================================
# SUMMARY
# =============================================================================

log_to_syslog "INFO" "=== Summary ==="
log_to_syslog "INFO" "Time Range: Last ${TIME_RANGE_MINUTES} minutes"
log_to_syslog "INFO" "Total Requests: ${total_requests}"
if [ "$total_requests" -gt 0 ]; then
    log_to_syslog "INFO" "Success Rate: $((status_2xx * 100 / total_requests))%"
    log_to_syslog "INFO" "Error Rate: $(((status_4xx + status_5xx) * 100 / total_requests))%"
fi

log_to_syslog "INFO" "Webserver log aggregation completed"

exit 0
