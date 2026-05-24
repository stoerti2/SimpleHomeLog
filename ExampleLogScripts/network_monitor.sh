#!/bin/bash
# =============================================================================
# SimpleHomeLog SIEM - Network Connectivity Monitor
# =============================================================================
#
# Author:       Klaus Baumdick
# Date:         2026-05-24
# Version:      1.0.0
#
# Description:  Monitors network connectivity using multiple methods
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

TAG="network_monitor"
LATENCY_CRITICAL=500
LATENCY_HIGH=200
LATENCY_MEDIUM=100
LATENCY_LOW=50

# Timeouts in seconds
PING_TIMEOUT=3
TCP_TIMEOUT=5
HTTP_TIMEOUT=10

# Number of ping packets
PING_COUNT=3

# SSL/TLS options for curl (disable certificate validation for internal/testing)
# Set to "true" to ignore certificate errors (useful for self-signed certs)
INSECURE_SSL=true

# Follow redirects (true/false)
FOLLOW_REDIRECTS=true

# Monitor all servers or stop on first failure
CONTINUE_ON_FAILURE="yes"

# =============================================================================
# MONITORING TARGETS
# =============================================================================

SERVERS="
8.8.8.8:Google-DNS::ping
1.1.1.1:Cloudflare-DNS::ping
208.67.222.222:OpenDNS::ping
142.251.157.119:www.google.com:443:https
"

# =============================================================================
# FUNCTIONS
# =============================================================================

log_to_syslog() {
    local severity="$1"
    local message="$2"
    local pid=$$
    
    case "$severity" in
        "CRITICAL") logger -p user.crit -t "${TAG}[${pid}]" "SimpleHomeLog: CRITICAL: $message" ;;
        "HIGH")     logger -p user.err -t "${TAG}[${pid}]" "SimpleHomeLog: HIGH: $message" ;;
        "MEDIUM")   logger -p user.warning -t "${TAG}[${pid}]" "SimpleHomeLog: MEDIUM: $message" ;;
        "LOW")      logger -p user.notice -t "${TAG}[${pid}]" "SimpleHomeLog: LOW: $message" ;;
        "ERROR")    logger -p user.err -t "${TAG}[${pid}]" "SimpleHomeLog: ERROR: $message" ;;
        *)          logger -p user.info -t "${TAG}[${pid}]" "SimpleHomeLog: INFO: $message" ;;
    esac
}

command_exists() {
    command -v "$1" >/dev/null 2>&1
}

check_ping() {
    local host="$1"
    
    if ! command_exists ping; then
        echo "DISABLED:ping command not found"
        return 1
    fi
    
    local ping_output=$(ping -c "$PING_COUNT" -W "$PING_TIMEOUT" "$host" 2>&1)
    local ping_exit=$?
    
    if [ $ping_exit -eq 0 ]; then
        local avg_latency=$(echo "$ping_output" | grep "rtt" | head -1 | awk -F'[ /]' '{for(i=1;i<=NF;i++) if($i ~ /^[0-9.]+$/) print $i}' | head -2 | tail -1)
        [ -z "$avg_latency" ] && avg_latency="1"
        echo "OK:${avg_latency}"
        return 0
    elif echo "$ping_output" | grep -q "Operation not permitted"; then
        echo "BLOCKED:ICMP blocked"
        return 2
    else
        echo "FAIL:no response"
        return 1
    fi
}

check_tcp() {
    local host="$1"
    local port="$2"
    
    if ! command_exists nc; then
        echo "DISABLED:nc not installed"
        return 1
    fi
    
    if [ -z "$port" ] || [ "$port" -lt 1 ] || [ "$port" -gt 65535 ]; then
        echo "FAIL:invalid port"
        return 1
    fi
    
    local start_time=$(date +%s%3N)
    
    if timeout "$TCP_TIMEOUT" nc -zv "$host" "$port" 2>&1 | grep -qi "succeeded\|Connected"; then
        local end_time=$(date +%s%3N)
        local latency=$((end_time - start_time))
        echo "OK:${latency}"
        return 0
    else
        echo "FAIL:port $port unreachable"
        return 1
    fi
}

# =============================================================================
# FIXED HTTP/HTTPS CHECK FUNCTION
# =============================================================================
check_http() {
    local url="$1"
    
    if ! command_exists curl; then
        echo "DISABLED:curl not installed"
        return 1
    fi
    
    # Build curl options
    local curl_opts=""
    curl_opts="-s -o /dev/null -w '%{http_code}|%{time_total}|%{remote_ip}'"
    curl_opts="$curl_opts --max-time $HTTP_TIMEOUT"
    curl_opts="$curl_opts --connect-timeout $TCP_TIMEOUT"
    
    # Add SSL options for HTTPS
    if [[ "$url" == https://* ]]; then
        # Ignore certificate validation if configured
        if [ "$INSECURE_SSL" = "true" ]; then
            curl_opts="$curl_opts -k"
        fi
        
        # Try with different SSL versions if needed
        curl_opts="$curl_opts --ssl-reqd"
        
        # Add verbose error output for debugging
        curl_opts="$curl_opts --show-error"
    fi
    
    # Follow redirects if configured
    if [ "$FOLLOW_REDIRECTS" = "true" ]; then
        curl_opts="$curl_opts -L"
    fi
    
    # Execute curl and capture output
    local curl_output
    local curl_exit_code
    
    curl_output=$(eval curl $curl_opts "$url" 2>&1)
    curl_exit_code=$?
    
    # Parse output (format: http_code|time_total|remote_ip)
    local http_code=$(echo "$curl_output" | cut -d'|' -f1)
    local time_total=$(echo "$curl_output" | cut -d'|' -f2)
    local remote_ip=$(echo "$curl_output" | cut -d'|' -f3)
    
    # Convert time_total from seconds to milliseconds
    local latency_ms=$(echo "$time_total * 1000" | bc 2>/dev/null | cut -d. -f1)
    [ -z "$latency_ms" ] && latency_ms="0"
    
    # Analyze result based on curl exit code and HTTP response
    case $curl_exit_code in
        0)
            # Success - HTTP request completed
            if [ -n "$http_code" ] && [ "$http_code" != "000" ]; then
                if [ "$http_code" -ge 200 ] && [ "$http_code" -lt 400 ]; then
                    echo "OK:${latency_ms}:${http_code}"
                    return 0
                elif [ "$http_code" -ge 400 ] && [ "$http_code" -lt 500 ]; then
                    echo "WARN:HTTP $http_code (client error) - service accessible"
                    return 0
                elif [ "$http_code" -ge 500 ]; then
                    echo "WARN:HTTP $http_code (server error) - service responding"
                    return 0
                else
                    echo "OK:${latency_ms}:${http_code}"
                    return 0
                fi
            else
                echo "FAIL:No HTTP response code"
                return 1
            fi
            ;;
        6)
            echo "FAIL:DNS resolution failed - host unknown"
            return 1
            ;;
        7)
            echo "FAIL:Connection refused - host unreachable"
            return 1
            ;;
        28)
            echo "FAIL:Connection timeout after ${HTTP_TIMEOUT}s"
            return 1
            ;;
        35|51|52|53|54|55|56|58|60)
            # SSL/TLS errors
            echo "WARN:SSL/TLS certificate issue - continuing (${curl_output})"
            # Still consider as accessible but with warning
            echo "OK:${latency_ms}:SSL_WARN"
            return 0
            ;;
        *)
            echo "FAIL:Curl error $curl_exit_code - $(echo "$curl_output" | head -c 100)"
            return 1
            ;;
    esac
}

get_severity_from_latency() {
    local latency="$1"
    
    if [ -z "$latency" ] || ! [[ "$latency" =~ ^[0-9]+(\.[0-9]+)?$ ]]; then
        echo "INFO"
        return
    fi
    
    local latency_int=$(echo "$latency" | cut -d. -f1)
    
    if [ "$latency_int" -ge "$LATENCY_CRITICAL" ] 2>/dev/null; then
        echo "CRITICAL"
    elif [ "$latency_int" -ge "$LATENCY_HIGH" ] 2>/dev/null; then
        echo "HIGH"
    elif [ "$latency_int" -ge "$LATENCY_MEDIUM" ] 2>/dev/null; then
        echo "MEDIUM"
    elif [ "$latency_int" -ge "$LATENCY_LOW" ] 2>/dev/null; then
        echo "LOW"
    else
        echo "INFO"
    fi
}

check_server() {
    local host="$1"
    local name="$2"
    local port="$3"
    local method="$4"
    
    local result=""
    local status=""
    local latency="0"
    local details=""
    local http_code=""
    
    case "$method" in
        "ping")
            result=$(check_ping "$host")
            if echo "$result" | grep -q "^OK:"; then
                status="OK"
                latency=$(echo "$result" | cut -d: -f2)
                [ -z "$latency" ] && latency="0"
                details="ICMP ping"
            else
                status="FAIL"
                details=$(echo "$result" | cut -d: -f2-)
            fi
            ;;
        "tcp")
            if [ -z "$port" ]; then
                status="FAIL"
                details="No port specified"
            else
                result=$(check_tcp "$host" "$port")
                if echo "$result" | grep -q "^OK:"; then
                    status="OK"
                    latency=$(echo "$result" | cut -d: -f2)
                    [ -z "$latency" ] && latency="0"
                    details="TCP port $port"
                else
                    status="FAIL"
                    details=$(echo "$result" | cut -d: -f2-)
                fi
            fi
            ;;
        "http"|"https")
            result=$(check_http "${method}://${host}")
            if echo "$result" | grep -q "^OK:"; then
                status="OK"
                latency=$(echo "$result" | cut -d: -f2)
                http_code=$(echo "$result" | cut -d: -f3)
                [ -z "$latency" ] && latency="0"
                details="${method^^} (HTTP ${http_code})"
            elif echo "$result" | grep -q "^WARN:"; then
                status="WARN"
                details=$(echo "$result" | cut -d: -f2-)
            else
                status="FAIL"
                details=$(echo "$result" | cut -d: -f2-)
            fi
            ;;
        *)
            status="FAIL"
            details="Unknown method: $method"
            ;;
    esac
    
    if [ "$status" = "OK" ]; then
        severity=$(get_severity_from_latency "$latency")
        log_to_syslog "$severity" "$name ($host) via $details - OK: ${latency}ms response time"
    elif [ "$status" = "WARN" ]; then
        log_to_syslog "MEDIUM" "$name ($host) - WARNING: $details"
    else
        log_to_syslog "CRITICAL" "$name ($host) - FAILED: $details"
    fi
    
    echo "${severity:-INFO}:$name"
}

# =============================================================================
# MAIN EXECUTION
# =============================================================================

START_TIME=$(date +%s%3N)
log_to_syslog "INFO" "Network connectivity check started"

TEMP_RESULTS=$(mktemp)
> "$TEMP_RESULTS"

echo "$SERVERS" | grep -v '^$' | while IFS=: read -r host name port method; do
    [ -z "$host" ] && continue
    [ -z "$method" ] && method="ping"
    
    check_server "$host" "$name" "$port" "$method" >> "$TEMP_RESULTS"
    
    if [ "$CONTINUE_ON_FAILURE" != "yes" ] && [ $? -ne 0 ]; then
        log_to_syslog "ERROR" "Stopping checks due to failure on $name"
        break
    fi
done

wait

# Statistics
critical_count=0
high_count=0
medium_count=0
low_count=0
info_count=0
failed_hosts=""

if [ -f "$TEMP_RESULTS" ] && [ -s "$TEMP_RESULTS" ]; then
    while IFS= read -r line; do
        case "$line" in
            CRITICAL:*)
                critical_count=$((critical_count + 1))
                failed_hosts="${failed_hosts}$(echo "$line" | cut -d: -f2) "
                ;;
            HIGH:*)
                high_count=$((high_count + 1))
                ;;
            MEDIUM:*)
                medium_count=$((medium_count + 1))
                ;;
            LOW:*)
                low_count=$((low_count + 1))
                ;;
            INFO:*)
                info_count=$((info_count + 1))
                ;;
        esac
    done < "$TEMP_RESULTS"
fi

total_servers=$(echo "$SERVERS" | grep -v '^$' | wc -l)
total_servers=$(echo "$total_servers" | tr -d ' \t\n\r')

END_TIME=$(date +%s%3N)
DURATION=$((END_TIME - START_TIME))

log_to_syslog "INFO" "Summary: ${total_servers} targets checked in ${DURATION}ms | OK:${info_count} LOW:${low_count} MEDIUM:${medium_count} HIGH:${high_count} CRITICAL:${critical_count}"

if [ "$critical_count" -gt 0 ] 2>/dev/null; then
    log_to_syslog "CRITICAL" "SUMMARY: ${critical_count} target(s) unreachable"
fi

if [ "$high_count" -gt 0 ] 2>/dev/null; then
    log_to_syslog "HIGH" "SUMMARY: ${high_count} target(s) with high latency"
fi

rm -f "$TEMP_RESULTS"
log_to_syslog "INFO" "Network connectivity check completed"

exit 0
