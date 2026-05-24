#!/bin/bash
# =============================================================================
# SimpleHomeLog SIEM - SSL/TLS Certificate Monitor
# =============================================================================
#
# Author:       Klaus Baumdick
# Date:         2026-05-24
# Version:      1.0.0
#
# Description:  Monitors SSL/TLS certificates for expiration and security issues
#               Sends structured logs to syslog for SIEM collection.
#
# Features:     - Certificate expiration tracking (remote and local)
#               - Let's Encrypt auto-renewal monitoring
#               - Certificate subject/issuer extraction
#               - Severity-based alerting (CRITICAL/HIGH/MEDIUM/INFO)
#               - PID in syslog tag for Perl collector compatibility
#
# Thresholds:   - CRITICAL: <7 days or expired
#               - HIGH: 7-13 days
#               - MEDIUM: 14-29 days
#               - INFO: >=30 days
#
# Dependencies: openssl, date
#
# Usage:        ./ssl_monitor.sh
# Crontab:      0 */12 * * * /path/to/ssl_monitor.sh
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

TAG="ssl_monitor"
PID=$$

EXPIRY_CRITICAL=7
EXPIRY_HIGH=14
EXPIRY_MEDIUM=30

# Domains to monitor (one per line)
DOMAINS="
1.1.1.1
www.google.com
"

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

check_certificate() {
    local host="$1"
    local port="${2:-443}"

    # Get certificate info
    local cert_info=$(echo | openssl s_client -servername "$host" -connect "${host}:${port}" 2>/dev/null | openssl x509 -noout -dates -subject -issuer 2>/dev/null)

    if [ -z "$cert_info" ]; then
        log_to_syslog "WARNING" "Cannot retrieve certificate for ${host}:${port}"
        return 1
    fi

    # Extract expiry date
    local expiry_date=$(echo "$cert_info" | grep "notAfter" | cut -d= -f2)
    local expiry_epoch=$(date -d "$expiry_date" +%s 2>/dev/null)
    local current_epoch=$(date +%s)
    local days_left=$(( (expiry_epoch - current_epoch) / 86400 ))

    # Extract subject and issuer
    local subject=$(echo "$cert_info" | grep "subject=" | cut -d= -f2-)
    local issuer=$(echo "$cert_info" | grep "issuer=" | cut -d= -f2-)

    # Determine severity
    if [ "$days_left" -lt 0 ]; then
        log_to_syslog "CRITICAL" "Certificate for ${host} EXPIRED on ${expiry_date}"
    elif [ "$days_left" -le "$EXPIRY_CRITICAL" ]; then
        log_to_syslog "CRITICAL" "Certificate for ${host} expires in ${days_left} days (${expiry_date})"
    elif [ "$days_left" -le "$EXPIRY_HIGH" ]; then
        log_to_syslog "HIGH" "Certificate for ${host} expires in ${days_left} days (${expiry_date})"
    elif [ "$days_left" -le "$EXPIRY_MEDIUM" ]; then
        log_to_syslog "MEDIUM" "Certificate for ${host} expires in ${days_left} days"
    else
        log_to_syslog "INFO" "Certificate for ${host} valid for ${days_left} days"
    fi

    log_to_syslog "INFO" "  Subject: ${subject}"
    log_to_syslog "INFO" "  Issuer: ${issuer}"
}

# =============================================================================
# MAIN
# =============================================================================

log_to_syslog "INFO" "SSL/TLS certificate monitoring started"

# Check local certificates
if [ -d /etc/ssl/certs ]; then
    log_to_syslog "INFO" "=== Local system certificates ==="

    # Find certificate files
    cert_files=$(find /etc/ssl/certs -maxdepth 1 -name "*.crt" -o -name "*.pem" 2>/dev/null)
    letsencrypt_files=$(find /etc/letsencrypt/live -name "fullchain.pem" 2>/dev/null)

    for cert in $cert_files $letsencrypt_files; do
        if [ -f "$cert" ]; then
            cert_expiry=$(openssl x509 -enddate -noout -in "$cert" 2>/dev/null | cut -d= -f2)
            if [ -n "$cert_expiry" ]; then
                expiry_epoch=$(date -d "$cert_expiry" +%s 2>/dev/null)
                current_epoch=$(date +%s)
                days_left=$(( (expiry_epoch - current_epoch) / 86400 ))
                cert_name=$(basename "$cert")

                if [ "$days_left" -lt "$EXPIRY_CRITICAL" ] && [ "$days_left" -ge 0 ]; then
                    log_to_syslog "CRITICAL" "Local cert ${cert_name} expires in ${days_left} days"
                elif [ "$days_left" -lt "$EXPIRY_HIGH" ] && [ "$days_left" -ge 0 ]; then
                    log_to_syslog "HIGH" "Local cert ${cert_name} expires in ${days_left} days"
                elif [ "$days_left" -lt 0 ]; then
                    log_to_syslog "CRITICAL" "Local cert ${cert_name} has EXPIRED"
                else
                    log_to_syslog "INFO" "Local cert ${cert_name}: ${days_left} days left"
                fi
            fi
        fi
    done
fi

# Check remote domains
log_to_syslog "INFO" "=== Remote domain certificates ==="
for domain in $DOMAINS; do
    # Skip empty lines
    if [ -n "$domain" ]; then
        check_certificate "$domain" 443
        sleep 1
    fi
done

# Check Let's Encrypt renewal status
if [ -d /etc/letsencrypt ]; then
    log_to_syslog "INFO" "=== Let's Encrypt status ==="

    if [ -f /var/log/letsencrypt/letsencrypt.log ]; then
        last_renewal=$(grep "renewal success" /var/log/letsencrypt/letsencrypt.log 2>/dev/null | tail -1)
        if [ -n "$last_renewal" ]; then
            log_to_syslog "INFO" "Last successful renewal: ${last_renewal}"
        fi
    fi

    failed_renewals=$(grep -E "renewal.*fail|failed.*renewal" /var/log/letsencrypt/letsencrypt.log 2>/dev/null | tail -5)
    if [ -n "$failed_renewals" ]; then
        log_to_syslog "HIGH" "Let's Encrypt renewal failures detected"
        echo "$failed_renewals" | while read line; do
            log_to_syslog "HIGH" "  ${line}"
        done
    fi
fi

log_to_syslog "INFO" "SSL/TLS certificate monitoring completed"

exit 0
