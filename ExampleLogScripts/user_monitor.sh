#!/bin/bash
# =============================================================================
# SimpleHomeLog SIEM - User Activity Monitor
# =============================================================================
#
# Author:       Klaus Baumdick
# Date:         2026-05-24
# Version:      1.0.0
#
# Description:  Comprehensive user activity monitoring for SIEM compliance.
#               Tracks user logins, sudo commands, account changes, SSH keys,
#               and suspicious activities. Detects privilege escalation,
#               account sharing, and security policy violations.
#
# Features:     - Real-time logged-in user tracking with session details
#               - Successful and failed login attempt monitoring
#               - Multiple IP detection (possible account sharing)
#               - Remote root login alerts (security policy violation)
#               - Sudo command logging with dangerous command detection
#               - New user account creation/deletion tracking
#               - Password aging policy enforcement monitoring
#               - SSH authorized_keys change detection
#               - Suspicious process detection (root processes in user homes)
#               - State persistence between runs for change detection
#               - Severity-based alerting for SIEM integration
#               - PID in syslog tag for Perl collector compatibility
#
# Security Alerts:
#   - HIGH: Remote root login, new/deleted users, SSH key changes,
#           failed login attempts, dangerous sudo commands
#   - MEDIUM: Multiple simultaneous logins, passwords that never expire
#   - INFO: Routine login tracking, session information
#
# Dependencies: who, last, grep, awk, getent, passwd, md5sum, ps
#
# State Files:  /var/tmp/siem_user_state/previous_users
#               /var/tmp/siem_user_state/ssh_keys_*
#
# Usage:        ./user_monitor.sh
# Check:        tail -f /var/log/syslog | grep user_monitor
# Crontab:      */30 * * * * /path/to/user_monitor.sh
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

TAG="user_monitor"
PID=$$
STATE_DIR="/var/tmp/siem_user_state"
MAX_FAILED_LOGINS_SHOW=20
MAX_SUDO_COMMANDS_SHOW=10
MAX_RECENT_LOGINS_SHOW=15

DANGEROUS_COMMANDS="rm -rf|dd if|mkfs|shred|> /dev/sd|chmod 777|chown|useradd|usermod|passwd|sudoers"
EXCLUDE_PASSWORD_USERS="root|administrator|daemon|bin|sys|sync|games|man|lp|mail|news|uucp|proxy|www-data"

# =============================================================================
# INITIALIZATION
# =============================================================================

mkdir -p "$STATE_DIR" 2>/dev/null
chmod 700 "$STATE_DIR" 2>/dev/null

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

# =============================================================================
# SECTION 1: Currently Logged In Users
# =============================================================================

monitor_current_users() {
    log_to_syslog "INFO" "=== Currently logged in users ==="

    if ! command_exists who; then
        log_to_syslog "INFO" "who command not available"
        return 1
    fi

    local current_users=$(who 2>/dev/null)

    if [ -z "$current_users" ]; then
        log_to_syslog "INFO" "No users currently logged in"
        return 0
    fi

    # Temp file for IP tracking
    local ip_temp="${STATE_DIR}/current_ips.tmp"
    > "$ip_temp"

    echo "$current_users" | while read line; do
        [ -z "$line" ] && continue

        local user=$(echo "$line" | awk '{print $1}')
        local tty=$(echo "$line" | awk '{print $2}')
        local login_time=$(echo "$line" | awk '{print $3, $4}')
        local login_ip=$(echo "$line" | awk '{print $5}' | tr -d '()')

        if [ -z "$login_ip" ] || [ "$login_ip" = ":" ]; then
            login_ip="local"
        fi

        log_to_syslog "INFO" "User: ${user} | Terminal: ${tty} | From: ${login_ip} | Since: ${login_time}"

        echo "${user}:${login_ip}" >> "$ip_temp"
    done

    # Check for multiple IPs per user
    if [ -f "$ip_temp" ]; then
        local users_with_multiple=$(awk -F: '{print $1}' "$ip_temp" | sort | uniq -c | awk '$1>1 {print $2}')

        for user in $users_with_multiple; do
            local ips=$(grep "^${user}:" "$ip_temp" | cut -d: -f2 | sort -u | tr '\n' ' ')
            log_to_syslog "MEDIUM" "User ${user} logged in from multiple IPs: ${ips}"
        done

        rm -f "$ip_temp"
    fi
}

# =============================================================================
# SECTION 2: Recent Successful Logins
# =============================================================================

monitor_recent_logins() {
    log_to_syslog "INFO" "=== Recent successful logins ==="

    if ! command_exists last; then
        log_to_syslog "INFO" "last command not available"
        return 1
    fi

    local recent_logins=$(last -n "$MAX_RECENT_LOGINS_SHOW" 2>/dev/null | grep -v "wtmp" | head -"$MAX_RECENT_LOGINS_SHOW")

    if [ -z "$recent_logins" ]; then
        log_to_syslog "INFO" "No recent login records found"
        return 0
    fi

    echo "$recent_logins" | while read line; do
        [ -z "$line" ] && continue

        log_to_syslog "INFO" "${line}"

        # Check for root login from remote IP
        if echo "$line" | grep -q "root.*pts/"; then
            local login_ip=$(echo "$line" | awk '{print $3}')

            if [ "$login_ip" != "localhost" ] && \
               [ "$login_ip" != "::1" ] && \
               [ "$login_ip" != "0.0.0.0" ]; then
                log_to_syslog "HIGH" "Remote root login from IP: ${login_ip}"
            fi
        fi
    done
}

# =============================================================================
# SECTION 3: Failed Login Attempts
# =============================================================================

monitor_failed_logins() {
    log_to_syslog "INFO" "=== Failed login attempts ==="

    local auth_log="/var/log/auth.log"

    if [ ! -f "$auth_log" ] && [ -f "/var/log/secure" ]; then
        auth_log="/var/log/secure"
    fi

    if [ ! -f "$auth_log" ]; then
        log_to_syslog "INFO" "Authentication log not found"
        return 1
    fi

    local failed_logins=$(grep "Failed password" "$auth_log" 2>/dev/null | tail -"$MAX_FAILED_LOGINS_SHOW")

    if [ -z "$failed_logins" ]; then
        log_to_syslog "INFO" "No failed login attempts found"
        return 0
    fi

    local total_fails=0

    echo "$failed_logins" | while read line; do
        [ -z "$line" ] && continue

        local user=$(echo "$line" | grep -oE "for [a-zA-Z0-9_-]+" | cut -d' ' -f2 | head -1)
        local ip=$(echo "$line" | grep -oE "from [0-9]+\.[0-9]+\.[0-9]+\.[0-9]+" | cut -d' ' -f2 | head -1)

        [ -z "$user" ] && user="unknown"
        [ -z "$ip" ] && ip="unknown"

        log_to_syslog "HIGH" "Failed login | User: ${user} | Source: ${ip}"
        total_fails=$((total_fails + 1))
    done

    local fail_count=$(echo "$failed_logins" | wc -l)
    if [ "$fail_count" -gt 5 ]; then
        log_to_syslog "HIGH" "Summary: ${fail_count} failed login attempts detected"
    fi
}

# =============================================================================
# SECTION 4: Sudo Command Monitoring
# =============================================================================

monitor_sudo_commands() {
    log_to_syslog "INFO" "=== Recent sudo commands ==="

    local auth_log="/var/log/auth.log"

    if [ ! -f "$auth_log" ] && [ -f "/var/log/secure" ]; then
        auth_log="/var/log/secure"
    fi

    if [ ! -f "$auth_log" ]; then
        log_to_syslog "INFO" "Authentication log not found"
        return 1
    fi

    local sudo_commands=$(grep "sudo.*COMMAND" "$auth_log" 2>/dev/null | tail -"$MAX_SUDO_COMMANDS_SHOW")

    if [ -z "$sudo_commands" ]; then
        log_to_syslog "INFO" "No sudo commands found"
        return 0
    fi

    echo "$sudo_commands" | while read line; do
        [ -z "$line" ] && continue

        local user=$(echo "$line" | grep -oE "user=[a-zA-Z0-9_-]+" | cut -d= -f2)
        local command=$(echo "$line" | grep -oE "COMMAND=[^:]+" | cut -d= -f2)

        [ -z "$user" ] && user="unknown"
        [ -z "$command" ] && command="unknown"

        if echo "$command" | grep -qE "$DANGEROUS_COMMANDS"; then
            log_to_syslog "HIGH" "DANGEROUS sudo | User: ${user} | Cmd: ${command}"
        else
            log_to_syslog "INFO" "Sudo command | User: ${user} | Cmd: ${command}"
        fi
    done
}

# =============================================================================
# SECTION 5: User Account Changes
# =============================================================================

monitor_account_changes() {
    log_to_syslog "INFO" "=== User account changes ==="

    local current_users=$(getent passwd 2>/dev/null | awk -F: '$3 >= 1000 && $3 < 65534 {print $1}' | sort)

    if [ -z "$current_users" ]; then
        log_to_syslog "INFO" "No human user accounts found"
        return 1
    fi

    local previous_file="${STATE_DIR}/previous_users"

    if [ -f "$previous_file" ]; then
        local previous_users=$(cat "$previous_file" 2>/dev/null)

        if [ -n "$previous_users" ]; then
            # New users
            local new_users=$(comm -13 <(echo "$previous_users") <(echo "$current_users") 2>/dev/null)

            for user in $new_users; do
                local user_info=$(getent passwd "$user" 2>/dev/null)
                local user_uid=$(echo "$user_info" | cut -d: -f3)
                local user_home=$(echo "$user_info" | cut -d: -f6)
                log_to_syslog "HIGH" "New user created: ${user} (UID: ${user_uid}, Home: ${user_home})"
            done

            # Deleted users
            local deleted_users=$(comm -23 <(echo "$previous_users") <(echo "$current_users") 2>/dev/null)

            for user in $deleted_users; do
                log_to_syslog "HIGH" "User deleted: ${user}"
            done
        fi
    fi

    echo "$current_users" > "$previous_file"
}

# =============================================================================
# SECTION 6: Password Aging Policy
# =============================================================================

monitor_password_aging() {
    log_to_syslog "INFO" "=== Password aging status ==="

    local users=$(getent passwd 2>/dev/null | awk -F: '$3 >= 1000 && $3 < 65534 {print $1}')

    if [ -z "$users" ]; then
        return 1
    fi

    local never_expires=0

    for user in $users; do
        if echo "$EXCLUDE_PASSWORD_USERS" | grep -q "$user"; then
            continue
        fi

        local passwd_info=$(passwd -S "$user" 2>/dev/null)

        if [ -n "$passwd_info" ]; then
            local status=$(echo "$passwd_info" | awk '{print $2}')

            if [ "$status" = "P" ]; then
                local last_change=$(echo "$passwd_info" | awk '{print $3}')

                if [ -z "$last_change" ] || [ "$last_change" = "never" ]; then
                    log_to_syslog "MEDIUM" "User ${user} has password that never expires"
                    never_expires=$((never_expires + 1))
                fi
            fi
        fi
    done

    if [ $never_expires -eq 0 ]; then
        log_to_syslog "INFO" "All users have password expiration configured"
    fi
}

# =============================================================================
# SECTION 7: SSH Authorized Keys Monitoring
# =============================================================================

monitor_ssh_keys() {
    log_to_syslog "INFO" "=== SSH key monitoring ==="

    local users=$(getent passwd 2>/dev/null | awk -F: '$3 >= 1000 && $3 < 65534 {print $1}')

    for user in $users; do
        local user_home=$(getent passwd "$user" 2>/dev/null | cut -d: -f6)

        if [ -z "$user_home" ] || [ ! -d "$user_home" ]; then
            continue
        fi

        local auth_keys="${user_home}/.ssh/authorized_keys"

        if [ -f "$auth_keys" ]; then
            local key_count=$(wc -l < "$auth_keys" 2>/dev/null | tr -d ' ')
            local key_hash=$(md5sum "$auth_keys" 2>/dev/null | cut -d' ' -f1)
            local key_file="${STATE_DIR}/ssh_keys_${user}"

            log_to_syslog "INFO" "User ${user}: ${key_count} SSH key(s)"

            if [ -f "$key_file" ]; then
                local old_hash=$(cat "$key_file" 2>/dev/null)

                if [ -n "$key_hash" ] && [ -n "$old_hash" ] && [ "$key_hash" != "$old_hash" ]; then
                    log_to_syslog "HIGH" "SSH authorized_keys changed for user ${user}"

                    # Log first new key (first line)
                    local first_key=$(head -1 "$auth_keys" 2>/dev/null | cut -c1-100)
                    if [ -n "$first_key" ]; then
                        log_to_syslog "INFO" "  New key sample: ${first_key}..."
                    fi
                fi
            fi

            echo "$key_hash" > "$key_file"
        fi
    done
}

# =============================================================================
# SECTION 8: Suspicious Processes
# =============================================================================

monitor_suspicious_processes() {
    log_to_syslog "INFO" "=== Suspicious process detection ==="

    # Processes running as root from user home directories
    local suspicious=$(ps aux 2>/dev/null | grep -E "^root.*/home/.*" | grep -v grep | head -5)

    if [ -n "$suspicious" ]; then
        log_to_syslog "MEDIUM" "Root processes in user home directories:"
        echo "$suspicious" | while read line; do
            log_to_syslog "MEDIUM" "  ${line:0:120}"
        done
    else
        log_to_syslog "INFO" "No suspicious processes detected"
    fi
}

# =============================================================================
# MAIN EXECUTION
# =============================================================================

main() {
    local start_time=$(date +%s%3N)

    log_to_syslog "INFO" "User activity monitoring started"
    log_to_syslog "INFO" "Host: $(hostname)"

    monitor_current_users
    monitor_recent_logins
    monitor_failed_logins
    monitor_sudo_commands
    monitor_account_changes
    monitor_password_aging
    monitor_ssh_keys
    monitor_suspicious_processes

    local end_time=$(date +%s%3N)
    local duration=$((end_time - start_time))

    log_to_syslog "INFO" "User activity monitoring completed (duration: ${duration}ms)"
}

main

exit 0

# =============================================================================
# CRONTAB ENTRY
# =============================================================================
# */30 * * * * /usr/local/bin/user_monitor.sh
# =============================================================================
