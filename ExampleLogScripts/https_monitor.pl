#!/usr/bin/env perl
# =============================================================================
# SimpleHomeLog SIEM - HTTPS Endpoint Monitor
# =============================================================================
#
# Author:       Klaus Baumdick
# Date:         2026-05-24
# Version:      1.0.0
#
# Description:  This script monitors HTTPS endpoints, measures response times,
#               checks SSL certificates, and logs results to syslog
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

use strict;
use warnings;

# =============================================================================
# CONFIGURATION
# =============================================================================

my $TAG = "https_monitor";
my $PID = $$;

# SSL/TLS options
my $INSECURE_SSL = 1;
my $FOLLOW_REDIRECTS = 1;
my $VERBOSE_ERRORS = 1;

# Timeout values in seconds
my $CONNECT_TIMEOUT = 10;
my $TOTAL_TIMEOUT = 30;

# Response time thresholds in milliseconds
my $RT_CRITICAL = 5000;
my $RT_HIGH = 2000;
my $RT_MEDIUM = 1000;
my $RT_LOW = 500;

# Certificate expiration thresholds in days
my $CERT_CRITICAL = 7;
my $CERT_HIGH = 30;
my $CERT_MEDIUM = 90;
my $CHECK_CERTIFICATES = 1;

# =============================================================================
# ENDPOINT CONFIGURATION
# =============================================================================

my @ENDPOINTS = (
    [ "SIEM_Test1", "https://www.google.com", 200 ],
    [ "SIEM_Test2", "https://www.google.de", 200 ],
);

# =============================================================================
# FUNCTIONS
# =============================================================================

sub log_to_syslog {
    my ($severity, $message) = @_;

    my $priority = "user.info";
    if ($severity eq "CRITICAL") {
        $priority = "user.crit";
    } elsif ($severity eq "HIGH") {
        $priority = "user.err";
    } elsif ($severity eq "MEDIUM") {
        $priority = "user.warning";
    } elsif ($severity eq "LOW") {
        $priority = "user.notice";
    }

    system("logger", "-p", $priority, "-t", "${TAG}[${PID}]", "SimpleHomeLog: $severity: $message");
}

sub execute_curl {
    my ($url) = @_;

    # Build curl command as a string (more reliable than array interpolation)
    my $curl_cmd = "curl -s -o /dev/null -w '%{http_code}|%{time_total}'";

    if ($INSECURE_SSL) {
        $curl_cmd .= " -k";
    }

    $curl_cmd .= " --connect-timeout $CONNECT_TIMEOUT";
    $curl_cmd .= " --max-time $TOTAL_TIMEOUT";

    if ($FOLLOW_REDIRECTS) {
        $curl_cmd .= " -L";
    }

    $curl_cmd .= " '$url'";

    # Execute curl
    my $output = `$curl_cmd 2>&1`;
    my $exit_code = $? >> 8;

    # Parse output
    my ($http_code, $time_total) = split(/\|/, $output);

    # Handle empty or invalid values
    if (!defined $http_code || $http_code eq "") {
        $http_code = "000";
    }

    if (!defined $time_total || $time_total eq "") {
        $time_total = 0;
    } else {
        $time_total =~ s/,/./g;  # Convert comma to dot for decimal
        $time_total = $time_total * 1000;  # Convert to milliseconds
        $time_total = int($time_total);     # Round to integer
    }

    my %result;
    $result{status} = "UNKNOWN";
    $result{http_code} = $http_code;
    $result{time_total} = $time_total;
    $result{exit_code} = $exit_code;
    $result{error_msg} = "";

    if ($exit_code == 0) {
        if ($http_code >= 200 && $http_code < 400) {
            $result{status} = "OK";
        } elsif ($http_code >= 400 && $http_code < 500) {
            $result{status} = "CLIENT_ERROR";
            $result{error_msg} = "HTTP ${http_code} client error";
        } elsif ($http_code >= 500) {
            $result{status} = "SERVER_ERROR";
            $result{error_msg} = "HTTP ${http_code} server error";
        } else {
            $result{status} = "UNKNOWN";
            $result{error_msg} = "Unexpected HTTP code: ${http_code}";
        }
    } else {
        $result{status} = "FAILED";

        my %curl_errors = (
            2 => "Failed to initialize",
            3 => "URL malformed",
            5 => "Couldn't resolve proxy",
            6 => "Could not resolve host",
            7 => "Failed to connect to host",
            28 => "Connection timeout",
            35 => "SSL/TLS handshake error",
            51 => "SSL peer certificate error",
            52 => "Empty response from server",
            60 => "SSL certificate verification failed",
        );

        $result{error_msg} = $curl_errors{$exit_code} || "Curl error ${exit_code}";

        if ($VERBOSE_ERRORS && $output) {
            $result{error_msg} .= " - $output";
        }
    }

    return \%result;
}

sub check_ssl_certificate {
    my ($host, $port) = @_;
    $port ||= 443;

    my %result;
    $result{days_left} = undef;
    $result{issuer} = undef;
    $result{subject} = undef;
    $result{error_msg} = undef;

    my $cmd = "echo | openssl s_client -servername ${host} -connect ${host}:${port} 2>/dev/null | openssl x509 -noout -dates -issuer -subject 2>/dev/null";
    my $output = `$cmd`;

    if ($? == 0 && $output) {
        if ($output =~ /notAfter=(.+)/) {
            my $expiry_date = $1;
            $expiry_date =~ s/\s+$//;

            my $expiry_epoch = `date -d "$expiry_date" +%s 2>/dev/null`;
            chomp $expiry_epoch;
            my $current_epoch = time();

            if ($expiry_epoch =~ /^\d+$/) {
                $result{days_left} = int(($expiry_epoch - $current_epoch) / 86400);
            }
        }

        if ($output =~ /issuer=(.+)/) {
            $result{issuer} = $1;
            $result{issuer} =~ s/\s+$//;
        }

        if ($output =~ /subject=(.+)/) {
            $result{subject} = $1;
            $result{subject} =~ s/\s+$//;
        }
    } else {
        $result{error_msg} = "Could not retrieve SSL certificate";
    }

    return \%result;
}

sub determine_severity {
    my ($status, $time_ms, $cert_days) = @_;

    if ($status eq "SERVER_ERROR" || $status eq "FAILED") {
        return "CRITICAL";
    }

    if ($status eq "CLIENT_ERROR") {
        return "HIGH";
    }

    if ($time_ms > $RT_CRITICAL) {
        return "CRITICAL";
    } elsif ($time_ms > $RT_HIGH) {
        return "HIGH";
    } elsif ($time_ms > $RT_MEDIUM) {
        return "MEDIUM";
    } elsif ($time_ms > $RT_LOW) {
        return "LOW";
    }

    if (defined $cert_days && $CHECK_CERTIFICATES) {
        if ($cert_days < $CERT_CRITICAL && $cert_days >= 0) {
            return "CRITICAL";
        } elsif ($cert_days < $CERT_HIGH && $cert_days >= 0) {
            return "HIGH";
        } elsif ($cert_days < $CERT_MEDIUM && $cert_days >= 0) {
            return "MEDIUM";
        }
    }

    return "INFO";
}

sub monitor_endpoint {
    my ($endpoint) = @_;

    my ($name, $url, $expected_status) = @$endpoint;
    $expected_status ||= 200;

    # Log start of check
    log_to_syslog("INFO", "Checking endpoint: $name");

    # Extract host for SSL check
    my ($host) = $url =~ m{https?://([^:/]+)};

    # Execute curl check
    my $curl_result = execute_curl($url);

    # Check SSL certificate if configured
    my $cert_result = {};
    if ($CHECK_CERTIFICATES && $host) {
        $cert_result = check_ssl_certificate($host, 443);
    }

    # Determine severity
    my $severity = determine_severity(
        $curl_result->{status},
        $curl_result->{time_total},
        $cert_result->{days_left}
    );

    # Build log message
    my $message = "$name - ";

    if ($curl_result->{status} eq "OK") {
        $message .= "HTTP $curl_result->{http_code}, $curl_result->{time_total}ms";

        if ($CHECK_CERTIFICATES && defined $cert_result->{days_left}) {
            if ($cert_result->{days_left} < 0) {
                $message .= ", SSL CERTIFICATE EXPIRED!";
            } else {
                $message .= ", SSL cert valid for $cert_result->{days_left} days";
            }
        }

        if ($curl_result->{http_code} != $expected_status) {
            $message .= " - Expected HTTP $expected_status";
            $severity = "HIGH" if $severity eq "INFO";
        }
    } else {
        $message .= "FAILED - $curl_result->{error_msg}";
    }

    log_to_syslog($severity, $message);

    if ($CHECK_CERTIFICATES && $cert_result->{issuer} && $curl_result->{status} eq "OK") {
        log_to_syslog("INFO", "  Cert: $cert_result->{subject} issued by $cert_result->{issuer}");
    }
}

# =============================================================================
# MAIN EXECUTION
# =============================================================================

sub main {
    log_to_syslog("INFO", "HTTPS endpoint monitoring started");

    my $total = scalar @ENDPOINTS;
    my $ok_count = 0;
    my $fail_count = 0;

    foreach my $endpoint (@ENDPOINTS) {
        monitor_endpoint($endpoint);

        # Small delay between requests
        select(undef, undef, undef, 0.5);
    }

    log_to_syslog("INFO", "HTTPS endpoint monitoring completed - ${total} endpoints checked");
}

main();

exit 0;
