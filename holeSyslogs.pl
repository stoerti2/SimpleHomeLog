#!/usr/bin/perl
# =============================================================================
# SimpleHomeLog SIEM Multi-Server Log Collector
# =============================================================================
#
# Author:       Klaus Baumdick
# Date:         2026-05-23
# Version:      1.0.0
#
# Description:  This script collects system logs from multiple remote servers
#               via HTTP/HTTPS, parses them in journalctl export format,
#               extracts security-relevant information (IP addresses, usernames),
#               groups related events, and stores them in a PostgreSQL database
#               for SIEM purposes.
#
# Features:     - Multi-server log collection
#               - Automatic severity classification
#               - Event deduplication via SHA256 hashing
#               - Related event grouping (same PID/host within timeframe)
#               - IP and username extraction
#               - Cron-friendly operation with statistics logging
#
# Dependencies: Perl modules: DBI, DBD::Pg, LWP::UserAgent, DateTime, Digest::SHA
#               PostgreSQL 12+ with SIEM database schema
#
# Usage:        ./holeSyslogs.pl
#               Add to crontab: */15 * * * * /path/to/holeSyslogs.pl >> /var/log/siem_collector.log 2>&1
#
# Configuration: Edit the @servers array and database credentials below
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
use DBI;
use LWP::UserAgent;
use HTTP::Request;
use DateTime;
use Digest::SHA qw(sha256_hex);
# SimpleHomeLog
# ================== KONFIGURATION ==================
my $DB_NAME = "SIEM"; # Change it to your database name
my $DB_USER = "postgres"; # Change it to your database username
my $DB_PASSWORD = "MyVeryGoodPassword"; # Change it
my $DB_HOST = "localhost"; # Change it or not

my $GROUP_TIMEFRAME = 60;  # Sekunden für Gruppierung

# Server-Konfigurationen (mehrere Server)
my @servers = (
    {
        name        => "server 1",
        url         => "https://www.myDomain.de/myExportedLogDir/mySysLog.log",
        description => "My best server"
    },
    {
        name        => "server 2",
        url         => "https://www.myDomain.com/myExportedLogDir/mySysLog.log",
        description => "My second best server"
    },
    {
        name        => "server 3",
        url         => "https://www.myDomain.net/myExportedLogDir/mySysLog.log",
        description => "My nearly best server"
    },
    {
        name        => "server 4",
        url         => "https://www.myDomain.world/myExportedLogDir/mySysLog.log",
        description => "So far server"
    },


);

# Regex für zu ignorierende Einträge
my @ignore_patterns = (
    qr/CRON\[\d+\]: pam_unix\(cron:session\): session opened for user/,
    qr/CRON\[\d+\]: pam_unix\(cron:session\): session closed for user/,
    qr/CRON\[\d+\]: \(root\) CMD \(/,
    qr/systemd\[1\]: Started Session \d+ of user/,
    qr/systemd\[1\]: Starting Session \d+ of user/,
    qr/pam_unix\(cron:session\): session opened for user/,
    qr/pam_unix\(cron:session\): session closed for user/,
);

# Regex für Extraktion
my $ip_pattern = qr/(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)/;
my $user_pattern = qr/user (\w+)/;

# ================== DATENBANK-SETUP ==================

sub init_database {
    my $dbh = DBI->connect(
        "DBI:Pg:dbname=$DB_NAME;host=$DB_HOST",
        $DB_USER,
        $DB_PASSWORD,
        { RaiseError => 1, AutoCommit => 0 }
    ) or die "Could not connect to database: $DBI::errstr";
    
    # Tabelle für Events (mit server_name)
    my $create_events_table = "
    CREATE TABLE IF NOT EXISTS security_events (
        id SERIAL PRIMARY KEY,
        event_hash TEXT UNIQUE NOT NULL,
        server_name TEXT NOT NULL,
        hostname TEXT NOT NULL,
        timestamp TIMESTAMP NOT NULL,
        pid INTEGER,
        process_name TEXT,
        message TEXT NOT NULL,
        event_group_id INTEGER,
        severity TEXT,
        source_ip TEXT,
        username TEXT,
        raw_log TEXT,
        collected_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );";
    
    my $create_groups_table = "
    CREATE TABLE IF NOT EXISTS event_groups (
        id SERIAL PRIMARY KEY,
        group_hash TEXT UNIQUE NOT NULL,
        server_name TEXT NOT NULL,
        start_time TIMESTAMP NOT NULL,
        end_time TIMESTAMP NOT NULL,
        hostname TEXT NOT NULL,
        pid INTEGER,
        process_name TEXT,
        first_message TEXT,
        event_count INTEGER DEFAULT 0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );";
    
    my $create_stats_table = "
    CREATE TABLE IF NOT EXISTS collection_stats (
        id SERIAL PRIMARY KEY,
        server_name TEXT NOT NULL,
        collection_time TIMESTAMP NOT NULL,
        events_fetched INTEGER DEFAULT 0,
        events_inserted INTEGER DEFAULT 0,
        groups_created INTEGER DEFAULT 0,
        status TEXT DEFAULT 'success',
        error_message TEXT,
        UNIQUE(server_name, collection_time)
    );";
    
    my $create_indexes = "
    CREATE INDEX IF NOT EXISTS idx_event_hash ON security_events(event_hash);
    CREATE INDEX IF NOT EXISTS idx_timestamp ON security_events(timestamp);
    CREATE INDEX IF NOT EXISTS idx_server_host ON security_events(server_name, hostname);
    CREATE INDEX IF NOT EXISTS idx_group_id ON security_events(event_group_id);
    CREATE INDEX IF NOT EXISTS idx_group_hash ON event_groups(group_hash);
    CREATE INDEX IF NOT EXISTS idx_stats_server ON collection_stats(server_name, collection_time);
    ";
    
    eval {
        $dbh->do($create_events_table);
        $dbh->do($create_groups_table);
        $dbh->do($create_stats_table);
        $dbh->do($create_indexes);
        $dbh->commit();
        print "Database tables verified/created successfully.\n";
    };
    if ($@) {
        $dbh->rollback();
        die "Failed to create tables: $@";
    }
    
    return $dbh;
}

# ================== LOG PARSING ==================

sub parse_timestamp {
    my ($month, $day, $time, $year) = @_;
    
    my %month_map = (
        'Jan' => 1, 'Feb' => 2, 'Mar' => 3, 'Apr' => 4,
        'May' => 5, 'Jun' => 6, 'Jul' => 7, 'Aug' => 8,
        'Sep' => 9, 'Oct' => 10, 'Nov' => 11, 'Dec' => 12
    );
    
    $year ||= 2026;
    
    my ($hour, $min, $sec) = split(/:/, $time);
    
    return DateTime->new(
        year   => $year,
        month  => $month_map{$month},
        day    => $day,
        hour   => $hour,
        minute => $min,
        second => $sec,
        time_zone => 'UTC'
    );
}

sub extract_ip {
    my ($message) = @_;
    if ($message =~ /($ip_pattern)/) {
        return $1;
    }
    return undef;
}

sub extract_username {
    my ($message) = @_;
    if ($message =~ /$user_pattern/) {
        return $1;
    }
    if ($message =~ /for (?:invalid user|user) (\w+)/) {
        return $1;
    }
    if ($message =~ /user=(\w+)/) {
        return $1;
    }
    return undef;
}

sub determine_severity {
    my ($process, $message) = @_;
    
    if ($message =~ /Failed password/ || $message =~ /Invalid user/) {
        return 'HIGH';
    }
    if ($message =~ /authentication failure/ || $message =~ /Invalid verification code/) {
        return 'HIGH';
    }
    if ($message =~ /pam_unix.*authentication failure/) {
        return 'MEDIUM';
    }
    if ($message =~ /session opened/ || $message =~ /session closed/) {
        return 'LOW';
    }
    if ($message =~ /Accepted password/ || $message =~ /Accepted publickey/) {
        return 'INFO';
    }
    return 'INFO';
}

sub should_ignore {
    my ($line) = @_;
    foreach my $pattern (@ignore_patterns) {
        if ($line =~ $pattern) {
            return 1;
        }
    }
    return 0;
}

# ================== LOG FETCHING ==================

sub fetch_logs {
    my ($server) = @_;
    
    my $ua = LWP::UserAgent->new(
        ssl_opts => { verify_hostname => 0 },
        timeout => 30,
        agent => 'SIEM-Collector/1.0'
    );
    
    print "  Fetching from: " . $server->{url} . "\n";
    my $request = HTTP::Request->new(GET => $server->{url});
    my $response = $ua->request($request);
    
    if ($response->is_success) {
        return $response->decoded_content;
    } else {
        die "Failed to fetch logs from " . $server->{name} . ": " . $response->status_line;
    }
}

# ================== EVENT GROUPING ==================

sub group_events {
    my ($events, $timeframe, $server_name) = @_;
    
    my @grouped = ();
    my $current_group = undef;
    my $last_timestamp = undef;
    my $last_pid = undef;
    my $last_host = undef;
    
    foreach my $event (sort { $a->{timestamp}->epoch() <=> $b->{timestamp}->epoch() } @$events) {
        my $timestamp = $event->{timestamp};
        my $pid = $event->{pid};
        my $host = $event->{hostname};
        
        if (!$current_group || 
            $last_pid != $pid ||
            $last_host ne $host ||
            ($timestamp->epoch() - $last_timestamp->epoch()) > $timeframe) {
            
            if ($current_group) {
                push @grouped, $current_group;
            }
            
            $current_group = {
                events => [],
                start_time => $timestamp,
                end_time => $timestamp,
                server_name => $server_name,
                hostname => $host,
                pid => $pid,
                process_name => $event->{process_name},
                first_message => $event->{message}
            };
        }
        
        push @{$current_group->{events}}, $event;
        $current_group->{end_time} = $timestamp;
        
        $last_timestamp = $timestamp;
        $last_pid = $pid;
        $last_host = $host;
    }
    
    if ($current_group) {
        push @grouped, $current_group;
    }
    
    return @grouped;
}

# ================== DATABASE INSERT ==================

sub insert_events {
    my ($dbh, $groups, $server_name) = @_;
    
    my $insert_event_sql = "
    INSERT INTO security_events 
    (event_hash, server_name, hostname, timestamp, pid, process_name, message, 
     event_group_id, severity, source_ip, username, raw_log)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ON CONFLICT (event_hash) DO NOTHING";
    
    my $insert_group_sql = "
    INSERT INTO event_groups 
    (group_hash, server_name, start_time, end_time, hostname, pid, process_name, first_message, event_count)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    ON CONFLICT (group_hash) DO UPDATE SET
        end_time = EXCLUDED.end_time,
        event_count = EXCLUDED.event_count
    RETURNING id";
    
    my $insert_stats_sql = "
    INSERT INTO collection_stats 
    (server_name, collection_time, events_fetched, events_inserted, groups_created, status, error_message)
    VALUES (?, ?, ?, ?, ?, ?, ?)";
    
    my $event_sth = $dbh->prepare($insert_event_sql);
    my $group_sth = $dbh->prepare($insert_group_sql);
    my $stats_sth = $dbh->prepare($insert_stats_sql);
    
    my $total_events = 0;
    my $total_inserted = 0;
    my $total_groups = scalar(@$groups);
    
    foreach my $group (@$groups) {
        my $events = $group->{events};
        $total_events += scalar(@$events);
        my $group_id = undef;
        
        my $group_hash = sha256_hex(
            $server_name . 
            $group->{hostname} . 
            $group->{pid} . 
            $group->{process_name} . 
            $group->{start_time}->epoch()
        );
        
        eval {
            $group_sth->execute(
                $group_hash,
                $server_name,
                $group->{start_time}->datetime(),
                $group->{end_time}->datetime(),
                $group->{hostname},
                $group->{pid},
                $group->{process_name},
                $group->{first_message},
                scalar(@$events)
            );
            $group_id = $group_sth->fetchrow_array();
        };
        
        if ($@) {
            warn "Error inserting group for $server_name: $@";
            next;
        }
        
        foreach my $event (@$events) {
            my $event_hash = sha256_hex(
                $server_name .
                $event->{hostname} . 
                $event->{timestamp}->epoch() . 
                $event->{pid} . 
                $event->{message}
            );
            
            eval {
                $event_sth->execute(
                    $event_hash,
                    $server_name,
                    $event->{hostname},
                    $event->{timestamp}->datetime(),
                    $event->{pid},
                    $event->{process_name},
                    $event->{message},
                    $group_id,
                    $event->{severity},
                    $event->{source_ip},
                    $event->{username},
                    $event->{raw_log}
                );
                $total_inserted++ if $event_sth->rows > 0;
            };
            
            if ($@) {
                warn "Error inserting event from $server_name: $@";
            }
        }
    }
    
    # Statistik speichern
    eval {
        $stats_sth->execute(
            $server_name,
            DateTime->now->datetime(),
            $total_events,
            $total_inserted,
            $total_groups,
            'success',
            undef
        );
    };
    if ($@) {
        warn "Error saving stats for $server_name: $@";
    }
    
    return ($total_inserted, $total_events, $total_groups);
}

# ================== PROCESS SERVER ==================

sub process_server {
    my ($dbh, $server) = @_;
    
    print "\n" . "=" x 60 . "\n";
    print "Processing server: " . $server->{name} . " (" . $server->{description} . ")\n";
    print "=" x 60 . "\n";
    
    # 1. Logs fetchen
    my $log_content = eval { fetch_logs($server); };
    if ($@) {
        warn "Failed to fetch from " . $server->{name} . ": $@";
        
        # Fehler in Statistik speichern
        my $insert_stats_sql = "
        INSERT INTO collection_stats 
        (server_name, collection_time, events_fetched, events_inserted, groups_created, status, error_message)
        VALUES (?, ?, ?, ?, ?, ?, ?)";
        my $stats_sth = $dbh->prepare($insert_stats_sql);
        $stats_sth->execute(
            $server->{name},
            DateTime->now->datetime(),
            0, 0, 0,
            'failed',
            $@
        );
        $dbh->commit();
        return 0;
    }
    
    print "  Fetched " . length($log_content) . " bytes of log data.\n";
    
    # 2. Logs parsen
    print "  Parsing logs...\n";
    my @events = ();
    my $current_year = (localtime)[5] + 1900;
    
    foreach my $line (split(/\n/, $log_content)) {
        next if should_ignore($line);
        
        if ($line =~ /^(\w{3})\s+(\d{1,2})\s+(\d{2}:\d{2}:\d{2})\s+(\S+)\s+(\S+)\[(\d+)\]:\s+(.*)$/) {
            my ($month, $day, $time, $hostname, $process, $pid, $message) = ($1, $2, $3, $4, $5, $6, $7);
            
            my $timestamp = parse_timestamp($month, $day, $time, $current_year);
            my $source_ip = extract_ip($message);
            my $username = extract_username($message);
            my $severity = determine_severity($process, $message);
            
            push @events, {
                hostname => $hostname,
                timestamp => $timestamp,
                pid => $pid,
                process_name => $process,
                message => $message,
                source_ip => $source_ip,
                username => $username,
                severity => $severity,
                raw_log => $line
            };
        } elsif ($line =~ /^(\w{3})\s+(\d{1,2})\s+(\d{2}:\d{2}:\d{2})\s+(\S+)\s+(.*)$/) {
            # Fallback für Zeilen ohne PID
            my ($month, $day, $time, $hostname, $message) = ($1, $2, $3, $4, $5);
            my $timestamp = parse_timestamp($month, $day, $time, $current_year);
            my $source_ip = extract_ip($message);
            my $username = extract_username($message);
            
            push @events, {
                hostname => $hostname,
                timestamp => $timestamp,
                pid => 0,
                process_name => "unknown",
                message => $message,
                source_ip => $source_ip,
                username => $username,
                severity => determine_severity("unknown", $message),
                raw_log => $line
            };
        }
    }
    
    print "  Parsed " . scalar(@events) . " relevant events.\n";
    
    if (scalar(@events) == 0) {
        print "  No events to process.\n";
        return 0;
    }
    
    # 3. Events gruppieren
    print "  Grouping related events...\n";
    my @groups = group_events(\@events, $GROUP_TIMEFRAME, $server->{name});
    print "  Created " . scalar(@groups) . " event groups.\n";
    
    # 4. In Datenbank einfügen
    print "  Inserting into database...\n";
    my ($inserted, $total, $groups_count) = insert_events($dbh, \@groups, $server->{name});
    $dbh->commit();
    
    print "  ✓ Successfully inserted $inserted new events (out of $total total events, $groups_count groups)\n";
    
    return $inserted;
}

# ================== MAIN ==================

sub main {
    print "=" x 60 . "\n";
    print "SIEM Multi-Server Log Collector\n";
    print "Started at: " . DateTime->now->datetime() . "\n";
    print "=" x 60 . "\n";
    
    # Datenbankverbindung
    print "\nConnecting to database...\n";
    my $dbh = init_database();
    
    my $total_inserted_all = 0;
    my $successful_servers = 0;
    
    # Verarbeite jeden Server
    foreach my $server (@servers) {
        my $inserted = process_server($dbh, $server);
        $total_inserted_all += $inserted if $inserted;
        $successful_servers++ if defined($inserted);
    }
    
    # Abschlussbericht
    print "\n" . "=" x 60 . "\n";
    print "SUMMARY\n";
    print "=" x 60 . "\n";
    print "Servers processed: " . scalar(@servers) . "\n";
    print "Successful: $successful_servers\n";
    print "Total new events inserted: $total_inserted_all\n";
    print "Completed at: " . DateTime->now->datetime() . "\n";
    print "=" x 60 . "\n";
    
    $dbh->disconnect();
    print "\nDone.\n";
}

# Run main function
main();

# ================== CRONTAB EINTRAG ==================
# Führe das Script alle 15 Minuten aus
# */15 * * * * /usr/bin/perl /pfad/zu/diesem/script.pl >> /var/log/siem_collector.log 2>&1
