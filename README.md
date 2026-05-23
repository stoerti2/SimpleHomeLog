# SimpleHomeLog

A lightweight, self-hosted SIEM solution for collecting, analyzing, and managing security logs from multiple servers. 
Perfect for small to medium-sized environments where commercial SIEM solutions are overkill or too expensive.

Core Functionality
- Multi-Server Log Collection - Collects system logs from multiple servers via HTTP/HTTPS (perl script)
- Automated Log Fetching - Cron-driven periodic log collection from configured endpoints
- Event Grouping - Automatically groups related events (same PID/host within time window)
- Deduplication - SHA256-based deduplication prevents duplicate entries
- Severity Classification - Automatic severity detection (INFO, LOW, MEDIUM, HIGH, CRITICAL)

Web Interface
- Interactive Dashboard - Real-time statistics with charts and graphs
- Event Viewer - Searchable, filterable table with all security events
- Severity Management - Manually adjust event severity levels
- Event Groups View - Browse grouped events to reduce noise
- Attacker Analysis - Top attacking IPs with server context
- Server Statistics - Per-server event distribution and collection stats
- CSV Export - Export filtered events for external analysis
- Bulk Delete - Remove filtered events with confirmation dialog

Data Extraction
- IP Address Extraction - Automatically extracts source IPs from log messages
- Username Extraction - Identifies usernames from authentication logs
- Process/Service Tracking - Tracks processes generating events (SSH, CRON, systemd, etc.)

Filtering Capabilities
- Time range (from/to dates)
- Server name
- Severity level
- Source IP address
- Username
- Full-text search in messages
- Adjustable result limit

Prerequisites

- PHP 7.4+ with PDO PostgreSQL extension
- PostgreSQL 12+
- Perl 5 with modules: DBI, DBD::Pg, LWP::UserAgent, DateTime, Digest::SHA
- Web Server (Apache/NGINX)


<H2>Installation</H2>

On your servers create a cronjob like 

*/15 * * * * /usr/bin/journalctl --since "16 minutes ago" > /home/USERNAME/www/A_DOMAIN/docs/A_DIRECTORY/mySysLog.log

<b>Attn: That homepath must be a browsable path</b>


<b>Install required Perl modules</b>

sudo cpan DBI DBD::Pg LWP::UserAgent DateTime Digest::SHA

<b>Create script directory on your monitor server or local PC</b>

sudo mkdir -p /opt/siem

sudo cp holeSyslogs.pl /opt/siem/

sudo chmod +x /opt/siem/holeSyslogs.pl


<b>Edit configuration in the script</b>

DB_NAME, DB_USER, DB_PASSWORD, DB_HOST
Add your servers to @servers array

<b>Test the collector</b>

perl /opt/siem/holeSyslogs.pl


<H2>Setup Crontab</H2>

crontab -e

Run every 15 minutes

*/15 * * * * /usr/bin/perl /opt/siem/holeSyslogs.pl >> /var/log/siem_collector.log 2>&1

<H2>Database Setup</H2>

sudo -u postgres psql

CREATE DATABASE SIEM;

CREATE USER siem_user WITH PASSWORD 'your_password';

GRANT ALL PRIVILEGES ON DATABASE SIEM TO siem_user;

<H2>Database Scheme (will be created when perl script runs!)</H2>

<b>security_events</b>
- id SERIAL PRIMARY KEY
- event_hash TEXT UNIQUE (SHA256 deduplication)
- server_name TEXT (source server)
- hostname TEXT (original hostname from log)
- timestamp TIMESTAMP
- pid INTEGER
- process_name TEXT
- message TEXT
- event_group_id INTEGER (FK to event_groups)
- severity TEXT (INFO/LOW/MEDIUM/HIGH/CRITICAL)
- source_ip TEXT (extracted IP)
- username TEXT (extracted username)
- raw_log TEXT (original log line)
- collected_at TIMESTAMP

<b>event_groups</b>
- id SERIAL PRIMARY KEY
- group_hash TEXT UNIQUE
- server_name TEXT
- start_time TIMESTAMP
- end_time TIMESTAMP
- hostname TEXT
- pid INTEGER
- process_name TEXT
- first_message TEXT
- event_count INTEGER

<b>collection_stats</b>
- id SERIAL PRIMARY KEY
- server_name TEXT
- collection_time TIMESTAMP
- events_fetched INTEGER
- events_inserted INTEGER
- groups_created INTEGER
- status TEXT
- error_message TEXT

CREATE INDEX CONCURRENTLY idx_timestamp ON security_events(timestamp);

CREATE INDEX CONCURRENTLY idx_source_ip ON security_events(source_ip);

CREATE INDEX CONCURRENTLY idx_severity ON security_events(severity);


