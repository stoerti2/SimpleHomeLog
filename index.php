<?php
/**
 * SimpleHomeLog SIEM - Security Information & Event Management System
 * ======================================================
 *
 * @author      Klaus Baumdick
 * @copyright   2026 Klaus Baumdick
 * @license     MIT
 * @version     1.0.4
 * @date        2026-05-23
 *
 * @description Web interface for SIEM log management
 *              Features: Dashboard, Event Viewer, Event Groups,
 *              Attacker Analysis, Statistics, Server Management
 *              NEW: Copy firewall rules to clipboard
 *
 * @requires    PHP 7.4+
 * @requires    PostgreSQL 12+
 * @requires    PDO PostgreSQL extension
 */

require_once 'db_config.php';
require_once 'functions.php';

// Aktueller Tab
$tab = $_GET['tab'] ?? 'dashboard';

// Statistiken für Dashboard
$stats = getStatistics($pdo);
$top_attackers = getTopAttackers($pdo, 10);
$severity_counts = getSeverityCounts($pdo);

// Filter für Log-Viewer
$filters = [
    'server' => $_GET['server'] ?? '',
    'severity' => $_GET['severity'] ?? '',
    'search' => $_GET['search'] ?? '',
    'date_from' => $_GET['date_from'] ?? date('Y-m-d', strtotime('-7 days')),
    'date_to' => $_GET['date_to'] ?? date('Y-m-d'),
    'source_ip' => $_GET['source_ip'] ?? '',
    'username' => $_GET['username'] ?? '',
    'limit' => $_GET['limit'] ?? 100
];

$events = getEvents($pdo, $filters);

// Filter für Attackers
$attackers_server_filter = $_GET['attackers_server'] ?? '';
$attackers_data = getTopAttackers($pdo, 20, $attackers_server_filter);

// Filter für Groups
$groups_server_filter = $_GET['groups_server'] ?? '';
$groups_process_filter = $_GET['groups_process'] ?? '';
$groups_data = getEventGroups($pdo, 100, $groups_server_filter, $groups_process_filter);
?>
<!DOCTYPE html>
<html lang="de">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SimpleHomeLog SIEM - Security Information & Event Management</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
    <link href="https://cdn.datatables.net/1.11.5/css/dataTables.bootstrap5.min.css" rel="stylesheet">
    <script src="https://code.jquery.com/jquery-3.6.0.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/js/bootstrap.bundle.min.js"></script>
    <script src="https://cdn.datatables.net/1.11.5/js/jquery.dataTables.min.js"></script>
    <script src="https://cdn.datatables.net/1.11.5/js/dataTables.bootstrap5.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        body { font-size: 0.85rem; }
        .severity-CRITICAL, .severity-HIGH, .severity-MEDIUM, .severity-LOW, .severity-INFO {
            display: inline-block;
            padding: 0.2rem 0.4rem;
            font-size: 0.7rem;
            font-weight: bold;
            border-radius: 0.2rem;
        }
        .severity-CRITICAL { background-color: #dc3545; color: white; }
        .severity-HIGH { background-color: #fd7e14; color: white; }
        .severity-MEDIUM { background-color: #ffc107; color: black; }
        .severity-LOW { background-color: #28a745; color: white; }
        .severity-INFO { background-color: #17a2b8; color: white; }
        .event-detail { cursor: pointer; }
        .event-detail:hover { background-color: #f8f9fa; }
        .log-message { font-family: monospace; font-size: 0.75rem; }
        .sidebar { min-height: 100vh; background-color: #343a40; }
        .sidebar .nav-link { color: #fff; font-size: 0.85rem; padding: 0.5rem 1rem; }
        .sidebar .nav-link:hover { background-color: #495057; }
        .sidebar .nav-link.active { background-color: #007bff; }
        .stats-card { transition: transform 0.2s; font-size: 0.8rem; }
        .stats-card:hover { transform: translateY(-2px); }
        .stats-card h2 { font-size: 1.8rem; margin: 0; }
        .stats-card h5 { font-size: 0.85rem; margin: 0 0 0.5rem 0; }
        .card-header { padding: 0.5rem 1rem; }
        .card-header h5 { font-size: 0.9rem; margin: 0; }
        .card-body { padding: 0.75rem; }
        .table td, .table th { padding: 0.4rem; vertical-align: middle; }
        .form-control, .form-select {
            font-size: 0.85rem;
            padding: 0.3rem 0.6rem;
            min-width: 100px;
        }
        .form-select-sm {
            font-size: 0.8rem;
            padding: 0.2rem 1.5rem 0.2rem 0.5rem;
        }
        .btn-sm { padding: 0.25rem 0.5rem; font-size: 0.75rem; }
        .badge { font-size: 0.7rem; }
        .container-fluid { padding: 0; }
        .row { margin: 0; }
        .col-md-2, .col-md-10 { padding: 0; }
        .p-3 { padding: 0.75rem !important; }
        .p-4 { padding: 0.75rem !important; }
        h2 { font-size: 1.3rem; margin-bottom: 0.5rem; }
        hr { margin: 0.5rem 0; }
        pre { font-size: 0.75rem; margin: 0; }
        canvas { max-height: 250px; }
        .severity-select {
            width: 95px !important;
            font-size: 0.75rem;
            padding: 0.2rem 0.4rem;
        }
        .filter-select {
            width: auto;
            min-width: 120px;
        }
        /* Breitere Spalten für bessere Lesbarkeit */
        .server-column { min-width: 140px; white-space: nowrap; }
        .sourceip-column { min-width: 130px; white-space: nowrap; font-family: monospace; }
        .host-column { min-width: 120px; }
        .process-column { min-width: 100px; }
        .time-column { min-width: 65px; }
        .user-column { min-width: 80px; }
        /* Toast Notification */
        .toast-notify {
            position: fixed;
            bottom: 20px;
            right: 20px;
            background: #28a745;
            color: white;
            padding: 10px 20px;
            border-radius: 5px;
            z-index: 9999;
            animation: fadeInOut 2s ease-in-out;
        }
        @keyframes fadeInOut {
            0% { opacity: 0; transform: translateY(20px); }
            10% { opacity: 1; transform: translateY(0); }
            90% { opacity: 1; transform: translateY(0); }
            100% { opacity: 0; transform: translateY(20px); }
        }
        /* Klickbare Zeilen im Dashboard */
        .clickable-row {
            cursor: pointer;
            transition: background-color 0.2s;
        }
        .clickable-row:hover {
            background-color: #f0f0f0 !important;
        }
    </style>
</head>
<body>
    <div class="container-fluid">
        <div class="row">
            <!-- Sidebar -->
            <div class="col-md-2 p-0 sidebar">
                <div class="p-3">
                    <h4 class="text-white mb-3" style="font-size: 1.1rem;">SimpleHomeLog SIEM</h4>
                    <nav class="nav flex-column">
                        <a class="nav-link <?= $tab == 'dashboard' ? 'active' : '' ?>" href="?tab=dashboard">
                            <i class="fas fa-tachometer-alt"></i> Dashboard
                        </a>
                        <a class="nav-link <?= $tab == 'events' ? 'active' : '' ?>" href="?tab=events">
                            <i class="fas fa-list"></i> Events
                        </a>
                        <a class="nav-link <?= $tab == 'groups' ? 'active' : '' ?>" href="?tab=groups">
                            <i class="fas fa-layer-group"></i> Event Groups
                        </a>
                        <a class="nav-link <?= $tab == 'attackers' ? 'active' : '' ?>" href="?tab=attackers">
                            <i class="fas fa-bug"></i> Attackers
                        </a>
                        <a class="nav-link <?= $tab == 'stats' ? 'active' : '' ?>" href="?tab=stats">
                            <i class="fas fa-chart-line"></i> Statistics
                        </a>
                        <a class="nav-link <?= $tab == 'servers' ? 'active' : '' ?>" href="?tab=servers">
                            <i class="fas fa-server"></i> Servers
                        </a>
                        <a class="nav-link" href="attack_graph.php">
                            <i class="fas fa-project-diagram"></i> Attack Graph
                        </a>
                    </nav>
                </div>
            </div>

            <!-- Main Content -->
            <div class="col-md-10 p-3">
                <?php if ($tab == 'dashboard'): ?>
                    <!-- Dashboard -->
                    <h2><i class="fas fa-tachometer-alt"></i> Dashboard</h2>
                    <hr>

                    <!-- Stats Cards -->
                    <div class="row mb-3">
                        <div class="col-md-3">
                            <div class="card stats-card text-white bg-primary">
                                <div class="card-body">
                                    <h5 class="card-title">Total Events</h5>
                                    <h2><?= number_format($stats['total_events']) ?></h2>
                                </div>
                            </div>
                        </div>
                        <div class="col-md-3">
                            <div class="card stats-card text-white bg-danger">
                                <div class="card-body">
                                    <h5 class="card-title">Critical/High</h5>
                                    <h2><?= number_format(($stats['critical_events'] ?? 0) + ($stats['high_events'] ?? 0)) ?></h2>
                                </div>
                            </div>
                        </div>
                        <div class="col-md-3">
                            <div class="card stats-card text-white bg-warning">
                                <div class="card-body">
                                    <h5 class="card-title">Unique Attackers</h5>
                                    <h2><?= number_format($stats['unique_attackers']) ?></h2>
                                </div>
                            </div>
                        </div>
                        <div class="col-md-3">
                            <div class="card stats-card text-white bg-info">
                                <div class="card-body">
                                    <h5 class="card-title">Servers</h5>
                                    <h2><?= number_format($stats['total_servers']) ?></h2>
                                </div>
                            </div>
                        </div>
                    </div>

                    <!-- Charts -->
                    <div class="row mb-3">
                        <div class="col-md-6">
                            <div class="card">
                                <div class="card-header">
                                    <h5>Events by Severity</h5>
                                </div>
                                <div class="card-body">
                                    <canvas id="severityChart" height="200"></canvas>
                                </div>
                            </div>
                        </div>
                        <div class="col-md-6">
                            <div class="card">
                                <div class="card-header">
                                    <h5>Top 10 Attackers</h5>
                                </div>
                                <div class="card-body">
                                    <canvas id="attackersChart" height="200"></canvas>
                                </div>
                            </div>
                        </div>
                    </div>

                    <!-- Recent Events - JETZT ANKLICKBAR -->
                    <div class="card">
                        <div class="card-header">
                            <h5>Recent Critical Events <small class="text-muted">(klickbar für Details)</small></h5>
                        </div>
                        <div class="card-body p-0">
                            <div class="table-responsive">
                                <table class="table table-sm mb-0">
                                    <thead>
                                        <tr><th style="font-size:0.7rem;">Time</th><th style="font-size:0.7rem;">Server</th><th style="font-size:0.7rem;">Source IP</th><th style="font-size:0.7rem;">Message</th><th style="font-size:0.7rem;">Severity</th></tr>
                                    </thead>
                                    <tbody id="recentCriticalEventsBody">
                                        <?php foreach (getRecentEvents($pdo, 15) as $event): ?>
                                        <tr class="clickable-row" data-event-id="<?= $event['id'] ?>" style="font-size:0.75rem;">
                                            <td><small><?= date('m-d H:i:s', strtotime($event['timestamp'])) ?></small></td>
                                            <td><small><?= htmlspecialchars(substr($event['server_name'], 0, 20)) ?></small></td>
                                            <td><small><code><?= htmlspecialchars($event['source_ip'] ?? '-') ?></code></small></td>
                                            <td class="log-message"><small><?= htmlspecialchars(substr($event['message'], 0, 80)) ?>...</small></td>
                                            <td><small><span class="severity-<?= $event['severity'] ?>"><?= $event['severity'] ?></span></small></td>
                                        </tr>
                                        <?php endforeach; ?>
                                    </tbody>
                                </table>
                            </div>
                        </div>
                    </div>

                <?php elseif ($tab == 'events'): ?>
                    <!-- Events Viewer -->
                    <h2><i class="fas fa-list"></i> Events</h2>
                    <hr>

                    <!-- Filter -->
                    <div class="card mb-2">
                        <div class="card-header">
                            <h5>Filter Events</h5>
                        </div>
                        <div class="card-body">
                            <form method="GET" class="row g-2" id="filterForm">
                                <input type="hidden" name="tab" value="events">
                                <div class="col-md-2">
                                    <select name="server" class="form-select form-select-sm filter-select">
                                        <option value="">All Servers</option>
                                        <?php foreach (getServers($pdo) as $server): ?>
                                        <option value="<?= htmlspecialchars($server) ?>" <?= $filters['server'] == $server ? 'selected' : '' ?>>
                                            <?= htmlspecialchars(substr($server, 0, 30)) ?>
                                        </option>
                                        <?php endforeach; ?>
                                    </select>
                                </div>
                                <div class="col-md-1">
                                    <select name="severity" class="form-select form-select-sm">
                                        <option value="">Severity</option>
                                        <option value="CRITICAL" <?= $filters['severity'] == 'CRITICAL' ? 'selected' : '' ?>>CRITICAL</option>
                                        <option value="HIGH" <?= $filters['severity'] == 'HIGH' ? 'selected' : '' ?>>HIGH</option>
                                        <option value="MEDIUM" <?= $filters['severity'] == 'MEDIUM' ? 'selected' : '' ?>>MEDIUM</option>
                                        <option value="LOW" <?= $filters['severity'] == 'LOW' ? 'selected' : '' ?>>LOW</option>
                                        <option value="INFO" <?= $filters['severity'] == 'INFO' ? 'selected' : '' ?>>INFO</option>
                                    </select>
                                </div>
                                <div class="col-md-2">
                                    <input type="date" name="date_from" class="form-control form-control-sm" value="<?= $filters['date_from'] ?>">
                                </div>
                                <div class="col-md-2">
                                    <input type="date" name="date_to" class="form-control form-control-sm" value="<?= $filters['date_to'] ?>">
                                </div>
                                <div class="col-md-2">
                                    <input type="text" name="source_ip" class="form-control form-control-sm" placeholder="Source IP" value="<?= htmlspecialchars($filters['source_ip']) ?>">
                                </div>
                                <div class="col-md-2">
                                    <input type="text" name="username" class="form-control form-control-sm" placeholder="Username" value="<?= htmlspecialchars($filters['username']) ?>">
                                </div>
                                <div class="col-md-3">
                                    <input type="text" name="search" class="form-control form-control-sm" placeholder="Search in messages..." value="<?= htmlspecialchars($filters['search']) ?>">
                                </div>
                                <div class="col-md-1">
                                    <select name="limit" class="form-select form-select-sm">
                                        <option value="50" <?= $filters['limit'] == 50 ? 'selected' : '' ?>>50</option>
                                        <option value="100" <?= $filters['limit'] == 100 ? 'selected' : '' ?>>100</option>
                                        <option value="250" <?= $filters['limit'] == 250 ? 'selected' : '' ?>>250</option>
                                        <option value="500" <?= $filters['limit'] == 500 ? 'selected' : '' ?>>500</option>
                                    </select>
                                </div>
                                <div class="col-md-12">
                                    <button type="submit" class="btn btn-sm btn-primary">Apply Filters</button>
                                    <a href="?tab=events" class="btn btn-sm btn-secondary">Reset</a>
                                    <a href="?tab=events&export=csv&<?= http_build_query($filters) ?>" class="btn btn-sm btn-success">Export CSV</a>
                                    <button type="button" class="btn btn-sm btn-danger" id="deleteFilteredBtn">
                                        <i class="fas fa-trash"></i> Delete Filtered Events
                                    </button>
                                </div>
                            </form>
                        </div>
                    </div>

                    <!-- Delete Confirmation Modal -->
                    <div class="modal fade" id="deleteConfirmModal" tabindex="-1">
                        <div class="modal-dialog">
                            <div class="modal-content">
                                <div class="modal-header bg-danger text-white">
                                    <h5 class="modal-title"><i class="fas fa-exclamation-triangle"></i> Confirm Deletion</h5>
                                    <button type="button" class="btn-close btn-close-white" data-bs-dismiss="modal"></button>
                                </div>
                                <div class="modal-body">
                                    <p><strong>WARNING: This action cannot be undone!</strong></p>
                                    <p>You are about to delete all events matching the current filters:</p>
                                    <ul id="deleteFilterList" style="font-size:0.8rem;">
                                        <li>Loading filter information...</li>
                                    </ul>
                                    <p class="text-danger mt-2"><strong>Total events to delete: <span id="deleteCount">0</span></strong></p>
                                    <div class="form-check mt-3">
                                        <input class="form-check-input" type="checkbox" id="confirmDeleteCheck">
                                        <label class="form-check-label" for="confirmDeleteCheck">
                                            I understand that this will permanently delete these events from the database
                                        </label>
                                    </div>
                                </div>
                                <div class="modal-footer">
                                    <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button>
                                    <button type="button" class="btn btn-danger" id="executeDeleteBtn" disabled>
                                        <i class="fas fa-trash"></i> Permanently Delete
                                    </button>
                                </div>
                            </div>
                        </div>
                    </div>

                    <!-- Events Table -->
                    <div class="card">
                        <div class="card-header">
                            <h5>Events (<?= count($events) ?> found)</h5>
                        </div>
                        <div class="card-body p-0">
                            <div class="table-responsive">
                                <table class="table table-sm table-hover mb-0" id="eventsTable">
                                    <thead>
                                        <tr>
                                            <th class="time-column">Time</th>
                                            <th class="server-column">Server</th>
                                            <th class="host-column">Host</th>
                                            <th class="process-column">Process</th>
                                            <th>Message</th>
                                            <th class="sourceip-column">Source IP</th>
                                            <th class="user-column">User</th>
                                            <th>Severity</th>
                                            <th></th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        <?php foreach ($events as $event): ?>
                                        <tr class="event-detail" data-id="<?= $event['id'] ?>" style="font-size:0.75rem;">
                                            <td class="time-column"><small><?= date('H:i:s', strtotime($event['timestamp'])) ?></small></td>
                                            <td class="server-column"><small><?= htmlspecialchars($event['server_name']) ?></small></td>
                                            <td class="host-column"><small><?= htmlspecialchars(substr($event['hostname'], 0, 15)) ?></small></td>
                                            <td class="process-column"><small><?= htmlspecialchars(substr($event['process_name'], 0, 12)) ?></small></td>
                                            <td class="log-message"><small><?= htmlspecialchars(substr($event['message'], 0, 60)) ?>...</small></td>
                                            <td class="sourceip-column"><code><small><?= htmlspecialchars($event['source_ip'] ?? '-') ?></small></code></td>
                                            <td class="user-column"><small><?= htmlspecialchars(substr($event['username'] ?? '-', 0, 10)) ?></small></td>
                                            <td>
                                                <select class="form-select form-select-sm severity-select" data-id="<?= $event['id'] ?>">
                                                    <option value="INFO" <?= $event['severity'] == 'INFO' ? 'selected' : '' ?>>INFO</option>
                                                    <option value="LOW" <?= $event['severity'] == 'LOW' ? 'selected' : '' ?>>LOW</option>
                                                    <option value="MEDIUM" <?= $event['severity'] == 'MEDIUM' ? 'selected' : '' ?>>MEDIUM</option>
                                                    <option value="HIGH" <?= $event['severity'] == 'HIGH' ? 'selected' : '' ?>>HIGH</option>
                                                    <option value="CRITICAL" <?= $event['severity'] == 'CRITICAL' ? 'selected' : '' ?>>CRITICAL</option>
                                                </select>
                                            </td>
                                            <td>
                                                <button class="btn btn-sm btn-info view-detail" data-id="<?= $event['id'] ?>" style="padding:0.1rem 0.3rem;">
                                                    <i class="fas fa-eye" style="font-size:0.7rem;"></i>
                                                </button>
                                            </td>
                                        </tr>
                                        <?php endforeach; ?>
                                    </tbody>
                                </table>
                            </div>
                        </div>
                    </div>

                    <!-- Delete Result Modal -->
                    <div class="modal fade" id="deleteResultModal" tabindex="-1">
                        <div class="modal-dialog">
                            <div class="modal-content">
                                <div class="modal-header">
                                    <h5 class="modal-title">Delete Result</h5>
                                    <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                                </div>
                                <div class="modal-body" id="deleteResultBody">
                                </div>
                                <div class="modal-footer">
                                    <button type="button" class="btn btn-primary" data-bs-dismiss="modal" onclick="location.reload();">Refresh Page</button>
                                </div>
                            </div>
                        </div>
                    </div>

                <?php elseif ($tab == 'groups'): ?>
                    <!-- Event Groups -->
                    <h2><i class="fas fa-layer-group"></i> Event Groups</h2>
                    <hr>

                    <!-- Filter für Groups -->
                    <div class="card mb-2">
                        <div class="card-header">
                            <h5>Filter Groups</h5>
                        </div>
                        <div class="card-body">
                            <form method="GET" class="row g-2">
                                <input type="hidden" name="tab" value="groups">
                                <div class="col-md-3">
                                    <select name="groups_server" class="form-select form-select-sm">
                                        <option value="">All Servers</option>
                                        <?php foreach (getServers($pdo) as $server): ?>
                                        <option value="<?= htmlspecialchars($server) ?>" <?= ($_GET['groups_server'] ?? '') == $server ? 'selected' : '' ?>>
                                            <?= htmlspecialchars($server) ?>
                                        </option>
                                        <?php endforeach; ?>
                                    </select>
                                </div>
                                <div class="col-md-3">
                                    <input type="text" name="groups_process" class="form-control form-control-sm" placeholder="Process name" value="<?= htmlspecialchars($_GET['groups_process'] ?? '') ?>">
                                </div>
                                <div class="col-md-3">
                                    <button type="submit" class="btn btn-sm btn-primary">Filter Groups</button>
                                    <a href="?tab=groups" class="btn btn-sm btn-secondary">Reset</a>
                                </div>
                            </form>
                        </div>
                    </div>

                    <div class="card">
                        <div class="card-body p-0">
                            <div class="table-responsive">
                                <table class="table table-sm mb-0" id="groupsTable">
                                    <thead>
                                        <tr>
                                            <th style="font-size:0.7rem;">Time Range</th>
                                            <th style="font-size:0.7rem;">Server</th>
                                            <th style="font-size:0.7rem;">Process</th>
                                            <th style="font-size:0.7rem;">Events</th>
                                            <th style="font-size:0.7rem;">First Message</th>
                                            <th style="font-size:0.7rem;"></th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        <?php foreach ($groups_data as $group): ?>
                                        <tr style="font-size:0.75rem;">
                                            <td><small><?= date('m-d H:i', strtotime($group['start_time'])) ?></small></td>
                                            <td><small><?= htmlspecialchars(substr($group['server_name'], 0, 20)) ?></small></td>
                                            <td><small><?= htmlspecialchars(substr($group['process_name'], 0, 20)) ?></small></td>
                                            <td><span class="badge bg-secondary"><?= $group['event_count'] ?></span></td>
                                            <td class="log-message"><small><?= htmlspecialchars(substr($group['first_message'], 0, 60)) ?>...</small></td>
                                            <td>
                                                <button class="btn btn-sm btn-primary view-group" data-id="<?= $group['id'] ?>">
                                                    <i class="fas fa-list"></i> View Events
                                                </button>
                                            </td>
                                        </tr>
                                        <?php endforeach; ?>
                                        <?php if (count($groups_data) == 0): ?>
                                        <tr>
                                            <td colspan="6" class="text-center text-muted">No event groups found</td>
                                        </tr>
                                        <?php endif; ?>
                                    </tbody>
                                </table>
                            </div>
                        </div>
                    </div>

                <?php elseif ($tab == 'attackers'): ?>
                    <!-- Attackers Analysis -->
                    <h2><i class="fas fa-bug"></i> Attackers</h2>
                    <hr>

                    <!-- Filter für Attackers -->
                    <div class="card mb-2">
                        <div class="card-header">
                            <h5>Filter Attackers</h5>
                        </div>
                        <div class="card-body">
                            <form method="GET" class="row g-2">
                                <input type="hidden" name="tab" value="attackers">
                                <div class="col-md-3">
                                    <select name="attackers_server" class="form-select form-select-sm">
                                        <option value="">All Servers</option>
                                        <?php foreach (getServers($pdo) as $server): ?>
                                        <option value="<?= htmlspecialchars($server) ?>" <?= ($_GET['attackers_server'] ?? '') == $server ? 'selected' : '' ?>>
                                            <?= htmlspecialchars($server) ?>
                                        </option>
                                        <?php endforeach; ?>
                                    </select>
                                </div>
                                <div class="col-md-3">
                                    <button type="submit" class="btn btn-sm btn-primary">Filter</button>
                                    <a href="?tab=attackers" class="btn btn-sm btn-secondary">Reset</a>
                                </div>
                            </form>
                        </div>
                    </div>

                    <div class="row">
                        <div class="col-md-8">
                            <div class="card">
                                <div class="card-header">
                                    <h5>Top Attackers by IP</h5>
                                </div>
                                <div class="card-body p-0">
                                    <div class="table-responsive">
                                        <table class="table table-sm mb-0" id="attackersTable">
                                            <thead>
                                                <tr><th>Source IP</th><th>Count</th><th>Last Seen</th><th>Server</th><th></th></tr>
                                            </thead>
                                            <tbody>
                                                <?php foreach ($attackers_data as $attacker): ?>
                                                <tr style="font-size:0.75rem;">
                                                    <td><code><?= htmlspecialchars($attacker['source_ip']) ?></code></td>
                                                    <td><span class="badge bg-danger"><?= $attacker['count'] ?></span></td>
                                                    <td><small><?= date('m-d H:i', strtotime($attacker['last_seen'])) ?></small></td>
                                                    <td><small><?= htmlspecialchars(substr($attacker['server_name'] ?? '-', 0, 20)) ?></small></td>
                                                    <td>
                                                        <a href="?tab=events&source_ip=<?= urlencode($attacker['source_ip']) ?>" class="btn btn-sm btn-info">
                                                            <i class="fas fa-search"></i> View Events
                                                        </a>
                                                      </td>
                                                </tr>
                                                <?php endforeach; ?>
                                                <?php if (count($attackers_data) == 0): ?>
                                                <tr>
                                                    <td colspan="5" class="text-center text-muted">No attackers found</td>
                                                </tr>
                                                <?php endif; ?>
                                            </tbody>
                                        </table>
                                    </div>
                                </div>
                            </div>
                        </div>
                        <div class="col-md-4">
                            <div class="card">
                                <div class="card-header">
                                    <h5>Attack Statistics</h5>
                                </div>
                                <div class="card-body">
                                    <canvas id="attackStatsChart" height="200"></canvas>
                                    <div class="mt-3 text-center">
                                        <small>Total Attacks: <strong><?= array_sum(array_column($attackers_data, 'count')) ?></strong></small><br>
                                        <small>Unique Attackers: <strong><?= count($attackers_data) ?></strong></small>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>

                <?php elseif ($tab == 'stats'): ?>
                    <!-- Statistics -->
                    <h2><i class="fas fa-chart-line"></i> Statistics</h2>
                    <hr>

                    <div class="row">
                        <div class="col-md-6">
                            <div class="card mb-2">
                                <div class="card-header">
                                    <h5>Events per Day</h5>
                                </div>
                                <div class="card-body">
                                    <canvas id="dailyChart" height="200"></canvas>
                                </div>
                            </div>
                        </div>
                        <div class="col-md-6">
                            <div class="card mb-2">
                                <div class="card-header">
                                    <h5>Events per Server</h5>
                                </div>
                                <div class="card-body">
                                    <canvas id="serverChart" height="200"></canvas>
                                </div>
                            </div>
                        </div>
                    </div>

                    <div class="card">
                        <div class="card-header">
                            <h5>Collection Stats</h5>
                        </div>
                        <div class="card-body p-0">
                            <div class="table-responsive">
                                <table class="table table-sm mb-0">
                                    <thead>
                                        <tr><th>Server</th><th>Time</th><th>Fetched</th><th>Inserted</th><th>Status</th></tr>
                                    </thead>
                                    <tbody>
                                        <?php foreach (getCollectionStats($pdo, 30) as $stat): ?>
                                        <tr style="font-size:0.75rem;">
                                            <td><small><?= htmlspecialchars(substr($stat['server_name'], 0, 20)) ?></small></td>
                                            <td><small><?= date('m-d H:i', strtotime($stat['collection_time'])) ?></small></td>
                                            <td><small><?= $stat['events_fetched'] ?></small></td>
                                            <td><small><?= $stat['events_inserted'] ?></small></td>
                                            <td><span class="badge bg-<?= $stat['status'] == 'success' ? 'success' : 'danger' ?>" style="font-size:0.65rem;"><?= $stat['status'] ?></span></td>
                                        </tr>
                                        <?php endforeach; ?>
                                    </tbody>
                                </table>
                            </div>
                        </div>
                    </div>

                <?php elseif ($tab == 'servers'): ?>
                    <!-- Server Management -->
                    <h2><i class="fas fa-server"></i> Servers</h2>
                    <hr>
                    <div class="card">
                        <div class="card-body p-0">
                            <div class="table-responsive">
                                <table class="table table-sm mb-0">
                                    <thead>
                                        <tr><th>Server Name</th><th>Events</th><th>Last Event</th><th></th></tr>
                                    </thead>
                                    <tbody>
                                        <?php foreach (getServerStats($pdo) as $server): ?>
                                        <tr style="font-size:0.75rem;">
                                            <td><strong><?= htmlspecialchars($server['server_name']) ?></strong></td>
                                            <td><?= number_format($server['event_count']) ?></td>
                                            <td><small><?= $server['last_event'] ? date('m-d H:i', strtotime($server['last_event'])) : '-' ?></small></td>
                                            <td>
                                                <a href="?tab=events&server=<?= urlencode($server['server_name']) ?>" class="btn btn-sm btn-primary">
                                                    <i class="fas fa-search"></i> View Events
                                                </a>
                                            </td>
                                        </tr>
                                        <?php endforeach; ?>
                                    </tbody>
                                </table>
                            </div>
                        </div>
                    </div>
                <?php endif; ?>
            </div>
        </div>
    </div>

    <!-- Event Detail Modal -->
    <div class="modal fade" id="eventModal" tabindex="-1">
        <div class="modal-dialog modal-lg">
            <div class="modal-content">
                <div class="modal-header py-2">
                    <h5 class="modal-title" style="font-size:1rem;">Event Details</h5>
                    <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                </div>
                <div class="modal-body" id="eventDetails" style="font-size:0.8rem;">
                    Loading...
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Close</button>
                    <button type="button" class="btn btn-warning" id="copyFirewallBtn" onclick="copyFirewallRule()">
                        <i class="fas fa-copy"></i> Copy Firewall Rule
                    </button>
                </div>
            </div>
        </div>
    </div>

    <!-- Toast Notification -->
    <div id="toast" style="display:none;" class="toast-notify">
        <i class="fas fa-check-circle"></i> Firewall rule copied to clipboard!
    </div>

    <script>
        // Variable to store current firewall rule
        let currentFirewallRule = '';

        // Globale Funktion zum Anzeigen von Event-Details
        function displayEventDetails(event) {
            // Generate firewall rule
            let firewallRule = '';
            if (event.source_ip && event.source_ip != '-' && event.source_ip != '') {
                firewallRule = `iptables -A INPUT -s ${event.source_ip} -j DROP`;
            } else {
                firewallRule = 'No source IP available for firewall rule';
            }
            currentFirewallRule = firewallRule;

            $('#eventDetails').html(`
                <table class="table table-sm">
                    <tr><th style="width:100px;">ID:</th><td>${event.id || '-'}</td></tr>
                    <tr><th>Server:</th><td>${escapeHtml(event.server_name) || '-'}</td></tr>
                    <tr><th>Hostname:</th><td>${escapeHtml(event.hostname) || '-'}</td></tr>
                    <tr><th>Timestamp:</th><td>${event.timestamp || '-'}</td></tr>
                    <tr><th>Process:</th><td>${escapeHtml(event.process_name) || '-'} [${event.pid || '?'}]</td></tr>
                    <tr><th>Message:</th><td><pre style="font-size:0.75rem; white-space:pre-wrap;">${escapeHtml(event.message || '-')}</pre></td></tr>
                    <tr><th>Source IP:</th><td>${event.source_ip || '-'}</td></tr>
                    <tr><th>Username:</th><td>${event.username || '-'}</td></tr>
                    <tr><th>Severity:</th><td><span class="severity-${event.severity}">${event.severity || '-'}</span></td></tr>
                    <tr><th>Event Group ID:</th><td>${event.event_group_id || '-'}</td></tr>
                    <tr><th>Raw Log:</th><td><pre style="max-height:150px; font-size:0.7rem; white-space:pre-wrap;">${escapeHtml(event.raw_log || 'N/A')}</pre></td></tr>
                </table>
                ${event.source_ip && event.source_ip != '-' && event.source_ip != '' ? `
                <div class="alert alert-info mt-2">
                    <strong><i class="fas fa-firewall"></i> Firewall Rule:</strong><br>
                    <code style="background:#1a1a2e; padding:8px; display:block; border-radius:5px; margin-top:5px; color:#0f0;">${firewallRule}</code>
                </div>
                ` : ''}
            `);
            $('#eventModal').modal('show');
        }

        // Escape HTML Funktion
        function escapeHtml(text) {
            if (!text) return '';
            return String(text).replace(/[&<>]/g, function(m) {
                if (m === '&') return '&amp;';
                if (m === '<') return '&lt;';
                if (m === '>') return '&gt;';
                return m;
            });
        }

        $(document).ready(function() {
            // ============================================================
            // NEU: Dashboard - Recent Critical Events anklickbar machen
            // ============================================================
            $('.clickable-row').on('click', function() {
                var eventId = $(this).data('event-id');
                if (eventId) {
                    // Event via AJAX laden
                    $.ajax({
                        url: 'ajax.php',
                        method: 'GET',
                        data: {
                            action: 'get_event',
                            event_id: eventId
                        },
                        dataType: 'json',
                        success: function(event) {
                            if (event && !event.error) {
                                displayEventDetails(event);
                            } else {
                                $('#eventDetails').html('<div class="alert alert-danger">Event not found or error loading details.</div>');
                                $('#eventModal').modal('show');
                            }
                        },
                        error: function(xhr, status, error) {
                            $('#eventDetails').html('<div class="alert alert-danger">Error loading event: ' + error + '</div>');
                            $('#eventModal').modal('show');
                        }
                    });
                }
            });

            // DataTables Initialisierung
            if ($('#eventsTable').length) {
                $('#eventsTable').DataTable({
                    "pageLength": 50,
                    "order": [[0, "desc"]],
                    "language": { "url": "//cdn.datatables.net/plug-ins/1.11.5/i18n/German.json" },
                    "scrollX": true,
                    "autoWidth": false,
                    "columnDefs": [
                        { "width": "60px", "targets": 0 },
                        { "width": "150px", "targets": 1 },
                        { "width": "100px", "targets": 2 },
                        { "width": "90px", "targets": 3 },
                        { "width": "250px", "targets": 4 },
                        { "width": "130px", "targets": 5 },
                        { "width": "80px", "targets": 6 },
                        { "width": "105px", "targets": 7 },
                        { "width": "40px", "targets": 8 }
                    ]
                });
            }

            if ($('#groupsTable').length) {
                $('#groupsTable').DataTable({
                    "pageLength": 25,
                    "order": [[0, "desc"]],
                    "scrollX": true
                });
            }

            if ($('#attackersTable').length) {
                $('#attackersTable').DataTable({
                    "pageLength": 25,
                    "order": [[1, "desc"]],
                    "scrollX": true
                });
            }

            // Severity change handler
            $('.severity-select').off('change').on('change', function() {
                var eventId = $(this).data('id');
                var severity = $(this).val();
                var selectElem = $(this);

                $.ajax({
                    url: 'ajax.php',
                    method: 'POST',
                    data: {
                        action: 'update_severity',
                        event_id: eventId,
                        severity: severity
                    },
                    success: function(response) {
                        var res = JSON.parse(response);
                        if (res.success) {
                            selectElem.css('background-color', '#d4edda');
                            setTimeout(function() {
                                selectElem.css('background-color', '');
                            }, 500);
                        } else {
                            alert('Error updating severity');
                        }
                    },
                    error: function() {
                        alert('AJAX error while updating severity');
                    }
                });
            });

            // View event details - Klick auf Auge
            $('.view-detail').off('click').on('click', function(e) {
                e.stopPropagation();
                var eventId = $(this).data('id');

                if (!eventId) {
                    console.error('No event ID found');
                    return;
                }

                $.ajax({
                    url: 'ajax.php',
                    method: 'GET',
                    data: {
                        action: 'get_event',
                        event_id: eventId
                    },
                    dataType: 'json',
                    success: function(event) {
                        if (event.error) {
                            $('#eventDetails').html('<div class="alert alert-danger">' + event.error + '</div>');
                            currentFirewallRule = '';
                        } else {
                            displayEventDetails(event);
                        }
                    },
                    error: function(xhr, status, error) {
                        $('#eventDetails').html('<div class="alert alert-danger">Error loading event details: ' + error + '</div>');
                        currentFirewallRule = '';
                        $('#eventModal').modal('show');
                    }
                });
            });

            // Klick auf ganze Zeile in Events Tabelle
            $('.event-detail').off('click').on('click', function(e) {
                if ($(e.target).hasClass('severity-select') || $(e.target).is('select')) {
                    return;
                }
                var eventId = $(this).data('id');
                if (eventId) {
                    $('.view-detail[data-id="' + eventId + '"]').click();
                }
            });

            // Group view handler
            $('.view-group').off('click').on('click', function() {
                var groupId = $(this).data('id');
                window.location.href = `?tab=events&group_id=${groupId}`;
            });

            // Delete filtered events functionality
            $('#deleteFilteredBtn').click(function() {
                var filters = {
                    server: $('select[name="server"]').val(),
                    severity: $('select[name="severity"]').val(),
                    date_from: $('input[name="date_from"]').val(),
                    date_to: $('input[name="date_to"]').val(),
                    source_ip: $('input[name="source_ip"]').val(),
                    username: $('input[name="username"]').val(),
                    search: $('input[name="search"]').val()
                };

                var filterList = [];
                if (filters.server) filterList.push('<strong>Server:</strong> ' + filters.server);
                if (filters.severity) filterList.push('<strong>Severity:</strong> ' + filters.severity);
                if (filters.date_from) filterList.push('<strong>From:</strong> ' + filters.date_from);
                if (filters.date_to) filterList.push('<strong>To:</strong> ' + filters.date_to);
                if (filters.source_ip) filterList.push('<strong>Source IP:</strong> ' + filters.source_ip);
                if (filters.username) filterList.push('<strong>Username:</strong> ' + filters.username);
                if (filters.search) filterList.push('<strong>Search:</strong> ' + filters.search);
                if (filterList.length === 0) filterList.push('<strong>No filters</strong> - ALL events will be deleted!');

                $('#deleteFilterList').html(filterList.map(f => '<li>' + f + '</li>').join(''));

                $.ajax({
                    url: 'ajax.php',
                    method: 'POST',
                    data: {
                        action: 'count_filtered',
                        filters: filters
                    },
                    dataType: 'json',
                    success: function(response) {
                        if (response.count !== undefined) {
                            $('#deleteCount').text(response.count);
                            if (response.count === 0) {
                                $('#executeDeleteBtn').prop('disabled', true);
                                $('#confirmDeleteCheck').prop('disabled', true);
                                $('#deleteFilterList').append('<li class="text-danger">No events match these filters!</li>');
                            } else {
                                $('#executeDeleteBtn').prop('disabled', true);
                                $('#confirmDeleteCheck').prop('disabled', false);
                            }
                        }
                    }
                });

                $('#confirmDeleteCheck').prop('checked', false);
                $('#executeDeleteBtn').prop('disabled', true);

                $('#confirmDeleteCheck').off('change').on('change', function() {
                    $('#executeDeleteBtn').prop('disabled', !$(this).is(':checked'));
                });

                $('#deleteConfirmModal').modal('show');
            });

            $('#executeDeleteBtn').click(function() {
                var filters = {
                    server: $('select[name="server"]').val(),
                    severity: $('select[name="severity"]').val(),
                    date_from: $('input[name="date_from"]').val(),
                    date_to: $('input[name="date_to"]').val(),
                    source_ip: $('input[name="source_ip"]').val(),
                    username: $('input[name="username"]').val(),
                    search: $('input[name="search"]').val()
                };

                $('#executeDeleteBtn').prop('disabled', true).html('<i class="fas fa-spinner fa-spin"></i> Deleting...');

                $.ajax({
                    url: 'ajax.php',
                    method: 'POST',
                    data: {
                        action: 'delete_filtered',
                        filters: filters
                    },
                    dataType: 'json',
                    success: function(response) {
                        $('#deleteConfirmModal').modal('hide');
                        if (response.success) {
                            $('#deleteResultBody').html(`
                                <div class="alert alert-success">
                                    <i class="fas fa-check-circle"></i> Successfully deleted <strong>${response.deleted}</strong> events!
                                </div>
                            `);
                        } else {
                            $('#deleteResultBody').html(`
                                <div class="alert alert-danger">
                                    <i class="fas fa-exclamation-triangle"></i> Error: ${response.error || 'Unknown error'}
                                </div>
                            `);
                        }
                        $('#deleteResultModal').modal('show');
                    },
                    error: function(xhr) {
                        $('#deleteConfirmModal').modal('hide');
                        $('#deleteResultBody').html(`
                            <div class="alert alert-danger">
                                <i class="fas fa-exclamation-triangle"></i> AJAX error: ${xhr.status} - ${xhr.statusText}
                            </div>
                        `);
                        $('#deleteResultModal').modal('show');
                    }
                });
            });
        });

        // Function to copy firewall rule to clipboard
        function copyFirewallRule() {
            if (currentFirewallRule && currentFirewallRule !== 'No source IP available for firewall rule') {
                if (navigator.clipboard && navigator.clipboard.writeText) {
                    navigator.clipboard.writeText(currentFirewallRule).then(function() {
                        showToast();
                    }).catch(function(err) {
                        console.error('Could not copy text: ', err);
                        fallbackCopy(currentFirewallRule);
                    });
                } else {
                    fallbackCopy(currentFirewallRule);
                }
            } else if (currentFirewallRule === 'No source IP available for firewall rule') {
                alert('No source IP available to create a firewall rule!');
            } else {
                alert('No firewall rule available!');
            }
        }

        function fallbackCopy(text) {
            var textarea = document.createElement('textarea');
            textarea.value = text;
            document.body.appendChild(textarea);
            textarea.select();
            document.execCommand('copy');
            document.body.removeChild(textarea);
            showToast();
        }

        function showToast() {
            var toast = document.getElementById('toast');
            toast.style.display = 'block';
            setTimeout(function() {
                toast.style.display = 'none';
            }, 2000);
        }

        <?php if ($tab == 'dashboard'): ?>
        var ctx = document.getElementById('severityChart').getContext('2d');
        var severityData = <?= json_encode(array_values($severity_counts)) ?>;
        var severityLabels = <?= json_encode(array_keys($severity_counts)) ?>;
        var colors = { 'CRITICAL': '#dc3545', 'HIGH': '#fd7e14', 'MEDIUM': '#ffc107', 'LOW': '#28a745', 'INFO': '#17a2b8' };

        new Chart(ctx, {
            type: 'pie',
            data: {
                labels: severityLabels,
                datasets: [{ data: severityData, backgroundColor: severityLabels.map(l => colors[l] || '#6c757d') }]
            },
            options: { responsive: true, maintainAspectRatio: true }
        });

        var ctx2 = document.getElementById('attackersChart').getContext('2d');
        var attackersData = <?= json_encode(array_column($top_attackers, 'count')) ?>;
        var attackersLabels = <?= json_encode(array_column($top_attackers, 'source_ip')) ?>;

        new Chart(ctx2, {
            type: 'bar',
            data: { labels: attackersLabels, datasets: [{ label: 'Attacks', data: attackersData, backgroundColor: '#dc3545' }] },
            options: { responsive: true, maintainAspectRatio: true, scales: { y: { beginAtZero: true } } }
        });
        <?php endif; ?>

        <?php if ($tab == 'stats'): ?>
        var dailyData = <?= json_encode(getDailyEvents($pdo, 30)) ?>;
        var ctxDaily = document.getElementById('dailyChart').getContext('2d');
        new Chart(ctxDaily, {
            type: 'line',
            data: {
                labels: dailyData.map(d => d.date),
                datasets: [{ label: 'Events', data: dailyData.map(d => parseInt(d.count)), borderColor: '#007bff', fill: false }]
            },
            options: { responsive: true, maintainAspectRatio: true }
        });

        var serverStats = <?= json_encode(getServerEventCounts($pdo)) ?>;
        var ctxServer = document.getElementById('serverChart').getContext('2d');
        new Chart(ctxServer, {
            type: 'pie',
            data: {
                labels: serverStats.map(s => s.server_name),
                datasets: [{ data: serverStats.map(s => parseInt(s.count)), backgroundColor: ['#007bff', '#28a745', '#dc3545', '#ffc107', '#17a2b8'] }]
            },
            options: { responsive: true, maintainAspectRatio: true }
        });
        <?php endif; ?>

        <?php if ($tab == 'attackers'): ?>
        var attackStatsData = <?= json_encode(array_column($attackers_data, 'count')) ?>;
        var attackStatsLabels = <?= json_encode(array_column($attackers_data, 'source_ip')) ?>;
        var ctxAttackStats = document.getElementById('attackStatsChart').getContext('2d');

        if (attackStatsData.length > 0) {
            new Chart(ctxAttackStats, {
                type: 'pie',
                data: {
                    labels: attackStatsLabels.slice(0, 10),
                    datasets: [{ data: attackStatsData.slice(0, 10), backgroundColor: '#dc3545' }]
                },
                options: { responsive: true, maintainAspectRatio: true }
            });
        } else {
            ctxAttackStats.fillStyle = '#ddd';
            ctxAttackStats.fillRect(0, 0, 200, 200);
            ctxAttackStats.fillStyle = '#666';
            ctxAttackStats.font = '12px Arial';
            ctxAttackStats.fillText('No data available', 60, 100);
        }
        <?php endif; ?>
    </script>
</body>
</html>
