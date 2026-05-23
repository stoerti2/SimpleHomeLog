<?php
/**
 * SimpleHomeLog SIEM - Attack Graph Visualization
 * ======================================================
 *
 * @author      Klaus Baumdick
 * @copyright   2026 Klaus Baumdick
 * @license     MIT
 * @version     1.0.0
 * @date        2026-05-23
 *
 * @description Web interface for SIEM log management
 *              Features: Dashboard, Event Viewer, Event Groups,
 *              Attacker Analysis, Statistics, Server Management
 *
 * @requires    PHP 7.4+
 * @requires    PostgreSQL 12+
 * @requires    PDO PostgreSQL extension
 *
 * @filesource
 *
 * MIT License
 *
 * Copyright (c) 2026 Klaus Baumdick
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */


require_once 'db_config.php';
require_once 'functions.php';

// Filter für Attack Graph
$server_filter = $_GET['server'] ?? '';
$days_filter = $_GET['days'] ?? 7;
$min_attacks = $_GET['min_attacks'] ?? 1;

// Daten für den Graph holen
$graph_data = getAttackGraphData($pdo, $server_filter, $days_filter, $min_attacks);
?>
<!DOCTYPE html>
<html lang="de">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SimpleHomeLog Attack Graph - SimpleHomeLog SIEM</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
    <script src="https://code.jquery.com/jquery-3.6.0.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/js/bootstrap.bundle.min.js"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/vis-network/9.1.6/dist/vis-network.min.js"></script>
    <style>
        body {
            font-size: 0.85rem;
            background: #1a1a2e;
            color: #eee;
        }
        .sidebar {
            min-height: 100vh;
            background-color: #16213e;
        }
        .sidebar .nav-link {
            color: #eee;
            font-size: 0.85rem;
            padding: 0.5rem 1rem;
        }
        .sidebar .nav-link:hover {
            background-color: #0f3460;
        }
        .sidebar .nav-link.active {
            background-color: #e94560;
        }
        .card {
            background-color: #16213e;
            border: none;
            border-radius: 10px;
        }
        .card-header {
            background-color: #0f3460;
            border-bottom: none;
            font-weight: bold;
        }
        .btn-primary {
            background-color: #e94560;
            border-color: #e94560;
        }
        .btn-primary:hover {
            background-color: #c73e56;
            border-color: #c73e56;
        }
        #network {
            height: 70vh;
            background-color: #0a0e27;
            border-radius: 10px;
            border: 1px solid #0f3460;
        }
        .form-control, .form-select {
            background-color: #0f3460;
            border: 1px solid #1a4a7a;
            color: #eee;
        }
        .form-control:focus, .form-select:focus {
            background-color: #1a4a7a;
            color: #eee;
        }
        .form-control::placeholder {
            color: #aaa;
        }
        .legend {
            background: #16213e;
            padding: 10px;
            border-radius: 8px;
            margin-top: 10px;
        }
        .legend-color {
            display: inline-block;
            width: 20px;
            height: 20px;
            border-radius: 50%;
            margin-right: 5px;
        }
        .stats-badge {
            background: #0f3460;
            padding: 8px 15px;
            border-radius: 8px;
            margin: 5px;
        }
        h2, h5 {
            color: #eee;
        }
        hr {
            background-color: #0f3460;
        }
        a {
            color: #e94560;
        }
        a:hover {
            color: #ff6b8a;
        }
        .node-tooltip {
            position: fixed;
            background: #16213e;
            border: 1px solid #e94560;
            padding: 10px;
            border-radius: 8px;
            font-size: 0.8rem;
            z-index: 1000;
            display: none;
            max-width: 300px;
            box-shadow: 0 4px 15px rgba(0,0,0,0.3);
        }
        .severity-CRITICAL { color: #ff4757; }
        .severity-HIGH { color: #ff6b81; }
        .severity-MEDIUM { color: #ffa502; }
        .severity-LOW { color: #1e90ff; }
    </style>
</head>
<body>
    <div class="container-fluid">
        <div class="row">
            <!-- Sidebar -->
            <div class="col-md-2 p-0 sidebar">
                <div class="p-3">
                    <h4 class="text-white mb-3" style="font-size: 1.1rem;">
                        <i class="fas fa-project-diagram"></i> Attack Graph
                    </h4>
                    <nav class="nav flex-column">
                        <a class="nav-link" href="index.php?tab=dashboard">
                            <i class="fas fa-tachometer-alt"></i> Dashboard
                        </a>
                        <a class="nav-link" href="index.php?tab=events">
                            <i class="fas fa-list"></i> Events
                        </a>
                        <a class="nav-link" href="index.php?tab=groups">
                            <i class="fas fa-layer-group"></i> Event Groups
                        </a>
                        <a class="nav-link" href="index.php?tab=attackers">
                            <i class="fas fa-bug"></i> Attackers
                        </a>
                        <a class="nav-link active" href="attack_graph.php">
                            <i class="fas fa-project-diagram"></i> Attack Graph
                        </a>
                        <a class="nav-link" href="index.php?tab=stats">
                            <i class="fas fa-chart-line"></i> Statistics
                        </a>
                        <a class="nav-link" href="index.php?tab=servers">
                            <i class="fas fa-server"></i> Servers
                        </a>
                    </nav>
                </div>
            </div>

            <!-- Main Content -->
            <div class="col-md-10 p-3">
                <h2><i class="fas fa-project-diagram"></i> SimpleHomeLog SIEM Attack Graph Visualization</h2>
                <hr>

                <!-- Filters -->
                <div class="card mb-3">
                    <div class="card-header">
                        <h5><i class="fas fa-filter"></i> Graph Filters</h5>
                    </div>
                    <div class="card-body">
                        <form method="GET" class="row g-2">
                            <div class="col-md-3">
                                <label class="form-label">Server</label>
                                <select name="server" class="form-select">
                                    <option value="">All Servers</option>
                                    <?php foreach (getServers($pdo) as $server): ?>
                                    <option value="<?= htmlspecialchars($server) ?>" <?= $server_filter == $server ? 'selected' : '' ?>>
                                        <?= htmlspecialchars($server) ?>
                                    </option>
                                    <?php endforeach; ?>
                                </select>
                            </div>
                            <div class="col-md-2">
                                <label class="form-label">Days</label>
                                <select name="days" class="form-select">
                                    <option value="1" <?= $days_filter == 1 ? 'selected' : '' ?>>Last 24 hours</option>
                                    <option value="7" <?= $days_filter == 7 ? 'selected' : '' ?>>Last 7 days</option>
                                    <option value="30" <?= $days_filter == 30 ? 'selected' : '' ?>>Last 30 days</option>
                                    <option value="90" <?= $days_filter == 90 ? 'selected' : '' ?>>Last 90 days</option>
                                </select>
                            </div>
                            <div class="col-md-2">
                                <label class="form-label">Min Attacks</label>
                                <select name="min_attacks" class="form-select">
                                    <option value="1" <?= $min_attacks == 1 ? 'selected' : '' ?>>1+ attacks</option>
                                    <option value="5" <?= $min_attacks == 5 ? 'selected' : '' ?>>5+ attacks</option>
                                    <option value="10" <?= $min_attacks == 10 ? 'selected' : '' ?>>10+ attacks</option>
                                    <option value="50" <?= $min_attacks == 50 ? 'selected' : '' ?>>50+ attacks</option>
                                </select>
                            </div>
                            <div class="col-md-3 d-flex align-items-end">
                                <button type="submit" class="btn btn-primary">
                                    <i class="fas fa-sync-alt"></i> Update Graph
                                </button>
                                <button type="button" class="btn btn-secondary ms-2" onclick="exportGraph()">
                                    <i class="fas fa-download"></i> Export PNG
                                </button>
                            </div>
                        </form>
                    </div>
                </div>

                <!-- Graph Container -->
                <div class="card">
                    <div class="card-header">
                        <h5><i class="fas fa-share-alt"></i> Attack Relationships</h5>
                        <small>Node size = number of attacks | Color = severity | Edge width = attack frequency</small>
                    </div>
                    <div class="card-body">
                        <div id="network"></div>
                    </div>
                </div>

                <!-- Statistics -->
                <div class="row mt-3">
                    <div class="col-md-12">
                        <div class="legend">
                            <strong><i class="fas fa-chart-pie"></i> Legend:</strong>
                            <span class="ms-3"><span class="legend-color" style="background: #ff4757;"></span> Critical</span>
                            <span class="ms-3"><span class="legend-color" style="background: #ff6b81;"></span> High</span>
                            <span class="ms-3"><span class="legend-color" style="background: #ffa502;"></span> Medium</span>
                            <span class="ms-3"><span class="legend-color" style="background: #1e90ff;"></span> Low/Info</span>
                            <span class="ms-3"><span class="legend-color" style="background: #00ff88;"></span> Server Node</span>
                            <span class="ms-3"><i class="fas fa-mouse-pointer"></i> Hover for details</span>
                            <span class="ms-3"><i class="fas fa-search-plus"></i> Scroll to zoom</span>
                        </div>
                    </div>
                </div>

                <!-- Attack Details Modal -->
                <div class="modal fade" id="attackModal" tabindex="-1">
                    <div class="modal-dialog modal-lg">
                        <div class="modal-content" style="background: #16213e;">
                            <div class="modal-header" style="border-bottom-color: #0f3460;">
                                <h5 class="modal-title"><i class="fas fa-bug"></i> Attack Details</h5>
                                <button type="button" class="btn-close btn-close-white" data-bs-dismiss="modal"></button>
                            </div>
                            <div class="modal-body" id="attackModalBody">
                                Loading...
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <script>
        // Graph data from PHP
        let graphData = <?= json_encode($graph_data) ?>;

        // Create nodes and edges
        let nodes = [];
        let edges = [];
        let nodeIds = new Set();

        // Add nodes for attackers
        graphData.attackers.forEach(attacker => {
            if (!nodeIds.has(attacker.id)) {
                nodes.push({
                    id: attacker.id,
                    label: attacker.ip,
                    title: `IP: ${attacker.ip}\nAttacks: ${attacker.count}\nLast Seen: ${attacker.last_seen}\nServer: ${attacker.server}`,
                    group: 'attacker',
                    value: Math.min(attacker.count, 50), // Size based on attack count
                    font: { color: '#fff', size: 12 },
                    shape: 'dot',
                    color: getSeverityColor(attacker.max_severity)
                });
                nodeIds.add(attacker.id);
            }
        });

        // Add nodes for servers
        graphData.servers.forEach(server => {
            if (!nodeIds.has(server.id)) {
                nodes.push({
                    id: server.id,
                    label: server.name,
                    title: `Server: ${server.name}\nTotal Events: ${server.event_count}\nTarget of: ${server.attacker_count} attackers`,
                    group: 'server',
                    value: Math.min(server.event_count / 10, 40),
                    font: { color: '#fff', size: 14, face: 'bold' },
                    shape: 'box',
                    color: { background: '#00ff88', border: '#00cc66', highlight: '#00ffaa' }
                });
                nodeIds.add(server.id);
            }
        });

        // Add edges (attacks)
        graphData.connections.forEach(conn => {
            edges.push({
                from: conn.attacker_id,
                to: conn.server_id,
                value: conn.attack_count,
                title: `${conn.attack_count} attacks from ${conn.attacker_ip} to ${conn.server_name}\nLast: ${conn.last_attack}`,
                color: { color: getEdgeColor(conn.max_severity), opacity: 0.6 },
                width: Math.min(conn.attack_count / 5, 8) + 1
            });
        });

        function getSeverityColor(severity) {
            switch(severity) {
                case 'CRITICAL': return '#ff4757';
                case 'HIGH': return '#ff6b81';
                case 'MEDIUM': return '#ffa502';
                default: return '#1e90ff';
            }
        }

        function getEdgeColor(severity) {
            switch(severity) {
                case 'CRITICAL': return '#ff4757';
                case 'HIGH': return '#ff6b81';
                case 'MEDIUM': return '#ffa502';
                default: return '#1e90ff';
            }
        }

        // Create network
        let container = document.getElementById('network');
        let data = { nodes: new vis.DataSet(nodes), edges: new vis.DataSet(edges) };
        let options = {
            nodes: {
                shape: 'dot',
                size: 20,
                font: { size: 12, color: '#fff' },
                borderWidth: 2,
                shadow: true
            },
            edges: {
                smooth: { type: 'continuous', roundness: 0.5 },
                arrows: { to: { enabled: true, scaleFactor: 0.8 } },
                shadow: true,
                font: { align: 'middle', size: 10, color: '#aaa' }
            },
            physics: {
                enabled: true,
                stabilization: { iterations: 100 },
                solver: 'forceAtlas2Based',
                forceAtlas2Based: { gravitationalConstant: -50, centralGravity: 0.01, springLength: 100 }
            },
            interaction: {
                hover: true,
                tooltipDelay: 100,
                zoomView: true,
                dragView: true,
                navigationButtons: true
            },
            layout: { improvedLayout: true }
        };

        let network = new vis.Network(container, data, options);

        // Add click handler for nodes
        network.on('click', function(params) {
            if (params.nodes.length > 0) {
                let nodeId = params.nodes[0];
                let node = nodes.find(n => n.id == nodeId);

                if (node && node.group === 'attacker') {
                    // Show attack details for this IP
                    let ip = node.label;
                    window.location.href = `index.php?tab=events&source_ip=${encodeURIComponent(ip)}`;
                } else if (node && node.group === 'server') {
                    // Show server details
                    let serverName = node.label;
                    window.location.href = `index.php?tab=events&server=${encodeURIComponent(serverName)}`;
                }
            }
        });

        // Add double-click for zoom reset
        network.on('doubleClick', function() {
            network.fit({ animation: true });
        });

        // Export graph as PNG
        function exportGraph() {
            let canvas = document.querySelector('#network canvas');
            if (canvas) {
                let link = document.createElement('a');
                link.download = 'attack_graph.png';
                link.href = canvas.toDataURL();
                link.click();
            }
        }

        // Show stats on console
        console.log(`Graph loaded: ${nodes.length} nodes, ${edges.length} edges`);

        // Auto-fit after stabilization
        network.once('stabilizationIterationsDone', function() {
            network.fit({ animation: true, duration: 500 });
        });

        // Resize handler
        window.addEventListener('resize', function() {
            network.fit();
        });
    </script>
</body>
</html>
