<?php
/**
 * SimpleHomeLog SIEM - Functions Library
 * ======================================================
 *
 * @author      Klaus Baumdick
 * @copyright   2026 Klaus Baumdick
 * @license     MIT
 * @version     1.0.2
 * @date        2026-05-23
 */

require_once 'db_config.php';

function getStatistics($pdo) {
    $sql = "SELECT
            COUNT(*) as total_events,
            COUNT(DISTINCT server_name) as total_servers,
            COUNT(DISTINCT source_ip) as unique_attackers,
            SUM(CASE WHEN severity = 'CRITICAL' THEN 1 ELSE 0 END) as critical_events,
            SUM(CASE WHEN severity = 'HIGH' THEN 1 ELSE 0 END) as high_events
            FROM security_events";

    $stmt = $pdo->query($sql);
    return $stmt->fetch();
}

function getSeverityCounts($pdo) {
    $sql = "SELECT severity, COUNT(*) as count FROM security_events GROUP BY severity ORDER BY
            CASE severity
                WHEN 'CRITICAL' THEN 1
                WHEN 'HIGH' THEN 2
                WHEN 'MEDIUM' THEN 3
                WHEN 'LOW' THEN 4
                ELSE 5
            END";
    $stmt = $pdo->query($sql);
    $result = [];
    while ($row = $stmt->fetch()) {
        $result[$row['severity']] = $row['count'];
    }
    return $result;
}

function getTopAttackers($pdo, $limit = 10, $server_filter = '') {
    $sql = "SELECT source_ip, server_name, COUNT(*) as count, MAX(timestamp) as last_seen
            FROM security_events
            WHERE source_ip IS NOT NULL AND source_ip != '' AND severity IN ('HIGH', 'CRITICAL')";

    if ($server_filter) {
        $sql .= " AND server_name = :server";
    }

    $sql .= " GROUP BY source_ip, server_name ORDER BY count DESC LIMIT :limit";

    $stmt = $pdo->prepare($sql);
    if ($server_filter) {
        $stmt->bindValue('server', $server_filter);
    }
    $stmt->bindValue('limit', $limit, PDO::PARAM_INT);
    $stmt->execute();
    return $stmt->fetchAll();
}

function getRecentEvents($pdo, $limit = 20) {
    $sql = "SELECT * FROM security_events
            WHERE severity IN ('HIGH', 'CRITICAL')
            ORDER BY timestamp DESC
            LIMIT :limit";
    $stmt = $pdo->prepare($sql);
    $stmt->execute(['limit' => $limit]);
    return $stmt->fetchAll();
}

function getEvents($pdo, $filters) {
    $sql = "SELECT * FROM security_events WHERE 1=1";
    $params = [];

    if (!empty($filters['server'])) {
        $sql .= " AND server_name = :server";
        $params['server'] = $filters['server'];
    }
    if (!empty($filters['severity'])) {
        $sql .= " AND severity = :severity";
        $params['severity'] = $filters['severity'];
    }
    if (!empty($filters['date_from'])) {
        $sql .= " AND timestamp >= :date_from";
        $params['date_from'] = $filters['date_from'] . ' 00:00:00';
    }
    if (!empty($filters['date_to'])) {
        $sql .= " AND timestamp <= :date_to";
        $params['date_to'] = $filters['date_to'] . ' 23:59:59';
    }
    if (!empty($filters['source_ip'])) {
        $sql .= " AND source_ip = :source_ip";
        $params['source_ip'] = $filters['source_ip'];
    }
    if (!empty($filters['username'])) {
        $sql .= " AND username = :username";
        $params['username'] = $filters['username'];
    }
    if (!empty($filters['search'])) {
        $sql .= " AND message ILIKE :search";
        $params['search'] = '%' . $filters['search'] . '%';
    }
    if (!empty($filters['group_id'])) {
        $sql .= " AND event_group_id = :group_id";
        $params['group_id'] = $filters['group_id'];
    }

    $sql .= " ORDER BY timestamp DESC LIMIT :limit";
    $params['limit'] = $filters['limit'];

    $stmt = $pdo->prepare($sql);
    foreach ($params as $key => $value) {
        $stmt->bindValue($key, $value);
    }
    $stmt->execute();
    return $stmt->fetchAll();
}

function getServers($pdo) {
    $sql = "SELECT DISTINCT server_name FROM security_events ORDER BY server_name";
    $stmt = $pdo->query($sql);
    return $stmt->fetchAll(PDO::FETCH_COLUMN);
}

function getEventGroups($pdo, $limit = 100, $server_filter = '', $process_filter = '') {
    $sql = "SELECT * FROM event_groups WHERE 1=1";
    $params = [];

    if ($server_filter) {
        $sql .= " AND server_name = :server";
        $params['server'] = $server_filter;
    }
    if ($process_filter) {
        $sql .= " AND process_name ILIKE :process";
        $params['process'] = '%' . $process_filter . '%';
    }

    $sql .= " ORDER BY start_time DESC LIMIT :limit";
    $params['limit'] = $limit;

    $stmt = $pdo->prepare($sql);
    foreach ($params as $key => $value) {
        $stmt->bindValue($key, $value);
    }
    $stmt->execute();
    return $stmt->fetchAll();
}

function getCollectionStats($pdo, $limit = 50) {
    $sql = "SELECT * FROM collection_stats ORDER BY collection_time DESC LIMIT :limit";
    $stmt = $pdo->prepare($sql);
    $stmt->execute(['limit' => $limit]);
    return $stmt->fetchAll();
}

function getServerStats($pdo) {
    $sql = "SELECT
            server_name,
            COUNT(*) as event_count,
            MAX(timestamp) as last_event
            FROM security_events
            GROUP BY server_name
            ORDER BY server_name";
    $stmt = $pdo->query($sql);
    return $stmt->fetchAll();
}

function getDailyEvents($pdo, $days = 30) {
    // PostgreSQL kompatible Version
    $sql = "SELECT DATE(timestamp) as date, COUNT(*) as count
            FROM security_events
            WHERE timestamp >= CURRENT_DATE - ($days || ' days')::INTERVAL
            GROUP BY DATE(timestamp)
            ORDER BY date ASC";

    $stmt = $pdo->prepare($sql);
    $stmt->execute();
    $results = $stmt->fetchAll();

    // Wenn keine Daten vorhanden sind, leeres Array zurückgeben
    if (empty($results)) {
        return [];
    }

    return $results;
}

function getServerEventCounts($pdo) {
    $sql = "SELECT server_name, COUNT(*) as count
            FROM security_events
            GROUP BY server_name
            ORDER BY count DESC";
    $stmt = $pdo->query($sql);
    return $stmt->fetchAll();
}

function getEventById($pdo, $event_id) {
    $sql = "SELECT * FROM security_events WHERE id = :event_id";
    $stmt = $pdo->prepare($sql);
    $stmt->execute(['event_id' => $event_id]);
    return $stmt->fetch();
}

function updateEventSeverity($pdo, $event_id, $severity) {
    $sql = "UPDATE security_events SET severity = :severity WHERE id = :event_id";
    $stmt = $pdo->prepare($sql);
    return $stmt->execute(['severity' => $severity, 'event_id' => $event_id]);
}

function countFilteredEvents($pdo, $filters) {
    $sql = "SELECT COUNT(*) as count FROM security_events WHERE 1=1";
    $params = [];

    if (!empty($filters['server'])) {
        $sql .= " AND server_name = :server";
        $params['server'] = $filters['server'];
    }
    if (!empty($filters['severity'])) {
        $sql .= " AND severity = :severity";
        $params['severity'] = $filters['severity'];
    }
    if (!empty($filters['date_from'])) {
        $sql .= " AND timestamp >= :date_from";
        $params['date_from'] = $filters['date_from'] . ' 00:00:00';
    }
    if (!empty($filters['date_to'])) {
        $sql .= " AND timestamp <= :date_to";
        $params['date_to'] = $filters['date_to'] . ' 23:59:59';
    }
    if (!empty($filters['source_ip'])) {
        $sql .= " AND source_ip = :source_ip";
        $params['source_ip'] = $filters['source_ip'];
    }
    if (!empty($filters['username'])) {
        $sql .= " AND username = :username";
        $params['username'] = $filters['username'];
    }
    if (!empty($filters['search'])) {
        $sql .= " AND message ILIKE :search";
        $params['search'] = '%' . $filters['search'] . '%';
    }

    $stmt = $pdo->prepare($sql);
    foreach ($params as $key => $value) {
        $stmt->bindValue($key, $value);
    }
    $stmt->execute();
    $result = $stmt->fetch();
    return $result['count'];
}

function deleteFilteredEvents($pdo, $filters) {
    try {
        $pdo->beginTransaction();

        $sql = "DELETE FROM security_events WHERE 1=1";
        $params = [];

        if (!empty($filters['server'])) {
            $sql .= " AND server_name = :server";
            $params['server'] = $filters['server'];
        }
        if (!empty($filters['severity'])) {
            $sql .= " AND severity = :severity";
            $params['severity'] = $filters['severity'];
        }
        if (!empty($filters['date_from'])) {
            $sql .= " AND timestamp >= :date_from";
            $params['date_from'] = $filters['date_from'] . ' 00:00:00';
        }
        if (!empty($filters['date_to'])) {
            $sql .= " AND timestamp <= :date_to";
            $params['date_to'] = $filters['date_to'] . ' 23:59:59';
        }
        if (!empty($filters['source_ip'])) {
            $sql .= " AND source_ip = :source_ip";
            $params['source_ip'] = $filters['source_ip'];
        }
        if (!empty($filters['username'])) {
            $sql .= " AND username = :username";
            $params['username'] = $filters['username'];
        }
        if (!empty($filters['search'])) {
            $sql .= " AND message ILIKE :search";
            $params['search'] = '%' . $filters['search'] . '%';
        }

        $stmt = $pdo->prepare($sql);
        foreach ($params as $key => $value) {
            $stmt->bindValue($key, $value);
        }
        $stmt->execute();
        $deletedCount = $stmt->rowCount();

        // Leere Gruppen löschen
        $cleanGroupsSql = "
            DELETE FROM event_groups
            WHERE id NOT IN (SELECT DISTINCT event_group_id FROM security_events WHERE event_group_id IS NOT NULL)
        ";
        $pdo->exec($cleanGroupsSql);

        $pdo->commit();
        return $deletedCount;

    } catch (Exception $e) {
        $pdo->rollBack();
        error_log("Delete error: " . $e->getMessage());
        return false;
    }
}
/**
 * Holt Daten für Attack Graph Visualization
 */
function getAttackGraphData($pdo, $server_filter = '', $days = 7, $min_attacks = 1) {
    // Hole alle Angreifer mit ihren Servern
    $sql = "
        SELECT
            source_ip,
            server_name,
            COUNT(*) as attack_count,
            MAX(timestamp) as last_attack,
            MAX(CASE
                WHEN severity = 'CRITICAL' THEN 'CRITICAL'
                WHEN severity = 'HIGH' THEN 'HIGH'
                WHEN severity = 'MEDIUM' THEN 'MEDIUM'
                ELSE 'LOW'
            END) as max_severity,
            MIN(timestamp) as first_attack
        FROM security_events
        WHERE source_ip IS NOT NULL
            AND source_ip != ''
            AND timestamp >= CURRENT_DATE - (:days || ' days')::INTERVAL
    ";

    $params = ['days' => $days];

    if ($server_filter) {
        $sql .= " AND server_name = :server";
        $params['server'] = $server_filter;
    }

    $sql .= " GROUP BY source_ip, server_name
              HAVING COUNT(*) >= :min_attacks
              ORDER BY attack_count DESC
              LIMIT 100";

    $params['min_attacks'] = $min_attacks;

    $stmt = $pdo->prepare($sql);
    foreach ($params as $key => $value) {
        $stmt->bindValue($key, $value);
    }
    $stmt->execute();
    $connections = $stmt->fetchAll();

    // Baue Nodes für Angreifer
    $attackers = [];
    $attacker_ids = [];
    $server_ids = [];

    foreach ($connections as $conn) {
        $attacker_id = 'attacker_' . md5($conn['source_ip']);
        $server_id = 'server_' . md5($conn['server_name']);

        if (!isset($attacker_ids[$conn['source_ip']])) {
            $attackers[] = [
                'id' => $attacker_id,
                'ip' => $conn['source_ip'],
                'count' => 0,
                'last_seen' => $conn['last_attack'],
                'server' => $conn['server_name'],
                'max_severity' => $conn['max_severity']
            ];
            $attacker_ids[$conn['source_ip']] = $attacker_id;
        }

        // Sammle Attack Count pro Attacker
        foreach ($attackers as &$att) {
            if ($att['ip'] == $conn['source_ip']) {
                $att['count'] += $conn['attack_count'];
                break;
            }
        }
    }

    // Baue Nodes für Server
    $sql_servers = "
        SELECT
            server_name,
            COUNT(*) as event_count,
            COUNT(DISTINCT source_ip) as attacker_count
        FROM security_events
        WHERE timestamp >= CURRENT_DATE - (:days || ' days')::INTERVAL
    ";

    $params = ['days' => $days];
    if ($server_filter) {
        $sql_servers .= " AND server_name = :server";
        $params['server'] = $server_filter;
    }

    $sql_servers .= " GROUP BY server_name LIMIT 50";

    $stmt = $pdo->prepare($sql_servers);
    foreach ($params as $key => $value) {
        $stmt->bindValue($key, $value);
    }
    $stmt->execute();
    $servers_data = $stmt->fetchAll();

    $servers = [];
    foreach ($servers_data as $server) {
        $server_id = 'server_' . md5($server['server_name']);
        $servers[] = [
            'id' => $server_id,
            'name' => $server['server_name'],
            'event_count' => $server['event_count'],
            'attacker_count' => $server['attacker_count']
        ];
        $server_ids[$server['server_name']] = $server_id;
    }

    // Baue Connections
    $graph_connections = [];
    foreach ($connections as $conn) {
        $graph_connections[] = [
            'attacker_id' => 'attacker_' . md5($conn['source_ip']),
            'attacker_ip' => $conn['source_ip'],
            'server_id' => 'server_' . md5($conn['server_name']),
            'server_name' => $conn['server_name'],
            'attack_count' => $conn['attack_count'],
            'last_attack' => $conn['last_attack'],
            'max_severity' => $conn['max_severity']
        ];
    }

    return [
        'attackers' => $attackers,
        'servers' => $servers,
        'connections' => $graph_connections
    ];
}
?>
