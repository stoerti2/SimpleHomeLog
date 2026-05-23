<?php
/**
 * SimpleHomeLog SIEM - Security Information & Event Management System
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
error_reporting(E_ALL);
ini_set('display_errors', 1);

require_once 'db_config.php';
require_once 'functions.php';

header('Content-Type: application/json');

$action = $_GET['action'] ?? $_POST['action'] ?? '';

try {
    if ($action == 'update_severity') {
        $event_id = $_POST['event_id'] ?? 0;
        $severity = $_POST['severity'] ?? '';

        if ($event_id && $severity) {
            $success = updateEventSeverity($pdo, $event_id, $severity);
            echo json_encode(['success' => $success]);
        } else {
            echo json_encode(['success' => false, 'error' => 'Missing parameters']);
        }
    }
    elseif ($action == 'get_event') {
        $event_id = $_GET['event_id'] ?? 0;
        if ($event_id) {
            $event = getEventById($pdo, $event_id);
            if ($event) {
                echo json_encode($event);
            } else {
                echo json_encode(['error' => 'Event not found']);
            }
        } else {
            echo json_encode(['error' => 'Event ID required']);
        }
    }
    elseif ($action == 'count_filtered') {
        $filters = $_POST['filters'] ?? [];
        if (!is_array($filters)) {
            $filters = [];
        }
        $count = countFilteredEvents($pdo, $filters);
        echo json_encode(['count' => $count]);
    }
    elseif ($action == 'delete_filtered') {
        $filters = $_POST['filters'] ?? [];
        if (!is_array($filters)) {
            $filters = [];
        }
        $deleted = deleteFilteredEvents($pdo, $filters);
        if ($deleted !== false) {
            echo json_encode(['success' => true, 'deleted' => $deleted]);
        } else {
            echo json_encode(['success' => false, 'error' => 'Delete operation failed']);
        }
    }
    else {
        echo json_encode(['error' => 'Invalid action: ' . $action]);
    }
} catch (Exception $e) {
    error_log("AJAX Error: " . $e->getMessage());
    echo json_encode(['error' => $e->getMessage()]);
}
?>
