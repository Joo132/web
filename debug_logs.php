<?php
define('LICENSE_SERVER', true);
require_once __DIR__ . '/config.php';
require_once __DIR__ . '/database.php';
require_once __DIR__ . '/discord_oauth.php';
require_once __DIR__ . '/logs.php';

header('Content-Type: text/plain');

echo "--- Debugging Logs System ---\n";

// 1. Check DB Connection
try {
    $db = Database::getInstance();
    echo "DB Connection: OK\n";
} catch (Exception $e) {
    die("DB Connection FAILED: " . $e->getMessage() . "\n");
}

// 2. Ensure Schema
try {
    SystemLog::ensureSchema();
    echo "ensureSchema: Executed\n";
} catch (Exception $e) {
    echo "ensureSchema FAILED: " . $e->getMessage() . "\n";
}

// 3. Test Log Creation
try {
    $id = SystemLog::log('System', 'Test', 'Debug log entry', 'System');
    echo "Log Created: ID $id\n";
} catch (Exception $e) {
    echo "Log Creation FAILED: " . $e->getMessage() . "\n";
}

// 4. Test Fetch Logs
try {
    $logs = SystemLog::getLogs(null, null, 10);
    echo "Fetch Logs: OK (" . count($logs) . " records)\n";
    if (count($logs) > 0) {
        print_r($logs[0]);
    }
} catch (Exception $e) {
    echo "Fetch Logs FAILED: " . $e->getMessage() . "\n";
}
