<?php
// Simple debug script to test feedback API
error_reporting(E_ALL);
ini_set('display_errors', 1);

define('LICENSE_SERVER', true);
require_once __DIR__ . '/config.php';
require_once __DIR__ . '/database.php';

header('Content-Type: application/json');

try {
    // 3: Check schema and add column if missing (Self-healing)
    $cols = Database::query("SHOW COLUMNS FROM `feedbacks` LIKE 'module_id'");
    if (empty($cols)) {
        try {
            Database::execute("ALTER TABLE `feedbacks` ADD COLUMN `module_id` INT UNSIGNED NULL AFTER `rating`", []);
        } catch (Exception $e) {}
    }

    // 4: Try to query feedbacks with module names
    $feedbacks = Database::query("
        SELECT f.`name`, f.`message`, f.`rating`, f.`created_at`, m.`name` as `module_name`
        FROM `feedbacks` f
        LEFT JOIN `modules` m ON f.`module_id` = m.`id`
        ORDER BY f.`created_at` DESC 
        LIMIT 20
    ");
    
    // 4: Final response
    echo json_encode(['success' => true, 'feedbacks' => $feedbacks]);
    
} catch (Exception $e) {
    echo json_encode(['error' => $e->getMessage(), 'trace' => $e->getTraceAsString()]);
}
