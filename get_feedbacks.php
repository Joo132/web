<?php
/**
 * Standalone Feedback Endpoint
 * Direct access without routing
 */

error_reporting(0);
ini_set('display_errors', 0);

define('LICENSE_SERVER', true);

header('Content-Type: application/json; charset=utf-8');
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: GET');

require_once __DIR__ . '/config.php';
require_once __DIR__ . '/database.php';

try {
    $feedbacks = Database::query("SELECT `name`, `message`, `rating`, `created_at` FROM `feedbacks` ORDER BY `created_at` DESC LIMIT 10");
    
    // Mask names
    foreach ($feedbacks as &$f) {
        $len = strlen($f['name']);
        if ($len > 3) {
            $f['name'] = substr($f['name'], 0, 2) . '***' . substr($f['name'], -1);
        }
    }
    
    echo json_encode(['success' => true, 'feedbacks' => $feedbacks], JSON_UNESCAPED_UNICODE);
    
} catch (Exception $e) {
    echo json_encode(['success' => false, 'error' => $e->getMessage()]);
}
