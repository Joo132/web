<?php
require_once 'modules.php';
require_once 'database.php';

$botId = 'system_bot';
$db = Database::getInstance();
$bot = $db->query("SELECT * FROM bots_data WHERE bot_id = ?", [$botId])->fetch();

header('Content-Type: application/json');
if ($bot) {
    echo json_encode([
        'success' => true,
        'bot_id' => $bot['bot_id'],
        'config' => json_decode($bot['config'], true)
    ], JSON_PRETTY_PRINT);
} else {
    echo json_encode(['success' => false, 'error' => 'Bot not found']);
}
