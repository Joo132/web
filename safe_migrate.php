<?php
require_once __DIR__ . '/database.php';

try {
    $db = Database::getInstance();
    
    // Check if column exists
    $columns = Database::query("SHOW COLUMNS FROM `modules` LIKE 'bot_token'");
    
    if (empty($columns)) {
        Database::execute("ALTER TABLE `modules` ADD COLUMN `bot_token` TEXT AFTER `description` ");
        echo "✅ Column 'bot_token' added successfully to 'modules' table.\n";
    } else {
        echo "ℹ️ Column 'bot_token' already exists.\n";
    }
    
} catch (Exception $e) {
    echo "❌ Error: " . $e->getMessage() . "\n";
}
