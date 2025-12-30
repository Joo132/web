<?php
define('LICENSE_SERVER', true);
require_once __DIR__ . '/config.php';
require_once __DIR__ . '/database.php';

try {
    echo "Converting 'expiry' column to DATETIME...\n";
    Database::execute("ALTER TABLE `licenses` MODIFY `expiry` DATETIME NOT NULL");
    echo "Success! Expiry column can now handle dates up to 9999.\n";
} catch (Exception $e) {
    echo "Error: " . $e->getMessage() . "\n";
}
