<?php
define('LICENSE_SERVER', true);
require_once 'config.php';
require_once 'database.php';
require_once 'modules.php';
require_once 'license.php';

echo "<pre>";
echo "DB DUMP AT: " . date('Y-m-d H:i:s') . "\n";
echo "====================================\n\n";

echo "PRODUCTS TABLE:\n";
$products = Database::query("SELECT id, product_id, name, bot_token, config FROM products");
foreach ($products as $p) {
    echo "ID: {$p['id']} | RID: {$p['product_id']} | Name: {$p['name']}\n";
    echo "Bot Token: {$p['bot_token']}\n";
    echo "Config Length: " . strlen($p['config']) . "\n";
    echo "Config: " . $p['config'] . "\n";
    echo "------------------------------------\n";
}

echo "\nLICENSES TABLE:\n";
$licenses = Database::query("SELECT l.id, l.license_key, l.product_id, l.owner_id, l.bot_token, l.config, a.username FROM licenses l LEFT JOIN accounts a ON l.owner_id = a.id");
foreach ($licenses as $l) {
    echo "ID: {$l['id']} | Key: {$l['license_key']} | PID: {$l['product_id']} | Owner: {$l['username']}\n";
    echo "Bot Token: {$l['bot_token']}\n";
    echo "Config: " . $l['config'] . "\n";
    echo "------------------------------------\n";
}

echo "</pre>";
