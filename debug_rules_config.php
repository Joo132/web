<?php
require 'database.php';
require 'modules.php';
require 'license.php';

echo "=== MODULE CONFIG ===\n";
$module = Module::getByModuleId('rules_system');
if ($module) {
    echo "ID: " . $module['id'] . "\n";
    echo "Config: " . $module['config'] . "\n";
} else {
    echo "Module 'rules_system' NOT found!\n";
}

echo "\n=== LICENSES FOR THIS MODULE ===\n";
if ($module) {
    $licenses = Database::query("SELECT * FROM licenses WHERE module_id = ?", [$module['id']]);
    foreach ($licenses as $l) {
        $cfg = License::getConfig($l['id']);
        echo "Key: " . $l['license_key'] . " | Status: " . $l['status'] . "\n";
        echo "Specific Config: " . json_encode($cfg) . "\n";
    }
}
?>
