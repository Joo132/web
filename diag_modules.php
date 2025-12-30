<?php
define('LICENSE_SERVER', true);
require_once __DIR__ . '/config.php';
require_once __DIR__ . '/database.php';
require_once __DIR__ . '/modules.php';

$modules = Module::getAll();
echo "Total Modules: " . count($modules) . "\n";
foreach ($modules as $m) {
    echo " - ID: " . $m['id'] . " | ModuleID: " . $m['module_id'] . " | Name: " . $m['name'] . "\n";
}
