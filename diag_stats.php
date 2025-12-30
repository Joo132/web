<?php
define('LICENSE_SERVER', true);
require_once __DIR__ . '/config.php';
require_once __DIR__ . '/database.php';
require_once __DIR__ . '/utils.php';
require_once __DIR__ . '/logs.php';
require_once __DIR__ . '/auth.php';
require_once __DIR__ . '/license.php';
require_once __DIR__ . '/modules.php';
require_once __DIR__ . '/blacklist.php';

try {
    echo "Starting Diag...\n";
    
    // Simulate an Owner admin
    $admin = [
        'id' => 1,
        'username' => 'Owner',
        'role' => 'Owner'
    ];

    echo "Fetching Module Stats...\n";
    $moduleStats = Module::getStats();
    echo "Module Stats: " . json_encode($moduleStats) . "\n";

    echo "Fetching License Stats...\n";
    $licenseStats = License::getStats();
    echo "License Stats: " . json_encode($licenseStats) . "\n";

    echo "Fetching Bot Data...\n";
    $botsData = BotData::getAll();
    echo "Bot Data Count: " . count($botsData) . "\n";

    echo "Fetching Total Server Count...\n";
    $totalServers = BotData::getTotalServerCount();
    echo "Total Servers: $totalServers\n";

    echo "Fetching All Categories...\n";
    $categories = Category::getAllWithModules();
    echo "Categories Count: " . count($categories) . "\n";

    echo "Fetching All Licenses...\n";
    $licenses = License::getAll();
    echo "Licenses Count: " . count($licenses) . "\n";

    echo "Diag Complete Output:\n";
    print_r([
        'total_licenses' => $licenseStats['total'] ?? 0,
        'total_modules' => $moduleStats['total_modules'] ?? 0,
        'active_licenses' => (int)($licenseStats['active'] ?? 0),
        'bots_count' => count($botsData),
        'licenses_count' => count($licenses),
        'categories_count' => count($categories)
    ]);

} catch (Throwable $e) {
    echo "FATAL ERROR CAUGHT:\n";
    echo $e->getMessage() . "\n";
    echo "In " . $e->getFile() . ":" . $e->getLine() . "\n";
    echo $e->getTraceAsString() . "\n";
}
