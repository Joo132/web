<?php
ini_set('display_errors', 1);
ini_set('display_startup_errors', 1);
error_reporting(E_ALL);

define('LICENSE_SERVER', true);

try {
    require_once 'config.php';
    require_once 'database.php';
    require_once 'logs.php'; // Assuming this exists for SystemLog
    require_once 'license.php';
    require_once 'auth.php';

    echo "Files included successfully.<br>";

    // Test DB connection
    $db = Database::getInstance();
    echo "DB Connected.<br>";

    // Test License Table Columns
    try {
        $cols = Database::query("SHOW COLUMNS FROM licenses");
        $found = false;
        foreach ($cols as $col) {
            if ($col['Field'] === 'claimed_by') {
                $found = true; 
                echo "Column 'claimed_by' FOUND in licenses table.<br>";
                break;
            }
        }
        if (!$found) echo "CRITICAL: Column 'claimed_by' NOT FOUND in licenses table!<br>";
    } catch (Exception $e) {
        echo "Error checking columns: " . $e->getMessage() . "<br>";
    }

    echo "Attempting dummy registration check...<br>";
    
    // We won't actually insert unless we want to, but let's check the logic methods
    $key = 'TEST-KEY'; 
    // Just check if methods exist and run without crashing on null data
    if (method_exists('License', 'isClaimed')) {
        echo "License::isClaimed method exists.<br>";
    } else {
        echo "License::isClaimed method MISSING.<br>";
    }

    echo "Debug connect complete. If you see this, basic PHP is working.";

} catch (Throwable $e) {
    echo "FATAL ERROR: " . $e->getMessage() . " on line " . $e->getLine() . " in file " . $e->getFile();
}
