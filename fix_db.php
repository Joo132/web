<?php
ini_set('display_errors', 1);
error_reporting(E_ALL);

require_once 'config.php';
require_once 'database.php';

echo "<h1>Database Fixer</h1>";

function run_query($sql, $description) {
    try {
        Database::execute($sql);
        echo "<div style='color:green'>[SUCCESS] $description</div><br>";
    } catch (Exception $e) {
        $msg = $e->getMessage();
        if (strpos($msg, "Duplicate column name") !== false) {
             echo "<div style='color:orange'>[SKIPPED] $description (Already exists)</div><br>";
        } else {
             echo "<div style='color:red'>[ERROR] $description: $msg</div><br>";
        }
    }
}

try {
    echo "Connecting to database...<br>";
    $db = Database::getInstance();
    echo "Connected.<br><hr>";

    // 1. claimed_by in licenses
    run_query(
        "ALTER TABLE `licenses` ADD COLUMN `claimed_by` INT UNSIGNED NULL AFTER `created_by`",
        "Adding 'claimed_by' to 'licenses' table"
    );

    // 2. Foreign key for claimed_by
    // Foreign keys can be tricky to check existence, but let's try adding it. 
    // If it fails with duplicate, ignored.
    run_query(
        "ALTER TABLE `licenses` ADD CONSTRAINT `fk_licenses_claimed_by` FOREIGN KEY (`claimed_by`) REFERENCES `admins`(`id`) ON DELETE SET NULL",
         "Adding Foreign Key 'fk_licenses_claimed_by'"
    );

    // 3. gpu_info in license_hwids
    run_query(
        "ALTER TABLE `license_hwids` ADD COLUMN `gpu_info` TEXT NULL AFTER `hostname`",
        "Adding 'gpu_info' to 'license_hwids' table"
    );

    // 4. gpu_info in authorized_hwids
    run_query(
         "ALTER TABLE `authorized_hwids` ADD COLUMN `gpu_info` TEXT NULL AFTER `hostname`",
         "Adding 'gpu_info' to 'authorized_hwids' table"
    );

    echo "<hr><h3>Fixes attempted. Please try Registering again.</h3>";

} catch (Exception $e) {
    echo "<h2 style='color:red'>FATAL ERROR: " . $e->getMessage() . "</h2>";
}
