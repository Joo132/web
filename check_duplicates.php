<?php
define('LICENSE_SERVER', true);
require_once 'database.php';

echo "Checking for duplicate product IDs...\n";
$duplicates = Database::query("SELECT product_id, COUNT(*) as count FROM products GROUP BY product_id HAVING count > 1");

if (empty($duplicates)) {
    echo "No duplicate product IDs found.\n";
} else {
    echo "FOUND DUPLICATES:\n";
    foreach ($duplicates as $d) {
        echo "Product ID: {$d['product_id']} | Count: {$d['count']}\n";
        $records = Database::query("SELECT id, name, category_id FROM products WHERE product_id = ?", [$d['product_id']]);
        foreach ($records as $r) {
            echo "  - Record ID: {$r['id']} | Name: {$r['name']} | Category: {$r['category_id']}\n";
        }
    }
}
