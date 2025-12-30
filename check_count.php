<?php
define('LICENSE_SERVER', true);
require_once __DIR__ . '/config.php';
require_once __DIR__ . '/database.php';
$count = Database::queryOne("SELECT COUNT(*) as c FROM feedbacks")['c'];
echo "Total feedbacks: " . $count;
?>
