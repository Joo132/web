<?php
/**
 * Router for PHP Built-in Server
 *
 * Usage: php -S localhost:5000 router.php
 */

$uri = $_SERVER['REQUEST_URI'];
$path = parse_url($uri, PHP_URL_PATH);

file_put_contents(__DIR__ . '/debug_router.log', date('H:i:s') . " | Router Hit: $uri\n", FILE_APPEND);


// Serve static files directly
if (preg_match('/\.(html|css|js|png|jpg|jpeg|gif|ico|svg|woff|woff2|ttf|eot)$/i', $path)) {
    $file = __DIR__ . $path;
    if (file_exists($file) && is_file($file)) {
        $mimeTypes = [
            'html' => 'text/html',
            'css' => 'text/css',
            'js' => 'application/javascript',
            'json' => 'application/json',
            'png' => 'image/png',
            'jpg' => 'image/jpeg',
            'jpeg' => 'image/jpeg',
            'gif' => 'image/gif',
            'ico' => 'image/x-icon',
            'svg' => 'image/svg+xml',
            'woff' => 'font/woff',
            'woff2' => 'font/woff2',
            'ttf' => 'font/ttf',
            'eot' => 'application/vnd.ms-fontobject'
        ];

        $ext = strtolower(pathinfo($file, PATHINFO_EXTENSION));
        $mime = $mimeTypes[$ext] ?? 'application/octet-stream';

        header('Content-Type: ' . $mime);
        readfile($file);
        return true;
    }
}

// Serve dashboard for root
if ($path === '/' || $path === '/dashboard' || $path === '/index.php') {
    $dashboard = __DIR__ . '/static/dashboard.html';
    if (file_exists($dashboard)) {
        header('Content-Type: text/html; charset=utf-8');
        readfile($dashboard);
        return true;
    }
}

// Route everything else through api.php
require __DIR__ . '/api.php';
