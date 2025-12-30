<?php
/**
 * License Server - Entry Point
 *
 * Serves the dashboard or routes to API
 */

$uri = $_SERVER['REQUEST_URI'] ?? '/';
$path = parse_url($uri, PHP_URL_PATH);

// Remove base path if present
$basePath = dirname($_SERVER['SCRIPT_NAME']);
if ($basePath !== '/' && $basePath !== '\\') {
    $path = substr($path, strlen($basePath));
}
$path = '/' . ltrim($path, '/');

// Serve dashboard for root
// Routing Logic
$routes = [
    '/' => 'static/home.html',
    '/index.php' => 'static/home.html',
    '/home' => 'static/home.html',
    '/login' => 'static/login.html',
    '/dashboard' => 'static/dashboard.html',
    '/overview' => 'static/overview.html',
    '/bot_setup' => 'static/bot_setup.html'
];

if (array_key_exists($path, $routes)) {
    $file = __DIR__ . '/' . $routes[$path];
    if (file_exists($file)) {
        header('Content-Type: text/html; charset=utf-8');
        readfile($file);
        exit;
    }
}

// Route API requests
require_once __DIR__ . '/api.php';
