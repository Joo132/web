<?php
/**
 * Discord OAuth Callback Handler
 * 
 * Handles the OAuth callback from Discord and stores user info in session
 */

// Start output buffering
ob_start();

// Load configuration
require_once __DIR__ . '/config.php';
require_once __DIR__ . '/database.php';
require_once __DIR__ . '/utils.php';
require_once __DIR__ . '/discord_oauth.php';
require_once __DIR__ . '/auth.php';

// Start session with explicit parameters
session_name(SESSION_NAME);
session_set_cookie_params([
    'lifetime' => 0,
    'path' => '/',
    'domain' => '',
    'secure' => (isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on'),
    'httponly' => true,
    'samesite' => 'Lax'
]);
session_start();

// Check for error from Discord
if (isset($_GET['error'])) {
    $error = htmlspecialchars($_GET['error']);
    die("Discord OAuth Error: {$error}");
}

// Get authorization code
$code = $_GET['code'] ?? null;
$state = $_GET['state'] ?? null;

if (!$code) {
    die('Missing authorization code');
}

// Handle OAuth callback
$result = DiscordOAuth::handleCallback($code, $state);

if (!$result['success']) {
    die('OAuth Error: ' . ($result['error'] ?? 'Unknown error'));
}

$discordUser = $result['discord_user'];

// Store Discord user info in session
$_SESSION['discord_user'] = [
    'id' => $discordUser['id'],
    'username' => $discordUser['username'],
    'discriminator' => $discordUser['discriminator'] ?? '0',
    'avatar' => $discordUser['avatar'] ?? null,
    'email' => $discordUser['email'] ?? null,
    'verified' => $discordUser['verified'] ?? false
];

// Check if user already exists
$existingUser = DiscordOAuth::findUserByDiscordId($discordUser['id']);

if ($existingUser) {
    // Refresh Discord profile info (username, avatar) on every login
    DiscordOAuth::linkToUser($discordUser, $existingUser['id']);
    
    // Fetch fresh user data AFTER link/refresh
    $authFull = Auth::getUserById($existingUser['id']);
    
    if ($authFull) {
        $_SESSION['authenticated_admin'] = $authFull;
        SystemLog::log('Auth', 'Discord Login', "User logged in via Discord: {$authFull['username']}", $authFull['username']);
        
        // Force write session before redirect
        session_write_close();
        
        // Role-based redirection to prevent Admin Dashboard flash
        $role = strtolower($authFull['role'] ?? 'client');
        if ($role === 'client') {
            header('Location: /overview');
        } else {
            header('Location: /dashboard');
        }
        exit;
    }
}

// New Discord account or linkage failed - redirect to key entry step
header('Location: /static/discord-login.html?step=enter-key');
exit;
