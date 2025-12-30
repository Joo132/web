<?php
/**
 * License Server Configuration
 *
 * This file contains all configuration settings for the license server.
 * IMPORTANT: Keep this file secure and never commit sensitive data to version control.
 */

// Prevent direct access
if (!defined('LICENSE_SERVER')) {
    http_response_code(403);
    exit('Direct access not allowed');
}

// ============================================================================
// DATABASE CONFIGURATION
// ============================================================================
define('DB_HOST', 'localhost');
define('DB_PORT', 3306);
define('DB_NAME', 'web_joo');
define('DB_USER', 'root');
define('DB_PASS', '');
define('DB_CHARSET', 'utf8mb4');

// ============================================================================
// APPLICATION SETTINGS
// ============================================================================
define('APP_NAME', 'License Server');
define('APP_VERSION', '2.0.0');
define('APP_DEBUG', true); // Debug mode enabled

// ============================================================================
// SECURITY SETTINGS
// ============================================================================
// Password hashing cost (higher = more secure but slower)
define('PASSWORD_COST', 12);

// Session settings
define('SESSION_LIFETIME', 3600); // 1 hour in seconds
define('SESSION_NAME', 'license_server_session');

// API rate limiting (requests per minute)
define('RATE_LIMIT_ENABLED', true);
define('RATE_LIMIT_REQUESTS', 60);
define('RATE_LIMIT_WINDOW', 60); // seconds

// CSRF Protection
define('CSRF_ENABLED', true);
define('CSRF_TOKEN_LIFETIME', 3600);

// ============================================================================
// LICENSE SETTINGS
// ============================================================================
// Default license duration in days
define('DEFAULT_LICENSE_DURATION', 30);

// Default HWID limit per license
define('DEFAULT_HWID_LIMIT', 1);

// License key format segments
define('LICENSE_KEY_SEGMENTS', 4);
define('LICENSE_KEY_SEGMENT_LENGTH', 4);

// ============================================================================
// LOGGING SETTINGS
// ============================================================================
// Maximum number of logs to keep in database
define('MAX_LOGS', 10000);

// Log categories
define('LOG_CATEGORIES', ['License', 'Auth', 'Admin', 'Module', 'Bot', 'System']);

// ============================================================================
// ADMIN ROLES
// ============================================================================
define('ROLE_OWNER', 'Owner');
define('ROLE_HIGH_ADMIN', 'High Admin');
define('ROLE_ADMIN', 'Admin');
define('ROLE_CLIENT', 'Client');

// Role hierarchy (higher number = more permissions)
define('ROLE_HIERARCHY', [
    'Client' => 0,
    'Admin' => 1,
    'High Admin' => 2,
    'Owner' => 3
]);

// ============================================================================
// DISCORD OAUTH SETTINGS
// ============================================================================
// Discord Application credentials (Get from: https://discord.com/developers/applications)
define('DISCORD_CLIENT_ID', '1454708213558808676');
define('DISCORD_CLIENT_SECRET', '6TaUwmfUZXjkt47m6pLc0PAzdB0vWOrk');
define('DISCORD_REDIRECT_URI', 'https://joo.securevm.io/oauth/callback'); // Update with your domain
define('DISCORD_OAUTH_SCOPES', ['identify', 'email']);

// ============================================================================
// CORS SETTINGS
// ============================================================================
define('CORS_ENABLED', true);
define('CORS_ALLOWED_ORIGINS', ['https://joo.kero-dev.tech', 'https://joo.securevm.io']); // Restricted to your domain only
define('CORS_ALLOWED_METHODS', ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS']);
define('CORS_ALLOWED_HEADERS', ['Content-Type', 'Authorization', 'X-Requested-With']);

// ============================================================================
// TIMEZONE
// ============================================================================
date_default_timezone_set('UTC');

// ============================================================================
// ERROR REPORTING
// ============================================================================
if (APP_DEBUG) {
    error_reporting(E_ALL);
    ini_set('display_errors', 1);
} else {
    error_reporting(0);
    ini_set('display_errors', 0);
}
