<?php
/**
 * License Server API
 *
 * Main API router and endpoint handler.
 * All requests are routed through this file.
 */

// Start output buffering as early as possible
ob_start();

// Define constant to allow includes
define('LICENSE_SERVER', true);

// Load configuration first
require_once __DIR__ . '/config.php';

$origin = $_SERVER['HTTP_ORIGIN'] ?? '';
$allowed_origins = defined('CORS_ALLOWED_ORIGINS') ? CORS_ALLOWED_ORIGINS : [];

if (in_array($origin, $allowed_origins)) {
    header('Access-Control-Allow-Origin: ' . $origin);
    header('Access-Control-Allow-Credentials: true');
} else if (empty($origin)) {
    // Same origin - no need for CORS headers, but headers are fine
    // Do not send * with Credentials: true
} else {
    header('Access-Control-Allow-Origin: ' . ($allowed_origins[0] ?? '*'));
}

header('Content-Type: application/json; charset=utf-8');
header('Access-Control-Allow-Methods: GET, POST, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type, Authorization, X-Requested-With');

// Start session
session_name(SESSION_NAME);
session_set_cookie_params([
    'lifetime' => 0, // Session cookie (deleted on browser close)
    'path' => '/',
    'domain' => '', // Use current domain
    'secure' => (isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on'),
    'httponly' => true,
    'samesite' => 'Lax'
]);
$session_started = session_start();

// DEBUG LOGGING
$session_id = session_id();
$has_authenticated_admin = isset($_SESSION['authenticated_admin']) ? 'YES' : 'NO';
$admin_name = isset($_SESSION['authenticated_admin']) ? $_SESSION['authenticated_admin']['username'] : 'N/A';
$source = isset($_SESSION['authenticated_admin']) ? ($_SESSION['authenticated_admin']['source_table'] ?? 'N/A') : 'N/A';
file_put_contents(__DIR__ . '/debug_session.log', date('Y-m-d H:i:s') . " | SID: $session_id | Started: " . ($session_started ? 'SUCCESS' : 'FAIL') . " | Auth: $has_authenticated_admin | User: $admin_name | Source: $source | Remote: {$_SERVER['REMOTE_ADDR']} | Path: {$_SERVER['REQUEST_URI']} \n", FILE_APPEND);

// Handle preflight
if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(204);
    exit;
}

// Get the request path
$requestUri = $_SERVER['REQUEST_URI'] ?? '/';
$path = parse_url($requestUri, PHP_URL_PATH);
$path = '/' . trim($path, '/');

// GLOBAL DEBUG LOG
file_put_contents(__DIR__ . '/debug_global.log', date('H:i:s') . " | Req: " . $_SERVER['REQUEST_URI'] . " | Path: $path \n", FILE_APPEND);


// For PHP built-in server: serve static files directly
if (php_sapi_name() === 'cli-server') {
    // Check if requesting a static file
    if (preg_match('/\.(html|css|js|png|jpg|gif|ico|svg)$/', $path)) {
        $filePath = __DIR__ . $path;
        if (file_exists($filePath)) {
            return false; // Let PHP built-in server handle it
        }
    }
}

// Load other dependencies
require_once __DIR__ . '/database.php';
require_once __DIR__ . '/utils.php';
require_once __DIR__ . '/logs.php';
require_once __DIR__ . '/auth.php';
require_once __DIR__ . '/license.php';
require_once __DIR__ . '/modules.php';
require_once __DIR__ . '/blacklist.php';
require_once __DIR__ . '/discord_oauth.php';

// Auto-fix schema on requests
License::ensureSchema();
SystemLog::ensureSchema();

// Get request info
$method = strtoupper($_SERVER['REQUEST_METHOD'] ?? 'GET');
$input = [];

// Parse JSON input
$rawInput = file_get_contents('php://input');
if (!empty($rawInput)) {
    $decoded = json_decode($rawInput, true);
    if (json_last_error() === JSON_ERROR_NONE) {
        $input = $decoded;
    }
}

// Helper function to send JSON response
function jsonResponse($data, $code = 200) {
    // Clear any previous output (warnings, notices, etc.)
    ob_end_clean();
    
    http_response_code($code);
    echo json_encode($data, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
    exit;
}

function successResponse($data = [], $message = null) {
    $response = ['success' => true];
    if ($message !== null) {
        $response['message'] = $message;
    }
    jsonResponse(array_merge($response, $data), 200);
}

function errorResponse($message, $code = 400) {
    jsonResponse(['success' => false, 'error' => $message], $code);
}

function requireMethod($required) {
    global $method;
    if ($method !== $required) {
        errorResponse('Method not allowed', 405);
    }
}

function requireAuth($input, $requireActive = true) {
    $admin = null;

    // 1. Check for session-based authentication (Priority for Dashboard)
    if (isset($_SESSION['authenticated_admin'])) {
        $sessionUser = $_SESSION['authenticated_admin'];
        
        // Always fetch from 'accounts' now
        $freshUser = Auth::getUserById($sessionUser['id']);
        
        if ($freshUser && (strcasecmp($freshUser['status'], 'active') === 0 || !$requireActive)) {
            // Update session with fresh data
            $_SESSION['authenticated_admin'] = $freshUser;
            $admin = $freshUser;
        } else {
            // Session user is no longer valid/active, clear session
            file_put_contents(__DIR__ . '/debug_auth.log', date('H:i:s') . " | Session invalidated for user ID {$sessionUser['id']} \n", FILE_APPEND);
            unset($_SESSION['authenticated_admin']);
        }
    }

    // 2. Check for license-key based authentication (Primary for Bots) if no session admin yet
    if (!$admin && !empty($input['license_key'])) {
        $license = License::getByKey($input['license_key']);
        if ($license && strcasecmp($license['status'], 'active') === 0) {
            $user = null;
            if (!empty($license['owner_id'])) {
                $user = Auth::getUserById($license['owner_id']);
            }
            
            if ($user && (strcasecmp($user['status'], 'active') === 0 || !$requireActive)) {
                $admin = $user;
            }
        }
        if (!$admin) errorResponse('Invalid or inactive license key', 403);
    }

    // 3. Check for credentials if still no admin
    if (!$admin) {
        $username = $input['username'] ?? '';
        $password = $input['password'] ?? '';
        if (empty($username) || empty($password)) {
            errorResponse('Authentication required', 401);
        }
        $result = Auth::checkAdmin($username, $password, $requireActive);
        if (!$result['success']) {
            SystemLog::log('Auth', 'Login Failed', "Failed login attempt for: $username", $username);
            errorResponse($result['error'], $result['code']);
        }
        $admin = $result['admin'];
    }

    // Impersonation Logic (Now reachable for Session users too)
    if (!empty($input['impersonate_user'])) {
        if ($admin['role'] !== ROLE_OWNER && $admin['role'] !== ROLE_HIGH_ADMIN) {
             // Silently ignore if not authorized? Or error? 
             // Error is safer to catch misuse
             errorResponse('Unauthorized impersonation attempt', 403);
        }

        $targetUsername = $input['impersonate_user'];
        $target = Auth::getAccountByUsername($targetUsername);
        
        if (!$target) {
            errorResponse('Target user not found', 404);
        }

        return $target;
    }

    return $admin;
}

// ============================================================================
// ROUTING
// ============================================================================

try {
    // Attempt Auto-Fix Schema safely
    try {
        License::ensureSchema();
    } catch (Throwable $e) {
        // Log but continue - don't crash the whole API if auto-fix fails
        error_log("Schema fix warning: " . $e->getMessage());
    }

    // Check database connection first
    try {
        Database::getInstance();
    } catch (Exception $e) {
        errorResponse('Database connection failed. Please check config.php and ensure MySQL is running. Error: ' . $e->getMessage(), 500);
    }

    // Mark offline bots periodically
    try {
        BotData::markOfflineBots();
    } catch (Exception $e) {
        // Ignore - table might not exist yet
    }

    switch ($path) {
        // ====================================================================
        // STATIC FILES
        // ====================================================================
        case '/':
        case '/login':
            header('Content-Type: text/html; charset=utf-8');
            $loginPath = __DIR__ . '/static/login.html';
            if (file_exists($loginPath)) {
                readfile($loginPath);
                exit;
            }
            errorResponse('Login page not found', 404);
            break;

        case '/overview':
            header('Content-Type: text/html; charset=utf-8');
            $overviewPath = __DIR__ . '/static/overview.html';
            if (file_exists($overviewPath)) {
                readfile($overviewPath);
                exit;
            }
            errorResponse('Overview page not found', 404);
            break;

        case '/dashboard':
            // Server-side role check to prevent Admin Dashboard flash
            if (isset($_SESSION['authenticated_admin'])) {
                $role = strtolower($_SESSION['authenticated_admin']['role'] ?? 'client');
                if ($role === 'client') {
                    header('Location: /overview');
                    exit;
                }
            }

            header('Content-Type: text/html; charset=utf-8');
            $dashboardPath = __DIR__ . '/static/dashboard.html';
            if (file_exists($dashboardPath)) {
                // Log the visit to dashboard
                SystemLog::log('System', 'Visit', 'Dashboard accessed');
                readfile($dashboardPath);
                exit;
            }
            errorResponse('Dashboard not found', 404);
            break;


        // ====================================================================
        // PUBLIC ENDPOINTS
        // ====================================================================
        // ====================================================================
        // PUBLIC ENDPOINTS
        // ====================================================================
        case '/api/public/feedback':
            requireMethod('POST');
            
            $ip = $_SERVER['REMOTE_ADDR'] ?? 'Unknown';
            $input = json_decode(file_get_contents('php://input'), true);
            
            // Try to get user from session
            $currentUser = null;
            if (isset($_SESSION['authenticated_admin'])) {
                $currentUser = Auth::getUserById($_SESSION['authenticated_admin']['id']);
            }

            $message = trim($input['message'] ?? '');
            $name = $currentUser ? ($currentUser['discord_username'] ?? $currentUser['username']) : trim($input['name'] ?? 'Anonymous');
            $accountId = $currentUser ? $currentUser['id'] : null;
            $rating = (int)($input['rating'] ?? 5);
            $moduleId = (int)($input['module_id'] ?? 0);
            
            if ($rating < 1) $rating = 1;
            if ($rating > 5) $rating = 5;

            if (empty($message)) {
                errorResponse('Message is required');
            }
            
            // Single submission restriction: Check if user already submitted feedback
            if ($name !== 'Anonymous') {
                $existing = Database::query("SELECT id FROM `feedbacks` WHERE `name` = ?", [$name]);
                if (!empty($existing)) {
                    errorResponse('You have already submitted feedback. Thank you for your support!', 403);
                }
            }

            // Ensure table and column exist
            Database::execute("CREATE TABLE IF NOT EXISTS `feedbacks` (
                `id` INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
                `name` VARCHAR(100) NULL,
                `message` TEXT NOT NULL,
                `rating` INT UNSIGNED NOT NULL DEFAULT 5,
                `module_id` INT UNSIGNED NULL,
                `ip_address` VARCHAR(45) NULL,
                `created_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci");

            // Add module_id column if it doesn't exist (for existing tables)
            $cols = Database::query("SHOW COLUMNS FROM `feedbacks` LIKE 'module_id'");
            if (empty($cols)) {
                try {
                    Database::execute("ALTER TABLE `feedbacks` ADD COLUMN `module_id` INT UNSIGNED NULL AFTER `rating`", []);
                } catch (Exception $e) { /* Might be added concurrently */ }
            }

            Database::execute(
                "INSERT INTO `feedbacks` (`account_id`, `name`, `message`, `rating`, `module_id`, `ip_address`) VALUES (?, ?, ?, ?, ?, ?)",
                [$accountId, $name, $message, $rating, $moduleId, $ip]
            );
            
            successResponse([], 'Feedback submitted successfully');
            break;

        case '/api/public/feedback/list':
            requireMethod('GET');
            
            // Ensure table exists
            Database::execute("CREATE TABLE IF NOT EXISTS `feedbacks` (
                `id` INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
                `name` VARCHAR(100) NULL,
                `message` TEXT NOT NULL,
                `rating` INT UNSIGNED NOT NULL DEFAULT 5,
                `ip_address` VARCHAR(45) NULL,
                `created_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci");
            
            $feedbacks = Database::query("
                SELECT f.`name`, f.`message`, f.`rating`, f.`created_at`, p.`name` as `module_name`, da.`discord_avatar`
                FROM `feedbacks` f
                LEFT JOIN `products` p ON f.`module_id` = p.`id`
                LEFT JOIN `discord_accounts` da ON f.`account_id` = da.`account_id`
                ORDER BY f.`created_at` DESC 
                LIMIT 10
            ");
            
            foreach ($feedbacks as &$f) {
                // Fallback for General Feedbacks
                if (empty($f['module_name'])) {
                    $f['module_name'] = 'Custom Bot';
                }
            }
            
            successResponse(['feedbacks' => $feedbacks]);
            break;

        case '/api/public/stats':
            requireMethod('GET');
            
            // Total Clients (Users)
            $totalClients = Database::queryOne("SELECT count(*) as count FROM `accounts` WHERE `role` = 'Client'")['count'];
            
            // Active Licenses (Status = Active)
            $activeLicenses = Database::queryOne("SELECT count(*) as count FROM `licenses` WHERE `status` = 'Active'")['count'];
            
            // Modules Sold (Total Licenses issued)
            $modulesSold = Database::queryOne("SELECT count(*) as count FROM `licenses`")['count'];
            
            successResponse([
                'total_clients' => (int)$totalClients,
                'active_licenses' => (int)$activeLicenses,
                'modules_sold' => (int)$modulesSold
            ]);
            break;

        // ====================================================================
        // AUTHENTICATION ENDPOINTS
        // ====================================================================
        case '/api/auth/login':
            requireMethod('POST');

            $missing = [];
            if (empty($input['username'])) $missing[] = 'username';
            if (empty($input['password'])) $missing[] = 'password';
            if (!empty($missing)) {
                errorResponse('Missing required fields: ' . implode(', ', $missing), 400);
            }

            $result = Auth::checkAdmin($input['username'], $input['password']);

            if (!$result['success']) {
                // If it's a license issue vs credentials issue
                errorResponse($result['error'] ?? $result['message'], $result['code'] ?? 401);
            }

            $admin = $result['admin'];
            $_SESSION['authenticated_admin'] = $admin;
            SystemLog::log('Auth', 'Login', "Admin logged in: {$admin['username']}", $admin['username']);

            successResponse([
                'username' => $admin['username'],
                'role' => $admin['role']
            ]);
            break;
        
        case '/api/auth/me':
            if (isset($_SESSION['authenticated_admin'])) {
                $sessionUser = $_SESSION['authenticated_admin'];
                
                // Perform a FRESH check
                $freshUser = Auth::getUserById($sessionUser['id']);
                
                if ($freshUser && strcasecmp($freshUser['status'], 'Active') === 0) {
                    $_SESSION['authenticated_admin'] = $freshUser;
                    
                    // Handle Impersonation
                    $effectiveUser = $freshUser;
                    if (!empty($input['impersonate_user']) && ($freshUser['role'] === ROLE_OWNER || $freshUser['role'] === ROLE_HIGH_ADMIN)) {
                        $target = Auth::getAccountByUsername($input['impersonate_user']);
                        if ($target) {
                            $effectiveUser = $target;
                        }
                    }

                    successResponse([
                        'logged_in' => true,
                        'username' => $effectiveUser['username'],
                        'role' => $effectiveUser['role'],
                        'discord_username' => $effectiveUser['discord_username'] ?? $effectiveUser['username'],
                        'discord_avatar' => $effectiveUser['discord_avatar'] ?? (!empty($effectiveUser['discord_id']) ? DiscordOAuth::getAvatarUrl($effectiveUser['discord_id'], null) : null)
                    ]);
                } else {
                    unset($_SESSION['authenticated_admin']);
                    successResponse(['logged_in' => false]);
                }
            } else {
                successResponse(['logged_in' => false]);
            }
            break;
            
        case '/api/auth/logout':
            session_destroy();
            successResponse(['message' => 'Logged out successfully']);
            break;

        case '/api/auth/register':
            requireMethod('POST');

            $missing = [];
            if (empty($input['username'])) $missing[] = 'username';
            if (empty($input['password'])) $missing[] = 'password';
            if (empty($input['key'])) $missing[] = 'license key';
            
            if (!empty($missing)) {
                errorResponse('Missing required fields: ' . implode(', ', $missing), 400);
            }

            $result = Auth::register($input['username'], $input['password'], $input['key']);

            if (!$result['success']) {
                errorResponse($result['message'], 400);
            }

            $admin = $result['admin'];
            
            SystemLog::log('Auth', 'Login/Register', "User authenticated: {$admin['username']}", $admin['username']);


            successResponse([
                'username' => $admin['username'],
                'role' => $admin['role'],
                'message' => $result['message']
            ]);
            break;

        case '/api/discord/auth-url':
            requireMethod('POST');
            
            // Load Discord OAuth handler
            require_once __DIR__ . '/discord_oauth.php';
            
            // Start session if not already started
            if (session_status() === PHP_SESSION_NONE) {
                session_name(SESSION_NAME);
                session_start();
            }
            
            $authUrl = DiscordOAuth::getAuthorizationUrl();
            
            successResponse(['auth_url' => $authUrl]);
            break;

        case '/api/discord/login':
            requireMethod('POST');
            require_once __DIR__ . '/discord_oauth.php';
            
            if (empty($_SESSION['discord_user'])) {
                errorResponse('Discord authentication required. Please login with Discord first.', 401);
            }
            
            $discordUser = $_SESSION['discord_user'];
            $key = $input['key'] ?? '';
            
            if (empty($key)) {
                errorResponse('License key is required', 400);
            }
            
            $license = License::getByKey($key);
            if (!$license) {
                errorResponse('Invalid license key', 400);
            }
            
            if (strcasecmp($license['status'], 'expired') === 0 || strcasecmp($license['status'], 'disabled') === 0) {
                errorResponse('License is ' . $license['status'], 400);
            }
            
            $existingUser = DiscordOAuth::findUserByDiscordId($discordUser['id']);
            
            if ($existingUser) {
                $userLicense = License::getByUserId($existingUser['id']);
                $canBypass = ($existingUser['role'] === 'Owner' || $existingUser['role'] === 'High Admin');
                
                if ($canBypass || ($userLicense && $userLicense['license_key'] === $key)) {
                    $authFull = Auth::getUserById($existingUser['id']);
                    
                    if (!$authFull || strcasecmp($authFull['status'], 'Active') !== 0) {
                         errorResponse('Account data missing or inactive', 403);
                    }
                    
                    $_SESSION['authenticated_admin'] = $authFull;
                    SystemLog::log('Auth', 'Discord Login', "User logged in via Discord: {$authFull['username']}", $authFull['username']);
                    
                    successResponse([
                        'username' => $authFull['username'],
                        'role' => $authFull['role'],
                        'discord_username' => $discordUser['username'],
                        'message' => 'Welcome back!'
                    ]);
                } else {
                    errorResponse('This Discord account is linked to a different license', 403);
                }
            } else {
                if (License::isClaimed($key)) {
                    errorResponse('This license key is already in use', 400);
                }
                
                $username = $discordUser['username'];
                if (isset($discordUser['discriminator']) && $discordUser['discriminator'] !== '0') {
                    $username .= '#' . $discordUser['discriminator'];
                }
                
                $randomPassword = bin2hex(random_bytes(16));
                $hashedPassword = Auth::hashPassword($randomPassword);
                
                try {
                    $email = $discordUser['email'] ?? null;
                    Database::execute(
                        "INSERT INTO `accounts` (`username`, `password`, `email`, `role`, `status`) VALUES (?, ?, ?, 'Client', 'Active')",
                        [$username, $hashedPassword, $email]
                    );
                    $newUserId = Database::lastInsertId();
                    
                    DiscordOAuth::linkToUser($discordUser, $newUserId);
                    License::claim($key, $newUserId);
                    
                    $newUser = Auth::getUserById($newUserId);
                    $_SESSION['authenticated_admin'] = $newUser;
                    SystemLog::log('Auth', 'Discord Register', "New user registered via Discord: $username with key $key", $username);
                    
                    successResponse([
                        'username' => $newUser['username'],
                        'role' => $newUser['role'],
                        'discord_username' => $discordUser['username'],
                        'message' => 'Account created successfully!'
                    ]);
                } catch (Exception $e) {
                    errorResponse('Registration failed: ' . $e->getMessage(), 500);
                }
            }
            break;

        case '/api/admin/request':
            requireMethod('POST');

            if (empty($input['username']) || empty($input['password'])) {
                errorResponse('Username and password are required', 400);
            }

            $result = Auth::createAdmin($input['username'], $input['password']);

            if (!$result['success']) {
                errorResponse($result['message'], 400);
            }

            successResponse(['message' => $result['message']]);
            break;

        // ====================================================================
        // LICENSE ENDPOINTS
        // ====================================================================
        case '/api/license/generate':
            requireMethod('POST');
            $admin = requireAuth($input);

            $module = $input['module'] ?? $input['module_id'] ?? null;
            $duration = (int)($input['duration'] ?? DEFAULT_LICENSE_DURATION);
            $hwidLimit = (int)($input['hwid_limit'] ?? DEFAULT_HWID_LIMIT);

            if (empty($module)) {
                errorResponse('Module ID is required', 400);
            }

            if ($duration < 1 || $duration > 3000000) { // Support up to ~8000 years
                errorResponse('Invalid duration (Max: 3,000,000 days)', 400);
            }

            if ($hwidLimit < 1) {
                errorResponse('HWID limit must be at least 1', 400);
            }

            $result = License::generate($module, $admin, $duration, $hwidLimit);

            if (!$result['success']) {
                errorResponse($result['error'], 400);
            }

            successResponse([
                'key' => $result['key'],
                'expiry' => $result['expiry']
            ]);
            break;

        case '/api/license/validate':
            requireMethod('POST');

            if (empty($input['key']) || empty($input['hwid'])) {
                errorResponse('Key and HWID are required', 400);
            }

            $key = $input['key'];
            $hwid = $input['hwid'];
            $moduleId = $input['module_id'] ?? 'broadcast_system';
            $hostname = $input['hostname'] ?? null;
            $gpuInfo = $input['gpu_info'] ?? null;

            $result = License::validate($key, $hwid, $moduleId, $hostname, $gpuInfo);

            if (!$result['success']) {
                errorResponse($result['error'], $result['code']);
            }

            successResponse([
                'message' => $result['message'],
                'module' => $result['module'],
                'bot_token' => $result['bot_token'] ?? null,
                'expiry' => $result['expiry']
            ]);
            break;

        case '/api/license/edit':
            requireMethod('POST');
            $admin = requireAuth($input);

            if (empty($input['key'])) {
                errorResponse('License key is required', 400);
            }

            $data = array_intersect_key($input, array_flip(['hwid_limit', 'expiry', 'status']));

            $result = License::edit($input['key'], $data, $admin);

            if (!$result['success']) {
                errorResponse($result['error'], $result['code'] ?? 400);
            }

            successResponse(['message' => $result['message']]);
            break;

        case '/api/license/reset':
            requireMethod('POST');
            $admin = requireAuth($input);

            if (empty($input['key'])) {
                errorResponse('License key is required', 400);
            }

            $result = License::resetHwids($input['key'], $admin);

            if (!$result['success']) {
                errorResponse($result['error'], $result['code'] ?? 400);
            }

            successResponse(['message' => $result['message']]);
            break;

        case '/api/license/delete':
            requireMethod('POST');
            $admin = requireAuth($input);

            if (empty($input['key'])) {
                errorResponse('License key is required', 400);
            }

            $result = License::delete($input['key'], $admin);

            if (!$result['success']) {
                errorResponse($result['error'], $result['code'] ?? 400);
            }

            successResponse();
            break;

        case '/api/license/list':
            requireMethod('POST');
            $admin = requireAuth($input);

            $licenses = License::getAll();

            successResponse(['licenses' => $licenses]);
            break;

        // ====================================================================
        // MODULE ENDPOINTS
        // ====================================================================
        case '/api/modules/create':
            requireMethod('POST');
            $admin = requireAuth($input);

            if (empty($input['name']) || empty($input['category'])) {
                errorResponse('Name and category are required', 400);
            }

            $name = $input['name'];
            $description = $input['description'] ?? '';
            $category = $input['category'];
            $botToken = $input['bot_token'] ?? null;

            $result = Module::create($name, $description, $category, $admin, $botToken);

            if (!$result['success']) {
                errorResponse($result['error'], 400);
            }

            successResponse([
                'message' => 'Module created successfully',
                'module_id' => $result['module_id']
            ]);
            break;

        case '/api/modules/edit':
            requireMethod('POST');
            $admin = requireAuth($input);

            if (empty($input['module_id'])) {
                errorResponse('Module ID is required', 400);
            }

            // Fetch module object once to support both numeric and string IDs
            $module = is_numeric($input['module_id']) ? Module::getById((int)$input['module_id']) : Module::getByModuleId($input['module_id']);
            if (!$module) errorResponse('Module not found', 404);

            // Handle partial config update if provided
            if (!empty($input['config_update']) && is_array($input['config_update'])) {
                if ($admin['role'] === 'Client') {
                    $license = License::getByUserIdAndModuleId($admin['id'], (int)$module['id']);
                    if ($license) {
                        $current = License::getConfig($license['id']) ?: [];
                        $new = array_merge($current, $input['config_update']);
                        License::updateConfig($license['id'], $new, $admin);
                    }
                } else {
                    $current = json_decode($module['config'] ?? 'null', true) ?: [];
                    $new = array_merge($current, $input['config_update']);
                    Module::updateConfig($module['product_id'], $new, $admin);
                }
            }

            // Re-fetch $module to get updated config if changed
            $module = Module::getById($module['id']);

            $version = $input['version'] ?? $module['version'];
            $downloadUrl = $input['download_url'] ?? $module['download_url'];
            $botToken = $input['bot_token'] ?? $module['bot_token'];

            $result = Module::edit($input['module_id'], $version, $downloadUrl, $admin, $botToken);

            if (!$result['success']) {
                errorResponse($result['error'], 400);
            }

            successResponse(['message' => 'Module updated successfully']);
            break;

        case '/api/modules/delete':
            requireMethod('POST');
            $admin = requireAuth($input);

            if (empty($input['module_id'])) {
                errorResponse('Module ID is required', 400);
            }

            $result = Module::delete($input['module_id'], $admin);

            if (!$result['success']) {
                errorResponse($result['error'], $result['code'] ?? 400);
            }

            successResponse(['message' => $result['message']]);
            break;

        case '/api/modules/upload':
            // DEBUG LOGGING - EARLY
            $logMsg = date('Y-m-d H:i:s') . " | Upload HIT | \$_POST keys: " . implode(',', array_keys($_POST)) . " | \$_FILES keys: " . implode(',', array_keys($_FILES)) . "\n";
            file_put_contents(__DIR__ . '/debug_upload_early.log', $logMsg, FILE_APPEND);

            requireMethod('POST');
            
            // For multipart uploads, params are in $_POST, not JSON input
            $authData = $input;
            if (empty($authData) && !empty($_POST)) {
                $authData = $_POST;
            }
            
            // Log auth data usage
            file_put_contents(__DIR__ . '/debug_upload_early.log', "Auth Data: " . print_r($authData, true) . "\n", FILE_APPEND);

            $admin = requireAuth($authData);


            if (empty($_POST['module_id']) || empty($_POST['version']) || empty($_FILES['file'])) {
                 errorResponse('Module ID, version, and file are required', 400);
            }

            $moduleId = $_POST['module_id'];
            $version = $_POST['version'];
            $file = $_FILES['file'];

            // Validation
            $module = Module::getByModuleId($moduleId);
            if (!$module) errorResponse('Module not found', 404);

            $allowed = ['py', 'exe'];
            $ext = strtolower(pathinfo($file['name'], PATHINFO_EXTENSION));
            if (!in_array($ext, $allowed)) errorResponse('Only .py and .exe files allowed', 400);

            // Upload
            $uploadDir = __DIR__ . '/static/uploads/bots/';
            if (!is_dir($uploadDir)) mkdir($uploadDir, 0777, true);
            
            $fileName = $moduleId . '_v' . $version . '.' . $ext;
            $targetPath = $uploadDir . $fileName;

            if (move_uploaded_file($file['tmp_name'], $targetPath)) {
                $downloadUrl = '/static/uploads/bots/' . $fileName;
                
                // FIXED: Pass arguments correctly (id, version, url, admin)
                Module::edit($moduleId, $version, $downloadUrl, $admin);
                
                SystemLog::log('Module', 'Update', "Uploaded version $version for $moduleId", $admin['username']);
                successResponse(['message' => 'Update published successfully']);
            } else {
                errorResponse('Failed to move uploaded file', 500);
            }
            break;

        case '/api/modules/update_check':
            requireMethod('POST');
            // No auth required for bots to check updates (unless we want to enforce it later)
            
            $moduleId = $input['module_id'] ?? '';
            $currentVer = $input['current_version'] ?? '0.0.0';

            if (!$moduleId) errorResponse('Module ID required', 400);

            $update = Module::checkUpdate($moduleId, $currentVer);
            
            // DEBUG LOGGING
            $logMsg = date('Y-m-d H:i:s') . " | Check: $moduleId | Client: $currentVer | Server: " . ($update['latest_version'] ?? 'N/A') . " | Avail: " . ($update['update_available'] ? 'YES' : 'NO') . "\n";
            file_put_contents(__DIR__ . '/debug_updates.log', $logMsg, FILE_APPEND);

            if (!$update['success']) {
                errorResponse($update['error'], 404);
            }

            if ($update['update_available']) {
                successResponse([
                    'success' => true, 
                    'update_available' => true,
                    'latest_version' => $update['latest_version'],
                    'download_url' => $update['download_url']
                ]);
            } else {
                successResponse([
                    'success' => true,
                    'update_available' => false
                ]);
            }
            break;

        case '/api/modules/get_config':
            requireMethod('POST');
            $admin = requireAuth($input);
            if (empty($input['module_id'])) errorResponse('Module ID required', 400);

            // Fetch module object once to support both numeric and string IDs
            $module = is_numeric($input['module_id']) ? Module::getById((int)$input['module_id']) : Module::getByModuleId($input['module_id']);
            if (!$module) errorResponse('Module not found', 404);

            if ($admin['role'] === 'Client') {
                $license = License::getByUserIdAndModuleId($admin['id'], (int)$module['id']); 
                if (!$license) errorResponse('No active license found for this module', 404);
                $config = License::getConfig($license['id']);
                // If license config is empty, fallback to module default config
                if (empty($config) || (count($config) == 1 && isset($config['bot_token']) && empty($config['bot_token']))) {
                    $config = json_decode($module['config'] ?? 'null', true) ?: [];
                }
            } else {
                $config = json_decode($module['config'] ?? 'null', true) ?: [];
                $config['bot_token'] = $module['bot_token'];
            }
            
            successResponse(['config' => $config]);
            break;

        case '/api/modules/update_config':
            requireMethod('POST');
            $admin = requireAuth($input);
            if (empty($input['module_id']) || !isset($input['config'])) {
                errorResponse('Module ID and configuration are required', 400);
            }

            // Fetch module object once
            $module = is_numeric($input['module_id']) ? Module::getById((int)$input['module_id']) : Module::getByModuleId($input['module_id']);
            if (!$module) errorResponse('Module not found', 404);

            if ($admin['role'] === 'Client') {
                $license = License::getByUserIdAndModuleId($admin['id'], (int)$module['id']);
                if (!$license) errorResponse('No active license found for this module', 404);
                $result = License::updateConfig($license['id'], $input['config'], $admin);
            } else {
                file_put_contents(__DIR__ . '/debug_save.log', date('Y-m-d H:i:s') . " | Save: " . $module['product_id'] . " | Config Keys: " . implode(',', array_keys($input['config'])) . " \n", FILE_APPEND);
                $result = Module::updateConfig($module['product_id'], $input['config'], $admin);
            }
            
            if (!$result['success']) errorResponse($result['error']);
            
            successResponse(['message' => $result['message']]);
            break;

        case '/api/bot/config':
            requireMethod('POST');
            // Public-facing for bots (authenticated via module check)
            if (empty($input['module_id'])) errorResponse('Module ID required', 400);
            
            $config = Module::getConfig($input['module_id']);
            successResponse(['config' => $config]);
            break;

        case '/api/bots':
            // Allow both to be safe

            $categories = Category::getAllWithModules();

            successResponse(['categories' => $categories]);
            break;

        case '/api/bot/report':
            requireMethod('POST');

            if (empty($input['bot_id']) || empty($input['name'])) {
                errorResponse('Bot ID and name are required', 400);
            }

            $botId = $input['bot_id'];
            $name = $input['name'];
            $serverCount = (int)($input['server_count'] ?? 0);
            $servers = $input['servers'] ?? [];
            $tokenPreview = $input['token_preview'] ?? null;
            $accessKey = $input['access_key'] ?? null;

            $result = BotData::report($botId, $name, $serverCount, $servers, $tokenPreview, $accessKey);

            if (!$result['success']) {
                errorResponse($result['error'], 400);
            }

            successResponse();
            break;

        // ====================================================================
        // ADMIN ENDPOINTS
        // ====================================================================
        case '/api/admin/list':
            requireMethod('POST');
            $admin = requireAuth($input);

            // Returns all staff (not Client)
            $admins = Auth::getAllAdmins();

            successResponse(['admins' => $admins]);
            break;

        case '/api/admin/users':
            requireMethod('POST');
            $admin = requireAuth($input);

            // Only High Admin and Owner can view full user list
            if (!Auth::hasRole($admin, ROLE_HIGH_ADMIN)) {
                errorResponse('Permission denied', 403);
            }

            $users = Auth::getAllUsers();
            successResponse(['users' => $users]);
            break;

        case '/api/admin/create':
            requireMethod('POST');
            $admin = requireAuth($input);

            // Only High Admin and Owner can create admins
            if (!Auth::hasRole($admin, ROLE_HIGH_ADMIN)) {
                errorResponse('Permission denied', 403);
            }

            if (empty($input['new_username']) || empty($input['new_password'])) {
                errorResponse('Username and password are required', 400);
            }

            $result = Auth::createAdminDirect(
                $input['new_username'],
                $input['new_password'],
                $admin
            );

            if (!$result['success']) {
                errorResponse($result['message'], 400);
            }

            successResponse(['message' => $result['message']]);
            break;

        case '/api/admin/manage':
            requireMethod('POST');
            $admin = requireAuth($input);

            if (empty($input['target_username']) || empty($input['action'])) {
                errorResponse('Target username and action are required', 400);
            }

            $targetUsername = $input['target_username'];
            $action = $input['action'];

            $validActions = ['approve', 'disable', 'delete'];
            if (!in_array($action, $validActions)) {
                errorResponse('Invalid action. Must be: ' . implode(', ', $validActions), 400);
            }

            $success = false;

            switch ($action) {
                case 'approve':
                    $success = Auth::approveAdmin($targetUsername, $admin);
                    break;
                case 'disable':
                    $success = Auth::disableAdmin($targetUsername, $admin);
                    break;
                case 'delete':
                    $success = Auth::deleteAdmin($targetUsername, $admin);
                    break;
            }

            if (!$success) {
                errorResponse('Failed to perform action. Check permissions and target user.', 403);
            }

            successResponse(['message' => ucfirst($action) . ' successful']);
            break;

        case '/api/admin/role':
            requireMethod('POST');
            $admin = requireAuth($input);

            if (empty($input['target_user']) || empty($input['new_role'])) {
                errorResponse('Target user and new role are required', 400);
            }

            $result = Auth::changeRole($input['target_user'], $input['new_role'], $admin);

            if (!$result['success']) {
                errorResponse($result['message'], 403);
            }

            successResponse(['message' => $result['message']]);
            break;

        // ====================================================================
        // BLACKLIST ENDPOINTS
        // ====================================================================
        case '/api/blacklist/add':
            requireMethod('POST');
            $admin = requireAuth($input);

            if (empty($input['hwid'])) errorResponse('HWID is required', 400);
            $reason = $input['reason'] ?? 'No reason provided';
            $gpuInfo = $input['gpu_info'] ?? null;
            $result = Blacklist::add($input['hwid'], $gpuInfo, $reason, $admin['username']);
            if (!$result['success']) errorResponse($result['error']);

            successResponse($result);
            break;

        case '/api/blacklist/remove':
            requireMethod('POST');
            $admin = requireAuth($input);

            if (empty($input['hwid'])) errorResponse('HWID is required', 400);

            $result = Blacklist::remove($input['hwid'], $admin['username']);
            if (!$result['success']) errorResponse($result['error']);

            successResponse($result);
            break;

        case '/api/blacklist/list':
            requireMethod('POST');
            $admin = requireAuth($input);

            $list = Blacklist::getAll();
            successResponse(['blacklist' => $list]);
            break;

        // ====================================================================
        // DASHBOARD ENDPOINTS
        // ====================================================================
        case '/api/stats':
    try {
        $admin = requireAuth($input);

        // Verify Database is reachable
        try {
            Database::getInstance();
        } catch (Exception $e) {
            errorResponse('Database connection failed in Stats: ' . $e->getMessage(), 500);
        }

        $moduleStats = ['total_modules' => 0, 'active' => 0];
        try { $moduleStats = Module::getStats() ?: $moduleStats; } catch (Throwable $e) {}

        $licenseStats = ['total' => 0, 'active' => 0];
        try { $licenseStats = License::getStats() ?: $licenseStats; } catch (Throwable $e) {}

        $botsData = [];
        try { $botsData = BotData::getAll() ?: []; } catch (Throwable $e) {}

        $totalServers = 0;
        try { $totalServers = BotData::getTotalServerCount() ?: 0; } catch (Throwable $e) {}

        if (strcasecmp($admin['role'], 'Client') === 0) {
            $licenses = [];
            try { $licenses = License::getAllByUserId((int)$admin['id']) ?: []; } catch (Throwable $e) {}
            
            $myModuleIds = [];
            foreach ($licenses as $l) {
                if (isset($l['product_id'])) $myModuleIds[] = (int)$l['product_id'];
            }
            $myModuleIds = array_unique($myModuleIds);
            
            $categories = [];
            try {
                $allCats = Category::getAllWithModules() ?: [];
                foreach ($allCats as $cat) {
                    $cat['bots'] = array_filter($cat['bots'] ?: [], function($bot) use ($myModuleIds) {
                        return in_array((int)($bot['num_id'] ?? 0), $myModuleIds);
                    });
                    if (!empty($cat['bots'])) {
                        $cat['bots'] = array_values($cat['bots']);
                        $categories[] = $cat;
                    }
                }
            } catch (Throwable $e) {}

            $total_licenses = count($licenses);
            $total_modules = count($myModuleIds);
            $total_admins = 0;
            try {
                $total_admins_res = Database::queryOne("SELECT COUNT(*) as c FROM accounts WHERE role != 'Client'");
                $total_admins = (int)($total_admins_res['c'] ?? 0);
            } catch (Throwable $e) {}
        } else {
            $categories = [];
            try { $categories = Category::getAllWithModules() ?: []; } catch (Throwable $e) {}
            
            $licenses = [];
            try { $licenses = License::getAll() ?: []; } catch (Throwable $e) {}
            
            $total_licenses = $licenseStats['total'] ?? 0;
            $total_modules = $moduleStats['total_modules'] ?? 0;
            $total_admins = 0;
            try {
                $total_admins_res = Database::queryOne("SELECT COUNT(*) as c FROM accounts WHERE role != 'Client'");
                $total_admins = (int)($total_admins_res['c'] ?? 0);
            } catch (Throwable $e) {}
        }

        $authorizedHwids = [];
        try { $authorizedHwids = AuthorizedHwid::getAll() ?: []; } catch (Throwable $e) {}

        $activeCount = 0;
        if (strcasecmp($admin['role'], 'Client') === 0) {
            foreach ($licenses as $l) {
                if (isset($l['status']) && strcasecmp($l['status'], 'Active') === 0) {
                    $activeCount++;
                }
            }
        } else {
            $activeCount = (int)($licenseStats['active'] ?? 0);
        }

        successResponse([
            'total_admins' => $total_admins,
            'total_licenses' => $total_licenses,
            'total_modules' => $total_modules,
            'total_servers' => $totalServers,
            'active_licenses' => $activeCount,
            'bots' => $botsData,
            'raw_licenses' => $licenses,
            'raw_modules' => $categories,
            'all_available_modules' => $categories,
            'authorized_hwids' => $authorizedHwids,
            'username' => $admin['username'] ?? 'User',
            'user_role' => $admin['role'] ?? 'Client',
            'discord_username' => $admin['discord_username'] ?? ($admin['username'] ?? 'User'),
            'discord_avatar' => $admin['discord_avatar'] ?? (!empty($admin['discord_id']) ? DiscordOAuth::getAvatarUrl($admin['discord_id'], null) : null)
        ]);
    } catch (Throwable $e) {
        $logMsg = date('H:i:s') . " | STATS ERROR: " . $e->getMessage() . " in " . $e->getFile() . ":" . $e->getLine() . "\n" . $e->getTraceAsString() . "\n";
        file_put_contents(__DIR__ . '/debug_fatal.log', $logMsg, FILE_APPEND);
        errorResponse('Critical Error in Stats: ' . $e->getMessage(), 500);
    }
    break;

        case '/api/logs':
            requireMethod('POST');
            $admin = requireAuth($input);

            $category = $input['category'] ?? null;
            $userFilter = $input['user_filter'] ?? null;

            if ($category === 'All') {
                $category = null;
            }

            $logs = SystemLog::getLogs($category, $userFilter, 1000);

            successResponse(['logs' => $logs]);
            break;

        case '/api/modules/get_token':
            requireMethod('POST');
            
            if (empty($input['module_id'])) {
                errorResponse('Module ID is required', 400);
            }

            // New logic: Require license key for per-license token
            if (empty($input['license_key'])) {
                errorResponse('License key is required', 400);
            }
            
            $module = Module::getByModuleId($input['module_id']);
            if (!$module) {
                errorResponse('Module not found', 404);
            }

            // Get license and its specific token
            $license = License::getByKey($input['license_key']);
            if (!$license) {
                 errorResponse('Invalid license key', 403);
            }

            // Verify module match
            if ($license['product_id'] != $module['id']) {
                errorResponse('License not valid for this module', 403);
            }

            // Check License Status
            if (isset($license['status']) && $license['status'] !== 'Active') {
                 errorResponse('License is ' . $license['status'], 403);
            }

            // Check Owner Account Status (Shutdown if user is banned)
            if (!empty($license['owner_id'])) {
                $owner = Auth::getUserById($license['owner_id']);
                if ($owner && strcasecmp($owner['status'], 'Active') !== 0) {
                     errorResponse('Account is ' . $owner['status'], 403);
                }
            }
            
            // Check Device Blacklist
            $hwid = $input['hwid'] ?? null;
            if ($hwid && Blacklist::isBanned($hwid)) {
                 errorResponse('Device Blacklisted', 403);
            }

            // Check Expiry
            if (!empty($license['expiry']) && strtotime($license['expiry']) < time()) {
                 errorResponse('License expired', 403);
            }
            
            // Get default module config
            $moduleConfig = json_decode($module['config'] ?? 'null', true) ?: [];

            // Get license specific config & token
            $licenseConfig = License::getConfig($license['id']) ?: [];
            $botTokenRaw = $licenseConfig['bot_token'] ?? $module['bot_token'];
            
            // Special handling for Broadcast System (Multi-Token support)
            $botTokens = [];
            if ($module['product_id'] === 'system_bot' || $module['product_id'] === 'broadcast_system' || $module['product_id'] === 'system') {
                $decodedTokens = json_decode($botTokenRaw, true);
                if (is_array($decodedTokens)) {
                    $botTokens = $decodedTokens;
                } else if (!empty($botTokenRaw)) {
                    $botTokens = [$botTokenRaw];
                }
            }

            // Merge: License settings override Module defaults
            // We use array_replace_recursive to handle nested objects like 'embed'
            $finalConfig = array_replace_recursive($moduleConfig, $licenseConfig);

            // Return tokens AND full merged config
            successResponse([
                'bot_token' => is_array($botTokens) && !empty($botTokens) ? $botTokens[0] : $botTokenRaw,
                'bot_tokens' => $botTokens, // Returns array for multi-bot workers
                'module_id' => $module['product_id'],
                'name' => $module['name'],
                'config' => $finalConfig
            ]);
            break;

        case '/api/modules/log':
            requireMethod('POST');
            if (empty($input['module_id']) || !isset($input['message'])) {
                errorResponse('Missing module_id or message', 400);
            }
            $moduleId = $input['module_id'];
            $msg = $input['message'];
            $logFile = __DIR__ . "/debug_rules_bot.log";
            $formatted = "[" . date('Y-m-d H:i:s') . "] " . $msg . "\n";
            
            if (file_put_contents($logFile, $formatted, FILE_APPEND) === false) {
                // If it fails, log to a system error log
                file_put_contents(__DIR__ . "/system_errors.log", date('H:i:s') . " | Failed to write to $logFile. Check permissions.\n", FILE_APPEND);
                errorResponse('Failed to save log', 500);
            }
            successResponse();
            break;

        case '/oauth/callback':
            require_once __DIR__ . '/discord-callback.php';
            exit;

        // ====================================================================
        // DEFAULT - 404
        // ====================================================================
        default:
            errorResponse('Endpoint not found: ' . $path, 404);
    }

} catch (Throwable $e) { // Catch ALL errors (Exception + Error)
    // Log the actual error to a file for debugging
    $logMsg = date('Y-m-d H:i:s') . " | FATAL ERROR: " . $e->getMessage() . " in " . $e->getFile() . ":" . $e->getLine() . "\n";
    file_put_contents(__DIR__ . '/debug_fatal.log', $logMsg, FILE_APPEND);

    errorResponse('Server Critical Error: ' . $e->getMessage(), 500);
}
