<?php
/**
 * Authentication Module
 *
 * Handles user authentication, password hashing, and authorization checks.
 */

// Prevent direct access
if (!defined('LICENSE_SERVER')) {
    http_response_code(403);
    exit('Direct access not allowed');
}
require_once __DIR__ . '/discord_oauth.php';
require_once __DIR__ . '/database.php';

class Auth
{
    /**
     * Authenticate user (Admins or Clients)
     *
     * @param string $username
     * @param string $password
     * @return array|null Returns user data or null if authentication fails
     */
    public static function authenticate(string $username, string $password): ?array
    {
        $sql = "SELECT a.*, da.`discord_id`, da.`discord_username`, da.`discord_avatar` 
                FROM `accounts` a
                LEFT JOIN `discord_accounts` da ON a.`id` = da.`account_id`
                WHERE a.`username` = ? LIMIT 1";
        $user = Database::queryOne($sql, [$username]);

        if (!$user) {
            return null;
        }

        if (!self::verifyPassword($password, $user['password'])) {
            return null;
        }

        // Rehash password if needed
        if (self::needsRehash($user['password'])) {
            $newHash = self::hashPassword($password);
            Database::execute(
                "UPDATE `accounts` SET `password` = ? WHERE `id` = ?",
                [$newHash, $user['id']]
            );
        }

        // Update last login
        Database::execute(
            "UPDATE `accounts` SET `last_login` = NOW() WHERE `id` = ?",
            [$user['id']]
        );

        // Standardize source_table for compatibility (it's always accounts now)
        $user['source_table'] = 'accounts';
        // Remove password from returned data
        unset($user['password']);

        return $user;
    }

    /**
     * Check credentials and return user data
     *
     * @param string $username
     * @param string $password
     * @param bool $requireActive Whether to require active status
     * @return array Returns ['success' => bool, 'admin' => array|null, 'error' => string|null]
     */
    public static function checkAdmin(string $username, string $password, bool $requireActive = true): array
    {
        if (empty($username) || empty($password)) {
            return [
                'success' => false,
                'admin' => null,
                'error' => 'Username and password are required',
                'code' => 400
            ];
        }

        $user = self::authenticate($username, $password);

        if (!$user) {
            SystemLog::log('Auth', 'Login Failed', "Failed login attempt for user: $username", $username);
            return [
                'success' => false,
                'admin' => null,
                'error' => 'Invalid credentials',
                'code' => 401
            ];
        }

        if ($requireActive && strtolower($user['status']) !== 'active') {
            SystemLog::log('Auth', 'Login Blocked', "Login blocked - account status: {$user['status']}", $username);
            return [
                'success' => false,
                'admin' => null,
                'error' => 'Account is not active. Status: ' . $user['status'],
                'code' => 403
            ];
        }

        // Verify user has a linked license (For Clients or Admins with Licenses)
        $license = License::getByUserId($user['id']);
        
        if (!$license || strtolower($license['status']) !== 'active') {
             // Exception: Owner and High Admin always get in without license
             if ($user['role'] === ROLE_OWNER || $user['role'] === ROLE_HIGH_ADMIN) {
                 return ['success' => true, 'admin' => $user, 'error' => null, 'code' => 200];
             }
             
             return [
                'success' => false,
                'error' => 'Valid license required. Please register/link a key.',
                'code' => 403
            ];
        }

        return [
            'success' => true,
            'admin' => $user,
            'error' => null,
            'code' => 200
        ];
    }

    /**
     * Legacy support for checkUser - redirects to checkAdmin
     */
    public static function checkUser(string $username, string $password): array
    {
        return self::checkAdmin($username, $password);
    }

    /**
     * Get user by ID (Universal)
     */
    public static function getUserById(int $id): ?array
    {
        $sql = "SELECT a.`id`, a.`username`, a.`role`, 'accounts' as `source_table`, a.`status`, a.`created_at`, a.`last_login`, da.`discord_id`, da.`discord_username`, da.`discord_avatar`
                FROM `accounts` a
                LEFT JOIN `discord_accounts` da ON a.`id` = da.`account_id`
                WHERE a.`id` = ? LIMIT 1";
        return Database::queryOne($sql, [$id]);
    }

    /**
     * Alias for getUserById
     */
    public static function getAdminById(int $id): ?array
    {
        return self::getUserById($id);
    }

    /**
     * Register or Authenticate with License Key
     */
    public static function register(string $username, string $password, string $key): array
    {
        if (strlen($username) < 3 || strlen($username) > 50) return ['success' => false, 'message' => 'Username must be 3-50 chars'];
        if (strlen($password) < 6) return ['success' => false, 'message' => 'Password must be at least 6 chars'];
        
        $license = License::getByKey($key);
        if (!$license) return ['success' => false, 'message' => 'Invalid License Key'];
        
        if (strtolower($license['status']) === 'expired' || strtolower($license['status']) === 'disabled') {
            return ['success' => false, 'message' => 'License is ' . $license['status']];
        }

        $existing = self::getAccountByUsername($username);

        if ($existing) {
            // Existing Account -> Login Flow
            if (!self::verifyPassword($password, $existing['password'])) {
                return ['success' => false, 'message' => "Username '$username' is already taken."];
            }

            // Check if license matches
            if (isset($license['owner_id']) && $license['owner_id'] == $existing['id']) {
                 return ['success' => true, 'admin' => $existing, 'message' => 'Welcome back'];
            }
            
            // If license is claimed by someone else
            if (!empty($license['owner_id'])) {
                return ['success' => false, 'message' => 'This license is linked to another account'];
            }
            
            // Link License to Account
            License::claim($key, $existing['id']);
            return ['success' => true, 'admin' => $existing, 'message' => 'License linked successfully'];

        } else {
            // New Account -> Register Flow
            if (License::isClaimed($key)) {
                return ['success' => false, 'message' => 'This license key is already in use'];
            }
            
            $hashed = self::hashPassword($password);
            try {
                Database::execute(
                    "INSERT INTO `accounts` (`username`, `password`, `role`, `status`) VALUES (?, ?, 'Client', 'Active')",
                    [$username, $hashed]
                );
                $newId = Database::lastInsertId();
                
                // Link License
                License::claim($key, $newId);
                
                $newUser = self::getUserById($newId);
                SystemLog::log('Auth', 'Register', "New user registered: $username with key $key", $username);
                
                return ['success' => true, 'admin' => $newUser, 'message' => 'Account created successfully'];
            } catch (Exception $e) {
                return ['success' => false, 'message' => 'Registration failed: ' . $e->getMessage()];
            }
        }
    }

    /**
     * Check role hierarchy
     */
    public static function hasRole(array $user, string $requiredRole): bool
    {
        $hierarchy = ROLE_HIERARCHY;
        $userLevel = $hierarchy[$user['role']] ?? 0;
        $requiredLevel = $hierarchy[$requiredRole] ?? PHP_INT_MAX;

        return $userLevel >= $requiredLevel;
    }

    /**
     * Permission check for management
     */
    public static function canManage(array $actor, array $target): bool
    {
        if ($target['role'] === ROLE_OWNER) return false;
        if ($actor['role'] === ROLE_OWNER) return true;
        if ($actor['role'] === ROLE_HIGH_ADMIN && $target['role'] === ROLE_ADMIN) return true;
        if ($actor['role'] === ROLE_HIGH_ADMIN && $target['role'] === ROLE_CLIENT) return true;
        if ($actor['role'] === ROLE_ADMIN && $target['role'] === ROLE_CLIENT) return true;

        return false;
    }

    /**
     * Get account by username
     */
    public static function getAccountByUsername(string $username): ?array
    {
        return Database::queryOne(
            "SELECT * FROM `accounts` WHERE `username` = ? LIMIT 1",
            [$username]
        );
    }

    /**
     * Alias for getAccountByUsername (limited fields)
     */
    public static function getAdminByUsername(string $username): ?array
    {
        return Database::queryOne(
            "SELECT `id`, `username`, `role`, `status`, `created_at`, `last_login`
             FROM `accounts` WHERE `username` = ? LIMIT 1",
            [$username]
        );
    }

    /**
     * Create account request (Pending status)
     */
    public static function createAdmin(string $username, string $password, string $role = ROLE_ADMIN): array
    {
        if (strlen($username) < 3 || strlen($username) > 50) return ['success' => false, 'message' => 'Username must be 3-50 chars'];
        if (self::getAccountByUsername($username)) return ['success' => false, 'message' => 'Username already exists'];
        if (strlen($password) < 6) return ['success' => false, 'message' => 'Password must be at least 6 chars'];

        $hashedPassword = self::hashPassword($password);
        try {
            Database::execute(
                "INSERT INTO `accounts` (`username`, `password`, `role`, `status`) VALUES (?, ?, ?, 'Pending')",
                [$username, $hashedPassword, $role]
            );
            SystemLog::log('Auth', 'Request', "New account request: $username", $username);
            return ['success' => true, 'message' => 'Request submitted. Awaiting approval.'];
        } catch (Exception $e) {
            return ['success' => false, 'message' => 'Failed to create request'];
        }
    }

    /**
     * Create account directly (Active status)
     */
    public static function createAdminDirect(string $username, string $password, array $creator, string $role = ROLE_ADMIN): array 
    {
        if (strlen($username) < 3 || strlen($username) > 50) return ['success' => false, 'message' => 'Username must be 3-50 chars'];
        if (self::getAccountByUsername($username)) return ['success' => false, 'message' => 'Username already exists'];
        
        $hashedPassword = self::hashPassword($password);
        try {
            Database::execute(
                "INSERT INTO `accounts` (`username`, `password`, `role`, `status`) VALUES (?, ?, ?, 'Active')",
                [$username, $hashedPassword, $role]
            );
            SystemLog::log('Admin', 'Create', "Account created: $username ($role) by {$creator['username']}", $creator['username']);
            return ['success' => true, 'message' => 'Account created successfully'];
        } catch (Exception $e) {
            return ['success' => false, 'message' => 'Failed to create account'];
        }
    }

    public static function approveAdmin(string $username, array $approver): bool
    {
        $target = self::getAccountByUsername($username);
        if (!$target || !in_array($target['status'], ['Pending', 'Disabled'])) return false;

        Database::execute("UPDATE `accounts` SET `status` = 'Active' WHERE `username` = ?", [$username]);
        SystemLog::log('Admin', 'Approve', "Account activated: $username by {$approver['username']}", $approver['username']);
        return true;
    }

    public static function disableAdmin(string $username, array $admin): bool
    {
        $target = self::getAccountByUsername($username);
        if (!$target || !self::canManage($admin, $target)) return false;

        Database::execute("UPDATE `accounts` SET `status` = 'Disabled' WHERE `username` = ?", [$username]);
        SystemLog::log('Admin', 'Disable', "Account disabled: $username by {$admin['username']}", $admin['username']);
        return true;
    }

    public static function deleteAdmin(string $username, array $admin): bool
    {
        $target = self::getAccountByUsername($username);
        if (!$target || !self::canManage($admin, $target)) return false;

        Database::execute("DELETE FROM `accounts` WHERE `username` = ?", [$username]);
        SystemLog::log('Admin', 'Delete', "Account deleted: $username by {$admin['username']}", $admin['username']);
        return true;
    }

    public static function changeRole(string $username, string $newRole, array $admin): array
    {
        if (!self::hasRole($admin, ROLE_HIGH_ADMIN)) return ['success' => false, 'message' => 'Permission denied'];
        $target = self::getAccountByUsername($username);
        if (!$target) return ['success' => false, 'message' => 'User not found'];
        if ($target['role'] === ROLE_OWNER) return ['success' => false, 'message' => 'Cannot modify owner'];
        if ($newRole === ROLE_HIGH_ADMIN && $admin['role'] !== ROLE_OWNER) return ['success' => false, 'message' => 'Only owner can promote to High Admin'];

        Database::execute("UPDATE `accounts` SET `role` = ? WHERE `username` = ?", [$newRole, $username]);
        SystemLog::log('Admin', 'Role Change', "Role for $username: {$target['role']} -> $newRole by {$admin['username']}", $admin['username']);
        return ['success' => true, 'message' => 'Role updated'];
    }

     public static function getAllAdmins(): array
    {
        $admins = Database::query(
            "SELECT a.`id`, a.`username`, a.`role`, a.`status`, a.`created_at`, a.`last_login`, da.`discord_id`, da.`discord_username`, da.`discord_avatar`
             FROM `accounts` a
             LEFT JOIN `discord_accounts` da ON a.`id` = da.`account_id`
             WHERE a.`role` != 'Client' ORDER BY a.`created_at` DESC"
        );
        foreach ($admins as &$a) {
            if (empty($a['discord_avatar']) && !empty($a['discord_id'])) {
                $a['discord_avatar'] = DiscordOAuth::getAvatarUrl($a['discord_id'], null);
            }
        }
        return $admins;
    }

     public static function getAllUsers(): array
    {
        $users = Database::query(
            "SELECT a.`id`, a.`username`, a.`role`, a.`status`, a.`created_at`, a.`last_login`, da.`discord_id`, da.`discord_username`, da.`discord_avatar`
             FROM `accounts` a
             LEFT JOIN `discord_accounts` da ON a.`id` = da.`account_id`
             WHERE a.`role` = 'Client' ORDER BY a.`created_at` DESC"
        );
        foreach ($users as &$u) {
            if (empty($u['discord_avatar']) && !empty($u['discord_id'])) {
                $u['discord_avatar'] = DiscordOAuth::getAvatarUrl($u['discord_id'], null);
            }
        }
        return $users;
    }

    public static function getUserByUsername(string $username): ?array
    {
        return self::getAccountByUsername($username);
    }

    /**
     * Hash a password
     */
    public static function hashPassword(string $password): string
    {
        return password_hash($password, PASSWORD_BCRYPT);
    }

    /**
     * Verify a password
     */
    public static function verifyPassword(string $password, string $hash): bool
    {
        return password_verify($password, $hash);
    }

    /**
     * Check if password needs rehash
     */
    public static function needsRehash(string $hash): bool
    {
        return password_needs_rehash($hash, PASSWORD_BCRYPT);
    }
}

/**
 * Rate Limiter
 */
class RateLimiter
{
    /**
     * Check if request should be rate limited
     *
     * @param string $ip IP address
     * @param string $endpoint Endpoint being accessed
     * @return bool True if should be blocked
     */
    public static function isLimited(string $ip, string $endpoint = 'default'): bool
    {
        if (!RATE_LIMIT_ENABLED) {
            return false;
        }

        $sql = "SELECT * FROM `rate_limits`
                WHERE `ip_address` = ? AND `endpoint` = ?
                AND `window_start` > DATE_SUB(NOW(), INTERVAL ? SECOND)
                LIMIT 1";

        $record = Database::queryOne($sql, [$ip, $endpoint, RATE_LIMIT_WINDOW]);

        if (!$record) {
            // Create new record
            Database::execute(
                "INSERT INTO `rate_limits` (`ip_address`, `endpoint`, `requests`, `window_start`)
                 VALUES (?, ?, 1, NOW())
                 ON DUPLICATE KEY UPDATE `requests` = 1, `window_start` = NOW()",
                [$ip, $endpoint]
            );
            return false;
        }

        if ($record['requests'] >= RATE_LIMIT_REQUESTS) {
            return true;
        }

        // Increment counter
        Database::execute(
            "UPDATE `rate_limits` SET `requests` = `requests` + 1
             WHERE `ip_address` = ? AND `endpoint` = ?",
            [$ip, $endpoint]
        );

        return false;
    }

    /**
     * Get remaining requests for IP
     *
     * @param string $ip
     * @param string $endpoint
     * @return int
     */
    public static function getRemainingRequests(string $ip, string $endpoint = 'default'): int
    {
        $sql = "SELECT `requests` FROM `rate_limits`
                WHERE `ip_address` = ? AND `endpoint` = ?
                AND `window_start` > DATE_SUB(NOW(), INTERVAL ? SECOND)
                LIMIT 1";

        $record = Database::queryOne($sql, [$ip, $endpoint, RATE_LIMIT_WINDOW]);

        if (!$record) {
            return RATE_LIMIT_REQUESTS;
        }

        return max(0, RATE_LIMIT_REQUESTS - $record['requests']);
    }

    /**
     * Clean old rate limit records
     */
    public static function cleanup(): void
    {
        Database::execute(
            "DELETE FROM `rate_limits` WHERE `window_start` < DATE_SUB(NOW(), INTERVAL 1 HOUR)"
        );
    }
}
