<?php
/**
 * System Logging Module
 *
 * Handles audit trail and system event logging.
 */

// Prevent direct access
if (!defined('LICENSE_SERVER')) {
    http_response_code(403);
    exit('Direct access not allowed');
}
require_once __DIR__ . '/discord_oauth.php';

class SystemLog
{
    /**
     * Ensure table exists
     */
    public static function ensureSchema(): void
    {
        // System Logs
        Database::execute("CREATE TABLE IF NOT EXISTS `system_logs` (
            `log_id` VARCHAR(36) NOT NULL PRIMARY KEY,
            `category` VARCHAR(50) NOT NULL,
            `action` VARCHAR(100) NOT NULL,
            `details` TEXT NULL,
            `user` VARCHAR(100) NULL,
            `ip_address` VARCHAR(45) NULL,
            `user_agent` TEXT NULL,
            `created_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            INDEX `idx_category` (`category`),
            INDEX `idx_user` (`user`),
            INDEX `idx_created_at` (`created_at`)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci");

        // License Logs
        Database::execute("CREATE TABLE IF NOT EXISTS `license_logs` (
            `id` INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
            `license_id` INT UNSIGNED NOT NULL,
            `message` TEXT NOT NULL,
            `created_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            INDEX `idx_license_id` (`license_id`)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci");
    }


    /**
     * Generate UUID v4
     */
    private static function generateUuid(): string
    {
        $data = random_bytes(16);
        $data[6] = chr(ord($data[6]) & 0x0f | 0x40);
        $data[8] = chr(ord($data[8]) & 0x3f | 0x80);

        return vsprintf('%s%s-%s-%s-%s-%s%s%s', str_split(bin2hex($data), 4));
    }

    /**
     * Log a system event
     *
     * @param string $category Log category (License, Auth, Admin, Module, Bot, System)
     * @param string $action Action performed
     * @param string $details Human-readable details
     * @param string|null $user Username who performed the action
     * @return string Log ID
     */
    public static function log(
        string $category,
        string $action,
        string $details,
        ?string $user = null
    ): string {
        // Validate category
        if (!in_array($category, LOG_CATEGORIES)) {
            $category = 'System';
        }

        $logId = self::generateUuid();
        $ipAddress = self::getClientIp();
        $userAgent = $_SERVER['HTTP_USER_AGENT'] ?? null;

        try {
            Database::execute(
                "INSERT INTO `system_logs`
                 (`log_id`, `category`, `action`, `details`, `user`, `ip_address`, `user_agent`)
                 VALUES (?, ?, ?, ?, ?, ?, ?)",
                [$logId, $category, $action, $details, $user, $ipAddress, $userAgent]
            );

            // Cleanup old logs if exceeding limit
            self::cleanupOldLogs();
        } catch (Exception $e) {
            // Log to error log if database fails
            error_log("Failed to write system log: $category - $action - $details");
        }

        return $logId;
    }

    /**
     * Get client IP address
     */
    private static function getClientIp(): string
    {
        $headers = [
            'HTTP_CF_CONNECTING_IP',     // Cloudflare
            'HTTP_X_FORWARDED_FOR',      // Proxy
            'HTTP_X_REAL_IP',            // Nginx
            'HTTP_CLIENT_IP',
            'REMOTE_ADDR'
        ];

        foreach ($headers as $header) {
            if (!empty($_SERVER[$header])) {
                $ip = $_SERVER[$header];
                // Handle comma-separated IPs (X-Forwarded-For)
                if (strpos($ip, ',') !== false) {
                    $ips = explode(',', $ip);
                    $ip = trim($ips[0]);
                }
                // Validate IP
                if (filter_var($ip, FILTER_VALIDATE_IP)) {
                    return $ip;
                }
            }
        }

        return '0.0.0.0';
    }

    /**
     * Get logs with optional filtering
     *
     * @param string|null $category Filter by category (null for all)
     * @param string|null $user Filter by user (null for all)
     * @param int $limit Maximum number of logs to return
     * @param int $offset Offset for pagination
     * @return array
     */
    public static function getLogs(
        ?string $category = null,
        ?string $user = null,
        int $limit = 100,
        int $offset = 0
    ): array {
        $sql = "SELECT l.`log_id` as `id`, l.`category`, l.`action`, l.`details`, l.`user`,
                       l.`ip_address`, l.`created_at` as `timestamp`, da.`discord_avatar`, da.`discord_id`
                FROM `system_logs` l
                LEFT JOIN `accounts` a ON l.`user` = a.`username`
                LEFT JOIN `discord_accounts` da ON a.`id` = da.`account_id`
                WHERE 1=1";
        $params = [];

        if ($category !== null && $category !== 'All') {
            $sql .= " AND `category` = ?";
            $params[] = $category;
        }

        if ($user !== null && $user !== '') {
            $sql .= " AND `user` LIKE ?";
            $params[] = "%$user%";
        }

        $sql .= " ORDER BY `created_at` DESC LIMIT ? OFFSET ?";
        $params[] = $limit;
        $params[] = $offset;

        $logs = [];
        try {
            $logs = Database::query($sql, $params);
        } catch (Exception $e) {
            // Log the error for debugging
            file_put_contents(__DIR__ . '/sql_error.log', date('Y-m-d H:i:s') . " | Log Query Failed: " . $e->getMessage() . "\n", FILE_APPEND);
            
            // Fallback: Simple query without joins (to avoid collation errors)
            $fallbackSql = "SELECT `log_id` as `id`, `category`, `action`, `details`, `user`,
                           `ip_address`, `created_at` as `timestamp`
                           FROM `system_logs` WHERE 1=1";
            $fallbackParams = [];
            
            if ($category !== null && $category !== 'All') {
                $fallbackSql .= " AND `category` = ?";
                $fallbackParams[] = $category;
            }
            if ($user !== null && $user !== '') {
                $fallbackSql .= " AND `user` LIKE ?";
                $fallbackParams[] = "%$user%";
            }
            $fallbackSql .= " ORDER BY `created_at` DESC LIMIT ? OFFSET ?";
            $fallbackParams[] = $limit;
            $fallbackParams[] = $offset;
            
            try {
                $logs = Database::query($fallbackSql, $fallbackParams);
            } catch (Exception $ex) {
                 // Even fallback failed? Return empty.
                 return [];
            }
        }

        foreach ($logs as &$log) {
            // Populate Avatar manually if missing (from Join failure or fallback)
            if (empty($log['discord_avatar'])) {
                // If we have discord_id (from join), use it. If not, we can't easily get it without N+1 queries.
                // For now, let frontend show default or we can try to fetch user if needed.
                if (!empty($log['discord_id'])) {
                     $log['discord_avatar'] = DiscordOAuth::getAvatarUrl($log['discord_id'], null);
                } else {
                     // Try to match user via separate query? (Expensive loop, better to leave empty for now)
                     $log['discord_avatar'] = null;
                }
            }
        }
        return $logs;
    }

    /**
     * Get log by ID
     *
     * @param string $logId
     * @return array|null
     */
    public static function getLogById(string $logId): ?array
    {
        $sql = "SELECT * FROM `system_logs` WHERE `log_id` = ? LIMIT 1";
        return Database::queryOne($sql, [$logId]);
    }

    /**
     * Get log statistics
     *
     * @return array
     */
    public static function getStats(): array
    {
        $stats = [];

        // Total logs
        $result = Database::queryOne("SELECT COUNT(*) as count FROM `system_logs`");
        $stats['total'] = (int)$result['count'];

        // Logs by category
        $categories = Database::query(
            "SELECT `category`, COUNT(*) as count FROM `system_logs` GROUP BY `category`"
        );
        $stats['by_category'] = [];
        foreach ($categories as $row) {
            $stats['by_category'][$row['category']] = (int)$row['count'];
        }

        // Logs today
        $result = Database::queryOne(
            "SELECT COUNT(*) as count FROM `system_logs` WHERE DATE(`created_at`) = CURDATE()"
        );
        $stats['today'] = (int)$result['count'];

        // Logs this hour
        $result = Database::queryOne(
            "SELECT COUNT(*) as count FROM `system_logs`
             WHERE `created_at` > DATE_SUB(NOW(), INTERVAL 1 HOUR)"
        );
        $stats['last_hour'] = (int)$result['count'];

        return $stats;
    }

    /**
     * Cleanup old logs to maintain maximum count
     */
    private static function cleanupOldLogs(): void
    {
        $result = Database::queryOne("SELECT COUNT(*) as count FROM `system_logs`");
        $count = (int)$result['count'];

        if ($count > MAX_LOGS) {
            $deleteCount = $count - MAX_LOGS;
            Database::execute(
                "DELETE FROM `system_logs`
                 ORDER BY `created_at` ASC
                 LIMIT ?",
                [$deleteCount]
            );
        }
    }

    /**
     * Delete all logs (admin only)
     *
     * @param array $admin Admin performing the action
     * @return bool
     */
    public static function clearAllLogs(array $admin): bool
    {
        if ($admin['role'] !== ROLE_OWNER) {
            return false;
        }

        Database::execute("TRUNCATE TABLE `system_logs`");

        // Log the clear action
        self::log('System', 'Clear Logs', 'All system logs cleared', $admin['username']);

        return true;
    }

    /**
     * Export logs to array format
     *
     * @param string|null $category
     * @param string|null $startDate
     * @param string|null $endDate
     * @return array
     */
    public static function exportLogs(
        ?string $category = null,
        ?string $startDate = null,
        ?string $endDate = null
    ): array {
        $sql = "SELECT * FROM `system_logs` WHERE 1=1";
        $params = [];

        if ($category !== null && $category !== 'All') {
            $sql .= " AND `category` = ?";
            $params[] = $category;
        }

        if ($startDate !== null) {
            $sql .= " AND `created_at` >= ?";
            $params[] = $startDate;
        }

        if ($endDate !== null) {
            $sql .= " AND `created_at` <= ?";
            $params[] = $endDate;
        }

        $sql .= " ORDER BY `created_at` DESC";

        return Database::query($sql, $params);
    }
}

/**
 * License-specific logging
 */
class LicenseLog
{
    /**
     * Add log entry to license
     *
     * @param int $licenseId
     * @param string $message
     */
    public static function add(int $licenseId, string $message): void
    {
        Database::execute(
            "INSERT INTO `license_logs` (`license_id`, `message`) VALUES (?, ?)",
            [$licenseId, $message]
        );
    }

    /**
     * Get logs for a license
     *
     * @param int $licenseId
     * @param int $limit
     * @return array
     */
    public static function get(int $licenseId, int $limit = 50): array
    {
        return Database::query(
            "SELECT `message`, `created_at` as `timestamp`
             FROM `license_logs`
             WHERE `license_id` = ?
             ORDER BY `created_at` DESC
             LIMIT ?",
            [$licenseId, $limit]
        );
    }

    /**
     * Clear logs for a license
     *
     * @param int $licenseId
     */
    public static function clear(int $licenseId): void
    {
        Database::execute(
            "DELETE FROM `license_logs` WHERE `license_id` = ?",
            [$licenseId]
        );
    }
}
