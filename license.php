<?php
/**
 * License Management Module
 *
 * Handles license generation, validation, and management.
 */

// Prevent direct access
if (!defined('LICENSE_SERVER')) {
    http_response_code(403);
    exit('Direct access not allowed');
}

class License
{
    /**
     * Auto-fix schema (Deprecated for new schema)
     */
    /**
     * Auto-fix schema (Smart Auto-Migration)
     */
    public static function ensureSchema(): void
    {
        // 1. Fix missing 'config' column in products (JSON type)
        try {
            $cols = Database::query("SHOW COLUMNS FROM `products` LIKE 'config'");
            if (empty($cols)) {
                Database::execute("ALTER TABLE `products` ADD COLUMN `config` JSON NULL AFTER `bot_token`");
                SystemLog::log('System', 'Schema Fix', "Added missing 'config' column to products table");
            }
        } catch (Throwable $e) { /* Ignore */ }

        // 2. Fix missing 'config' and 'bot_token' in licenses
        try {
            $cols = Database::query("SHOW COLUMNS FROM `licenses` LIKE 'config'");
            if (empty($cols)) {
                Database::execute("ALTER TABLE `licenses` ADD COLUMN `config` JSON NULL AFTER `status`");
                SystemLog::log('System', 'Schema Fix', "Added missing 'config' column to licenses table");
            }
            
            $cols = Database::query("SHOW COLUMNS FROM `licenses` LIKE 'bot_token'");
            if (empty($cols)) {
                Database::execute("ALTER TABLE `licenses` ADD COLUMN `bot_token` TEXT NULL AFTER `config`");
                SystemLog::log('System', 'Schema Fix', "Added missing 'bot_token' column to licenses table");
            }
        } catch (Throwable $e) { /* Ignore */ }
    }

    /**
     * Generate a new license
     *
     * @param string $moduleId Module/bot ID
     * @param int $duration Duration in days
     * @param int $hwidLimit Maximum allowed devices
     * @param array $admin Admin creating the license
     * @return array ['success' => bool, 'key' => string, 'expiry' => string] or ['success' => false, 'error' => string]
     */
    public static function generate(
        ?string $moduleId,
        array $admin,
        int $duration = DEFAULT_LICENSE_DURATION,
        int $hwidLimit = DEFAULT_HWID_LIMIT
    ): array {
        if (empty($moduleId)) {
            return ['success' => false, 'error' => 'Module ID is required'];
        }
        // Validate product exists
        $product = Product::getByProductId($moduleId);
        if (!$product) {
            return ['success' => false, 'error' => 'Product not found'];
        }

        // Generate unique key
        $key = Utils::generateLicenseKey();

        // Make sure key is unique
        $attempts = 0;
        while (self::getByKey($key) !== null && $attempts < 10) {
            $key = Utils::generateLicenseKey();
            $attempts++;
        }

        if ($attempts >= 10) {
            return ['success' => false, 'error' => 'Failed to generate unique key'];
        }

        // Calculate expiry
        $duration = max(1, min((int)$duration, 2900000)); // Max ~8000 years (Year 9999 limit)
        $expiry = Utils::addDays($duration);

        try {
            Database::execute(
                "INSERT INTO `licenses` (`license_key`, `product_id`, `hwid_limit`, `expiry`, `created_by`)
                 VALUES (?, ?, ?, ?, ?)",
                [$key, $product['id'], (int)$hwidLimit, $expiry, $admin['id']]
            );

            $licenseId = Database::lastInsertId();

            // Log the creation
            LicenseLog::add($licenseId, 'License created');
            SystemLog::log(
                'License',
                'Generate',
                "License generated: $key for product {$product['name']}, expires: $expiry",
                $admin['username']
            );

            return [
                'success' => true,
                'key' => $key,
                'expiry' => Utils::toIso8601($expiry)
            ];
        } catch (Exception $e) {
            return ['success' => false, 'error' => 'DB Error: ' . $e->getMessage()];
        }
    }

    /**
     * Validate a license and register device
     *
     * @param string $key License key
     * @param string $hwid Hardware ID
     * @param string $moduleId Module ID to validate against
     * @param string|null $hostname Device hostname
     * @return array
     */
    public static function validate(
        string $key,
        string $hwid,
        string $moduleId,
        ?string $hostname = null,
        ?string $gpuInfo = null
    ): array {
        // Validate HWID format
        if (!Utils::isValidHwid($hwid)) {
            return ['success' => false, 'error' => 'Invalid HWID format', 'code' => 400];
        }

        // Check if device is banned
        if (Blacklist::isBanned($hwid, $gpuInfo)) {
            SystemLog::log('License', 'Ban Block', "Blocked blacklisted device: $hwid" . ($gpuInfo ? " (GPU: $gpuInfo)" : ""));
            return [
                'success' => false,
                'error' => '🚫 ACCESS DENIED - Your device has been banned from using this service. If you believe this is a mistake, please contact support.',
                'code' => 403,
                'banned' => true
            ];
        }

        // Get license with module info
        $license = self::getByKeyWithModule($key);

        if (!$license) {
            return ['success' => false, 'error' => 'Invalid license key', 'code' => 404];
        }

        // Check module match
        if ($license['product_id_str'] !== $moduleId) {
            SystemLog::log(
                'License',
                'Module Mismatch',
                "License $key attempted for wrong product: $moduleId (expected: {$license['product_id_str']})"
            );
            return [
                'success' => false,
                'error' => 'License not valid for this product',
                'code' => 403
            ];
        }

        // Initial status for logging
        $currentStatus = $license['status'];

        // Block if disabled
        if (strcasecmp($license['status'], 'Disabled') === 0) {
            return [
                'success' => false,
                'error' => 'License is disabled',
                'code' => 403
            ];
        }

        // Check expiry for Active/Expired keys
        if (strcasecmp($license['status'], 'New') !== 0 && Utils::isExpired($license['expiry'])) {
            if (strcasecmp($license['status'], 'Expired') !== 0) {
                self::updateStatus($license['id'], 'Expired');
            }
            return [
                'success' => false,
                'error' => 'License has expired',
                'code' => 403
            ];
        }

        // Get current HWIDs for this license
        $registeredHwids = self::getHwids($license['id']);
        $hwidExists = false;

        foreach ($registeredHwids as $reg) {
            if ($reg['hwid'] === $hwid) {
                $hwidExists = true;
                break;
            }
        }

        if ($hwidExists) {
            // Update hostname, gpu_info and last seen
            self::updateHwid($license['id'], $hwid, $hostname, $gpuInfo);
            LicenseLog::add($license['id'], "Device reconnected: $hwid");

            return [
                'success' => true,
                'message' => 'License valid',
                'module' => $license['product_name'],
                'bot_token' => $license['bot_token'] ?? $license['product_bot_token'],
                'expiry' => Utils::toIso8601($license['expiry'])
            ];
        }

        // Check HWID limit
        if (count($registeredHwids) >= $license['hwid_limit']) {
            return [
                'success' => false,
                'error' => 'Device limit reached. Maximum: ' . $license['hwid_limit'],
                'code' => 403
            ];
        }

        // Register new HWID FIRST
        try {
            self::registerHwid($license['id'], $hwid, $hostname, $gpuInfo);
            
            // Auto-activate new licenses ONLY after successfull device registration
            if (strcasecmp($license['status'], 'New') === 0) {
                self::updateStatus($license['id'], 'Active');
                $license['status'] = 'Active';
                LicenseLog::add($license['id'], 'License activated on first device registration');
            }

            LicenseLog::add($license['id'], "New device registered: $hwid ($hostname)" . ($gpuInfo ? " [GPU: $gpuInfo]" : ""));
            
            // Also add to authorized_hwids (if exists, else skip)
            try {
                Database::execute(
                    "INSERT INTO `authorized_hwids` (`hwid`, `module_id`, `hostname`, `gpu_info`) VALUES (?, ?, ?, ?)
                     ON DUPLICATE KEY UPDATE `hostname` = VALUES(`hostname`), `gpu_info` = VALUES(`gpu_info`), `updated_at` = NOW()",
                    [$hwid, $license['product_db_id'], $hostname, $gpuInfo]
                );
            } catch (Exception $e) {}

            SystemLog::log(
                'License',
                'Device Register',
                "Device registered for license $key: $hwid ($hostname)"
            );

            return [
                'success' => true,
                'message' => 'Device registered successfully',
                'module' => $license['product_name'],
                'bot_token' => $license['bot_token'] ?? $license['product_bot_token'],
                'expiry' => Utils::toIso8601($license['expiry'])
            ];
        } catch (Exception $e) {
            error_log("HWID registration failed for license $key: " . $e->getMessage());
            return [
                'success' => false,
                'error' => 'Failed to register device. Please try again or contact support.',
                'code' => 500
            ];
        }
    }

    /**
     * Get license by key
     *
     * @param string $key
     * @return array|null
     */
    public static function getByKey(string $key): ?array
    {
        return Database::queryOne(
            "SELECT * FROM `licenses` WHERE `license_key` = ? LIMIT 1",
            [$key]
        );
    }

    /**
     * Get license by key with product information
     *
     * @param string $key
     * @return array|null
     */
    public static function getByKeyWithModule(string $key): ?array
    {
        return Database::queryOne(
            "SELECT l.*, p.product_id as product_id_str, p.name as product_name, p.id as product_db_id, p.bot_token as product_bot_token, p.config as product_config
             FROM `licenses` l
             JOIN `products` p ON l.product_id = p.id
             WHERE l.license_key = ?
             LIMIT 1",
            [$key]
        );
    }

    /**
     * Get license by owner ID
     * 
     * @param int $id Account ID
     */
    public static function getByUserId(int $id): ?array
    {
        return Database::queryOne(
            "SELECT l.*, p.product_id as product_id_str, p.name as product_name
             FROM `licenses` l
             JOIN `products` p ON l.product_id = p.id
             WHERE l.owner_id = ?
             LIMIT 1",
            [$id]
        );
    }

    /**
     * Get specific license by user and product ID
     */
    public static function getByUserIdAndModuleId(int $userId, int $productId): ?array
    {
        return Database::queryOne(
            "SELECT l.*, p.product_id as product_id_str, p.name as product_name
             FROM `licenses` l
             JOIN `products` p ON l.product_id = p.id
             WHERE l.owner_id = ? AND l.product_id = ?
             LIMIT 1",
            [$userId, $productId]
        );
    }

    /**
     * Get all licenses by user ID
     */
    public static function getAllByUserId(int $userId): array
    {
        $licenses = Database::query(
            "SELECT l.*, p.product_id as module, p.name as module_name,
                    a.username as created_by_name
             FROM `licenses` l
             JOIN `products` p ON l.product_id = p.id
             LEFT JOIN `accounts` a ON l.created_by = a.id
             WHERE l.owner_id = ?
             ORDER BY l.created_at DESC",
            [$userId]
        );

        foreach ($licenses as &$license) {
            $license['hwids'] = array_column(self::getHwids($license['id']), 'hwid');
            $license['device_names'] = [];
            $hwids = self::getHwids($license['id']);
            foreach ($hwids as $h) {
                if ($h['hostname']) $license['device_names'][$h['hwid']] = $h['hostname'];
            }
            $license['key'] = $license['license_key'];
            $license['expiry'] = Utils::toIso8601($license['expiry']);
        }

        return $licenses;
    }

    /**
     * Get all licenses with full data
     */
    public static function getAll(): array
    {
        $licenses = Database::query(
            "SELECT l.*, p.product_id as module, p.name as module_name,
                    a.username as created_by_name,
                    o.username as owner_name
             FROM `licenses` l
             JOIN `products` p ON l.product_id = p.id
             LEFT JOIN `accounts` a ON l.created_by = a.id
             LEFT JOIN `accounts` o ON l.owner_id = o.id
             ORDER BY l.created_at DESC"
        );

        // Add HWIDs and logs to each license
        foreach ($licenses as &$license) {
            $license['hwids'] = array_column(self::getHwids($license['id']), 'hwid');
            $license['device_names'] = [];
            $license['gpu_infos'] = [];

            $hwids = self::getHwids($license['id']);
            foreach ($hwids as $h) {
                if ($h['hostname']) {
                    $license['device_names'][$h['hwid']] = $h['hostname'];
                }
                if (!empty($h['gpu_info'])) {
                    $license['gpu_infos'][$h['hwid']] = $h['gpu_info'];
                }
            }

            $license['logs'] = LicenseLog::get($license['id']);
            $license['key'] = $license['license_key'];

            // Format dates
            $license['expiry'] = Utils::toIso8601($license['expiry']);
            $license['created_at'] = Utils::toIso8601($license['created_at']);
        }

        return $licenses;
    }

    /**
     * Get HWIDs registered to a license
     *
     * @param int $licenseId
     * @return array
     */
    public static function getHwids(int $licenseId): array
    {
        return Database::query(
            "SELECT * FROM `hwid_locks` WHERE `license_id` = ?",
            [$licenseId]
        );
    }

    /**
     * Register HWID to license
     *
     * @param int $licenseId
     * @param string $hwid
     * @param string|null $hostname
     */
    public static function registerHwid(int $licenseId, string $hwid, ?string $hostname = null, ?string $gpuInfo = null): void
    {
        Database::execute(
            "INSERT INTO `hwid_locks` (`license_id`, `hwid`, `hostname`, `gpu_info`)
             VALUES (?, ?, ?, ?)
             ON DUPLICATE KEY UPDATE `hostname` = VALUES(`hostname`), `gpu_info` = VALUES(`gpu_info`), `last_seen` = NOW()",
            [$licenseId, $hwid, $hostname, $gpuInfo]
        );
    }

    /**
     * Update HWID info
     *
     * @param int $licenseId
     * @param string $hwid
     * @param string|null $hostname
     */
    public static function updateHwid(int $licenseId, string $hwid, ?string $hostname = null, ?string $gpuInfo = null): void
    {
        Database::execute(
            "UPDATE `hwid_locks`
             SET `hostname` = COALESCE(?, `hostname`), 
                 `gpu_info` = COALESCE(?, `gpu_info`), 
                 `last_seen` = NOW()
             WHERE `license_id` = ? AND `hwid` = ?",
            [$hostname, $gpuInfo, $licenseId, $hwid]
        );
    }

    /**
     * Update license status
     *
     * @param int $licenseId
     * @param string $status
     */
    public static function updateStatus(int $licenseId, string $status): void
    {
        Database::execute(
            "UPDATE `licenses` SET `status` = ? WHERE `id` = ?",
            [$status, $licenseId]
        );
    }

    /**
     * Edit license properties
     *
     * @param string $key License key
     * @param array $data Data to update (hwid_limit, expiry, status)
     * @param array $admin Admin performing the action
     * @return array
     */
    public static function edit(string $key, array $data, array $admin): array
    {
        // Check permissions
        if (!Auth::hasRole($admin, ROLE_HIGH_ADMIN)) {
            return ['success' => false, 'error' => 'Permission denied', 'code' => 403];
        }

        $license = self::getByKey($key);
        if (!$license) {
            return ['success' => false, 'error' => 'License not found', 'code' => 404];
        }

        $updates = [];
        $params = [];
        $changes = [];

        if (isset($data['hwid_limit'])) {
            $hwidLimit = (int)$data['hwid_limit'];
            if ($hwidLimit < 1) {
                return ['success' => false, 'error' => 'HWID limit must be at least 1', 'code' => 400];
            }
            $updates[] = '`hwid_limit` = ?';
            $params[] = $hwidLimit;
            $changes[] = "hwid_limit: {$license['hwid_limit']} -> $hwidLimit";
        }

        if (isset($data['expiry'])) {
            try {
                $date = new DateTime($data['expiry']);
                if ($date->format('Y') > 9999) {
                    $expiry = '9999-12-31 23:59:59';
                } else {
                    $expiry = $date->format('Y-m-d H:i:s');
                }
                $updates[] = '`expiry` = ?';
                $params[] = $expiry;
                $changes[] = "expiry updated to $expiry";
            } catch (Exception $e) {
                // Ignore invalid date format or handle as error? 
                // Let's keep existing logic but with DateTime safety
            }
        }

        if (isset($data['status'])) {
            $validStatuses = ['New', 'Active', 'Expired', 'Disabled'];
            $status = ucfirst(strtolower($data['status'])); // Normalize input
            
            if (!in_array($status, $validStatuses)) {
                return ['success' => false, 'error' => 'Invalid status', 'code' => 400];
            }
            $updates[] = '`status` = ?';
            $params[] = $status;
            $changes[] = "status: {$license['status']} -> {$status}";
        }

        if (empty($updates)) {
            return ['success' => false, 'error' => 'No changes provided', 'code' => 400];
        }

        $params[] = $license['id'];
        $sql = "UPDATE `licenses` SET " . implode(', ', $updates) . " WHERE `id` = ?";

        Database::execute($sql, $params);

        $changeStr = implode(', ', $changes);
        LicenseLog::add($license['id'], "License edited by {$admin['username']}: $changeStr");
        SystemLog::log('License', 'Edit', "License $key edited: $changeStr", $admin['username']);

        return ['success' => true, 'message' => 'License updated'];
    }

    /**
     * Reset all HWIDs for a license
     *
     * @param string $key License key
     * @param array $admin Admin performing the action
     * @return array
     */
    public static function resetHwids(string $key, array $admin): array
    {
        if (!Auth::hasRole($admin, ROLE_HIGH_ADMIN)) {
            return ['success' => false, 'error' => 'Permission denied', 'code' => 403];
        }

        $license = self::getByKey($key);
        if (!$license) {
            return ['success' => false, 'error' => 'License not found', 'code' => 404];
        }

        // Get current HWIDs before deletion
        $hwids = self::getHwids($license['id']);
        $hwidCount = count($hwids);

        // Delete HWIDs
        Database::execute(
            "DELETE FROM `hwid_locks` WHERE `license_id` = ?",
            [$license['id']]
        );

        LicenseLog::add($license['id'], "HWIDs reset by {$admin['username']} ($hwidCount devices removed)");
        SystemLog::log('License', 'Reset', "License $key HWIDs reset ($hwidCount devices)", $admin['username']);

        return ['success' => true, 'message' => "Reset $hwidCount devices"];
    }

    /**
     * Delete a license
     *
     * @param string $key License key
     * @param array $admin Admin performing the action
     * @return array
     */
    public static function delete(string $key, array $admin): array
    {
        if (!Auth::hasRole($admin, ROLE_HIGH_ADMIN)) {
            return ['success' => false, 'error' => 'Permission denied', 'code' => 403];
        }

        $license = self::getByKey($key);
        if (!$license) {
            return ['success' => false, 'error' => 'License not found', 'code' => 404];
        }

        Database::execute("DELETE FROM `licenses` WHERE `id` = ?", [$license['id']]);

        SystemLog::log('License', 'Delete', "License deleted: $key", $admin['username']);

        return ['success' => true, 'message' => 'License deleted'];
    }

    /**
     * Get license statistics
     *
     * @return array
     */
    public static function getStats(): array
    {
        $stats = [];

        // Total licenses
        $result = Database::queryOne("SELECT COUNT(*) as count FROM `licenses`");
        $stats['total'] = (int)$result['count'];

        // Active licenses
        $result = Database::queryOne(
            "SELECT COUNT(*) as count FROM `licenses` WHERE `status` = 'Active'"
        );
        $stats['active'] = (int)$result['count'];

        // Expired licenses
        $result = Database::queryOne(
            "SELECT COUNT(*) as count FROM `licenses` WHERE `status` = 'Expired'"
        );
        $stats['expired'] = (int)$result['count'];

        // New licenses
        $result = Database::queryOne(
            "SELECT COUNT(*) as count FROM `licenses` WHERE `status` = 'New'"
        );
        $stats['new'] = (int)$result['count'];

        // Total registered devices
        $result = Database::queryOne("SELECT COUNT(*) as count FROM `hwid_locks`");
        $stats['total_devices'] = (int)$result['count'];

        return $stats;
    }


    /**
     * Check if license is claimed by a user
     */
    public static function isClaimed(string $key): bool
    {
        $license = self::getByKey($key);
        return $license && !empty($license['owner_id']);
    }

    public static function claim(string $key, int $id): bool
    {
        $license = self::getByKey($key);
        if (!$license) return false;
        
        // If already claimed by THIS user, return true
        if ($license['owner_id'] == $id) return true;
        
        // If claimed by anyone else
        if (!empty($license['owner_id'])) return false;

        Database::execute(
            "UPDATE `licenses` SET `owner_id` = ?, `status` = 'Active' WHERE `id` = ?",
            [$id, $license['id']]
        );

        LicenseLog::add($license['id'], "License claimed by account ID: $id");
        return true;
    }

    /**
     * Get configuration for a specific license
     */
    public static function getConfig(int $licenseId): ?array
    {
        $license = Database::queryOne("SELECT `config`, `bot_token` FROM `licenses` WHERE `id` = ?", [$licenseId]);
        if (!$license) return null;
        
        $config = json_decode($license['config'] ?? 'null', true) ?: [];
        $config['bot_token'] = $license['bot_token'];
        return $config;
    }

    /**
     * Update configuration for a specific license
     */
    public static function updateConfig(int $licenseId, array $config, array $admin): array
    {
        $botToken = $config['bot_token'] ?? null;
        unset($config['bot_token']); // Don't store token inside the JSON config blob
        
        Database::execute(
            "UPDATE `licenses` SET `config` = ?, `bot_token` = ? WHERE `id` = ?",
            [json_encode($config), $botToken, $licenseId]
        );
        
        LicenseLog::add($licenseId, "Configuration/Token updated by {$admin['username']}");
        return ['success' => true, 'message' => 'Configuration updated successfully'];
    }
}

/**
 * Authorized HWID Management
 */
class AuthorizedHwid
{
    /**
     * Register HWID in global registry
     *
     * @param string $hwid
     * @param int $moduleId
     * @param string|null $hostname
     */
    public static function register(string $hwid, int $moduleId, ?string $hostname = null, ?string $gpuInfo = null): void
    {
        Database::execute(
            "INSERT INTO `authorized_hwids` (`hwid`, `module_id`, `hostname`, `gpu_info`)
             VALUES (?, ?, ?, ?)
             ON DUPLICATE KEY UPDATE 
                `hostname` = COALESCE(?, `hostname`), 
                `gpu_info` = COALESCE(?, `gpu_info`), 
                `updated_at` = NOW()",
            [$hwid, $moduleId, $hostname, $gpuInfo, $hostname, $gpuInfo]
        );
    }

    /**
     * Get all authorized HWIDs
     *
     * @return array
     */
    public static function getAll(): array
    {
        return Database::query(
            "SELECT ah.*, p.product_id as bot_id, p.name as module_name
             FROM `authorized_hwids` ah
             JOIN `products` p ON ah.module_id = p.id
             ORDER BY ah.created_at DESC"
        );
    }

    /**
     * Check if HWID is authorized for module
     *
     * @param string $hwid
     * @param string $moduleId
     * @return bool
     */
    public static function isAuthorized(string $hwid, string $productId): bool
    {
        $result = Database::queryOne(
            "SELECT 1 FROM `authorized_hwids` ah
             JOIN `products` p ON ah.module_id = p.id
             WHERE ah.hwid = ? AND p.product_id = ?
             LIMIT 1",
            [$hwid, $productId]
        );
        return $result !== null;
    }

    /**
     * Remove HWID authorization
     *
     * @param string $hwid
     * @param int $moduleId
     */
    public static function remove(string $hwid, int $moduleId): void
    {
        Database::execute(
            "DELETE FROM `authorized_hwids` WHERE `hwid` = ? AND `module_id` = ?",
            [$hwid, $moduleId]
        );
    }
}
