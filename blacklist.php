<?php
/**
 * Blacklist Management
 *
 * Handles banning and unbanning of devices using HWID and GPU signatures.
 */

// Prevent direct access
if (!defined('LICENSE_SERVER')) {
    http_response_code(403);
    exit('Direct access not allowed');
}

class Blacklist
{
    /**
     * Add a device to the blacklist
     *
     * @param string $hwid Device HWID
     * @param string|null $gpuInfo GPU Information
     * @param string $reason Reason for ban
     * @param string $admin Admin who performed the ban
     * @return array
     */
    public static function add(string $hwid, ?string $gpuInfo, string $reason, string $admin): array
    {
        if (empty($hwid)) {
            return ['success' => false, 'error' => 'HWID is required'];
        }

        try {
            Database::execute(
                "INSERT INTO `blacklist` (`hwid`, `gpu_info`, `reason`, `banned_by`)
                 VALUES (?, ?, ?, ?)
                 ON DUPLICATE KEY UPDATE 
                    `gpu_info` = COALESCE(?, `gpu_info`),
                    `reason` = ?,
                    `banned_by` = ?,
                    `created_at` = NOW()",
                [$hwid, $gpuInfo, $reason, $admin, $gpuInfo, $reason, $admin]
            );

            SystemLog::log('Admin', 'Blacklist Add', "Banned HWID: $hwid" . ($gpuInfo ? " (GPU: $gpuInfo)" : ""), $admin);

            return ['success' => true];
        } catch (Exception $e) {
            return ['success' => false, 'error' => 'Failed to add to blacklist: ' . $e->getMessage()];
        }
    }

    /**
     * Remove a device from the blacklist
     *
     * @param string $hwid
     * @param string $admin
     * @return array
     */
    public static function remove(string $hwid, string $admin): array
    {
        try {
            Database::execute("DELETE FROM `blacklist` WHERE `hwid` = ?", [$hwid]);
            SystemLog::log('Admin', 'Blacklist Remove', "Unbanned HWID: $hwid", $admin);
            return ['success' => true];
        } catch (Exception $e) {
            return ['success' => false, 'error' => 'Failed to remove from blacklist'];
        }
    }

    /**
     * Get all blacklisted devices
     *
     * @return array
     */
    public static function getAll(): array
    {
        return Database::query("SELECT * FROM `blacklist` ORDER BY `created_at` DESC");
    }

    /**
     * Check if a device is blacklisted
     *
     * @param string $hwid
     * @param string|null $gpuInfo
     * @return bool
     */
    public static function isBanned(string $hwid, ?string $gpuInfo = null): bool
    {
        // Check HWID first (most specific)
        $result = Database::queryOne(
            "SELECT 1 FROM `blacklist` WHERE `hwid` = ? LIMIT 1",
            [$hwid]
        );
        if ($result) return true;

        // If HWID not banned, check GPU if provided
        if ($gpuInfo && $gpuInfo !== 'Unknown' && $gpuInfo !== 'N/A') {
            $result = Database::queryOne(
                "SELECT 1 FROM `blacklist` WHERE `gpu_info` = ? AND `gpu_info` IS NOT NULL LIMIT 1",
                [$gpuInfo]
            );
            if ($result) return true;
        }

        return false;
    }
}
