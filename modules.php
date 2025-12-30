<?php
/**
 * Module/Bot Management
 *
 * Handles module (bot) and category management.
 */

// Prevent direct access
if (!defined('LICENSE_SERVER')) {
    http_response_code(403);
    exit('Direct access not allowed');
}

class Category
{
    /**
     * Get category by ID
     *
     * @param int $id
     * @return array|null
     */
    public static function getById(int $id): ?array
    {
        return Database::queryOne(
            "SELECT * FROM `categories` WHERE `id` = ? LIMIT 1",
            [$id]
        );
    }

    /**
     * Get category by category_id string
     *
     * @param string $categoryId
     * @return array|null
     */
    public static function getByCategoryId(string $categoryId): ?array
    {
        return Database::queryOne(
            "SELECT * FROM `categories` WHERE `category_id` = ? LIMIT 1",
            [$categoryId]
        );
    }

    /**
     * Get or create category by name
     *
     * @param string $name
     * @return array
     */
    public static function getOrCreate(string $name): array
    {
        $categoryId = Utils::generateCategoryId($name);

        $existing = self::getByCategoryId($categoryId);
        if ($existing) {
            return $existing;
        }

        Database::execute(
            "INSERT INTO `categories` (`category_id`, `name`) VALUES (?, ?)",
            [$categoryId, $name]
        );

        return [
            'id' => (int)Database::lastInsertId(),
            'category_id' => $categoryId,
            'name' => $name
        ];
    }

    /**
     * Get all categories with their products
     *
     * @return array
     */
    public static function getAllWithModules(): array
    {
        $categories = Database::query(
            "SELECT * FROM `categories` ORDER BY `name` ASC"
        );
 
        foreach ($categories as &$category) {
            $category['bots'] = Database::query(
                "SELECT `id`, `id` as `num_id`, `product_id` as `module_id`, `product_id` as `mid`, `name`, `description`, `bot_token`, `status`, `version`, `download_url`
                 FROM `products`
                 WHERE `category_id` = ?
                 ORDER BY `name` ASC",
                [$category['id']]
            );
        }
 
        return $categories;
    }

    /**
     * Delete category if empty
     *
     * @param int $id
     * @return bool
     */
    public static function deleteIfEmpty(int $id): bool
    {
        // Check if category has products
        $result = Database::queryOne(
            "SELECT COUNT(*) as count FROM `products` WHERE `category_id` = ?",
            [$id]
        );

        if ((int)$result['count'] === 0) {
            Database::execute("DELETE FROM `categories` WHERE `id` = ?", [$id]);
            return true;
        }

        return false;
    }
}

class Product
{
    /**
     * Get product by database ID
     *
     * @param int $id
     * @return array|null
     */
    public static function getById(int $id): ?array
    {
        return Database::queryOne(
            "SELECT * FROM `products` WHERE `id` = ? LIMIT 1",
            [$id]
        );
    }

    /**
     * Get product by product_id string
     *
     * @param string $productId
     * @return array|null
     */
    public static function getByProductId(string $productId): ?array
    {
        // Try exact match on string product_id first
        $product = Database::queryOne(
            "SELECT * FROM `products` WHERE `product_id` = ? LIMIT 1",
            [$productId]
        );

        // Fallback to numeric ID if not found and input is numeric
        if (!$product && is_numeric($productId)) {
            $product = self::getById((int)$productId);
        }

        return $product;
    }

    // Keep Module for backward compatibility
    public static function getByModuleId(string $moduleId): ?array {
        return self::getByProductId($moduleId);
    }

    /**
     * Create a new product
     *
     * @param string $name Product name
     * @param string $description Product description
     * @param string $categoryName Category name (will create if not exists)
     * @param array $admin Admin creating the product
     * @return array
     */
    public static function create(
        string $name,
        string $description,
        string $categoryName,
        array $admin,
        ?string $botToken = null
    ): array {
        // Validate name
        $name = trim($name);
        if (strlen($name) < 2 || strlen($name) > 100) {
            return ['success' => false, 'error' => 'Product name must be 2-100 characters'];
        }

        // Generate product ID
        $productId = Utils::generateModuleId($name); // Reuse utility

        // Check if product exists
        if (self::getByProductId($productId)) {
            return ['success' => false, 'error' => 'Product already exists'];
        }

        // Get or create category
        $category = Category::getOrCreate($categoryName);

        try {
            Database::execute(
                "INSERT INTO `products` (`product_id`, `name`, `description`, `bot_token`, `category_id`)
                 VALUES (?, ?, ?, ?, ?)",
                [$productId, $name, $description, $botToken, $category['id']]
            );

            SystemLog::log(
                'Product',
                'Create',
                "Product created: $name ($productId) in category {$category['name']}",
                $admin['username']
            );

            return [
                'success' => true,
                'module_id' => $productId,
                'message' => 'Product created successfully'
            ];
        } catch (Exception $e) {
            return ['success' => false, 'error' => 'Failed to create product'];
        }
    }

    /**
     * Delete a product
     *
     * @param string $productId
     * @param array $admin Admin deleting the product
     * @return array
     */
    public static function delete(string $productId, array $admin): array
    {
        $product = self::getByProductId($productId);
        if (!$product) {
            return ['success' => false, 'error' => 'Product not found', 'code' => 404];
        }

        // Check if product has licenses
        $result = Database::queryOne(
            "SELECT COUNT(*) as count FROM `licenses` WHERE `product_id` = ?",
            [$product['id']]
        );

        if ((int)$result['count'] > 0) {
            return [
                'success' => false,
                'error' => 'Cannot delete product with existing licenses',
                'code' => 400
            ];
        }

        $categoryId = $product['category_id'];

        // Delete product
        Database::execute("DELETE FROM `products` WHERE `id` = ?", [$product['id']]);

        // Delete empty category
        Category::deleteIfEmpty($categoryId);

        // Delete bot data
        BotData::delete($product['id']);

        SystemLog::log(
            'Product',
            'Delete',
            "Product deleted: {$product['name']} ($productId)",
            $admin['username']
        );

        return ['success' => true, 'message' => 'Product deleted'];
    }

    /**
     * Update product status
     */
    public static function updateStatus(string $productId, string $status): void
    {
        Database::execute(
            "UPDATE `products` SET `status` = ? WHERE `product_id` = ?",
            [$status, $productId]
        );
    }

    /**
     * Get all products
     *
     * @return array
     */
    public static function getAll(): array
    {
        return Database::query(
            "SELECT p.*, c.name as category_name, c.category_id as category_id_str
             FROM `products` p
             JOIN `categories` c ON p.category_id = c.id
             ORDER BY c.name ASC, p.name ASC"
        );
    }

    /**
     * Get product statistics
     *
     * @return array
     */
    public static function getStats(): array
    {
        $stats = [];

        // Total products
        $result = Database::queryOne("SELECT COUNT(*) as count FROM `products`");
        $stats['total_modules'] = (int)$result['count'];

        // Total categories
        $result = Database::queryOne("SELECT COUNT(*) as count FROM `categories`");
        $stats['total_categories'] = (int)$result['count'];

        // Online products
        $result = Database::queryOne(
            "SELECT COUNT(*) as count FROM `products` WHERE `status` = 'online'"
        );
        $stats['online_modules'] = (int)$result['count'];

        return $stats;
    }

    /**
     * Edit product
     */
    public static function edit(string $productId, string $version, ?string $downloadUrl, array $admin, ?string $botToken = null): array
    {
        $product = self::getByProductId($productId);
        if (!$product) {
            return ['success' => false, 'error' => 'Product not found'];
        }

        // Keep existing token if not provided
        if ($botToken === null) {
            $botToken = $product['bot_token'];
        }

        Database::execute(
            "UPDATE `products` SET `version` = ?, `download_url` = ?, `bot_token` = ? WHERE `id` = ?",
            [$version, $downloadUrl, $botToken, $product['id']]
        );

        SystemLog::log(
            'Product',
            'Edit',
            "Product updated: {$product['name']} ($productId) - v$version",
            $admin['username']
        );

        return ['success' => true, 'message' => 'Product updated successfully'];
    }

    /**
     * Check for updates
     */
    public static function checkUpdate(string $productId, string $currentVersion): array
    {
        $product = self::getByProductId($productId);
        if (!$product) {
            return ['success' => false, 'error' => 'Product not found'];
        }

        $isUpdate = version_compare($product['version'], $currentVersion, '>');

        return [
            'success' => true,
            'update_available' => $isUpdate,
            'latest_version' => $product['version'],
            'download_url' => $product['download_url']
        ];
    }

    /**
     * Get product configuration
     */
    public static function getConfig(string $productId): ?array
    {
        $product = self::getByProductId($productId);
        if (!$product || !$product['config']) {
            return null;
        }
        return json_decode($product['config'], true);
    }

    /**
     * Update product configuration
     */
    public static function updateConfig(string $productId, array $config, array $admin): array
    {
        $product = self::getByProductId($productId);
        if (!$product) {
            return ['success' => false, 'error' => 'Product not found'];
        }

        // Extract bot_token if present in config (frontend sends it here)
        $botToken = $config['bot_token'] ?? $product['bot_token'];
        unset($config['bot_token']); // Don't store it inside the JSON blob

        Database::execute(
            "UPDATE `products` SET `config` = ?, `bot_token` = ? WHERE `id` = ?",
            [json_encode($config), $botToken, $product['id']]
        );

        SystemLog::log(
            'Product',
            'ConfigUpdate',
            "Configuration updated for product: {$product['name']} ($productId)",
            $admin['username']
        );

        return ['success' => true, 'message' => 'Configuration updated successfully'];
    }
}

// Add Module class as alias for Product for backward compatibility
class Module extends Product {}

class BotData
{
    /**
     * Report bot status
     *
     * @param string $botId Module ID
     * @param string $name Bot name
     * @param int $serverCount Number of servers
     * @param array $servers Server list
     * @param string|null $tokenPreview Partial token
     * @param string|null $accessKey Bot access key
     * @return array
     */
    public static function report(
        string $productId,
        string $name,
        int $serverCount,
        array $servers = [],
        ?string $tokenPreview = null,
        ?string $accessKey = null
    ): array {
        $product = Product::getByProductId($productId);
        if (!$product) {
            return ['success' => false, 'error' => 'Product not found'];
        }

        // Update product status to online
        Product::updateStatus($productId, 'online');

        // Upsert bot data
        Database::execute(
            "INSERT INTO `bots_data`
             (`product_id`, `name`, `server_count`, `servers`, `status`, `last_seen`, `token_preview`, `access_key`)
             VALUES (?, ?, ?, ?, 'online', NOW(), ?, ?)
             ON DUPLICATE KEY UPDATE
             `name` = VALUES(`name`),
             `server_count` = VALUES(`server_count`),
             `servers` = VALUES(`servers`),
             `status` = 'online',
             `last_seen` = NOW(),
             `token_preview` = COALESCE(VALUES(`token_preview`), `token_preview`),
             `access_key` = COALESCE(VALUES(`access_key`), `access_key`)",
            [
                $product['id'],
                $name,
                $serverCount,
                json_encode($servers),
                $tokenPreview,
                $accessKey
            ]
        );

        return ['success' => true];
    }

    /**
     * Get all bot data
     *
     * @return array
     */
    public static function getAll(): array
    {
        $data = Database::query(
            "SELECT bd.*, p.product_id as bot_id
             FROM `bots_data` bd
             JOIN `products` p ON bd.product_id = p.id
             ORDER BY bd.last_seen DESC"
        );

        $result = [];
        foreach ($data as $row) {
            $result[$row['bot_id']] = [
                'name' => $row['name'],
                'server_count' => (int)$row['server_count'],
                'servers' => json_decode($row['servers'] ?? '[]', true),
                'status' => $row['status'],
                'last_seen' => $row['last_seen'] ? Utils::toIso8601($row['last_seen']) : null,
                'token_preview' => $row['token_preview'],
                'access_key' => $row['access_key']
            ];
        }

        return $result;
    }

    /**
     * Get bot data by module ID
     *
     * @param string $botId
     * @return array|null
     */
    public static function get(string $productId): ?array
    {
        $data = Database::queryOne(
            "SELECT bd.*, p.product_id as bot_id
             FROM `bots_data` bd
             JOIN `products` p ON bd.product_id = p.id
             WHERE p.product_id = ?
             LIMIT 1",
            [$productId]
        );

        if (!$data) {
            return null;
        }

        return [
            'name' => $data['name'],
            'server_count' => (int)$data['server_count'],
            'servers' => json_decode($data['servers'] ?? '[]', true),
            'status' => $data['status'],
            'last_seen' => $data['last_seen'] ? Utils::toIso8601($data['last_seen']) : null,
            'token_preview' => $data['token_preview'],
            'access_key' => $data['access_key']
        ];
    }

    /**
     * Delete bot data for a module
     *
     * @param int $moduleId Database module ID
     */
    public static function delete(int $productId): void
    {
        Database::execute(
            "DELETE FROM `bots_data` WHERE `product_id` = ?",
            [$productId]
        );
    }

    /**
     * Mark offline products (not seen in last 5 minutes)
     */
    public static function markOfflineBots(): void
    {
        // Update bot data status
        Database::execute(
            "UPDATE `bots_data`
             SET `status` = 'offline'
             WHERE `last_seen` < DATE_SUB(NOW(), INTERVAL 5 MINUTE)
             AND `status` = 'online'"
        );

        // Update product status
        Database::execute(
            "UPDATE `products` p
             JOIN `bots_data` bd ON p.id = bd.product_id
             SET p.`status` = 'offline'
             WHERE bd.`status` = 'offline'"
        );
    }

    /**
     * Get total server count across all bots
     *
     * @return int
     */
    public static function getTotalServerCount(): int
    {
        $result = Database::queryOne(
            "SELECT COALESCE(SUM(`server_count`), 0) as total FROM `bots_data`"
        );
        return (int)$result['total'];
    }
}
