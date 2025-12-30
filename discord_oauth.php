<?php
/**
 * Discord OAuth Handler
 * 
 * Handles Discord OAuth2 authentication flow
 */

// Prevent direct access
if (!defined('LICENSE_SERVER')) {
    http_response_code(403);
    exit('Direct access not allowed');
}

class DiscordOAuth
{
    private const API_ENDPOINT = 'https://discord.com/api/v10';
    private const OAUTH_ENDPOINT = 'https://discord.com/api/oauth2';
    
    /**
     * Generate Discord OAuth authorization URL
     * 
     * @param string|null $state Optional state parameter for CSRF protection
     * @return string Authorization URL
     */
    public static function getAuthorizationUrl(?string $state = null): string
    {
        if ($state === null) {
            $state = bin2hex(random_bytes(16));
            $_SESSION['discord_oauth_state'] = $state;
        }
        
        $params = [
            'client_id' => DISCORD_CLIENT_ID,
            'redirect_uri' => DISCORD_REDIRECT_URI,
            'response_type' => 'code',
            'scope' => implode(' ', DISCORD_OAUTH_SCOPES),
            'state' => $state
        ];
        
        return self::OAUTH_ENDPOINT . '/authorize?' . http_build_query($params);
    }
    
    /**
     * Exchange authorization code for access token
     * 
     * @param string $code Authorization code from Discord
     * @return array|null Token data or null on failure
     */
    public static function exchangeCode(string $code): ?array
    {
        $data = [
            'client_id' => DISCORD_CLIENT_ID,
            'client_secret' => DISCORD_CLIENT_SECRET,
            'grant_type' => 'authorization_code',
            'code' => $code,
            'redirect_uri' => DISCORD_REDIRECT_URI
        ];
        
        $logFile = __DIR__ . '/debug_oauth.log';
        file_put_contents($logFile, date('Y-m-d H:i:s') . " | Token Req: code=" . substr($code, 0, 5) . "... | URI: " . DISCORD_REDIRECT_URI . "\n", FILE_APPEND);
        
        $ch = curl_init(self::OAUTH_ENDPOINT . '/token');
        curl_setopt_array($ch, [
            CURLOPT_POST => true,
            CURLOPT_POSTFIELDS => http_build_query($data),
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_HTTPHEADER => [
                'Content-Type: application/x-www-form-urlencoded'
            ]
        ]);
        
        $response = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);
        
        file_put_contents($logFile, date('Y-m-d H:i:s') . " | Token Res: HTTP $httpCode | Body: $response \n", FILE_APPEND);
        
        if ($httpCode !== 200) {
            return null;
        }
        
        return json_decode($response, true);
    }
    
    /**
     * Get Discord user information using access token
     * 
     * @param string $accessToken Access token from Discord
     * @return array|null User data or null on failure
     */
    public static function getUserInfo(string $accessToken): ?array
    {
        $ch = curl_init(self::API_ENDPOINT . '/users/@me');
        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_HTTPHEADER => [
                'Authorization: Bearer ' . $accessToken
            ]
        ]);
        
        $response = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);
        
        if ($httpCode !== 200) {
            return null;
        }
        
        return json_decode($response, true);
    }
    
    /**
     * Get Discord avatar URL
     * 
     * @param string $userId Discord user ID
     * @param string|null $avatarHash Avatar hash from Discord API
     * @return string Avatar URL
     */
    public static function getAvatarUrl(string $userId, ?string $avatarHash): string
    {
        if (empty($avatarHash)) {
            // Default Discord avatar
            $defaultAvatar = (int)$userId % 5;
            return "https://cdn.discordapp.com/embed/avatars/{$defaultAvatar}.png";
        }
        
        $extension = str_starts_with($avatarHash, 'a_') ? 'gif' : 'png';
        return "https://cdn.discordapp.com/avatars/{$userId}/{$avatarHash}.{$extension}";
    }
    
    /**
     * Link Discord account to user
     * 
     * @param array $discordUser Discord user data
     * @param int $accountId Account ID to link to
     * @return bool Success status
     */
    public static function linkToUser(array $discordUser, int $accountId): bool
    {
        // Check if Discord ID is already linked to another account
        $existing = Database::queryOne(
            "SELECT `account_id` FROM `discord_accounts` WHERE `discord_id` = ? AND `account_id` != ?",
            [$discordUser['id'], $accountId]
        );
        
        if ($existing) {
            return false; // Already linked to another account
        }
        
        $username = $discordUser['username'];
        if (isset($discordUser['discriminator']) && $discordUser['discriminator'] !== '0') {
            $username .= '#' . $discordUser['discriminator'];
        }
        
        $avatarUrl = self::getAvatarUrl($discordUser['id'], $discordUser['avatar'] ?? null);
        
        Database::execute(
            "INSERT INTO `discord_accounts` (`account_id`, `discord_id`, `discord_username`, `discord_avatar`, `linked_at`)
             VALUES (?, ?, ?, ?, NOW())
             ON DUPLICATE KEY UPDATE 
                `discord_username` = VALUES(`discord_username`),
                `discord_avatar` = VALUES(`discord_avatar`)",
            [$accountId, $discordUser['id'], $username, $avatarUrl]
        );
        
        return true;
    }
    
    /**
     * Find user by Discord ID
     * 
     * @param string $discordId Discord user ID
     * @return array|null User data from accounts table
     */
    public static function findUserByDiscordId(string $discordId): ?array
    {
        // Query linked account via discord_accounts table
        $user = Database::queryOne(
            "SELECT a.* 
             FROM `accounts` a
             JOIN `discord_accounts` da ON a.id = da.account_id
             WHERE da.discord_id = ?
             ORDER BY (a.status = 'Active') DESC, a.id ASC
             LIMIT 1",
            [$discordId]
        );
        
        if ($user) {
            unset($user['password']);
            file_put_contents(__DIR__ . '/debug_auth.log', date('H:i:s') . " | Found Account for $discordId: {$user['username']} ({$user['id']}) \n", FILE_APPEND);
            return $user;
        }
        
        file_put_contents(__DIR__ . '/debug_auth.log', date('H:i:s') . " | No account found for $discordId \n", FILE_APPEND);
        return null;
    }
    
    /**
     * Complete OAuth flow and return user info
     * 
     * @param string $code Authorization code
     * @param string|null $state State parameter for verification
     * @return array Result with 'success', 'discord_user', or 'error'
     */
    public static function handleCallback(string $code, ?string $state = null): array
    {
        // Verify state for CSRF protection
        if ($state !== null && isset($_SESSION['discord_oauth_state'])) {
            if ($state !== $_SESSION['discord_oauth_state']) {
                return ['success' => false, 'error' => 'Invalid state parameter'];
            }
            unset($_SESSION['discord_oauth_state']);
        }
        
        // Exchange code for token
        $tokenData = self::exchangeCode($code);
        if (!$tokenData || !isset($tokenData['access_token'])) {
            return ['success' => false, 'error' => 'Failed to exchange authorization code'];
        }
        
        // Get user info
        $discordUser = self::getUserInfo($tokenData['access_token']);
        if (!$discordUser) {
            return ['success' => false, 'error' => 'Failed to fetch user information'];
        }
        
        return [
            'success' => true,
            'discord_user' => $discordUser,
            'access_token' => $tokenData['access_token']
        ];
    }
}
