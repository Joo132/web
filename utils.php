<?php
/**
 * Utility Functions
 *
 * Common helper functions used throughout the application.
 */

// Prevent direct access
if (!defined('LICENSE_SERVER')) {
    http_response_code(403);
    exit('Direct access not allowed');
}

class Utils
{
    /**
     * Generate a license key in format XXXX-XXXX-XXXX-XXXX
     *
     * @return string
     */
    public static function generateLicenseKey(): string
    {
        $segments = [];
        $chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
        $charLen = strlen($chars);

        for ($i = 0; $i < LICENSE_KEY_SEGMENTS; $i++) {
            $segment = '';
            for ($j = 0; $j < LICENSE_KEY_SEGMENT_LENGTH; $j++) {
                $segment .= $chars[random_int(0, $charLen - 1)];
            }
            $segments[] = $segment;
        }

        return implode('-', $segments);
    }

    /**
     * Validate license key format
     *
     * @param string $key
     * @return bool
     */
    public static function isValidLicenseKeyFormat(string $key): bool
    {
        $pattern = '/^[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}$/';
        return (bool)preg_match($pattern, $key);
    }

    /**
     * Sanitize string input
     *
     * @param string $input
     * @param int $maxLength
     * @return string
     */
    public static function sanitize(string $input, int $maxLength = 255): string
    {
        $input = trim($input);
        $input = strip_tags($input);
        $input = htmlspecialchars($input, ENT_QUOTES, 'UTF-8');

        if (strlen($input) > $maxLength) {
            $input = substr($input, 0, $maxLength);
        }

        return $input;
    }

    /**
     * Validate HWID format (basic validation)
     *
     * @param string $hwid
     * @return bool
     */
    public static function isValidHwid(string $hwid): bool
    {
        // HWID should be alphanumeric and reasonable length
        if (strlen($hwid) < 8 || strlen($hwid) > 255) {
            return false;
        }

        return (bool)preg_match('/^[a-zA-Z0-9_\-:]+$/', $hwid);
    }

    /**
     * Generate module ID from name
     *
     * @param string $name
     * @return string
     */
    public static function generateModuleId(string $name): string
    {
        $id = strtolower(trim($name));
        $id = preg_replace('/[^a-z0-9]+/', '_', $id);
        $id = trim($id, '_');

        if (empty($id)) {
            $id = 'module_' . bin2hex(random_bytes(4));
        }

        return $id;
    }

    /**
     * Generate category ID from name
     *
     * @param string $name
     * @return string
     */
    public static function generateCategoryId(string $name): string
    {
        $id = strtolower(trim($name));
        $id = preg_replace('/[^a-z0-9]+/', '_', $id);
        $id = trim($id, '_');

        if (empty($id)) {
            $id = 'category_' . bin2hex(random_bytes(4));
        }

        return $id;
    }

    /**
     * Format date for display
     *
     * @param string $date MySQL datetime
     * @param string $format
     * @return string
     */
    public static function formatDate(string $date, string $format = 'Y-m-d H:i:s'): string
    {
        $timestamp = strtotime($date);
        return date($format, $timestamp);
    }

    /**
     * Format date as ISO 8601
     *
     * @param string $date
     * @return string
     */
    public static function toIso8601(string $date): string
    {
        $timestamp = strtotime($date);
        return date('c', $timestamp);
    }

    /**
     * Check if date is expired
     *
     * @param string $date
     * @return bool
     */
    public static function isExpired(string $date): bool
    {
        return strtotime($date) < time();
    }

    /**
     * Add days to current date
     *
     * @param int $days
     * @return string MySQL datetime format
     */
    public static function addDays(int $days): string
    {
        $date = new DateTime();
        $date->modify("+$days days");
        // Cap at Year 9999
        if ($date->format('Y') > 9999) {
            return '9999-12-31 23:59:59';
        }
        return $date->format('Y-m-d H:i:s');
    }

    /**
     * Get current datetime in MySQL format
     *
     * @return string
     */
    public static function now(): string
    {
        return date('Y-m-d H:i:s');
    }

    /**
     * Parse JSON request body
     *
     * @return array
     */
    public static function getJsonInput(): array
    {
        $input = file_get_contents('php://input');
        if (empty($input)) {
            return [];
        }

        $data = json_decode($input, true);
        if (json_last_error() !== JSON_ERROR_NONE) {
            return [];
        }

        return $data;
    }

    /**
     * Send JSON response
     *
     * @param array $data
     * @param int $statusCode
     */
    public static function jsonResponse(array $data, int $statusCode = 200): void
    {
        http_response_code($statusCode);
        header('Content-Type: application/json; charset=utf-8');
        echo json_encode($data, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
        exit;
    }

    /**
     * Send success response
     *
     * @param array $data Additional data to include
     * @param string|null $message Optional message
     */
    public static function success(array $data = [], ?string $message = null): void
    {
        $response = ['success' => true];

        if ($message !== null) {
            $response['message'] = $message;
        }

        $response = array_merge($response, $data);
        self::jsonResponse($response, 200);
    }

    /**
     * Send error response
     *
     * @param string $message Error message
     * @param int $statusCode HTTP status code
     * @param array $data Additional data
     */
    public static function error(string $message, int $statusCode = 400, array $data = []): void
    {
        $response = [
            'success' => false,
            'error' => $message
        ];

        $response = array_merge($response, $data);
        self::jsonResponse($response, $statusCode);
    }

    /**
     * Validate required fields in array
     *
     * @param array $data
     * @param array $required Required field names
     * @return array Missing fields
     */
    public static function validateRequired(array $data, array $required): array
    {
        $missing = [];
        foreach ($required as $field) {
            if (!isset($data[$field]) || (is_string($data[$field]) && trim($data[$field]) === '')) {
                $missing[] = $field;
            }
        }
        return $missing;
    }

    /**
     * Get value from array with default
     *
     * @param array $array
     * @param string $key
     * @param mixed $default
     * @return mixed
     */
    public static function get(array $array, string $key, $default = null)
    {
        return $array[$key] ?? $default;
    }

    /**
     * Setup CORS headers
     */
    public static function setupCors(): void
    {
        if (!CORS_ENABLED) {
            return;
        }

        $origin = $_SERVER['HTTP_ORIGIN'] ?? '*';

        // Check if origin is allowed
        if (!in_array('*', CORS_ALLOWED_ORIGINS) && !in_array($origin, CORS_ALLOWED_ORIGINS)) {
            return;
        }

        header("Access-Control-Allow-Origin: $origin");
        header('Access-Control-Allow-Methods: ' . implode(', ', CORS_ALLOWED_METHODS));
        header('Access-Control-Allow-Headers: ' . implode(', ', CORS_ALLOWED_HEADERS));
        header('Access-Control-Allow-Credentials: true');
        header('Access-Control-Max-Age: 86400');

        // Handle preflight request
        if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
            http_response_code(204);
            exit;
        }
    }

    /**
     * Get request method
     *
     * @return string
     */
    public static function getMethod(): string
    {
        return strtoupper($_SERVER['REQUEST_METHOD'] ?? 'GET');
    }

    /**
     * Get request path
     *
     * @return string
     */
    public static function getPath(): string
    {
        $path = $_SERVER['REQUEST_URI'] ?? '/';
        $path = parse_url($path, PHP_URL_PATH);
        $path = trim($path, '/');

        // Remove base directory if present
        $scriptDir = dirname($_SERVER['SCRIPT_NAME']);
        if ($scriptDir !== '/' && $scriptDir !== '\\') {
            $scriptDir = trim($scriptDir, '/');
            if (strpos($path, $scriptDir) === 0) {
                $path = substr($path, strlen($scriptDir));
                $path = ltrim($path, '/');
            }
        }

        return '/' . $path;
    }

    /**
     * Check if request is AJAX
     *
     * @return bool
     */
    public static function isAjax(): bool
    {
        return !empty($_SERVER['HTTP_X_REQUESTED_WITH']) &&
               strtolower($_SERVER['HTTP_X_REQUESTED_WITH']) === 'xmlhttprequest';
    }

    /**
     * Get client IP address
     *
     * @return string
     */
    public static function getClientIp(): string
    {
        $headers = [
            'HTTP_CF_CONNECTING_IP',
            'HTTP_X_FORWARDED_FOR',
            'HTTP_X_REAL_IP',
            'HTTP_CLIENT_IP',
            'REMOTE_ADDR'
        ];

        foreach ($headers as $header) {
            if (!empty($_SERVER[$header])) {
                $ip = $_SERVER[$header];
                if (strpos($ip, ',') !== false) {
                    $ips = explode(',', $ip);
                    $ip = trim($ips[0]);
                }
                if (filter_var($ip, FILTER_VALIDATE_IP)) {
                    return $ip;
                }
            }
        }

        return '0.0.0.0';
    }

    /**
     * Mask sensitive string (e.g., for token preview)
     *
     * @param string $str
     * @param int $showStart Number of chars to show at start
     * @param int $showEnd Number of chars to show at end
     * @return string
     */
    public static function maskString(string $str, int $showStart = 4, int $showEnd = 4): string
    {
        $length = strlen($str);
        if ($length <= $showStart + $showEnd) {
            return str_repeat('*', $length);
        }

        $start = substr($str, 0, $showStart);
        $end = substr($str, -$showEnd);
        $middleLength = $length - $showStart - $showEnd;

        return $start . str_repeat('*', min($middleLength, 10)) . $end;
    }
}
