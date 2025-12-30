-- Database Masterpiece Redesign
-- Created for Broadcast System & Licensing Platform

SET SQL_MODE = "NO_AUTO_VALUE_ON_ZERO";
START TRANSACTION;
SET time_zone = "+00:00";

-- --------------------------------------------------------
-- 1. Identity & Access Management
-- --------------------------------------------------------

-- Accounts Table (Unified Admins & Clients)
CREATE TABLE `accounts` (
    `id` INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    `username` VARCHAR(50) UNIQUE NOT NULL,
    `password` VARCHAR(255) NOT NULL,
    `email` VARCHAR(255) NULL,
    `role` ENUM('Owner', 'High Admin', 'Admin', 'Client') DEFAULT 'Client',
    `status` ENUM('Active', 'Pending', 'Disabled') DEFAULT 'Active',
    `last_login` TIMESTAMP NULL,
    `last_ip` VARCHAR(45) NULL,
    `created_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    `updated_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX `idx_username` (`username`),
    INDEX `idx_role` (`role`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Discord Accounts Linkage
CREATE TABLE `discord_accounts` (
    `id` INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    `account_id` INT UNSIGNED NOT NULL,
    `discord_id` VARCHAR(50) UNIQUE NOT NULL,
    `discord_username` VARCHAR(100) NOT NULL,
    `discord_avatar` TEXT NULL,
    `linked_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (`account_id`) REFERENCES `accounts`(`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Session Management (Optional but good for tracking)
CREATE TABLE `sessions` (
    `id` VARCHAR(128) PRIMARY KEY,
    `account_id` INT UNSIGNED NOT NULL,
    `payload` TEXT NOT NULL,
    `last_activity` INT NOT NULL,
    FOREIGN KEY (`account_id`) REFERENCES `accounts`(`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- --------------------------------------------------------
-- 2. Products & Categories
-- --------------------------------------------------------

-- Categories
CREATE TABLE `categories` (
    `id` INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    `category_id` VARCHAR(50) UNIQUE NOT NULL,
    `name` VARCHAR(100) NOT NULL,
    `icon` VARCHAR(50) DEFAULT 'package',
    `created_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Products (replaces modules)
CREATE TABLE `products` (
    `id` INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    `product_id` VARCHAR(50) UNIQUE NOT NULL,
    `category_id` INT UNSIGNED NOT NULL,
    `name` VARCHAR(100) NOT NULL,
    `description` TEXT NULL,
    `version` VARCHAR(20) DEFAULT '1.0.0',
    `download_url` TEXT NULL,
    `bot_token` TEXT NULL,
    `config` JSON NULL,
    `status` ENUM('online', 'offline', 'maintenance') DEFAULT 'offline',
    `created_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (`category_id`) REFERENCES `categories`(`id`) ON DELETE CASCADE,
    INDEX `idx_product_id` (`product_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- --------------------------------------------------------
-- 3. Licensing & HWID Control
-- --------------------------------------------------------

-- Licenses
CREATE TABLE `licenses` (
    `id` INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    `license_key` VARCHAR(100) UNIQUE NOT NULL,
    `product_id` INT UNSIGNED NOT NULL,
    `owner_id` INT UNSIGNED NULL, -- NULL if not claimed yet
    `hwid_limit` INT DEFAULT 1,
    `expiry` TIMESTAMP NOT NULL,
    `status` ENUM('Active', 'Expired', 'Disabled', 'New') DEFAULT 'New',
    `config` JSON NULL,
    `bot_token` TEXT NULL,
    `created_by` INT UNSIGNED NOT NULL,
    `created_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (`product_id`) REFERENCES `products`(`id`) ON DELETE CASCADE,
    FOREIGN KEY (`owner_id`) REFERENCES `accounts`(`id`) ON DELETE SET NULL,
    FOREIGN KEY (`created_by`) REFERENCES `accounts`(`id`),
    INDEX `idx_license_key` (`license_key`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- HWID Locks
CREATE TABLE `hwid_locks` (
    `id` INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    `license_id` INT UNSIGNED NOT NULL,
    `hwid` VARCHAR(255) NOT NULL,
    `hostname` VARCHAR(255) NULL,
    `gpu_info` TEXT NULL,
    `last_seen` TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    `created_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE KEY `unique_license_hwid` (`license_id`, `hwid`),
    FOREIGN KEY (`license_id`) REFERENCES `licenses`(`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- --------------------------------------------------------
-- 4. Logging & Activity
-- --------------------------------------------------------

-- Activity Logs (Unified)
CREATE TABLE `activity_logs` (
    `id` INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    `category` VARCHAR(50) NOT NULL, -- 'Auth', 'License', 'Admin', 'Module'
    `action` VARCHAR(100) NOT NULL,   -- 'Login', 'Activation', 'Delete'
    `message` TEXT NOT NULL,
    `user` VARCHAR(100) NULL,        -- Username or 'System'
    `ip` VARCHAR(45) NULL,
    `created_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX `idx_category` (`category`),
    INDEX `idx_created_at` (`created_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- --------------------------------------------------------
-- 5. System Config & Security
-- --------------------------------------------------------

-- Blacklist
CREATE TABLE `blacklist` (
    `id` INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    `hwid` VARCHAR(255) UNIQUE NOT NULL,
    `gpu_info` TEXT NULL,
    `reason` TEXT NULL,
    `banned_by` VARCHAR(100) NULL,
    `created_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Bot Statistics (Transient Data)
CREATE TABLE `bots_data` (
    `id` INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    `product_id` INT UNSIGNED NOT NULL,
    `name` VARCHAR(100) NOT NULL,
    `server_count` INT DEFAULT 0,
    `servers` JSON NULL,
    `status` ENUM('online', 'offline') DEFAULT 'offline',
    `last_seen` TIMESTAMP NULL,
    `token_preview` VARCHAR(100) NULL,
    `access_key` VARCHAR(100) NULL,
    UNIQUE KEY `unique_product_bot` (`product_id`),
    FOREIGN KEY (`product_id`) REFERENCES `products`(`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Rate Limits
CREATE TABLE `rate_limits` (
    `ip_address` VARCHAR(45) NOT NULL,
    `endpoint` VARCHAR(100) NOT NULL,
    `requests` INT DEFAULT 1,
    `window_start` TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (`ip_address`, `endpoint`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Feedbacks
CREATE TABLE `feedbacks` (
    `id` INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    `name` VARCHAR(100) NULL,
    `message` TEXT NOT NULL,
    `rating` TINYINT DEFAULT 5,
    `product_id` INT UNSIGNED NULL,
    `ip_address` VARCHAR(45) NULL,
    `created_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (`product_id`) REFERENCES `products`(`id`) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- --------------------------------------------------------
-- Default Data
-- --------------------------------------------------------

-- Insert default Owner (Password: owner123)
INSERT INTO `accounts` (`id`, `username`, `password`, `role`, `status`) 
VALUES (1, 'Owner', '$2y$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi', 'Owner', 'Active');

-- Pre-link your Discord account to the Owner account
INSERT INTO `discord_accounts` (`account_id`, `discord_id`, `discord_username`, `linked_at`)
VALUES (1, '922205713206480927', 'Owner_Discord', NOW());

COMMIT;
