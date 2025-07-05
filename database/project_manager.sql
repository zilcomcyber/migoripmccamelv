-- phpMyAdmin SQL Dump
-- version 5.2.1
-- https://www.phpmyadmin.net/
--
-- Host: 127.0.0.1
-- Generation Time: Jul 04, 2025 at 11:49 PM
-- Server version: 10.4.32-MariaDB
-- PHP Version: 8.2.12

SET SQL_MODE = "NO_AUTO_VALUE_ON_ZERO";
START TRANSACTION;
SET time_zone = "+00:00";


/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8mb4 */;

--
-- Database: `project_manager`
--

-- --------------------------------------------------------

--
-- Table structure for table `admins`
--

CREATE TABLE `admins` (
  `id` int(11) NOT NULL,
  `name` varchar(100) NOT NULL,
  `email` varchar(100) NOT NULL,
  `password_hash` varchar(255) NOT NULL,
  `role` enum('super_admin','admin','viewer') DEFAULT 'admin',
  `is_active` tinyint(1) DEFAULT 1,
  `created_at` timestamp NOT NULL DEFAULT current_timestamp(),
  `last_login` timestamp NULL DEFAULT NULL,
  `last_ip` varchar(45) DEFAULT NULL,
  `permissions` longtext CHARACTER SET utf8mb4 COLLATE utf8mb4_bin DEFAULT NULL CHECK (json_valid(`permissions`)),
  `two_factor_secret` varchar(255) DEFAULT NULL,
  `last_password_change` datetime DEFAULT NULL,
  `password_reset_token` varchar(255) DEFAULT NULL,
  `token_expires` datetime DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Dumping data for table `admins`
--

INSERT INTO `admins` (`id`, `name`, `email`, `password_hash`, `role`, `is_active`, `created_at`, `last_login`, `last_ip`, `permissions`, `two_factor_secret`, `last_password_change`, `password_reset_token`, `token_expires`) VALUES
(1, 'MIGORI COUNTY', 'hamisi@gmail.com', '$argon2id$v=19$m=65536,t=4,p=1$Qm82Z0ltS3VveTcxVzl0Wg$K7VZMwiZmUSlev7Hezyp7kYkWDBOz4B21nBqfOVaUUY', 'super_admin', 1, '2025-05-29 15:20:11', '2025-07-04 19:27:43', '::1', NULL, NULL, NULL, NULL, NULL),
(2, 'WEST KANYAMKAGO', 'hamweed68@gmail.com', '$argon2id$v=19$m=65536,t=4,p=1$MVE3Q29yeVdCVzBDV0lnTQ$nmxJ24JzhC+SBgPrrGSF90m7ndkRefdInfsPRmQRYXc', 'admin', 1, '2025-06-13 07:00:04', '2025-07-04 20:05:46', '::1', NULL, NULL, NULL, NULL, NULL),
(3, 'Steve Odoyo', 'stevekyle106@gmail.com', '$argon2id$v=19$m=65536,t=4,p=1$cWpxTU9jbWVEVDQ2bVhWYQ$NTkZZWsvPsAwQyTPpoWcQBUrihbgaV3wOP53d4vWtco', 'admin', 1, '2025-07-02 11:51:08', NULL, NULL, NULL, NULL, NULL, NULL, NULL);

-- --------------------------------------------------------

--
-- Table structure for table `admin_activity_log`
--

CREATE TABLE `admin_activity_log` (
  `id` int(11) NOT NULL,
  `admin_id` int(11) NOT NULL,
  `activity_type` varchar(50) NOT NULL,
  `activity_description` text NOT NULL,
  `target_type` varchar(50) DEFAULT NULL,
  `target_id` int(11) DEFAULT NULL,
  `ip_address` varchar(45) DEFAULT NULL,
  `user_agent` text DEFAULT NULL,
  `additional_data` longtext CHARACTER SET utf8mb4 COLLATE utf8mb4_bin DEFAULT NULL CHECK (json_valid(`additional_data`)),
  `created_at` timestamp NOT NULL DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Dumping data for table `admin_activity_log`
--

INSERT INTO `admin_activity_log` (`id`, `admin_id`, `activity_type`, `activity_description`, `target_type`, `target_id`, `ip_address`, `user_agent`, `additional_data`, `created_at`) VALUES
(1, 1, 'dashboard_access', 'Accessed admin dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-06-29 22:08:52'),
(2, 1, 'csv_import_access', 'Accessed CSV import page', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-06-29 22:08:54'),
(3, 1, 'dashboard_access', 'Accessed admin dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-06-29 22:08:54'),
(4, 1, 'dashboard_access', 'Accessed admin dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-06-29 22:09:48'),
(5, 1, 'dashboard_access', 'Accessed admin dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-06-29 22:13:01'),
(6, 1, 'dashboard_access', 'Accessed admin dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-06-29 22:13:19'),
(7, 1, 'dashboard_access', 'Accessed admin dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-06-29 22:13:55'),
(8, 1, 'dashboard_access', 'Accessed admin dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-06-29 22:14:13'),
(9, 1, 'dashboard_access', 'Accessed admin dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-06-29 22:30:01'),
(10, 1, 'dashboard_access', 'Accessed admin dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-06-29 23:21:14'),
(11, 1, 'dashboard_access', 'Accessed admin dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-06-29 23:25:36'),
(12, 1, 'dashboard_access', 'Accessed admin dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-06-29 23:26:11'),
(13, 1, 'dashboard_access', 'Accessed admin dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-06-29 23:26:17'),
(14, 1, 'dashboard_access', 'Accessed admin dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-06-29 23:26:19'),
(15, 1, 'Added project step for project ID: 10', '1', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-06-29 23:26:39'),
(16, 1, 'dashboard_access', 'Accessed admin dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-06-29 23:26:39'),
(17, 1, 'Added project step for project ID: 10', '1', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-06-29 23:26:53'),
(18, 1, 'dashboard_access', 'Accessed admin dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-06-29 23:26:53'),
(19, 1, 'Added project step for project ID: 10', '1', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-06-29 23:27:06'),
(20, 1, 'dashboard_access', 'Accessed admin dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-06-29 23:27:06'),
(21, 1, 'Added project step for project ID: 10', '1', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-06-29 23:27:17'),
(22, 1, 'dashboard_access', 'Accessed admin dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-06-29 23:27:17'),
(23, 1, 'Updated project visibility to \'published\' for proj', '1', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-06-29 23:27:38'),
(24, 1, 'dashboard_access', 'Accessed admin dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-06-29 23:27:38'),
(25, 1, 'dashboard_access', 'Accessed admin dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-06-29 23:38:58'),
(26, 1, 'dashboard_access', 'Accessed admin dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-06-29 23:43:24'),
(27, 1, 'dashboard_access', 'Accessed admin dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-06-29 23:43:54'),
(28, 1, 'dashboard_access', 'Accessed admin dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-06-30 00:12:31'),
(29, 1, 'dashboard_access', 'Accessed admin dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-06-30 00:18:45'),
(30, 1, 'dashboard_access', 'Accessed admin dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-06-30 00:19:02'),
(31, 1, 'dashboard_access', 'Accessed admin dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-06-30 00:19:32'),
(32, 1, 'dashboard_access', 'Accessed admin dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-06-30 00:20:38'),
(33, 1, 'dashboard_access', 'Accessed admin dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-06-30 00:21:36'),
(34, 1, 'dashboard_access', 'Accessed admin dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-06-30 00:32:19'),
(35, 1, 'dashboard_access', 'Accessed admin dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-06-30 00:32:52'),
(36, 1, 'dashboard_access', 'Accessed admin dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-06-30 00:32:53'),
(37, 1, 'dashboard_access', 'Accessed admin dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-06-30 00:32:59'),
(38, 1, 'dashboard_access', 'Accessed admin dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-06-30 00:33:01'),
(39, 1, 'dashboard_access', 'Accessed admin dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-06-30 00:33:03'),
(40, 1, 'dashboard_access', 'Accessed admin dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-06-30 00:34:31'),
(41, 1, 'dashboard_access', 'Accessed admin dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-06-30 00:35:11'),
(42, 1, 'dashboard_access', 'Accessed admin dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-06-30 00:35:18'),
(43, 1, 'dashboard_access', 'Accessed admin dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-06-30 00:35:30'),
(44, 1, 'dashboard_access', 'Accessed admin dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-06-30 00:35:37'),
(45, 1, 'dashboard_access', 'Accessed admin dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-06-30 00:35:47'),
(46, 1, 'dashboard_access', 'Accessed admin dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-06-30 00:35:56'),
(47, 1, 'dashboard_access', 'Accessed admin dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-06-30 00:36:08'),
(48, 1, 'dashboard_access', 'Accessed admin dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-06-30 00:40:09'),
(49, 1, 'dashboard_access', 'Accessed admin dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-06-30 00:42:13'),
(50, 1, 'dashboard_access', 'Accessed admin dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-06-30 00:42:40'),
(51, 1, 'dashboard_access', 'Accessed admin dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-06-30 00:48:05'),
(52, 1, 'dashboard_access', 'Accessed admin dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-06-30 00:48:06'),
(53, 1, 'dashboard_access', 'Accessed admin dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-06-30 00:56:54'),
(54, 1, 'dashboard_access', 'Accessed admin dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-06-30 00:57:06'),
(55, 1, 'dashboard_access', 'Accessed admin dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-06-30 00:57:19'),
(56, 1, 'dashboard_access', 'Accessed admin dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-06-30 01:04:50'),
(57, 1, 'dashboard_access', 'Accessed admin dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-06-30 01:15:19'),
(58, 1, 'dashboard_access', 'Accessed admin dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-06-30 01:16:55'),
(59, 1, 'dashboard_access', 'Accessed admin dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-06-30 01:25:53'),
(60, 1, 'dashboard_access', 'Accessed admin dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-06-30 01:26:38'),
(61, 1, 'dashboard_access', 'Accessed admin dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-06-30 01:26:49'),
(62, 1, 'dashboard_access', 'Accessed admin dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-06-30 01:27:07'),
(63, 1, 'dashboard_access', 'Accessed admin dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-06-30 02:17:41'),
(64, 1, 'dashboard_access', 'Accessed admin dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-06-30 02:18:06'),
(65, 1, 'dashboard_access', 'Accessed admin dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-06-30 02:19:47'),
(66, 1, 'admin_dashboard_access', 'Accessed main admin dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-06-30 02:23:22'),
(67, 1, 'dashboard_access', 'Accessed admin dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-06-30 02:23:22'),
(68, 1, 'csv_import_access', 'Accessed CSV import page', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-06-30 02:24:59'),
(69, 1, 'dashboard_access', 'Accessed admin dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-06-30 02:24:59'),
(70, 1, 'dashboard_access', 'Accessed admin dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-06-30 02:26:18'),
(71, 1, 'csv_import_access', 'Accessed CSV import page', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-06-30 02:26:24'),
(72, 1, 'dashboard_access', 'Accessed admin dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-06-30 02:26:24'),
(73, 1, 'dashboard_access', 'Accessed admin dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-06-30 02:26:28'),
(74, 1, 'dashboard_access', 'Accessed admin dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-06-30 02:27:12'),
(75, 1, 'dashboard_access', 'Accessed admin dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-06-30 02:27:31'),
(76, 1, 'dashboard_access', 'Accessed admin dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-06-30 02:29:54'),
(77, 1, 'dashboard_access', 'Accessed admin dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-06-30 02:30:02'),
(78, 1, 'dashboard_access', 'Accessed admin dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-06-30 02:30:19'),
(79, 1, 'dashboard_access', 'Accessed admin dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-06-30 02:30:29'),
(80, 1, 'dashboard_access', 'Accessed admin dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-06-30 02:31:04'),
(81, 1, 'dashboard_access', 'Accessed admin dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-06-30 02:34:08'),
(82, 1, 'dashboard_access', 'Accessed admin dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-06-30 02:34:16'),
(83, 1, 'dashboard_access', 'Accessed admin dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-06-30 02:34:19'),
(84, 1, 'dashboard_access', 'Accessed admin dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-06-30 02:34:30'),
(85, 1, 'dashboard_access', 'Accessed admin dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-06-30 02:34:34'),
(86, 1, 'dashboard_access', 'Accessed admin dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-06-30 02:34:44'),
(87, 1, 'dashboard_access', 'Accessed admin dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-06-30 02:34:51'),
(88, 1, 'Updated step status for project ID: 10', '1', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-06-30 02:34:59'),
(89, 1, 'dashboard_access', 'Accessed admin dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-06-30 02:34:59'),
(90, 1, 'Updated step status for project ID: 10', '1', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-06-30 02:35:29'),
(91, 1, 'dashboard_access', 'Accessed admin dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-06-30 02:35:29'),
(92, 1, 'Updated step status for project ID: 10', '1', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-06-30 02:35:37'),
(93, 1, 'dashboard_access', 'Accessed admin dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-06-30 02:35:37'),
(94, 1, 'Updated step status for project ID: 10', '1', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-06-30 02:35:53'),
(95, 1, 'dashboard_access', 'Accessed admin dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-06-30 02:35:53'),
(96, 1, 'dashboard_access', 'Accessed admin dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-06-30 02:47:19'),
(97, 1, 'dashboard_access', 'Accessed admin dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-06-30 02:47:28'),
(98, 1, 'Updated project visibility to \'published\' for proj', '1', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-06-30 02:47:35'),
(99, 1, 'dashboard_access', 'Accessed admin dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-06-30 02:47:35'),
(100, 1, 'Added project step for project ID: 2', '1', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-06-30 02:47:50'),
(101, 1, 'dashboard_access', 'Accessed admin dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-06-30 02:47:50'),
(102, 1, 'Added project step for project ID: 2', '1', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-06-30 02:49:15'),
(103, 1, 'dashboard_access', 'Accessed admin dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-06-30 02:49:15'),
(104, 1, 'Updated step status for project ID: 2', '1', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-06-30 02:49:22'),
(105, 1, 'dashboard_access', 'Accessed admin dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-06-30 02:49:22'),
(106, 1, 'dashboard_access', 'Accessed admin dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-06-30 02:53:11'),
(107, 1, 'admin_dashboard_access', 'Accessed main admin dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-06-30 08:31:39'),
(108, 1, 'dashboard_access', 'Accessed admin dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-06-30 08:31:40'),
(109, 1, 'dashboard_access', 'Accessed admin dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-06-30 08:31:48'),
(110, 1, 'dashboard_access', 'Accessed admin dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-06-30 08:57:02'),
(111, 1, 'admin_dashboard_access', 'Accessed main admin dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-06-30 09:15:40'),
(112, 1, 'dashboard_access', 'Accessed admin dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-06-30 09:15:40'),
(113, 1, 'csv_import_access', 'Accessed CSV import page', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-06-30 09:15:43'),
(114, 1, 'dashboard_access', 'Accessed admin dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-06-30 09:15:43'),
(115, 1, 'dashboard_access', 'Accessed admin dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-06-30 09:15:44'),
(116, 1, 'dashboard_access', 'Accessed admin dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-06-30 09:15:45'),
(117, 1, 'dashboard_access', 'Accessed admin dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-06-30 09:15:46'),
(118, 1, 'dashboard_access', 'Accessed admin dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-06-30 09:15:47'),
(119, 1, 'dashboard_access', 'Accessed admin dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-06-30 09:15:49'),
(120, 1, 'dashboard_access', 'Accessed admin dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-06-30 09:15:57'),
(121, 1, 'dashboard_access', 'Accessed admin dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-06-30 09:16:05'),
(122, 1, 'dashboard_access', 'Accessed admin dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-06-30 09:16:16'),
(123, 1, 'dashboard_access', 'Accessed admin dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-06-30 09:16:39'),
(124, 1, 'dashboard_access', 'Accessed admin dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-06-30 09:16:44'),
(125, 1, 'admin_dashboard_access', 'Accessed main admin dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-06-30 09:16:58'),
(126, 1, 'dashboard_access', 'Accessed admin dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-06-30 09:16:58'),
(127, 1, 'csv_import_access', 'Accessed CSV import page', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-06-30 09:17:02'),
(128, 1, 'dashboard_access', 'Accessed admin dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-06-30 09:17:02'),
(129, 1, 'dashboard_access', 'Accessed admin dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-06-30 09:17:06'),
(130, 1, 'dashboard_access', 'Accessed admin dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-06-30 09:57:35'),
(131, 1, 'dashboard_access', 'Accessed admin dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-06-30 09:57:53'),
(132, 1, 'dashboard_access', 'Accessed admin dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-06-30 09:58:17'),
(133, 1, 'dashboard_access', 'Accessed admin dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-06-30 09:58:22'),
(134, 1, 'dashboard_access', 'Accessed admin dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-06-30 09:58:24'),
(135, 1, 'role_change', 'Changed role to viewer for admin ID: 2', 'admin', 2, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-06-30 09:58:27'),
(136, 1, 'dashboard_access', 'Accessed admin dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-06-30 09:58:27'),
(137, 1, 'admin_status_changed', 'Changed status for admin ID: 2', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-06-30 09:58:33'),
(138, 1, 'dashboard_access', 'Accessed admin dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-06-30 09:58:33'),
(139, 1, 'admin_status_changed', 'Changed status for admin ID: 2', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-06-30 09:58:38'),
(140, 1, 'dashboard_access', 'Accessed admin dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-06-30 09:58:38'),
(141, 1, 'role_change', 'Changed role to admin for admin ID: 2', 'admin', 2, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-06-30 09:58:43'),
(142, 1, 'dashboard_access', 'Accessed admin dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-06-30 09:58:43'),
(143, 1, 'admin_dashboard_access', 'Accessed main admin dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-06-30 16:11:48'),
(144, 1, 'admin_dashboard_access', 'Accessed main admin dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-06-30 16:13:22'),
(145, 1, 'admin_dashboard_access', 'Accessed main admin dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-06-30 16:17:43'),
(146, 1, 'admin_dashboard_access', 'Accessed main admin dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-06-30 16:22:34'),
(147, 2, 'admin_dashboard_access', 'Accessed main admin dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36 Edg/138.0.0.0', NULL, '2025-06-30 16:26:30'),
(148, 2, 'admin_dashboard_access', 'Accessed main admin dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36 Edg/138.0.0.0', NULL, '2025-06-30 16:28:10'),
(149, 2, 'admin_dashboard_access', 'Accessed main admin dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36 Edg/138.0.0.0', NULL, '2025-06-30 16:28:48'),
(150, 2, 'admin_dashboard_access', 'Accessed main admin dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36 Edg/138.0.0.0', NULL, '2025-06-30 16:28:59'),
(151, 1, 'admin_dashboard_access', 'Accessed main admin dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-06-30 16:46:02'),
(152, 2, 'admin_dashboard_access', 'Accessed main admin dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36 Edg/138.0.0.0', NULL, '2025-06-30 16:46:17'),
(153, 1, 'permissions_updated', 'Updated permissions for admin ID 2. Granted 1 permissions.', 'admin', 2, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"permissions\":[\"manage_feedback\"]}', '2025-06-30 16:47:41'),
(154, 2, 'admin_dashboard_access', 'Accessed main admin dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36 Edg/138.0.0.0', NULL, '2025-06-30 16:47:52'),
(155, 2, 'admin_dashboard_access', 'Accessed main admin dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36 Edg/138.0.0.0', NULL, '2025-06-30 16:47:58'),
(156, 2, 'admin_dashboard_access', 'Accessed main admin dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36 Edg/138.0.0.0', NULL, '2025-06-30 16:48:09'),
(157, 2, 'admin_dashboard_access', 'Accessed main admin dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36 Edg/138.0.0.0', NULL, '2025-06-30 16:51:36'),
(158, 2, 'admin_dashboard_access', 'Accessed main admin dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36 Edg/138.0.0.0', NULL, '2025-06-30 16:53:53'),
(159, 2, 'admin_dashboard_access', 'Accessed main admin dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36 Edg/138.0.0.0', NULL, '2025-06-30 16:54:10'),
(160, 2, 'admin_dashboard_access', 'Accessed main admin dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36 Edg/138.0.0.0', NULL, '2025-06-30 16:54:32'),
(161, 2, 'admin_dashboard_access', 'Accessed main admin dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36 Edg/138.0.0.0', NULL, '2025-06-30 16:54:33'),
(162, 2, 'admin_dashboard_access', 'Accessed main admin dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36 Edg/138.0.0.0', NULL, '2025-06-30 16:54:34'),
(163, 2, 'admin_dashboard_access', 'Accessed main admin dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36 Edg/138.0.0.0', NULL, '2025-06-30 16:54:35'),
(164, 1, 'permissions_updated', 'Updated permissions for admin ID 2. Granted 11 permissions.', 'admin', 2, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"permissions\":[\"dashboard_access\",\"profile_access\",\"view_projects\",\"create_projects\",\"edit_projects\",\"manage_projects\",\"manage_project_steps\",\"import_data\",\"manage_documents\",\"manage_budgets\",\"manage_feedback\"]}', '2025-06-30 16:58:26'),
(165, 2, 'admin_dashboard_access', 'Accessed main admin dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36 Edg/138.0.0.0', NULL, '2025-06-30 16:58:32'),
(166, 1, 'permissions_updated', 'Updated permissions for admin ID 2. Granted 11 permissions.', 'admin', 2, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"permissions\":[\"dashboard_access\",\"profile_access\",\"view_projects\",\"create_projects\",\"edit_projects\",\"manage_projects\",\"manage_project_steps\",\"import_data\",\"manage_documents\",\"manage_budgets\",\"manage_feedback\"]}', '2025-06-30 17:10:30'),
(167, 2, 'csv_import_access', 'Accessed CSV import page', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36 Edg/138.0.0.0', NULL, '2025-06-30 17:11:18'),
(168, 1, 'permissions_updated', 'Updated permissions for admin ID 2. Granted 10 permissions.', 'admin', 2, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"permissions\":[\"dashboard_access\",\"profile_access\",\"view_projects\",\"create_projects\",\"edit_projects\",\"manage_projects\",\"manage_project_steps\",\"manage_documents\",\"manage_budgets\",\"manage_feedback\"]}', '2025-06-30 17:12:09'),
(169, 2, 'admin_dashboard_access', 'Accessed main admin dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36 Edg/138.0.0.0', NULL, '2025-06-30 17:18:32'),
(170, 1, 'permissions_updated', 'Updated permissions for admin ID 2. Granted 11 permissions.', 'admin', 2, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"permissions\":[\"dashboard_access\",\"profile_access\",\"view_projects\",\"create_projects\",\"edit_projects\",\"manage_projects\",\"manage_project_steps\",\"manage_documents\",\"manage_budgets\",\"manage_feedback\",\"view_reports\"]}', '2025-06-30 17:20:29'),
(171, 2, 'admin_dashboard_access', 'Accessed main admin dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36 Edg/138.0.0.0', NULL, '2025-06-30 17:20:36'),
(172, 2, 'admin_dashboard_access', 'Accessed main admin dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36 Edg/138.0.0.0', NULL, '2025-06-30 17:20:38'),
(173, 2, 'admin_dashboard_access', 'Accessed main admin dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36 Edg/138.0.0.0', NULL, '2025-06-30 17:20:43'),
(174, 2, 'admin_dashboard_access', 'Accessed main admin dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36 Edg/138.0.0.0', NULL, '2025-06-30 17:20:48'),
(175, 2, 'admin_dashboard_access', 'Accessed main admin dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36 Edg/138.0.0.0', NULL, '2025-06-30 17:20:50'),
(176, 2, 'admin_dashboard_access', 'Accessed main admin dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36 Edg/138.0.0.0', NULL, '2025-06-30 17:20:54'),
(177, 2, 'admin_dashboard_access', 'Accessed main admin dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36 Edg/138.0.0.0', NULL, '2025-06-30 17:21:12'),
(178, 2, 'admin_dashboard_access', 'Accessed main admin dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36 Edg/138.0.0.0', NULL, '2025-06-30 17:21:22'),
(179, 2, 'admin_dashboard_access', 'Accessed main admin dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36 Edg/138.0.0.0', NULL, '2025-06-30 17:22:04'),
(180, 2, 'admin_dashboard_access', 'Accessed main admin dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36 Edg/138.0.0.0', NULL, '2025-06-30 17:22:30'),
(181, 2, 'admin_dashboard_access', 'Accessed main admin dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36 Edg/138.0.0.0', NULL, '2025-06-30 17:22:31'),
(182, 2, 'admin_dashboard_access', 'Accessed main admin dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36 Edg/138.0.0.0', NULL, '2025-06-30 17:22:35'),
(183, 2, 'admin_dashboard_access', 'Accessed main admin dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36 Edg/138.0.0.0', NULL, '2025-06-30 17:23:14'),
(184, 2, 'admin_dashboard_access', 'Accessed main admin dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36 Edg/138.0.0.0', NULL, '2025-06-30 17:23:16'),
(185, 2, 'admin_dashboard_access', 'Accessed main admin dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36 Edg/138.0.0.0', NULL, '2025-06-30 17:23:17'),
(186, 2, 'admin_dashboard_access', 'Accessed main admin dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36 Edg/138.0.0.0', NULL, '2025-06-30 17:25:53'),
(187, 2, 'admin_dashboard_access', 'Accessed main admin dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36 Edg/138.0.0.0', NULL, '2025-06-30 17:25:59'),
(188, 1, 'permissions_updated', 'Updated permissions for admin ID 2. Granted 12 permissions.', 'admin', 2, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"permissions\":[\"dashboard_access\",\"profile_access\",\"view_projects\",\"create_projects\",\"edit_projects\",\"manage_projects\",\"manage_project_steps\",\"import_data\",\"manage_documents\",\"manage_budgets\",\"manage_feedback\",\"view_reports\"]}', '2025-06-30 17:26:21'),
(189, 1, 'csv_import_access', 'Accessed CSV import page', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-06-30 17:27:17'),
(190, 1, 'admin_dashboard_access', 'Accessed main admin dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-06-30 17:27:19'),
(191, 2, 'admin_dashboard_access', 'Accessed main admin dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36 Edg/138.0.0.0', NULL, '2025-06-30 17:45:34'),
(192, 2, 'admin_dashboard_access', 'Accessed main admin dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36 Edg/138.0.0.0', NULL, '2025-06-30 17:45:36'),
(193, 2, 'admin_dashboard_access', 'Accessed main admin dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36 Edg/138.0.0.0', NULL, '2025-06-30 17:45:37'),
(194, 2, 'admin_dashboard_access', 'Accessed main admin dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36 Edg/138.0.0.0', NULL, '2025-06-30 17:45:37'),
(195, 2, 'admin_dashboard_access', 'Accessed main admin dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36 Edg/138.0.0.0', NULL, '2025-06-30 17:45:37'),
(196, 2, 'admin_dashboard_access', 'Accessed main admin dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36 Edg/138.0.0.0', NULL, '2025-06-30 17:45:37'),
(197, 2, 'admin_dashboard_access', 'Accessed main admin dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36 Edg/138.0.0.0', NULL, '2025-06-30 17:45:37'),
(198, 2, 'admin_dashboard_access', 'Accessed main admin dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36 Edg/138.0.0.0', NULL, '2025-06-30 17:45:38'),
(199, 2, 'admin_dashboard_access', 'Accessed main admin dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36 Edg/138.0.0.0', NULL, '2025-06-30 17:45:38'),
(200, 2, 'admin_dashboard_access', 'Accessed main admin dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36 Edg/138.0.0.0', NULL, '2025-06-30 17:45:38'),
(201, 2, 'admin_dashboard_access', 'Accessed main admin dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36 Edg/138.0.0.0', NULL, '2025-06-30 17:45:38'),
(202, 2, 'csv_import_access', 'Accessed CSV import page', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36 Edg/138.0.0.0', NULL, '2025-06-30 17:45:40'),
(203, 2, 'admin_dashboard_access', 'Accessed main admin dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36 Edg/138.0.0.0', NULL, '2025-06-30 17:45:43'),
(204, 2, 'admin_dashboard_access', 'Accessed main admin dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36 Edg/138.0.0.0', NULL, '2025-06-30 17:45:48'),
(205, 2, 'admin_dashboard_access', 'Accessed main admin dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36 Edg/138.0.0.0', NULL, '2025-06-30 17:45:51'),
(206, 2, 'admin_dashboard_access', 'Accessed main admin dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36 Edg/138.0.0.0', NULL, '2025-06-30 17:45:55'),
(207, 2, 'admin_dashboard_access', 'Accessed main admin dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36 Edg/138.0.0.0', NULL, '2025-06-30 17:46:00'),
(208, 2, 'admin_dashboard_access', 'Accessed main admin dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36 Edg/138.0.0.0', NULL, '2025-06-30 17:46:06'),
(209, 2, 'admin_dashboard_access', 'Accessed main admin dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36 Edg/138.0.0.0', NULL, '2025-06-30 17:48:07'),
(210, 1, 'permissions_updated', 'Updated permissions for admin ID 2. Granted 11 permissions.', 'admin', 2, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"permissions\":[\"dashboard_access\",\"profile_access\",\"view_projects\",\"create_projects\",\"edit_projects\",\"manage_projects\",\"manage_project_steps\",\"import_data\",\"manage_documents\",\"manage_budgets\",\"manage_feedback\"]}', '2025-06-30 17:48:44'),
(211, 2, 'admin_dashboard_access', 'Accessed main admin dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36 Edg/138.0.0.0', NULL, '2025-06-30 17:48:51'),
(212, 1, 'permissions_updated', 'Updated permissions for admin ID 2. Granted 8 permissions.', 'admin', 2, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"permissions\":[\"dashboard_access\",\"profile_access\",\"view_projects\",\"create_projects\",\"edit_projects\",\"manage_projects\",\"manage_project_steps\",\"manage_feedback\"]}', '2025-06-30 17:49:25');
INSERT INTO `admin_activity_log` (`id`, `admin_id`, `activity_type`, `activity_description`, `target_type`, `target_id`, `ip_address`, `user_agent`, `additional_data`, `created_at`) VALUES
(213, 2, 'admin_dashboard_access', 'Accessed main admin dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36 Edg/138.0.0.0', NULL, '2025-06-30 17:49:31'),
(214, 1, 'permissions_updated', 'Updated permissions for admin ID 2. Granted 2 permissions.', 'admin', 2, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"permissions\":[\"dashboard_access\",\"profile_access\"]}', '2025-06-30 17:50:05'),
(215, 2, 'admin_dashboard_access', 'Accessed main admin dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36 Edg/138.0.0.0', NULL, '2025-06-30 17:50:11'),
(216, 1, 'dashboard_access', 'Accessed PMC analytics dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-06-30 19:37:23'),
(217, 1, 'csv_import_access', 'Accessed CSV import page', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-06-30 20:18:49'),
(218, 2, 'admin_dashboard_access', 'Accessed main admin dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-07-01 16:39:25'),
(219, 1, 'admin_dashboard_access', 'Accessed main admin dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-07-01 16:40:05'),
(220, 1, 'permissions_updated', 'Updated permissions for admin ID 2. Granted 3 permissions.', 'admin', 2, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"permissions\":[\"dashboard_access\",\"profile_access\",\"manage_feedback\"]}', '2025-07-01 16:40:33'),
(221, 2, 'admin_dashboard_access', 'Accessed main admin dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-07-01 16:40:57'),
(222, 2, 'admin_dashboard_access', 'Accessed main admin dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-07-01 16:41:01'),
(223, 2, 'admin_dashboard_access', 'Accessed main admin dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-07-01 16:41:05'),
(224, 2, 'admin_dashboard_access', 'Accessed main admin dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-07-01 18:52:48'),
(225, 2, 'admin_dashboard_access', 'Accessed main admin dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-07-01 18:52:50'),
(226, 2, 'dashboard_access', 'Accessed PMC analytics dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-07-01 19:01:28'),
(227, 2, 'admin_dashboard_access', 'Accessed main admin dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-07-01 19:01:41'),
(228, 2, 'admin_dashboard_access', 'Accessed main admin dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-07-01 19:17:35'),
(229, 1, 'admin_dashboard_access', 'Accessed main admin dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36 Edg/138.0.0.0', NULL, '2025-07-01 19:19:19'),
(230, 1, 'permissions_updated', 'Updated permissions for admin ID 2. Granted 15 permissions.', 'admin', 2, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36 Edg/138.0.0.0', '{\"permissions\":[\"profile_access\",\"view_projects\",\"create_projects\",\"edit_projects\",\"manage_projects\",\"manage_project_steps\",\"import_data\",\"manage_documents\",\"manage_budgets\",\"manage_feedback\",\"view_reports\",\"view_activity_logs\",\"manage_users\",\"manage_roles\",\"system_settings\"]}', '2025-07-01 19:20:11'),
(231, 2, 'admin_dashboard_access', 'Accessed main admin dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-07-01 19:20:25'),
(232, 2, 'csv_import_access', 'Accessed CSV import page', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-07-01 19:20:29'),
(233, 2, 'admin_dashboard_access', 'Accessed main admin dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-07-01 19:20:31'),
(234, 2, 'admin_dashboard_access', 'Accessed main admin dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-07-01 19:20:36'),
(235, 2, 'admin_dashboard_access', 'Accessed main admin dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-07-01 19:22:01'),
(236, 2, 'admin_dashboard_access', 'Accessed main admin dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-07-01 19:22:44'),
(237, 2, 'admin_dashboard_access', 'Accessed main admin dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-07-01 19:24:01'),
(238, 2, 'admin_dashboard_access', 'Accessed main admin dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-07-01 19:25:40'),
(239, 2, 'admin_dashboard_access', 'Accessed main admin dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-07-01 19:31:27'),
(240, 2, 'csv_import_access', 'Accessed CSV import page', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-07-01 19:31:31'),
(241, 2, 'csv_import_access', 'Accessed CSV import page', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-07-01 19:32:09'),
(242, 2, 'admin_dashboard_access', 'Accessed main admin dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-07-01 19:32:10'),
(243, 2, 'admin_dashboard_access', 'Accessed main admin dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-07-01 20:09:09'),
(244, 2, 'csv_import_access', 'Accessed CSV import page', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-07-01 20:09:16'),
(245, 1, 'admin_dashboard_access', 'Accessed main admin dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-07-01 20:18:34'),
(246, 1, 'csv_import_access', 'Accessed CSV import page', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-07-01 20:18:40'),
(247, 1, 'csv_import_access', 'Accessed CSV import page', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-07-01 20:20:41'),
(248, 2, 'admin_dashboard_access', 'Accessed main admin dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36 Edg/138.0.0.0', NULL, '2025-07-01 20:21:27'),
(249, 2, 'csv_import_access', 'Accessed CSV import page', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36 Edg/138.0.0.0', NULL, '2025-07-01 20:21:46'),
(250, 2, 'admin_dashboard_access', 'Accessed main admin dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36 Edg/138.0.0.0', NULL, '2025-07-01 20:22:43'),
(251, 2, 'admin_dashboard_access', 'Accessed main admin dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36 Edg/138.0.0.0', NULL, '2025-07-01 20:25:28'),
(252, 1, 'permissions_updated', 'Updated permissions for admin ID 2. Granted 8 permissions.', 'admin', 2, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"permissions\":[\"dashboard_access\",\"profile_access\",\"import_data\",\"manage_documents\",\"manage_budgets\",\"manage_feedback\",\"view_reports\",\"view_activity_logs\"]}', '2025-07-01 20:28:20'),
(253, 2, 'admin_dashboard_access', 'Accessed main admin dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36 Edg/138.0.0.0', NULL, '2025-07-01 20:28:32'),
(254, 2, 'activity_logs_access', 'Viewed activity logs page', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36 Edg/138.0.0.0', NULL, '2025-07-01 20:29:29'),
(255, 2, 'activity_logs_access', 'Viewed activity logs page', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36 Edg/138.0.0.0', NULL, '2025-07-01 20:29:31'),
(256, 2, 'activity_logs_access', 'Viewed activity logs page', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36 Edg/138.0.0.0', NULL, '2025-07-01 20:29:32'),
(257, 1, 'permissions_updated', 'Updated permissions for admin ID 2. Granted 7 permissions.', 'admin', 2, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"permissions\":[\"dashboard_access\",\"profile_access\",\"import_data\",\"manage_documents\",\"manage_budgets\",\"manage_feedback\",\"view_reports\"]}', '2025-07-01 20:29:54'),
(258, 2, 'dashboard_access', 'Accessed PMC analytics dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36 Edg/138.0.0.0', NULL, '2025-07-01 20:30:42'),
(259, 2, 'admin_dashboard_access', 'Accessed main admin dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36 Edg/138.0.0.0', NULL, '2025-07-01 20:30:49'),
(260, 2, 'admin_dashboard_access', 'Accessed main admin dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36 Edg/138.0.0.0', NULL, '2025-07-01 20:30:55'),
(261, 1, 'permissions_updated', 'Updated permissions for admin ID 2. Granted 6 permissions.', 'admin', 2, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"permissions\":[\"dashboard_access\",\"profile_access\",\"import_data\",\"manage_documents\",\"manage_budgets\",\"manage_feedback\"]}', '2025-07-01 20:31:42'),
(262, 1, 'permissions_updated', 'Updated permissions for admin ID 2. Granted 1 permissions.', 'admin', 2, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"permissions\":[\"manage_feedback\"]}', '2025-07-01 20:40:01'),
(263, 2, 'admin_dashboard_access', 'Accessed main admin dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36 Edg/138.0.0.0', NULL, '2025-07-01 20:41:52'),
(264, 2, 'admin_dashboard_access', 'Accessed main admin dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36 Edg/138.0.0.0', NULL, '2025-07-01 20:41:56'),
(265, 1, 'permissions_updated', 'Updated permissions for admin ID 2. Granted 1 permissions.', 'admin', 2, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"permissions\":[\"manage_feedback\"]}', '2025-07-01 20:44:48'),
(266, 1, 'permissions_updated', 'Updated permissions for admin ID 2. Granted 16 permissions.', 'admin', 2, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"permissions\":[\"dashboard_access\",\"profile_access\",\"view_projects\",\"create_projects\",\"edit_projects\",\"manage_projects\",\"manage_project_steps\",\"import_data\",\"manage_documents\",\"manage_budgets\",\"manage_feedback\",\"view_reports\",\"view_activity_logs\",\"manage_users\",\"manage_roles\",\"system_settings\"]}', '2025-07-01 20:45:43'),
(267, 1, 'permissions_updated', 'Updated permissions for admin ID 2. Granted 0 permissions.', 'admin', 2, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"permissions\":[]}', '2025-07-01 20:46:26'),
(268, 1, 'admin_dashboard_access', 'Accessed main admin dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-07-01 20:51:09'),
(269, 1, 'csv_import_access', 'Accessed CSV import page', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-07-01 20:51:11'),
(270, 1, 'admin_dashboard_access', 'Accessed main admin dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-07-01 21:21:16'),
(271, 1, 'csv_import_access', 'Accessed CSV import page', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-07-01 21:21:19'),
(272, 1, 'csv_import_access', 'Accessed CSV import page', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-07-01 21:22:17'),
(273, 1, 'admin_dashboard_access', 'Accessed main admin dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-07-01 21:24:57'),
(274, 1, 'csv_import_access', 'Accessed CSV import page', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-07-01 21:24:59'),
(275, 1, 'activity_logs_access', 'Viewed activity logs page', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-07-01 21:25:24'),
(276, 1, 'activity_logs_access', 'Viewed activity logs page', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-07-01 22:02:20'),
(277, 1, 'admin_dashboard_access', 'Accessed main admin dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-07-02 07:07:44'),
(278, 1, 'dashboard_access', 'Accessed PMC analytics dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-07-02 07:33:13'),
(279, 1, 'grievances_access', 'Accessed grievance management page', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-07-02 07:34:13'),
(280, 1, 'grievances_access', 'Accessed grievance management page', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-07-02 07:35:26'),
(281, 1, 'email_sent', 'Email sent to hamweed@gmail.com with subject: Response to Your Grievance - Makerero public ICT Lab', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-07-02 07:35:28'),
(282, 1, 'grievance_responded', 'Responded to grievance #2 for project: Makerero public ICT Lab', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-07-02 07:35:28'),
(283, 1, 'csv_import_access', 'Accessed CSV import page', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-07-02 07:40:57'),
(284, 1, 'pmc_reports_access', 'Accessed PMC reports page', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-07-02 07:42:00'),
(285, 1, 'document_manager_access', 'Accessed document manager', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-07-02 07:42:42'),
(286, 1, 'grievances_access', 'Accessed grievance management page', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-07-02 07:43:18'),
(287, 1, 'grievances_access', 'Accessed grievance management page', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-07-02 07:43:28'),
(288, 1, 'grievance_status_updated', 'Updated grievance #2 status to resolved', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-07-02 07:43:28'),
(289, 1, 'activity_logs_access', 'Viewed activity logs page', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-07-02 07:45:18'),
(290, 1, 'pmc_reports_access', 'Accessed PMC reports page', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-07-02 07:59:54'),
(291, 1, 'csv_import_access', 'Accessed CSV import page', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-07-02 08:00:49'),
(292, 1, 'document_manager_access', 'Accessed document manager', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-07-02 08:01:42'),
(293, 1, 'activity_logs_access', 'Viewed activity logs page', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-07-02 08:03:58'),
(294, 1, 'admin_dashboard_access', 'Accessed main admin dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-07-02 08:04:41'),
(295, 1, 'dashboard_access', 'Accessed PMC analytics dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-07-02 08:04:43'),
(296, 2, 'admin_dashboard_access', 'Accessed main admin dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36 Edg/138.0.0.0', NULL, '2025-07-02 08:05:19'),
(297, 2, 'dashboard_access', 'Accessed PMC analytics dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36 Edg/138.0.0.0', NULL, '2025-07-02 08:05:44'),
(298, 2, 'admin_dashboard_access', 'Accessed main admin dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36 Edg/138.0.0.0', NULL, '2025-07-02 08:06:03'),
(299, 1, 'permissions_updated', 'Updated permissions for admin ID 2. Granted 3 permissions.', 'admin', 2, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"permissions\":[\"dashboard_access\",\"create_projects\",\"view_projects\"]}', '2025-07-02 08:07:02'),
(300, 2, 'admin_dashboard_access', 'Accessed main admin dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36 Edg/138.0.0.0', NULL, '2025-07-02 08:07:14'),
(301, 2, 'admin_dashboard_access', 'Accessed main admin dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36 Edg/138.0.0.0', NULL, '2025-07-02 08:07:19'),
(302, 2, 'Project created: Kanyasa Irrigation Scheme', '2', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36 Edg/138.0.0.0', NULL, '2025-07-02 08:12:20'),
(303, 2, 'dashboard_access', 'Accessed PMC analytics dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36 Edg/138.0.0.0', NULL, '2025-07-02 08:28:39'),
(304, 2, 'Project created: Kanyasa Irrigation Scheme', '2', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36 Edg/138.0.0.0', NULL, '2025-07-02 08:36:46'),
(305, 1, 'admin_dashboard_access', 'Accessed main admin dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-07-02 08:57:27'),
(306, 1, 'admin_dashboard_access', 'Accessed main admin dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-07-02 10:02:57'),
(307, 1, 'dashboard_access', 'Accessed PMC analytics dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-07-02 10:03:01'),
(308, 1, 'csv_import_access', 'Accessed CSV import page', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-07-02 10:03:44'),
(309, 1, 'projects_page_access', 'Accessed projects management page', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-07-02 10:04:32'),
(310, 1, 'projects_page_access', 'Accessed projects management page', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-07-02 10:04:51'),
(311, 1, 'Updated project visibility to \'published\' for proj', '1', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-07-02 10:05:14'),
(312, 1, 'Added project step for project ID: 18', '1', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-07-02 10:05:24'),
(313, 1, 'Added project step for project ID: 18', '1', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-07-02 10:05:35'),
(314, 1, 'Added project step for project ID: 18', '1', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-07-02 10:05:44'),
(315, 1, 'Updated step status for project ID: 18', '1', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-07-02 10:05:50'),
(316, 1, 'projects_page_access', 'Accessed projects management page', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-07-02 10:06:02'),
(317, 2, 'admin_dashboard_access', 'Accessed main admin dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36 Edg/138.0.0.0', NULL, '2025-07-02 10:06:55'),
(318, 2, 'admin_dashboard_access', 'Accessed main admin dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36 Edg/138.0.0.0', NULL, '2025-07-02 10:07:02'),
(319, 2, 'projects_page_access', 'Accessed projects management page', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36 Edg/138.0.0.0', NULL, '2025-07-02 10:07:06'),
(320, 1, 'pmc_reports_access', 'Accessed PMC reports page', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-07-02 10:07:33'),
(321, 1, 'document_manager_access', 'Accessed document manager', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-07-02 10:07:38'),
(322, 1, 'permissions_updated', 'Updated permissions for admin ID 2. Granted 13 permissions.', 'admin', 2, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"permissions\":[\"dashboard_access\",\"profile_access\",\"create_projects\",\"view_projects\",\"edit_projects\",\"manage_projects\",\"import_data\",\"manage_project_steps\",\"manage_budgets\",\"view_reports\",\"manage_feedback\",\"manage_documents\",\"manage_users\"]}', '2025-07-02 10:09:50'),
(323, 1, 'permissions_updated', 'Updated permissions for admin ID 2. Granted 13 permissions.', 'admin', 2, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"permissions\":[\"dashboard_access\",\"profile_access\",\"create_projects\",\"view_projects\",\"edit_projects\",\"manage_projects\",\"import_data\",\"manage_project_steps\",\"manage_budgets\",\"view_reports\",\"manage_feedback\",\"manage_documents\",\"manage_users\"]}', '2025-07-02 10:20:51'),
(324, 1, 'permissions_updated', 'Updated permissions for admin ID 2. Granted 6 permissions.', 'admin', 2, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"permissions\":[\"dashboard_access\",\"profile_access\",\"create_projects\",\"view_projects\",\"edit_projects\",\"manage_projects\"]}', '2025-07-02 10:29:26'),
(325, 1, 'permissions_updated', 'Updated permissions for admin ID 2. Granted 0 permissions.', 'admin', 2, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"permissions\":[]}', '2025-07-02 10:29:37'),
(326, 2, 'dashboard_access', 'Accessed PMC analytics dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36 Edg/138.0.0.0', NULL, '2025-07-02 10:30:26'),
(327, 2, 'dashboard_access', 'Accessed PMC analytics dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36 Edg/138.0.0.0', NULL, '2025-07-02 10:30:28'),
(328, 1, 'permissions_updated', 'Updated permissions for admin ID 2. Granted 13 permissions.', 'admin', 2, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"permissions\":[\"dashboard_access\",\"profile_access\",\"create_projects\",\"view_projects\",\"edit_projects\",\"manage_projects\",\"import_data\",\"manage_project_steps\",\"manage_budgets\",\"view_reports\",\"manage_feedback\",\"manage_documents\",\"manage_users\"]}', '2025-07-02 10:31:14'),
(329, 2, 'dashboard_access', 'Accessed PMC analytics dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36 Edg/138.0.0.0', NULL, '2025-07-02 10:34:42'),
(330, 2, 'dashboard_access', 'Accessed PMC analytics dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36 Edg/138.0.0.0', NULL, '2025-07-02 10:34:44'),
(331, 2, 'dashboard_access', 'Accessed PMC analytics dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36 Edg/138.0.0.0', NULL, '2025-07-02 10:35:19'),
(332, 2, 'admin_dashboard_access', 'Accessed main admin dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36 Edg/138.0.0.0', NULL, '2025-07-02 10:35:25'),
(333, 1, 'permissions_updated', 'Updated permissions for admin ID 2. Granted 12 permissions.', 'admin', 2, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"permissions\":[\"dashboard_access\",\"profile_access\",\"create_projects\",\"view_projects\",\"edit_projects\",\"manage_projects\",\"import_data\",\"manage_project_steps\",\"manage_budgets\",\"view_reports\",\"manage_feedback\",\"manage_documents\"]}', '2025-07-02 11:04:05'),
(334, 2, 'admin_dashboard_access', 'Accessed main admin dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36 Edg/138.0.0.0', NULL, '2025-07-02 11:04:12'),
(335, 2, 'csv_import_access', 'Accessed CSV import page', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36 Edg/138.0.0.0', NULL, '2025-07-02 11:06:04'),
(336, 2, 'projects_page_access', 'Accessed projects management page', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36 Edg/138.0.0.0', NULL, '2025-07-02 11:06:12'),
(337, 2, 'pmc_reports_access', 'Accessed PMC reports page', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36 Edg/138.0.0.0', NULL, '2025-07-02 11:06:16'),
(338, 2, 'document_manager_access', 'Accessed document manager', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36 Edg/138.0.0.0', NULL, '2025-07-02 11:06:19'),
(339, 2, 'pmc_reports_access', 'Accessed PMC reports page', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36 Edg/138.0.0.0', NULL, '2025-07-02 11:06:33'),
(340, 2, 'projects_page_access', 'Accessed projects management page', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36 Edg/138.0.0.0', NULL, '2025-07-02 11:06:45'),
(341, 2, 'Updated step status for project ID: 18', '2', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36 Edg/138.0.0.0', NULL, '2025-07-02 11:07:19'),
(342, 2, 'Updated step status for project ID: 18', '2', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36 Edg/138.0.0.0', NULL, '2025-07-02 11:07:26'),
(343, 2, 'Project created: Kanyasa Irrigation Scheme 2', '2', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36 Edg/138.0.0.0', NULL, '2025-07-02 11:09:18'),
(344, 2, 'Updated project visibility to \'published\' for proj', '2', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36 Edg/138.0.0.0', NULL, '2025-07-02 11:09:35'),
(345, 2, 'Updated step status for project ID: 19', '2', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36 Edg/138.0.0.0', NULL, '2025-07-02 11:09:42'),
(346, 1, 'admin_created', 'Created new administrator: Steve Odoyo (stevekyle106@gmail.com) with role: admin', 'admin', 3, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"name\":\"Steve Odoyo\",\"email\":\"stevekyle106@gmail.com\",\"role\":\"admin\"}', '2025-07-02 11:51:08'),
(347, 1, 'permissions_updated', 'Updated permissions for admin ID 3. Granted 2 permissions.', 'admin', 3, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"permissions\":[\"dashboard_access\",\"profile_access\"]}', '2025-07-02 11:51:31'),
(348, 1, 'permissions_updated', 'Updated permissions for admin ID 3. Granted 1 permissions.', 'admin', 3, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"permissions\":[\"dashboard_access\"]}', '2025-07-02 11:53:45'),
(349, 1, 'permissions_updated', 'Updated permissions for admin ID 2. Granted 1 permissions.', 'admin', 2, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"permissions\":[\"dashboard_access\"]}', '2025-07-02 11:54:22'),
(350, 2, 'admin_dashboard_access', 'Accessed main admin dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36 Edg/138.0.0.0', NULL, '2025-07-02 11:54:41'),
(351, 2, 'admin_dashboard_access', 'Accessed main admin dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36 Edg/138.0.0.0', NULL, '2025-07-02 11:54:42'),
(352, 2, 'dashboard_access', 'Accessed PMC analytics dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36 Edg/138.0.0.0', NULL, '2025-07-02 11:55:11'),
(353, 1, 'permissions_updated', 'Updated permissions for admin ID 2. Granted 2 permissions.', 'admin', 2, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"permissions\":[\"dashboard_access\",\"manage_feedback\"]}', '2025-07-02 11:56:53'),
(354, 2, 'admin_dashboard_access', 'Accessed main admin dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36 Edg/138.0.0.0', NULL, '2025-07-02 12:44:10'),
(355, 2, 'dashboard_access', 'Accessed PMC analytics dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36 Edg/138.0.0.0', NULL, '2025-07-02 12:44:23'),
(356, 1, 'admin_dashboard_access', 'Accessed main admin dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-07-02 15:20:23'),
(357, 1, 'projects_page_access', 'Accessed projects management page', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-07-02 15:20:39'),
(358, 2, 'admin_dashboard_access', 'Accessed main admin dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36 Edg/138.0.0.0', NULL, '2025-07-02 15:22:53'),
(359, 2, 'dashboard_access', 'Accessed PMC analytics dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36 Edg/138.0.0.0', NULL, '2025-07-02 15:27:30'),
(360, 1, 'csv_import_access', 'Accessed CSV import page', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-07-02 15:31:13'),
(361, 1, 'admin_dashboard_access', 'Accessed main admin dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-07-02 15:31:27'),
(362, 1, 'admin_dashboard_access', 'Accessed main admin dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-07-02 15:39:38'),
(363, 1, 'admin_dashboard_access', 'Accessed main admin dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-07-02 15:41:11'),
(364, 1, 'admin_dashboard_access', 'Accessed main admin dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-07-02 15:46:54'),
(365, 1, 'admin_dashboard_access', 'Accessed main admin dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-07-02 15:51:09'),
(366, 1, 'admin_dashboard_access', 'Accessed main admin dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-07-02 15:53:24'),
(367, 1, 'admin_dashboard_access', 'Accessed main admin dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-07-02 16:00:06'),
(368, 1, 'admin_dashboard_access', 'Accessed main admin dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-07-02 16:00:22'),
(369, 1, 'admin_dashboard_access', 'Accessed main admin dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-07-02 16:05:56'),
(370, 1, 'dashboard_access', 'Accessed PMC analytics dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-07-02 16:06:43'),
(371, 1, 'admin_dashboard_access', 'Accessed main admin dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-07-02 16:06:47'),
(372, 1, 'admin_dashboard_access', 'Accessed main admin dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-07-02 16:07:42'),
(373, 2, 'admin_dashboard_access', 'Accessed main admin dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36 Edg/138.0.0.0', NULL, '2025-07-02 16:14:05'),
(374, 2, 'admin_dashboard_access', 'Accessed main admin dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36 Edg/138.0.0.0', NULL, '2025-07-02 16:14:42'),
(375, 2, 'admin_dashboard_access', 'Accessed main admin dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36 Edg/138.0.0.0', NULL, '2025-07-02 16:15:32'),
(376, 1, 'csv_import_access', 'Accessed CSV import page', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-07-02 16:15:45'),
(377, 1, 'projects_page_access', 'Accessed projects management page', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-07-02 16:16:38'),
(378, 1, 'projects_page_access', 'Accessed projects management page', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-07-02 16:24:16'),
(379, 1, 'projects_page_access', 'Accessed projects management page', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-07-02 16:24:57'),
(380, 1, 'projects_page_access', 'Accessed projects management page', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-07-02 16:25:04'),
(381, 1, 'projects_page_access', 'Accessed projects management page', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-07-02 16:25:11'),
(382, 1, 'projects_page_access', 'Accessed projects management page', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-07-02 16:25:18'),
(383, 1, 'projects_page_access', 'Accessed projects management page', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-07-02 16:25:23'),
(384, 1, 'projects_page_access', 'Accessed projects management page', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-07-02 16:25:28'),
(385, 1, 'projects_page_access', 'Accessed projects management page', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-07-02 16:25:34'),
(386, 1, 'admin_dashboard_access', 'Accessed main admin dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-07-02 16:27:14'),
(387, 1, 'projects_page_access', 'Accessed projects management page', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-07-02 16:27:36'),
(388, 1, 'projects_page_access', 'Accessed projects management page', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-07-02 16:27:45'),
(389, 1, 'projects_page_access', 'Accessed projects management page', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-07-02 16:27:51'),
(390, 1, 'projects_page_access', 'Accessed projects management page', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-07-02 16:28:02'),
(391, 1, 'csv_import_access', 'Accessed CSV import page', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-07-02 16:28:13'),
(392, 1, 'projects_page_access', 'Accessed projects management page', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-07-02 17:20:43'),
(393, 1, 'admin_dashboard_access', 'Accessed main admin dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-07-02 17:47:22'),
(394, 1, 'permissions_updated', 'Updated permissions for admin ID 2. Granted 13 permissions.', 'admin', 2, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"permissions\":[\"dashboard_access\",\"profile_access\",\"create_projects\",\"view_projects\",\"edit_projects\",\"manage_projects\",\"import_data\",\"manage_project_steps\",\"manage_budgets\",\"view_reports\",\"manage_feedback\",\"manage_documents\",\"manage_users\"]}', '2025-07-02 17:50:25'),
(395, 2, 'admin_dashboard_access', 'Accessed main admin dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36 Edg/138.0.0.0', NULL, '2025-07-02 17:50:58'),
(396, 2, 'csv_import_access', 'Accessed CSV import page', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36 Edg/138.0.0.0', NULL, '2025-07-02 17:51:26'),
(397, 2, 'projects_page_access', 'Accessed projects management page', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36 Edg/138.0.0.0', NULL, '2025-07-02 17:53:59'),
(398, 1, 'projects_page_access', 'Accessed projects management page', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-07-02 17:54:17'),
(399, 2, 'dashboard_access', 'Accessed PMC analytics dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36 Edg/138.0.0.0', NULL, '2025-07-02 17:55:00'),
(400, 2, 'projects_page_access', 'Accessed projects management page', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36 Edg/138.0.0.0', NULL, '2025-07-02 17:55:02'),
(401, 1, 'projects_page_access', 'Accessed projects management page', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-07-02 17:56:18'),
(402, 1, 'admin_dashboard_access', 'Accessed main admin dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-07-02 17:59:26'),
(403, 1, 'dashboard_access', 'Accessed PMC analytics dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-07-02 18:06:59'),
(404, 1, 'admin_dashboard_access', 'Accessed main admin dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-07-02 18:07:06'),
(405, 1, 'admin_dashboard_access', 'Accessed main admin dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-07-02 18:07:25'),
(406, 1, 'permissions_updated', 'Updated permissions for admin ID 2. Granted 3 permissions.', 'admin', 2, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"permissions\":[\"dashboard_access\",\"profile_access\",\"create_projects\"]}', '2025-07-02 18:09:20'),
(407, 2, 'admin_dashboard_access', 'Accessed main admin dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36 Edg/138.0.0.0', NULL, '2025-07-02 18:09:30'),
(408, 2, 'admin_dashboard_access', 'Accessed main admin dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36 Edg/138.0.0.0', NULL, '2025-07-02 18:09:32'),
(409, 2, 'admin_dashboard_access', 'Accessed main admin dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36 Edg/138.0.0.0', NULL, '2025-07-02 18:11:11');
INSERT INTO `admin_activity_log` (`id`, `admin_id`, `activity_type`, `activity_description`, `target_type`, `target_id`, `ip_address`, `user_agent`, `additional_data`, `created_at`) VALUES
(410, 1, 'admin_dashboard_access', 'Accessed main admin dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-07-02 18:12:11'),
(411, 2, 'dashboard_access', 'Accessed PMC analytics dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36 Edg/138.0.0.0', NULL, '2025-07-02 18:12:22'),
(412, 2, 'dashboard_access', 'Accessed PMC analytics dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36 Edg/138.0.0.0', NULL, '2025-07-02 18:12:26'),
(413, 2, 'dashboard_access', 'Accessed PMC analytics dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36 Edg/138.0.0.0', NULL, '2025-07-02 18:15:17'),
(414, 2, 'admin_dashboard_access', 'Accessed main admin dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36 Edg/138.0.0.0', NULL, '2025-07-02 18:15:21'),
(415, 1, 'permissions_updated', 'Updated permissions for admin ID 2. Granted 2 permissions.', 'admin', 2, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"permissions\":[\"dashboard_access\",\"profile_access\"]}', '2025-07-02 18:22:09'),
(416, 2, 'dashboard_access', 'Accessed PMC analytics dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36 Edg/138.0.0.0', NULL, '2025-07-02 18:56:04'),
(417, 2, 'dashboard_access', 'Accessed PMC analytics dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36 Edg/138.0.0.0', NULL, '2025-07-02 18:57:08'),
(418, 1, 'csv_import_access', 'Accessed CSV import page', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-07-02 19:28:50'),
(419, 1, 'admin_dashboard_access', 'Accessed main admin dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-07-02 20:02:40'),
(420, 1, 'admin_dashboard_access', 'Accessed main admin dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-07-02 20:03:07'),
(421, 1, 'admin_dashboard_access', 'Accessed main admin dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-07-02 20:05:21'),
(422, 1, 'admin_dashboard_access', 'Accessed main admin dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36 Edg/138.0.0.0', NULL, '2025-07-02 20:11:11'),
(423, 2, 'admin_dashboard_access', 'Accessed main admin dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-07-02 20:20:51'),
(424, 1, 'admin_dashboard_access', 'Accessed main admin dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-07-02 20:21:14'),
(425, 1, 'csv_import_access', 'Accessed CSV import page', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-07-02 20:21:20'),
(426, 1, 'csv_import_access', 'Accessed CSV import page', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-07-02 20:22:23'),
(427, 1, 'projects_page_access', 'Accessed projects management page', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-07-02 20:22:38'),
(428, 1, 'pmc_reports_access', 'Accessed PMC reports page', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-07-02 20:22:44'),
(429, 1, 'admin_dashboard_access', 'Accessed main admin dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36 Edg/138.0.0.0', NULL, '2025-07-02 21:52:09'),
(430, 1, 'csv_import_access', 'Accessed CSV import page', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36 Edg/138.0.0.0', NULL, '2025-07-02 21:52:12'),
(431, 1, 'admin_dashboard_access', 'Accessed main admin dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-07-02 23:20:36'),
(432, 1, 'csv_import_access', 'Accessed CSV import page', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-07-02 23:20:41'),
(433, 1, 'projects_page_access', 'Accessed projects management page', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-07-02 23:20:44'),
(434, 1, 'Project deleted: North Kamagambo Public Project', '1', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-07-02 23:20:54'),
(435, 1, 'projects_page_access', 'Accessed projects management page', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-07-02 23:20:54'),
(436, 1, 'csv_import_access', 'Accessed CSV import page', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-07-02 23:20:59'),
(437, 2, 'admin_dashboard_access', 'Accessed main admin dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36 Edg/138.0.0.0', NULL, '2025-07-02 23:22:07'),
(438, 1, 'permissions_updated', 'Updated permissions for admin ID 2. Granted 12 permissions.', 'admin', 2, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"permissions\":[\"dashboard_access\",\"profile_access\",\"create_projects\",\"view_projects\",\"edit_projects\",\"manage_projects\",\"import_data\",\"manage_project_steps\",\"manage_budgets\",\"view_reports\",\"manage_feedback\",\"manage_documents\"]}', '2025-07-02 23:22:39'),
(439, 2, 'admin_dashboard_access', 'Accessed main admin dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36 Edg/138.0.0.0', NULL, '2025-07-02 23:22:43'),
(440, 1, 'permissions_updated', 'Updated permissions for admin ID 2. Granted 3 permissions.', 'admin', 2, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"permissions\":[\"dashboard_access\",\"profile_access\",\"create_projects\"]}', '2025-07-02 23:23:19'),
(441, 2, 'admin_dashboard_access', 'Accessed main admin dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36 Edg/138.0.0.0', NULL, '2025-07-02 23:23:26'),
(442, 2, 'admin_dashboard_access', 'Accessed main admin dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36 Edg/138.0.0.0', NULL, '2025-07-02 23:23:28'),
(443, 2, 'admin_dashboard_access', 'Accessed main admin dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36 Edg/138.0.0.0', NULL, '2025-07-02 23:23:30'),
(444, 2, 'admin_dashboard_access', 'Accessed main admin dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36 Edg/138.0.0.0', NULL, '2025-07-02 23:23:58'),
(445, 1, 'permissions_updated', 'Updated permissions for admin ID 2. Granted 8 permissions.', 'admin', 2, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"permissions\":[\"dashboard_access\",\"profile_access\",\"create_projects\",\"view_projects\",\"edit_projects\",\"manage_projects\",\"import_data\",\"manage_project_steps\"]}', '2025-07-02 23:24:27'),
(446, 2, 'admin_dashboard_access', 'Accessed main admin dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36 Edg/138.0.0.0', NULL, '2025-07-02 23:24:31'),
(447, 2, 'projects_page_access', 'Accessed projects management page', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36 Edg/138.0.0.0', NULL, '2025-07-02 23:24:33'),
(448, 2, 'csv_import_access', 'Accessed CSV import page', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36 Edg/138.0.0.0', NULL, '2025-07-02 23:24:36'),
(449, 1, 'permissions_updated', 'Updated permissions for admin ID 2. Granted 1 permissions.', 'admin', 2, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"permissions\":[\"dashboard_access\"]}', '2025-07-02 23:25:28'),
(450, 2, 'dashboard_access', 'Accessed PMC analytics dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36 Edg/138.0.0.0', NULL, '2025-07-02 23:25:53'),
(451, 1, 'permissions_updated', 'Updated permissions for admin ID 2. Granted 2 permissions.', 'admin', 2, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"permissions\":[\"dashboard_access\",\"manage_roles\"]}', '2025-07-02 23:26:10'),
(452, 2, 'dashboard_access', 'Accessed PMC analytics dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36 Edg/138.0.0.0', NULL, '2025-07-02 23:26:18'),
(453, 2, 'admin_dashboard_access', 'Accessed main admin dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36 Edg/138.0.0.0', NULL, '2025-07-02 23:26:49'),
(454, 2, 'admin_dashboard_access', 'Accessed main admin dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36 Edg/138.0.0.0', NULL, '2025-07-02 23:27:02'),
(455, 1, 'permissions_updated', 'Updated permissions for admin ID 2. Granted 1 permissions.', 'admin', 2, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"permissions\":[\"dashboard_access\"]}', '2025-07-02 23:27:15'),
(456, 2, 'admin_dashboard_access', 'Accessed main admin dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36 Edg/138.0.0.0', NULL, '2025-07-02 23:27:21'),
(457, 2, 'admin_dashboard_access', 'Accessed main admin dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36 Edg/138.0.0.0', NULL, '2025-07-02 23:27:22'),
(458, 2, 'dashboard_access', 'Accessed PMC analytics dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36 Edg/138.0.0.0', NULL, '2025-07-02 23:27:35'),
(459, 2, 'admin_dashboard_access', 'Accessed main admin dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36 Edg/138.0.0.0', NULL, '2025-07-02 23:27:48'),
(460, 1, 'admin_dashboard_access', 'Accessed main admin dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-07-03 06:11:47'),
(461, 1, 'csv_import_access', 'Accessed CSV import page', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-07-03 06:12:38'),
(462, 1, 'Project created: Rongo stage', '1', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-07-03 06:19:54'),
(463, 1, 'Project updated: Rongo stage 2', '1', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-07-03 06:20:20'),
(464, 1, 'projects_page_access', 'Accessed projects management page', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-07-03 06:20:20'),
(465, 1, 'Updated project visibility to \'published\' for proj', '1', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-07-03 06:23:05'),
(466, 1, 'Updated step status for project ID: 21', '1', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-07-03 06:23:47'),
(467, 1, 'Updated step status for project ID: 21', '1', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-07-03 06:24:50'),
(468, 1, 'Updated step status for project ID: 21', '1', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-07-03 06:25:02'),
(469, 1, 'Updated step status for project ID: 21', '1', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-07-03 06:25:42'),
(470, 1, 'Updated step status for project ID: 21', '1', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-07-03 06:25:56'),
(471, 1, 'Updated step status for project ID: 21', '1', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-07-03 06:26:03'),
(472, 1, 'pmc_reports_access', 'Accessed PMC reports page', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-07-03 06:33:15'),
(473, 1, 'document_manager_access', 'Accessed document manager', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-07-03 06:33:40'),
(474, 1, 'document_manager_access', 'Accessed document manager', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-07-03 06:36:48'),
(475, 1, 'grievances_access', 'Accessed grievance management page', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-07-03 06:39:53'),
(476, 1, 'permissions_updated', 'Updated permissions for admin ID 2. Granted 12 permissions.', 'admin', 2, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"permissions\":[\"dashboard_access\",\"profile_access\",\"create_projects\",\"view_projects\",\"edit_projects\",\"manage_projects\",\"import_data\",\"manage_project_steps\",\"manage_budgets\",\"view_reports\",\"manage_feedback\",\"manage_documents\"]}', '2025-07-03 06:43:15'),
(477, 2, 'admin_dashboard_access', 'Accessed main admin dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-07-03 06:43:47'),
(478, 1, 'permissions_updated', 'Updated permissions for admin ID 2. Granted 1 permissions.', 'admin', 2, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"permissions\":[\"dashboard_access\"]}', '2025-07-03 06:48:04'),
(479, 2, 'admin_dashboard_access', 'Accessed main admin dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-07-03 06:48:57'),
(480, 1, 'permissions_updated', 'Updated permissions for admin ID 2. Granted 13 permissions.', 'admin', 2, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"permissions\":[\"dashboard_access\",\"profile_access\",\"create_projects\",\"view_projects\",\"edit_projects\",\"manage_projects\",\"import_data\",\"manage_project_steps\",\"manage_budgets\",\"view_reports\",\"manage_feedback\",\"manage_documents\",\"manage_users\"]}', '2025-07-03 06:50:05'),
(481, 2, 'admin_dashboard_access', 'Accessed main admin dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-07-03 06:50:14'),
(482, 2, 'csv_import_access', 'Accessed CSV import page', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-07-03 06:50:18'),
(483, 2, 'projects_page_access', 'Accessed projects management page', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-07-03 06:50:22'),
(484, 2, 'pmc_reports_access', 'Accessed PMC reports page', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-07-03 06:50:48'),
(485, 2, 'document_manager_access', 'Accessed document manager', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-07-03 06:50:54'),
(486, 2, 'admin_dashboard_access', 'Accessed main admin dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-07-03 06:52:00'),
(487, 1, 'activity_logs_access', 'Viewed activity logs page', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-07-03 06:52:25'),
(488, 1, 'activity_logs_access', 'Viewed activity logs page', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-07-03 06:54:19'),
(489, 1, 'activity_logs_access', 'Viewed activity logs page', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-07-03 06:54:40'),
(490, 1, 'activity_logs_access', 'Viewed activity logs page', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-07-03 06:54:57'),
(491, 1, 'dashboard_access', 'Accessed PMC analytics dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-07-03 06:56:16'),
(492, 1, 'admin_dashboard_access', 'Accessed main admin dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-07-03 09:35:01'),
(493, 1, 'projects_page_access', 'Accessed projects management page', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-07-03 09:36:03'),
(494, 1, 'Updated project step for project ID: 19', '1', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-07-03 09:43:00'),
(495, 1, 'admin_dashboard_access', 'Accessed main admin dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-07-03 09:56:43'),
(496, 1, 'admin_dashboard_access', 'Accessed main admin dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-07-03 15:41:44'),
(497, 1, 'admin_dashboard_access', 'Accessed main admin dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-07-03 15:45:06'),
(498, 1, 'admin_dashboard_access', 'Accessed main admin dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-07-03 15:46:57'),
(499, 1, 'admin_dashboard_access', 'Accessed main admin dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-07-03 15:50:15'),
(500, 1, 'admin_dashboard_access', 'Accessed main admin dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-07-03 15:55:45'),
(501, 1, 'csv_import_access', 'Accessed CSV import page', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-07-03 15:55:46'),
(502, 1, 'projects_page_access', 'Accessed projects management page', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-07-03 15:55:51'),
(503, 1, 'pmc_reports_access', 'Accessed PMC reports page', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-07-03 15:55:56'),
(504, 1, 'document_manager_access', 'Accessed document manager', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-07-03 15:55:58'),
(505, 1, 'grievances_access', 'Accessed grievance management page', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-07-03 15:56:06'),
(506, 1, 'grievances_access', 'Accessed grievance management page', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-07-03 15:56:27'),
(507, 1, 'email_sent', 'Email sent to steve@gmail.com with subject: Response to Your Grievance - Makerero public ICT Lab', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-07-03 15:56:29'),
(508, 1, 'grievance_responded', 'Responded to grievance #5 for project: Makerero public ICT Lab', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-07-03 15:56:29'),
(509, 1, 'permissions_updated', 'Updated permissions for admin ID 2. Granted 4 permissions.', 'admin', 2, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"permissions\":[\"dashboard_access\",\"profile_access\",\"create_projects\",\"manage_users\"]}', '2025-07-03 15:56:56'),
(510, 1, 'activity_logs_access', 'Viewed activity logs page', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-07-03 15:57:01'),
(511, 1, 'csv_import_access', 'Accessed CSV import page', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-07-03 16:10:43'),
(512, 1, 'csv_import_access', 'Accessed CSV import page', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-07-03 17:01:30'),
(513, 1, 'admin_dashboard_access', 'Accessed main admin dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-07-04 04:18:51'),
(514, 1, 'admin_dashboard_access', 'Accessed main admin dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-07-04 04:53:26'),
(515, 2, 'admin_dashboard_access', 'Accessed main admin dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-07-04 04:55:56'),
(516, 2, 'admin_dashboard_access', 'Accessed main admin dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-07-04 04:57:44'),
(517, 1, 'admin_dashboard_access', 'Accessed main admin dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-07-04 04:58:06'),
(518, 1, 'csv_import_access', 'Accessed CSV import page', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-07-04 04:58:10'),
(519, 1, 'admin_dashboard_access', 'Accessed main admin dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-07-04 04:58:12'),
(520, 1, 'permissions_updated', 'Updated permissions for admin ID 2. Granted 1 permissions.', 'admin', 2, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"permissions\":[\"dashboard_access\"]}', '2025-07-04 04:58:54'),
(521, 2, 'admin_dashboard_access', 'Accessed main admin dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-07-04 04:59:17'),
(522, 1, 'permissions_updated', 'Updated permissions for admin ID 2. Granted 12 permissions.', 'admin', 2, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"permissions\":[\"dashboard_access\",\"profile_access\",\"create_projects\",\"view_projects\",\"edit_projects\",\"manage_projects\",\"import_data\",\"manage_project_steps\",\"manage_budgets\",\"view_reports\",\"manage_feedback\",\"manage_documents\"]}', '2025-07-04 05:00:38'),
(523, 2, 'admin_dashboard_access', 'Accessed main admin dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-07-04 05:00:47'),
(524, 2, 'csv_import_access', 'Accessed CSV import page', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-07-04 05:00:49'),
(525, 2, 'projects_page_access', 'Accessed projects management page', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-07-04 05:01:26'),
(526, 2, 'Updated project visibility to \'published\' for proj', '2', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-07-04 05:01:38'),
(527, 2, 'Updated step status for project ID: 17', '2', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-07-04 05:01:48'),
(528, 2, 'pmc_reports_access', 'Accessed PMC reports page', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-07-04 05:02:36'),
(529, 1, 'admin_dashboard_access', 'Accessed main admin dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-07-04 18:07:06'),
(530, 1, 'admin_dashboard_access', 'Accessed main admin dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-07-04 18:08:01'),
(531, 1, 'admin_dashboard_access', 'Accessed main admin dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-07-04 18:08:16'),
(532, 1, 'admin_dashboard_access', 'Accessed main admin dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-07-04 18:08:38'),
(533, 1, 'csv_import_access', 'Accessed CSV import page', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-07-04 18:08:45'),
(534, 1, 'projects_page_access', 'Accessed projects management page', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-07-04 18:18:12'),
(535, 1, 'projects_page_access', 'Accessed projects management page', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-07-04 18:18:19'),
(536, 1, 'projects_page_access', 'Accessed projects management page', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-07-04 18:18:28'),
(537, 1, 'Project deleted: North Kamagambo Public Project', '1', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-07-04 18:18:35'),
(538, 1, 'projects_page_access', 'Accessed projects management page', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-07-04 18:18:35'),
(539, 1, 'Project deleted: Rongo stage 2', '1', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-07-04 18:18:40'),
(540, 1, 'projects_page_access', 'Accessed projects management page', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-07-04 18:18:40'),
(541, 1, 'Project deleted: Kanyasa Irrigation Scheme 2', '1', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-07-04 18:18:46'),
(542, 1, 'projects_page_access', 'Accessed projects management page', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-07-04 18:18:46'),
(543, 1, 'Project deleted: Kanyasa Irrigation Scheme', '1', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-07-04 18:18:52'),
(544, 1, 'projects_page_access', 'Accessed projects management page', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-07-04 18:18:52'),
(545, 1, 'Project deleted: Kanyasa Irrigation Scheme', '1', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-07-04 18:18:57'),
(546, 1, 'projects_page_access', 'Accessed projects management page', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-07-04 18:18:58'),
(547, 1, 'Project deleted: Rongo Bus stage Upgrade', '1', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-07-04 18:19:04'),
(548, 1, 'projects_page_access', 'Accessed projects management page', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-07-04 18:19:04'),
(549, 1, 'Project deleted: Central Kamagambo Adults school', '1', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-07-04 18:19:11'),
(550, 1, 'projects_page_access', 'Accessed projects management page', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-07-04 18:19:11'),
(551, 1, 'Project deleted: Migori-Isebania Road Improvement', '1', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-07-04 18:19:17'),
(552, 1, 'projects_page_access', 'Accessed projects management page', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-07-04 18:19:18'),
(553, 1, 'Project deleted: Central Sakwa police post constru', '1', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-07-04 18:19:23'),
(554, 1, 'projects_page_access', 'Accessed projects management page', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-07-04 18:19:23'),
(555, 1, 'Project deleted: South Sakwa Lands, Project', '1', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-07-04 18:19:29'),
(556, 1, 'projects_page_access', 'Accessed projects management page', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-07-04 18:19:29'),
(557, 1, 'Project deleted: Migori County Health Center Const', '1', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-07-04 18:19:35'),
(558, 1, 'projects_page_access', 'Accessed projects management page', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-07-04 18:19:35'),
(559, 1, 'Project deleted: Isibania Health Center Extension', '1', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-07-04 18:19:40'),
(560, 1, 'projects_page_access', 'Accessed projects management page', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-07-04 18:19:40'),
(561, 1, 'Project deleted: Construction of Koyieko secondary', '1', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-07-04 18:19:45'),
(562, 1, 'projects_page_access', 'Accessed projects management page', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-07-04 18:19:45'),
(563, 1, 'Project deleted: Makerero public ICT Lab', '1', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-07-04 18:19:51'),
(564, 1, 'projects_page_access', 'Accessed projects management page', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-07-04 18:19:51'),
(565, 1, 'Project deleted: West Kanyamkago Chicken butchery', '1', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-07-04 18:19:58'),
(566, 1, 'projects_page_access', 'Accessed projects management page', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-07-04 18:19:58'),
(567, 1, 'Project deleted: Suna Central Agriculture, Project', '1', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-07-04 18:20:05'),
(568, 1, 'projects_page_access', 'Accessed projects management page', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-07-04 18:20:05'),
(569, 1, 'Project deleted: West Kanyamkago Water Project', '1', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-07-04 18:20:28'),
(570, 1, 'projects_page_access', 'Accessed projects management page', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-07-04 18:20:28'),
(571, 1, 'Project deleted: God Jope Secondary school laborat', '1', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-07-04 18:20:35'),
(572, 1, 'projects_page_access', 'Accessed projects management page', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-07-04 18:20:35'),
(573, 1, 'Project deleted: Wiga Market construction', '1', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-07-04 18:20:41'),
(574, 1, 'projects_page_access', 'Accessed projects management page', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-07-04 18:20:41'),
(575, 1, 'admin_dashboard_access', 'Accessed main admin dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-07-04 18:20:45'),
(576, 1, 'csv_import_access', 'Accessed CSV import page', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-07-04 18:22:02'),
(577, 1, 'csv_import_access', 'Accessed CSV import page', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-07-04 18:28:52'),
(578, 1, 'projects_page_access', 'Accessed projects management page', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-07-04 18:29:11'),
(579, 1, 'projects_page_access', 'Accessed projects management page', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-07-04 18:31:21'),
(580, 1, 'Updated project visibility to \'published\' for proj', '1', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-07-04 18:31:31'),
(581, 1, 'Added project step for project ID: 22', '1', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-07-04 18:44:40'),
(582, 1, 'Updated step status for project ID: 22', '1', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-07-04 18:44:48'),
(583, 1, 'Project created: Awendo sewage', '1', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-07-04 18:59:22'),
(584, 1, 'projects_page_access', 'Accessed projects management page', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-07-04 18:59:35'),
(585, 1, 'transaction_added', 'Added new adjustment transaction for project ID 31', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-07-04 19:07:42'),
(586, 1, 'transaction_updated', 'Edited adjustment transaction for project ID 31', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-07-04 19:08:35'),
(587, 1, 'admin_dashboard_access', 'Accessed main admin dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-07-04 19:25:45'),
(588, 1, 'dashboard_access', 'Accessed PMC analytics dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-07-04 19:25:51'),
(589, 1, 'csv_import_access', 'Accessed CSV import page', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-07-04 19:26:09'),
(590, 1, 'admin_dashboard_access', 'Accessed main admin dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-07-04 19:27:14'),
(591, 1, 'admin_dashboard_access', 'Accessed main admin dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-07-04 19:27:43'),
(592, 1, 'projects_page_access', 'Accessed projects management page', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-07-04 19:28:11'),
(593, 1, 'csv_import_access', 'Accessed CSV import page', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-07-04 19:58:32'),
(594, 1, 'transaction_added', 'Added new disbursement transaction for project ID 22', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-07-04 20:02:26'),
(595, 1, 'transaction_updated', 'Edited disbursement transaction for project ID 22', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-07-04 20:03:39'),
(596, 2, 'admin_dashboard_access', 'Accessed main admin dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-07-04 20:05:46'),
(597, 2, 'projects_page_access', 'Accessed projects management page', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-07-04 20:06:18'),
(598, 2, 'csv_import_access', 'Accessed CSV import page', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-07-04 20:06:25'),
(599, 2, 'admin_dashboard_access', 'Accessed main admin dashboard', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-07-04 20:07:07'),
(600, 1, 'transaction_added', 'Added new adjustment transaction for project ID 22', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-07-04 20:20:14'),
(601, 1, 'transaction_deleted', 'Marked transaction ID 17 as deleted', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-07-04 20:26:53'),
(602, 1, 'transaction_added', 'Added new budget_increase transaction for project ID 22', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-07-04 20:58:15'),
(603, 1, 'transaction_added', 'Added new expenditure transaction for project ID 22', NULL, NULL, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', NULL, '2025-07-04 21:04:13');

-- --------------------------------------------------------

--
-- Table structure for table `admin_permissions`
--

CREATE TABLE `admin_permissions` (
  `id` int(11) NOT NULL,
  `admin_id` int(11) NOT NULL,
  `permission_key` varchar(100) NOT NULL,
  `granted_by` int(11) NOT NULL,
  `is_active` tinyint(1) DEFAULT 1,
  `created_at` timestamp NOT NULL DEFAULT current_timestamp(),
  `updated_at` timestamp NOT NULL DEFAULT current_timestamp() ON UPDATE current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

--
-- Dumping data for table `admin_permissions`
--

INSERT INTO `admin_permissions` (`id`, `admin_id`, `permission_key`, `granted_by`, `is_active`, `created_at`, `updated_at`) VALUES
(1, 2, 'dashboard_access', 1, 1, '2025-07-02 11:04:05', '2025-07-04 05:00:38'),
(13, 3, 'dashboard_access', 1, 1, '2025-07-02 11:51:08', '2025-07-02 11:53:45'),
(66, 2, 'profile_access', 1, 1, '2025-07-04 05:00:38', '2025-07-04 05:00:38'),
(67, 2, 'create_projects', 1, 1, '2025-07-04 05:00:38', '2025-07-04 05:00:38'),
(68, 2, 'view_projects', 1, 1, '2025-07-04 05:00:38', '2025-07-04 05:00:38'),
(69, 2, 'edit_projects', 1, 1, '2025-07-04 05:00:38', '2025-07-04 05:00:38'),
(70, 2, 'manage_projects', 1, 1, '2025-07-04 05:00:38', '2025-07-04 05:00:38'),
(71, 2, 'import_data', 1, 1, '2025-07-04 05:00:38', '2025-07-04 05:00:38'),
(72, 2, 'manage_project_steps', 1, 1, '2025-07-04 05:00:38', '2025-07-04 05:00:38'),
(73, 2, 'manage_budgets', 1, 1, '2025-07-04 05:00:38', '2025-07-04 05:00:38'),
(74, 2, 'view_reports', 1, 1, '2025-07-04 05:00:38', '2025-07-04 05:00:38'),
(75, 2, 'manage_feedback', 1, 1, '2025-07-04 05:00:38', '2025-07-04 05:00:38'),
(76, 2, 'manage_documents', 1, 1, '2025-07-04 05:00:38', '2025-07-04 05:00:38');

-- --------------------------------------------------------

--
-- Table structure for table `budget_allocations`
--

CREATE TABLE `budget_allocations` (
  `id` int(11) NOT NULL,
  `project_id` int(11) NOT NULL,
  `budget_id` int(11) NOT NULL,
  `allocation_type` enum('initial','supplementary','reallocation') DEFAULT 'initial',
  `allocated_amount` decimal(15,2) NOT NULL,
  `fund_source` varchar(255) NOT NULL,
  `funding_category` enum('development','recurrent','emergency','donor') DEFAULT 'development',
  `allocation_date` date NOT NULL,
  `financial_year` varchar(20) NOT NULL,
  `budget_line_item` varchar(255) DEFAULT NULL,
  `allocation_reference` varchar(100) DEFAULT NULL,
  `conditions` text DEFAULT NULL,
  `status` enum('pending','approved','active','exhausted','cancelled') DEFAULT 'pending',
  `allocated_by` int(11) NOT NULL,
  `approved_by` int(11) DEFAULT NULL,
  `approved_at` timestamp NULL DEFAULT NULL,
  `created_at` timestamp NOT NULL DEFAULT current_timestamp(),
  `updated_at` timestamp NOT NULL DEFAULT current_timestamp() ON UPDATE current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- --------------------------------------------------------

--
-- Table structure for table `counties`
--

CREATE TABLE `counties` (
  `id` int(11) NOT NULL,
  `name` varchar(100) NOT NULL,
  `code` varchar(10) DEFAULT NULL,
  `created_at` timestamp NOT NULL DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Dumping data for table `counties`
--

INSERT INTO `counties` (`id`, `name`, `code`, `created_at`) VALUES
(1, 'Migori', 'MGR', '2025-06-21 09:39:15');

-- --------------------------------------------------------

--
-- Table structure for table `departments`
--

CREATE TABLE `departments` (
  `id` int(11) NOT NULL,
  `name` varchar(100) NOT NULL,
  `description` text DEFAULT NULL,
  `created_at` timestamp NOT NULL DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Dumping data for table `departments`
--

INSERT INTO `departments` (`id`, `name`, `description`, `created_at`) VALUES
(1, 'Public Health and Medical Services', 'Oversees healthcare services, hospitals, clinics, and public health programs across Migori County.', '2025-06-21 09:39:48'),
(2, 'Water and Energy', 'Responsible for water supply, irrigation systems, and energy development projects in the county.', '2025-06-21 09:39:48'),
(3, 'Finance and Economic Planning', 'Manages county budgeting, financial planning, revenue collection and economic development strategies.', '2025-06-21 09:39:48'),
(4, 'Public Service Management and Devolution', 'Handles human resource management, capacity building and implementation of devolution policies.', '2025-06-21 09:39:48'),
(5, 'Roads, Transport and Public Works', 'Develops and maintains road infrastructure, public transport systems and county government buildings.', '2025-06-21 09:39:48'),
(6, 'Education, Gender, Youth, Sports, Culture and Social Services', 'Coordinates education programs, youth empowerment, sports development and cultural activities.', '2025-06-21 09:39:48'),
(7, 'Lands, Housing, Physical Planning and Urban Development', 'Manages land administration, housing projects, urban planning and development control.', '2025-06-21 09:39:48'),
(8, 'Agriculture, Livestock, Veterinary Services, Fisheries and Blue Economy', 'Promotes agricultural development, livestock health, fisheries and blue economy initiatives.', '2025-06-21 09:39:48'),
(9, 'Environment, Natural Resources, Climate Change and Disaster Management', 'Leads environmental conservation, natural resource management and climate resilience programs.', '2025-06-21 09:39:48'),
(10, 'Trade, Tourism, Industrialization and Cooperative Development', 'Facilitates trade, tourism promotion, industrialization and cooperative society development.', '2025-06-21 09:39:48'),
(11, 'ICT, e-Governance and Innovation', 'Drives digital transformation, e-government services and innovation in public service delivery.', '2025-06-21 09:39:48'),
(12, 'County Assembly', 'The legislative arm of Migori County Government that makes laws and oversees county operations.', '2025-06-21 09:39:48'),
(13, 'Public Service Board', 'Responsible for human resource management and public service administration in the county.', '2025-06-21 09:39:48');

-- --------------------------------------------------------

--
-- Table structure for table `feedback`
--

CREATE TABLE `feedback` (
  `id` int(11) NOT NULL,
  `project_id` int(11) NOT NULL,
  `citizen_name` varchar(255) NOT NULL,
  `citizen_email` varchar(255) DEFAULT NULL,
  `citizen_phone` varchar(20) DEFAULT NULL,
  `subject` varchar(500) DEFAULT 'Project Comment',
  `message` text NOT NULL,
  `status` enum('pending','approved','rejected','responded','grievance') DEFAULT 'pending',
  `priority` enum('low','medium','high') DEFAULT 'medium',
  `sentiment` enum('positive','neutral','negative') DEFAULT 'neutral',
  `parent_comment_id` int(11) DEFAULT 0,
  `user_ip` varchar(45) DEFAULT NULL,
  `user_agent` text DEFAULT NULL,
  `admin_response` text DEFAULT NULL,
  `responded_by` int(11) DEFAULT NULL,
  `responded_at` timestamp NULL DEFAULT NULL,
  `moderated_by` int(11) DEFAULT NULL,
  `moderated_at` timestamp NULL DEFAULT NULL,
  `internal_notes` text DEFAULT NULL,
  `is_featured` tinyint(1) DEFAULT 0,
  `engagement_score` int(11) DEFAULT 0,
  `response_time_hours` decimal(10,2) DEFAULT NULL,
  `follow_up_required` tinyint(1) DEFAULT 0,
  `tags` longtext CHARACTER SET utf8mb4 COLLATE utf8mb4_bin DEFAULT NULL CHECK (json_valid(`tags`)),
  `attachments` longtext CHARACTER SET utf8mb4 COLLATE utf8mb4_bin DEFAULT NULL CHECK (json_valid(`attachments`)),
  `created_at` timestamp NOT NULL DEFAULT current_timestamp(),
  `updated_at` timestamp NOT NULL DEFAULT current_timestamp() ON UPDATE current_timestamp(),
  `visitor_id` varchar(255) DEFAULT NULL,
  `grievance_status` enum('open','resolved') DEFAULT 'open',
  `resolved_by` int(11) DEFAULT NULL,
  `resolution_notes` text DEFAULT NULL,
  `resolved_at` datetime DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- --------------------------------------------------------

--
-- Table structure for table `feedback_notifications`
--

CREATE TABLE `feedback_notifications` (
  `id` int(11) NOT NULL,
  `feedback_id` int(11) NOT NULL,
  `notification_type` enum('response_sent','status_updated','follow_up') NOT NULL,
  `recipient_email` varchar(255) NOT NULL,
  `sent_at` timestamp NOT NULL DEFAULT current_timestamp(),
  `delivery_status` enum('pending','sent','failed') DEFAULT 'pending',
  `error_message` text DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- --------------------------------------------------------

--
-- Table structure for table `fund_sources`
--

CREATE TABLE `fund_sources` (
  `id` int(11) NOT NULL,
  `source_name` varchar(255) NOT NULL,
  `source_code` varchar(50) NOT NULL,
  `source_type` enum('government','donor','loan','grant','internally_generated') NOT NULL,
  `description` text DEFAULT NULL,
  `contact_person` varchar(255) DEFAULT NULL,
  `contact_details` varchar(255) DEFAULT NULL,
  `terms_conditions` text DEFAULT NULL,
  `is_active` tinyint(1) DEFAULT 1,
  `created_at` timestamp NOT NULL DEFAULT current_timestamp(),
  `updated_at` timestamp NOT NULL DEFAULT current_timestamp() ON UPDATE current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Dumping data for table `fund_sources`
--

INSERT INTO `fund_sources` (`id`, `source_name`, `source_code`, `source_type`, `description`, `contact_person`, `contact_details`, `terms_conditions`, `is_active`, `created_at`, `updated_at`) VALUES
(1, 'County Development Fund', 'CDF', 'government', 'Primary county development funding', NULL, NULL, NULL, 1, '2025-07-04 07:54:29', '2025-07-04 07:54:29'),
(2, 'World Bank', 'WB', 'donor', 'World Bank development projects', NULL, NULL, NULL, 1, '2025-07-04 07:54:29', '2025-07-04 07:54:29'),
(3, 'African Development Bank', 'ADB', 'donor', 'African Development Bank funding', NULL, NULL, NULL, 1, '2025-07-04 07:54:29', '2025-07-04 07:54:29'),
(4, 'USAID', 'USAID', 'donor', 'United States Agency for International Development', NULL, NULL, NULL, 1, '2025-07-04 07:54:29', '2025-07-04 07:54:29'),
(5, 'Emergency Fund', 'EMF', 'government', 'County emergency response fund', NULL, NULL, NULL, 1, '2025-07-04 07:54:29', '2025-07-04 07:54:29'),
(6, 'Internally Generated Revenue', 'IGR', 'internally_generated', 'County own revenue sources', NULL, NULL, NULL, 1, '2025-07-04 07:54:29', '2025-07-04 07:54:29'),
(7, 'Kenya Urban Support Programme', 'KUSP', 'donor', NULL, NULL, NULL, NULL, 1, '2025-07-04 20:16:20', '2025-07-04 20:16:20'),
(8, 'Equalization Fund', 'EQF', 'government', NULL, NULL, NULL, NULL, 1, '2025-07-04 20:16:20', '2025-07-04 20:16:20'),
(9, 'Conditional Grants', 'CG', 'government', NULL, NULL, NULL, NULL, 1, '2025-07-04 20:16:20', '2025-07-04 20:16:20'),
(10, 'Other', 'OTHER', '', NULL, NULL, NULL, NULL, 1, '2025-07-04 20:16:20', '2025-07-04 20:16:20');

-- --------------------------------------------------------

--
-- Table structure for table `import_logs`
--

CREATE TABLE `import_logs` (
  `id` int(11) NOT NULL,
  `filename` varchar(255) NOT NULL,
  `total_rows` int(11) NOT NULL,
  `successful_imports` int(11) NOT NULL,
  `failed_imports` int(11) NOT NULL,
  `error_details` text DEFAULT NULL,
  `imported_by` int(11) NOT NULL,
  `imported_at` timestamp NOT NULL DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Dumping data for table `import_logs`
--

INSERT INTO `import_logs` (`id`, `filename`, `total_rows`, `successful_imports`, `failed_imports`, `error_details`, `imported_by`, `imported_at`) VALUES
(1, '6838cd091aa11_1748552969.csv', 3, 0, 3, 'Row 2: Column count mismatch\nRow 3: Column count mismatch\nRow 4: Column count mismatch', 1, '2025-05-29 18:09:29');

-- --------------------------------------------------------

--
-- Table structure for table `login_attempts`
--

CREATE TABLE `login_attempts` (
  `id` int(11) NOT NULL,
  `email` varchar(255) NOT NULL,
  `attempts` int(11) NOT NULL,
  `last_attempt` datetime NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Dumping data for table `login_attempts`
--

INSERT INTO `login_attempts` (`id`, `email`, `attempts`, `last_attempt`) VALUES
(2, 'jenifermuhonja01@gmail.com', 2, '2025-07-03 20:02:21'),
(4, 'hamweed8@gmail.com', 2, '2025-07-03 09:48:45');

-- --------------------------------------------------------

--
-- Table structure for table `prepared_responses`
--

CREATE TABLE `prepared_responses` (
  `id` int(11) NOT NULL,
  `name` varchar(255) NOT NULL,
  `content` text NOT NULL,
  `category` varchar(100) DEFAULT 'general',
  `is_active` tinyint(1) DEFAULT 1,
  `created_at` timestamp NOT NULL DEFAULT current_timestamp(),
  `updated_at` timestamp NOT NULL DEFAULT current_timestamp() ON UPDATE current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Dumping data for table `prepared_responses`
--

INSERT INTO `prepared_responses` (`id`, `name`, `content`, `category`, `is_active`, `created_at`, `updated_at`) VALUES
(1, 'Thank You', 'Thank you for your feedback. We appreciate your input and will review it carefully.', 'acknowledgment', 1, '2025-06-19 14:28:09', '2025-06-19 14:28:09'),
(2, 'Under Review', 'Your feedback is currently under review by our team. We will respond within 3-5 business days.', 'status', 1, '2025-06-19 14:28:09', '2025-06-19 14:28:09'),
(3, 'More Information Needed', 'Thank you for reaching out. To better assist you, could you please provide more specific details about your concern?', 'inquiry', 1, '2025-06-19 14:28:09', '2025-06-19 14:28:09'),
(4, 'Issue Resolved', 'Thank you for bringing this to our attention. The issue has been resolved and appropriate measures have been taken.', 'resolution', 1, '2025-06-19 14:28:09', '2025-06-19 14:28:09'),
(5, 'Project Progress Update', 'Thank you for your inquiry about the project progress. We are currently on track with our planned timeline and will provide regular updates as work continues.', 'progress', 1, '2025-06-19 14:28:09', '2025-06-19 14:28:09');

-- --------------------------------------------------------

--
-- Table structure for table `projects`
--

CREATE TABLE `projects` (
  `id` int(11) NOT NULL,
  `project_name` varchar(255) NOT NULL,
  `description` text DEFAULT NULL,
  `department_id` int(11) NOT NULL,
  `project_year` int(11) NOT NULL,
  `county_id` int(11) NOT NULL,
  `sub_county_id` int(11) NOT NULL,
  `ward_id` int(11) NOT NULL,
  `location_address` text DEFAULT NULL,
  `location_coordinates` varchar(100) DEFAULT NULL,
  `start_date` date DEFAULT NULL,
  `expected_completion_date` date DEFAULT NULL,
  `actual_completion_date` date DEFAULT NULL,
  `contractor_name` varchar(255) DEFAULT NULL,
  `contractor_contact` varchar(100) DEFAULT NULL,
  `status` enum('planning','ongoing','completed','suspended','cancelled') NOT NULL DEFAULT 'planning',
  `visibility` enum('private','published') DEFAULT 'private',
  `step_status` enum('awaiting','running','completed') DEFAULT 'awaiting',
  `progress_percentage` decimal(5,2) DEFAULT 0.00,
  `total_steps` int(11) DEFAULT 0,
  `completed_steps` int(11) DEFAULT 0,
  `created_by` int(11) DEFAULT NULL,
  `created_at` timestamp NOT NULL DEFAULT current_timestamp(),
  `updated_at` timestamp NOT NULL DEFAULT current_timestamp() ON UPDATE current_timestamp(),
  `average_rating` decimal(3,2) DEFAULT 5.00,
  `total_ratings` int(11) DEFAULT 0,
  `allocated_budget` decimal(15,2) DEFAULT 0.00,
  `spent_budget` decimal(15,2) DEFAULT 0.00,
  `budget_status` enum('not_allocated','allocated','overspent') DEFAULT 'not_allocated',
  `total_budget` decimal(15,2) DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Dumping data for table `projects`
--

INSERT INTO `projects` (`id`, `project_name`, `description`, `department_id`, `project_year`, `county_id`, `sub_county_id`, `ward_id`, `location_address`, `location_coordinates`, `start_date`, `expected_completion_date`, `actual_completion_date`, `contractor_name`, `contractor_contact`, `status`, `visibility`, `step_status`, `progress_percentage`, `total_steps`, `completed_steps`, `created_by`, `created_at`, `updated_at`, `average_rating`, `total_ratings`, `allocated_budget`, `spent_budget`, `budget_status`, `total_budget`) VALUES
(16, 'Siro Girls secondary Domitory', 'construction of a modern domitory at Siro Girls Secondary school', 6, 2025, 1, 5, 17, 'Kisii', '-0.942752, 34.430065', NULL, NULL, NULL, 'XYZ construction ltd', '702353585', 'planning', 'private', 'awaiting', 0.00, 1, 0, 1, '2025-06-29 22:09:32', '2025-06-29 22:09:32', 5.00, 0, 0.00, 0.00, 'not_allocated', NULL),
(22, 'Migori County Health Center Construction', 'Construction of a modern health center to serve the local community with medical facilities and equipment', 2, 2024, 1, 3, 10, 'Migori Town Center, near the main market', '-1.063583, 34.298915', NULL, NULL, NULL, 'ABC Construction Ltd', '25471274674', 'ongoing', 'published', 'awaiting', 25.00, 2, 0, 1, '2025-07-04 18:29:01', '2025-07-04 18:44:48', 5.00, 0, 0.00, 0.00, 'not_allocated', 25000000.00),
(23, 'Migori-Isebania Road Improvement', 'Upgrading of 15km stretch of Migori-Isebania road with tarmac surface and proper drainage', 3, 2024, 1, 8, 35, 'Migori-Isebania Highway, Migori Town', '-0.835649, 34.189739', NULL, NULL, NULL, 'Kens Construction Ltd', '25476473647', 'planning', 'private', 'awaiting', 0.00, 1, 0, 1, '2025-07-04 18:29:01', '2025-07-04 18:29:01', 5.00, 0, 0.00, 0.00, 'not_allocated', 15000000.00),
(24, 'Rongo Bus stage Upgrade', 'Construction of modern market stalls with proper sanitation and drainage facilities', 4, 2024, 1, 5, 18, 'Rongo Town Center', '-0.762871, 34.599666', NULL, NULL, NULL, 'Unity Builders', '25478947485', 'planning', 'private', 'awaiting', 0.00, 1, 0, 1, '2025-07-04 18:29:01', '2025-07-04 18:29:01', 5.00, 0, 0.00, 0.00, 'not_allocated', 5000000.00),
(25, 'Isibania Health Center Extension', 'Addition of maternity wing and medical equipment procurement', 2, 2024, 1, 2, 8, 'Nyatike Health Center', '-1.218048, 34.482936', NULL, NULL, NULL, 'Medical Contractors Kenya', '25471252674', 'planning', 'private', 'awaiting', 0.00, 1, 0, 1, '2025-07-04 18:29:01', '2025-07-04 18:29:01', 5.00, 0, 0.00, 0.00, 'not_allocated', 12000000.00),
(26, 'Lela Dispensary expansion', 'contruction of ward fercility', 8, 2025, 1, 2, 7, 'Oyani SDA', '-0.975707, 34.241237', NULL, NULL, NULL, 'ABC Construction Ltd', '25484648599', 'planning', 'private', 'awaiting', 0.00, 1, 0, 1, '2025-07-04 18:29:01', '2025-07-04 18:29:01', 5.00, 0, 0.00, 0.00, 'not_allocated', 17500000.00),
(27, 'Lela market construction', 'kaminolewe market improvement to market standards', 7, 2026, 1, 3, 12, 'Kaminolewe market', '-0.941379, 34.432811', NULL, NULL, NULL, 'ABC Construction Ltd', '25473574848', 'planning', 'private', 'awaiting', 0.00, 1, 0, 1, '2025-07-04 18:29:01', '2025-07-04 18:29:01', 5.00, 0, 0.00, 0.00, 'not_allocated', 13000500.00),
(28, 'Central Sakwa police post construction', 'Implementation of public service management and devolution in Central Sakwa ward under Awendo sub-county.', 13, 2024, 1, 2, 8, 'Central Sakwa Area, Awendo Sub-county', '-1.200886, 34.621639', NULL, NULL, NULL, 'Blue Economy Partners', '25463848848', 'planning', 'private', 'awaiting', 0.00, 1, 0, 1, '2025-07-04 18:29:01', '2025-07-04 18:29:01', 5.00, 0, 0.00, 0.00, 'not_allocated', 50900000.00),
(29, 'South Sakwa Lands, Project', 'Implementation of lands, housing, physical planning and urban development in South Sakwa ward under Awendo sub-county.', 4, 2023, 1, 1, 3, 'South Sakwa Area, Awendo Sub-county', '-0.904305, 34.528255', NULL, NULL, NULL, 'MajiWorks Kenya', '25475465154', 'planning', 'private', 'awaiting', 0.00, 1, 0, 1, '2025-07-04 18:29:01', '2025-07-04 18:29:01', 5.00, 0, 0.00, 0.00, 'not_allocated', 44000000.00),
(30, 'North Kamagambo Public Project', 'Implementation of public service management and devolution in North Kamagambo ward under Rongo sub-county.', 9, 2025, 1, 3, 11, 'North Kamagambo Area, Rongo Sub-county', '-0.874096, 34.581813', NULL, NULL, NULL, 'EcoDev Works', '25471163680', 'planning', 'private', 'awaiting', 0.00, 1, 0, 1, '2025-07-04 18:29:01', '2025-07-04 18:29:01', 5.00, 0, 0.00, 0.00, 'not_allocated', 19000000.00),
(31, 'Awendo sewage', 'lets make awendo clean', 2, 2025, 1, 2, 8, 'awendo central', '0.777342, 34.595696', '2025-01-01', NULL, NULL, 'ABC constructors', '0702353585', 'planning', 'private', 'awaiting', 0.00, 2, 0, 1, '2025-07-04 18:59:22', '2025-07-04 18:59:22', 5.00, 0, 0.00, 0.00, 'not_allocated', 2000000.00);

-- --------------------------------------------------------

--
-- Table structure for table `project_documents`
--

CREATE TABLE `project_documents` (
  `id` int(11) NOT NULL,
  `project_id` int(11) NOT NULL,
  `document_type` varchar(100) NOT NULL,
  `filename` varchar(255) NOT NULL,
  `original_name` varchar(255) NOT NULL,
  `description` text DEFAULT NULL,
  `uploaded_by` int(11) DEFAULT NULL,
  `created_at` timestamp NOT NULL DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- --------------------------------------------------------

--
-- Stand-in structure for view `project_financial_summary`
-- (See below for the actual view)
--
CREATE TABLE `project_financial_summary` (
`project_id` int(11)
,`project_name` varchar(255)
,`approved_budget` decimal(15,2)
,`budget_increases` decimal(37,2)
,`total_disbursed` decimal(37,2)
,`total_spent` decimal(37,2)
,`total_allocated` decimal(38,2)
,`remaining_balance` decimal(38,2)
);

-- --------------------------------------------------------

--
-- Table structure for table `project_steps`
--

CREATE TABLE `project_steps` (
  `id` int(11) NOT NULL,
  `project_id` int(11) NOT NULL,
  `step_number` int(11) NOT NULL,
  `step_name` varchar(255) NOT NULL,
  `description` text DEFAULT NULL,
  `status` enum('pending','in_progress','completed','skipped') DEFAULT 'pending',
  `start_date` date DEFAULT NULL,
  `expected_end_date` date DEFAULT NULL,
  `actual_end_date` date DEFAULT NULL,
  `created_at` timestamp NOT NULL DEFAULT current_timestamp(),
  `updated_at` timestamp NOT NULL DEFAULT current_timestamp() ON UPDATE current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Dumping data for table `project_steps`
--

INSERT INTO `project_steps` (`id`, `project_id`, `step_number`, `step_name`, `description`, `status`, `start_date`, `expected_end_date`, `actual_end_date`, `created_at`, `updated_at`) VALUES
(20, 22, 1, 'Project Planning & Approval', 'Initial project planning, design review, and regulatory approval process', 'in_progress', '2025-07-04', NULL, NULL, '2025-07-04 18:29:01', '2025-07-04 18:44:48'),
(21, 23, 1, 'Road Survey and Design', 'Conduct topographical survey and prepare detailed engineering designs', 'pending', NULL, NULL, NULL, '2025-07-04 18:29:01', '2025-07-04 18:29:01'),
(22, 24, 1, 'Site Preparation', 'Clear site and prepare foundation for market construction', 'pending', NULL, NULL, NULL, '2025-07-04 18:29:01', '2025-07-04 18:29:01'),
(23, 25, 1, 'Architectural Planning', 'Design maternity wing and plan equipment installation', 'pending', NULL, NULL, NULL, '2025-07-04 18:29:01', '2025-07-04 18:29:01'),
(24, 26, 1, 'Project Planning & Approval', 'Initial project planning, design review, and regulatory approval process', 'pending', NULL, NULL, NULL, '2025-07-04 18:29:01', '2025-07-04 18:29:01'),
(25, 27, 1, 'Project Planning & Approval', 'Initial project planning, design review, and regulatory approval process', 'pending', NULL, NULL, NULL, '2025-07-04 18:29:01', '2025-07-04 18:29:01'),
(26, 28, 1, 'Design and Costing', 'Drafting architectural drawings and estimating costs.', 'pending', NULL, NULL, NULL, '2025-07-04 18:29:01', '2025-07-04 18:29:01'),
(27, 29, 1, 'Land Survey', 'Carrying out land demarcation and topographical survey.', 'pending', NULL, NULL, NULL, '2025-07-04 18:29:01', '2025-07-04 18:29:01'),
(28, 30, 1, 'Feasibility Study', 'Conducting technical and social feasibility assessment.', 'pending', NULL, NULL, NULL, '2025-07-04 18:29:01', '2025-07-04 18:29:01'),
(29, 22, 2, 'procurement', 'proc', 'pending', NULL, NULL, NULL, '2025-07-04 18:44:40', '2025-07-04 18:44:40'),
(30, 31, 2, 'Project Planning & Approval', 'Initial project planning, design review, and regulatory approval process', 'pending', NULL, NULL, NULL, '2025-07-04 18:59:22', '2025-07-04 18:59:22'),
(31, 31, 3, 'Establishment of proj committee', 'pmc creation', 'pending', NULL, NULL, NULL, '2025-07-04 18:59:22', '2025-07-04 18:59:22');

-- --------------------------------------------------------

--
-- Table structure for table `project_transactions`
--

CREATE TABLE `project_transactions` (
  `id` int(11) NOT NULL,
  `project_id` int(11) NOT NULL,
  `transaction_type` enum('budget_increase','expenditure','disbursement','adjustment') NOT NULL,
  `amount` decimal(15,2) NOT NULL,
  `description` text NOT NULL,
  `transaction_date` date NOT NULL,
  `reference_number` varchar(100) DEFAULT NULL,
  `document_path` varchar(255) DEFAULT NULL,
  `document_type` enum('invoice','receipt','voucher','other') DEFAULT NULL,
  `created_by` int(11) DEFAULT NULL,
  `created_at` timestamp NOT NULL DEFAULT current_timestamp(),
  `updated_at` timestamp NOT NULL DEFAULT current_timestamp() ON UPDATE current_timestamp(),
  `fund_source` varchar(255) DEFAULT 'County Development Fund',
  `funding_category` enum('development','recurrent','emergency','donor') DEFAULT 'development',
  `disbursement_method` enum('cheque','bank_transfer','mobile_money','cash') DEFAULT 'bank_transfer',
  `voucher_number` varchar(100) DEFAULT NULL,
  `approval_status` enum('pending','approved','rejected') DEFAULT 'pending',
  `approved_by` int(11) DEFAULT NULL,
  `approved_at` timestamp NULL DEFAULT NULL,
  `payment_status` enum('pending','processed','completed','failed') DEFAULT 'pending',
  `transaction_status` enum('active','edited','deleted','reversed') DEFAULT 'active',
  `original_transaction_id` int(11) DEFAULT NULL,
  `edit_reason` text DEFAULT NULL,
  `deletion_reason` text DEFAULT NULL,
  `modified_by` int(11) DEFAULT NULL,
  `modified_at` timestamp NULL DEFAULT NULL,
  `receipt_number` varchar(100) DEFAULT NULL,
  `bank_receipt_reference` varchar(100) DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Dumping data for table `project_transactions`
--

INSERT INTO `project_transactions` (`id`, `project_id`, `transaction_type`, `amount`, `description`, `transaction_date`, `reference_number`, `document_path`, `document_type`, `created_by`, `created_at`, `updated_at`, `fund_source`, `funding_category`, `disbursement_method`, `voucher_number`, `approval_status`, `approved_by`, `approved_at`, `payment_status`, `transaction_status`, `original_transaction_id`, `edit_reason`, `deletion_reason`, `modified_by`, `modified_at`, `receipt_number`, `bank_receipt_reference`) VALUES
(13, 31, '', 500000.00, 'Additional Allocation', '2025-07-04', 'GSTE567', NULL, NULL, 1, '2025-07-04 19:07:42', '2025-07-04 19:08:35', 'World Bank', 'development', 'bank_transfer', '', 'pending', NULL, NULL, 'pending', 'active', NULL, NULL, NULL, 1, '2025-07-04 19:08:35', '', ''),
(14, 31, '', 500000.00, 'Additional Allocation', '2025-07-04', 'GSTE567', NULL, NULL, 1, '2025-07-04 19:07:42', '2025-07-04 19:08:35', 'County Development Fund', 'development', 'bank_transfer', '', 'pending', NULL, NULL, 'pending', 'edited', 13, 'typo at the amount column', NULL, 1, '2025-07-04 19:08:35', '', ''),
(15, 22, 'disbursement', 5000000.00, 'First Tranche', '2025-07-03', 'GSTE534', NULL, NULL, 1, '2025-07-04 20:02:26', '2025-07-04 20:03:39', 'County Development Fund', '', 'bank_transfer', '', 'pending', NULL, NULL, 'pending', 'active', NULL, NULL, NULL, 1, '2025-07-04 20:03:39', '', ''),
(16, 22, 'disbursement', 5000000.00, 'First Tranche', '2025-07-04', 'GSTE534', NULL, NULL, 1, '2025-07-04 20:02:26', '2025-07-04 20:03:39', 'County Development Fund', '', 'bank_transfer', '', 'pending', NULL, NULL, 'pending', 'edited', 15, 'date only', NULL, 1, '2025-07-04 20:03:39', '', ''),
(17, 22, 'adjustment', 1000000.00, 'BEING PROMISSED DONATION', '2025-07-04', 'GSTE522', NULL, NULL, 1, '2025-07-04 20:20:14', '2025-07-04 20:26:53', 'hamisi foundation', 'donor', 'bank_transfer', '', 'pending', NULL, NULL, 'pending', 'deleted', NULL, NULL, 'WRONG PROJECT', 1, '2025-07-04 20:26:53', '', ''),
(18, 22, 'budget_increase', 127999.00, 'HAMISI FOUNDATION DONATION', '2025-07-04', 'GSTE56y', NULL, NULL, 1, '2025-07-04 20:58:15', '2025-07-04 20:58:15', 'hamisi foundation', 'donor', 'bank_transfer', '', 'pending', NULL, NULL, 'pending', 'active', NULL, NULL, NULL, NULL, NULL, '', ''),
(19, 22, 'expenditure', 4000000.00, 'Payment of contactor', '2025-07-04', 'GSTE53D', NULL, NULL, 1, '2025-07-04 21:04:13', '2025-07-04 21:04:13', 'County Development Fund', 'development', 'bank_transfer', '', 'pending', NULL, NULL, 'pending', 'active', NULL, NULL, NULL, NULL, NULL, '', '');

-- --------------------------------------------------------

--
-- Table structure for table `project_transaction_documents`
--

CREATE TABLE `project_transaction_documents` (
  `id` int(11) NOT NULL,
  `transaction_id` int(11) NOT NULL,
  `file_path` varchar(255) NOT NULL,
  `original_filename` varchar(255) NOT NULL,
  `file_size` int(11) DEFAULT 0,
  `mime_type` varchar(100) DEFAULT NULL,
  `uploaded_by` int(11) DEFAULT NULL,
  `created_at` timestamp NOT NULL DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Dumping data for table `project_transaction_documents`
--

INSERT INTO `project_transaction_documents` (`id`, `transaction_id`, `file_path`, `original_filename`, `file_size`, `mime_type`, `uploaded_by`, `created_at`) VALUES
(10, 13, 'doc_6868267e951ed9.62058468.pdf', 'doc_6861f44368bda9.34398036.pdf', 788924, 'application/pdf', 1, '2025-07-04 19:07:42'),
(11, 15, 'doc_68683352d87e64.20282671.pdf', 'doc_6861f3de080ee2.51056796.pdf', 19854, 'application/pdf', 1, '2025-07-04 20:02:26'),
(12, 17, 'doc_6868377e130ec4.83032555.pdf', 'doc_6861f3de080ee2.51056796.pdf', 19854, 'application/pdf', 1, '2025-07-04 20:20:14'),
(13, 18, 'doc_6868406753a9a7.02829851.pdf', 'doc_6861f3de080ee2.51056796.pdf', 19854, 'application/pdf', 1, '2025-07-04 20:58:15'),
(14, 19, 'doc_686841cd87a2f0.49995915.pdf', '6861f6e825fa7_1751250664.pdf', 788924, 'application/pdf', 1, '2025-07-04 21:04:13');

-- --------------------------------------------------------

--
-- Table structure for table `security_logs`
--

CREATE TABLE `security_logs` (
  `id` int(11) NOT NULL,
  `event_type` varchar(50) NOT NULL,
  `admin_id` int(11) DEFAULT NULL,
  `ip_address` varchar(45) DEFAULT NULL,
  `user_agent` text DEFAULT NULL,
  `details` longtext CHARACTER SET utf8mb4 COLLATE utf8mb4_bin DEFAULT NULL CHECK (json_valid(`details`)),
  `created_at` timestamp NOT NULL DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

--
-- Dumping data for table `security_logs`
--

INSERT INTO `security_logs` (`id`, `event_type`, `admin_id`, `ip_address`, `user_agent`, `details`, `created_at`) VALUES
(1, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"feedback.php\",\"url\":\"\\/Migoripmc\\/admin\\/feedback.php\",\"referrer\":\"http:\\/\\/localhost\\/Migoripmc\\/admin\\/roles_permissions.php\",\"method\":\"GET\",\"timestamp\":1751308141}', '2025-06-30 18:29:01'),
(2, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"feedback.php\",\"url\":\"\\/Migoripmc\\/admin\\/feedback.php\",\"referrer\":\"http:\\/\\/localhost\\/Migoripmc\\/admin\\/roles_permissions.php\",\"method\":\"GET\",\"timestamp\":1751308177}', '2025-06-30 18:29:37'),
(3, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"feedback.php\",\"url\":\"\\/Migoripmc\\/admin\\/feedback.php\",\"referrer\":\"http:\\/\\/localhost\\/Migoripmc\\/admin\\/roles_permissions.php\",\"method\":\"GET\",\"timestamp\":1751308192}', '2025-06-30 18:29:52'),
(4, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"feedback.php\",\"url\":\"\\/Migoripmc\\/admin\\/feedback.php\",\"referrer\":\"http:\\/\\/localhost\\/Migoripmc\\/admin\\/roles_permissions.php\",\"method\":\"GET\",\"timestamp\":1751308220}', '2025-06-30 18:30:20'),
(5, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"projects.php\",\"url\":\"\\/migoripmc\\/admin\\/projects.php\",\"referrer\":\"http:\\/\\/localhost\\/migoripmc\\/project_details\\/2?project_id=2&parent_comment_id=0&citizen_name=hamisi&citizen_email=jenifermuhonja01%40gmail.com&message=how+about+next+week\",\"method\":\"GET\",\"timestamp\":1751308497}', '2025-06-30 18:34:57'),
(6, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"feedback.php\",\"url\":\"\\/migoripmc\\/admin\\/feedback.php\",\"referrer\":\"http:\\/\\/localhost\\/migoripmc\\/admin\\/projects.php\",\"method\":\"GET\",\"timestamp\":1751308504}', '2025-06-30 18:35:04'),
(7, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"feedback.php\",\"url\":\"\\/Migoripmc\\/admin\\/feedback.php\",\"referrer\":\"http:\\/\\/localhost\\/Migoripmc\\/admin\\/roles_permissions.php\",\"method\":\"GET\",\"timestamp\":1751308588}', '2025-06-30 18:36:28'),
(8, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"feedback.php\",\"url\":\"\\/Migoripmc\\/admin\\/feedback.php\",\"referrer\":\"http:\\/\\/localhost\\/Migoripmc\\/admin\\/feedback.php\",\"method\":\"POST\",\"timestamp\":1751308599}', '2025-06-30 18:36:39'),
(9, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"feedback.php\",\"url\":\"\\/Migoripmc\\/admin\\/feedback.php\",\"referrer\":\"http:\\/\\/localhost\\/Migoripmc\\/admin\\/feedback.php\",\"method\":\"POST\",\"timestamp\":1751308599}', '2025-06-30 18:36:39'),
(10, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"feedback.php\",\"url\":\"\\/Migoripmc\\/admin\\/feedback.php\",\"referrer\":\"http:\\/\\/localhost\\/Migoripmc\\/admin\\/feedback.php\",\"method\":\"POST\",\"timestamp\":1751308603}', '2025-06-30 18:36:43'),
(11, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"feedback.php\",\"url\":\"\\/Migoripmc\\/admin\\/feedback.php\",\"referrer\":\"http:\\/\\/localhost\\/Migoripmc\\/admin\\/feedback.php\",\"method\":\"POST\",\"timestamp\":1751308603}', '2025-06-30 18:36:43'),
(12, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"feedback.php\",\"url\":\"\\/Migoripmc\\/admin\\/feedback.php\",\"referrer\":\"http:\\/\\/localhost\\/Migoripmc\\/admin\\/roles_permissions.php\",\"method\":\"GET\",\"timestamp\":1751310713}', '2025-06-30 19:11:53'),
(13, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"feedback.php\",\"url\":\"\\/Migoripmc\\/admin\\/feedback.php\",\"referrer\":\"http:\\/\\/localhost\\/Migoripmc\\/admin\\/roles_permissions.php\",\"method\":\"GET\",\"timestamp\":1751310790}', '2025-06-30 19:13:10'),
(14, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"roles_permissions.php\",\"url\":\"\\/Migoripmc\\/admin\\/roles_permissions.php\",\"referrer\":\"http:\\/\\/localhost\\/Migoripmc\\/admin\\/feedback.php\",\"method\":\"GET\",\"timestamp\":1751310816}', '2025-06-30 19:13:36'),
(15, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"roles_permissions.php\",\"url\":\"\\/Migoripmc\\/admin\\/roles_permissions.php\",\"referrer\":null,\"method\":\"GET\",\"timestamp\":1751311082}', '2025-06-30 19:18:02'),
(16, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"feedback.php\",\"url\":\"\\/migoripmc\\/admin\\/feedback.php\",\"referrer\":\"http:\\/\\/localhost\\/migoripmc\\/admin\\/projects.php\",\"method\":\"GET\",\"timestamp\":1751311095}', '2025-06-30 19:18:15'),
(17, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"feedback.php\",\"url\":\"\\/migoripmc\\/admin\\/feedback.php\",\"referrer\":\"http:\\/\\/localhost\\/migoripmc\\/project_details\\/10\",\"method\":\"GET\",\"timestamp\":1751311323}', '2025-06-30 19:22:03'),
(18, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"feedback.php\",\"url\":\"\\/migoripmc\\/admin\\/feedback.php\",\"referrer\":\"http:\\/\\/localhost\\/migoripmc\\/admin\\/feedback.php\",\"method\":\"POST\",\"timestamp\":1751311339}', '2025-06-30 19:22:19'),
(19, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"feedback.php\",\"url\":\"\\/migoripmc\\/admin\\/feedback.php\",\"referrer\":\"http:\\/\\/localhost\\/migoripmc\\/admin\\/feedback.php\",\"method\":\"GET\",\"timestamp\":1751311339}', '2025-06-30 19:22:19'),
(20, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"feedback.php\",\"url\":\"\\/migoripmc\\/admin\\/feedback.php\",\"referrer\":\"http:\\/\\/localhost\\/migoripmc\\/admin\\/projects.php\",\"method\":\"GET\",\"timestamp\":1751311489}', '2025-06-30 19:24:49'),
(21, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"grievances.php\",\"url\":\"\\/migoripmc\\/admin\\/grievances.php\",\"referrer\":\"http:\\/\\/localhost\\/migoripmc\\/admin\\/dashboard\",\"method\":\"GET\",\"timestamp\":1751312353}', '2025-06-30 19:39:13'),
(22, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"grievances.php\",\"url\":\"\\/migoripmc\\/admin\\/grievances.php\",\"referrer\":\"http:\\/\\/localhost\\/migoripmc\\/admin\\/dashboard\",\"method\":\"GET\",\"timestamp\":1751312355}', '2025-06-30 19:39:15'),
(23, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"grievances.php\",\"url\":\"\\/migoripmc\\/admin\\/grievances.php\",\"referrer\":\"http:\\/\\/localhost\\/migoripmc\\/admin\\/dashboard\",\"method\":\"GET\",\"timestamp\":1751312434}', '2025-06-30 19:40:34'),
(24, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"grievances.php\",\"url\":\"\\/migoripmc\\/admin\\/grievances\",\"referrer\":null,\"method\":\"GET\",\"timestamp\":1751312439}', '2025-06-30 19:40:39'),
(25, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"grievances.php\",\"url\":\"\\/migoripmc\\/admin\\/grievances\",\"referrer\":null,\"method\":\"GET\",\"timestamp\":1751312528}', '2025-06-30 19:42:08'),
(26, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"grievances.php\",\"url\":\"\\/migoripmc\\/admin\\/grievances\",\"referrer\":null,\"method\":\"GET\",\"timestamp\":1751312529}', '2025-06-30 19:42:09'),
(27, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"grievances.php\",\"url\":\"\\/migoripmc\\/admin\\/grievances\",\"referrer\":null,\"method\":\"GET\",\"timestamp\":1751312959}', '2025-06-30 19:49:19'),
(28, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"grievances.php\",\"url\":\"\\/migoripmc\\/admin\\/grievances\",\"referrer\":null,\"method\":\"GET\",\"timestamp\":1751314289}', '2025-06-30 20:11:29'),
(29, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"grievances.php\",\"url\":\"\\/migoripmc\\/admin\\/grievances\",\"referrer\":null,\"method\":\"GET\",\"timestamp\":1751314351}', '2025-06-30 20:12:31'),
(30, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"grievances.php\",\"url\":\"\\/migoripmc\\/admin\\/grievances?status=open&project_id=2&search=\",\"referrer\":\"http:\\/\\/localhost\\/migoripmc\\/admin\\/grievances\",\"method\":\"GET\",\"timestamp\":1751314393}', '2025-06-30 20:13:13'),
(31, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"grievances.php\",\"url\":\"\\/migoripmc\\/admin\\/grievances?status=open&project_id=2&search=\",\"referrer\":\"http:\\/\\/localhost\\/migoripmc\\/admin\\/grievances\",\"method\":\"GET\",\"timestamp\":1751314658}', '2025-06-30 20:17:38'),
(32, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"feedback.php\",\"url\":\"\\/migoripmc\\/admin\\/feedback.php\",\"referrer\":\"http:\\/\\/localhost\\/migoripmc\\/admin\\/grievances?status=open&project_id=2&search=\",\"method\":\"GET\",\"timestamp\":1751314685}', '2025-06-30 20:18:05'),
(33, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"pmc_reports.php\",\"url\":\"\\/migoripmc\\/admin\\/pmc_reports.php\",\"referrer\":\"http:\\/\\/localhost\\/migoripmc\\/admin\\/document_manager.php\",\"method\":\"GET\",\"timestamp\":1751314720}', '2025-06-30 20:18:40'),
(34, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"projects.php\",\"url\":\"\\/migoripmc\\/admin\\/projects.php\",\"referrer\":\"http:\\/\\/localhost\\/migoripmc\\/admin\\/budget_management.php\",\"method\":\"GET\",\"timestamp\":1751314725}', '2025-06-30 20:18:45'),
(35, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"create_project.php\",\"url\":\"\\/migoripmc\\/admin\\/create_project.php\",\"referrer\":\"http:\\/\\/localhost\\/migoripmc\\/admin\\/projects.php\",\"method\":\"GET\",\"timestamp\":1751314727}', '2025-06-30 20:18:47'),
(36, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"import_csv.php\",\"url\":\"\\/migoripmc\\/admin\\/import_csv.php\",\"referrer\":\"http:\\/\\/localhost\\/migoripmc\\/admin\\/create_project.php\",\"method\":\"GET\",\"timestamp\":1751314729}', '2025-06-30 20:18:49'),
(37, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"projects.php\",\"url\":\"\\/migoripmc\\/admin\\/projects.php\",\"referrer\":\"http:\\/\\/localhost\\/migoripmc\\/admin\\/import_csv.php\",\"method\":\"GET\",\"timestamp\":1751314732}', '2025-06-30 20:18:52'),
(38, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"grievances.php\",\"url\":\"\\/migoripmc\\/admin\\/grievances.php\",\"referrer\":\"http:\\/\\/localhost\\/migoripmc\\/admin\\/projects.php\",\"method\":\"GET\",\"timestamp\":1751314846}', '2025-06-30 20:20:46'),
(39, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"grievances.php\",\"url\":\"\\/migoripmc\\/admin\\/grievances.php\",\"referrer\":\"http:\\/\\/localhost\\/migoripmc\\/admin\\/projects.php\",\"method\":\"GET\",\"timestamp\":1751314879}', '2025-06-30 20:21:19'),
(40, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"grievances.php\",\"url\":\"\\/migoripmc\\/admin\\/grievances.php?status=open\",\"referrer\":\"http:\\/\\/localhost\\/migoripmc\\/admin\\/grievances.php\",\"method\":\"GET\",\"timestamp\":1751314891}', '2025-06-30 20:21:31'),
(41, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"grievances.php\",\"url\":\"\\/migoripmc\\/admin\\/grievances.php?status=all\",\"referrer\":\"http:\\/\\/localhost\\/migoripmc\\/admin\\/grievances.php?status=open\",\"method\":\"GET\",\"timestamp\":1751314893}', '2025-06-30 20:21:33'),
(42, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"grievances.php\",\"url\":\"\\/migoripmc\\/admin\\/grievances.php?status=resolved\",\"referrer\":\"http:\\/\\/localhost\\/migoripmc\\/admin\\/grievances.php?status=all\",\"method\":\"GET\",\"timestamp\":1751314894}', '2025-06-30 20:21:34'),
(43, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"grievances.php\",\"url\":\"\\/migoripmc\\/admin\\/grievances.php?status=open\",\"referrer\":\"http:\\/\\/localhost\\/migoripmc\\/admin\\/grievances.php?status=resolved\",\"method\":\"GET\",\"timestamp\":1751314897}', '2025-06-30 20:21:37'),
(44, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"grievances.php\",\"url\":\"\\/migoripmc\\/admin\\/grievances.php?status=open\",\"referrer\":\"http:\\/\\/localhost\\/migoripmc\\/admin\\/grievances.php?status=resolved\",\"method\":\"GET\",\"timestamp\":1751314935}', '2025-06-30 20:22:15'),
(45, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"grievances.php\",\"url\":\"\\/migoripmc\\/admin\\/grievances.php?status=open\",\"referrer\":\"http:\\/\\/localhost\\/migoripmc\\/admin\\/grievances.php?status=resolved\",\"method\":\"GET\",\"timestamp\":1751315239}', '2025-06-30 20:27:19'),
(46, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"grievances.php\",\"url\":\"\\/migoripmc\\/admin\\/grievances.php?status=open\",\"referrer\":\"http:\\/\\/localhost\\/migoripmc\\/admin\\/grievances.php?status=resolved\",\"method\":\"GET\",\"timestamp\":1751315264}', '2025-06-30 20:27:44'),
(47, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"grievances.php\",\"url\":\"\\/migoripmc\\/admin\\/grievances.php\",\"referrer\":\"http:\\/\\/localhost\\/migoripmc\\/admin\\/grievances.php?status=open\",\"method\":\"POST\",\"timestamp\":1751315272}', '2025-06-30 20:27:52'),
(48, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"grievances.php\",\"url\":\"\\/migoripmc\\/admin\\/grievances.php?status=open\",\"referrer\":\"http:\\/\\/localhost\\/migoripmc\\/admin\\/grievances.php?status=open\",\"method\":\"POST\",\"timestamp\":1751315272}', '2025-06-30 20:27:52'),
(49, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"grievances.php\",\"url\":\"\\/migoripmc\\/admin\\/grievances.php?status=open\",\"referrer\":null,\"method\":\"GET\",\"timestamp\":1751315276}', '2025-06-30 20:27:56'),
(50, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"grievances.php\",\"url\":\"\\/migoripmc\\/admin\\/grievances.php?status=open\",\"referrer\":\"http:\\/\\/localhost\\/migoripmc\\/admin\\/grievances.php?status=open\",\"method\":\"POST\",\"timestamp\":1751315284}', '2025-06-30 20:28:04'),
(51, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"grievances.php\",\"url\":\"\\/migoripmc\\/admin\\/grievances.php\",\"referrer\":\"http:\\/\\/localhost\\/migoripmc\\/admin\\/grievances.php?status=open\",\"method\":\"POST\",\"timestamp\":1751315286}', '2025-06-30 20:28:06'),
(52, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"grievances.php\",\"url\":\"\\/migoripmc\\/admin\\/grievances.php?status=open\",\"referrer\":\"http:\\/\\/localhost\\/migoripmc\\/admin\\/grievances.php?status=open\",\"method\":\"POST\",\"timestamp\":1751315288}', '2025-06-30 20:28:08'),
(53, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"grievances.php\",\"url\":\"\\/migoripmc\\/admin\\/grievances.php\",\"referrer\":\"http:\\/\\/localhost\\/migoripmc\\/admin\\/grievances.php?status=open\",\"method\":\"POST\",\"timestamp\":1751315290}', '2025-06-30 20:28:10'),
(54, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"grievances.php\",\"url\":\"\\/migoripmc\\/admin\\/grievances.php\",\"referrer\":\"http:\\/\\/localhost\\/migoripmc\\/admin\\/grievances.php?status=open\",\"method\":\"POST\",\"timestamp\":1751315292}', '2025-06-30 20:28:12'),
(55, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"grievances.php\",\"url\":\"\\/migoripmc\\/admin\\/grievances.php?status=open\",\"referrer\":\"http:\\/\\/localhost\\/migoripmc\\/admin\\/grievances.php?status=open\",\"method\":\"POST\",\"timestamp\":1751315294}', '2025-06-30 20:28:14'),
(56, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"grievances.php\",\"url\":\"\\/migoripmc\\/admin\\/grievances.php\",\"referrer\":\"http:\\/\\/localhost\\/migoripmc\\/admin\\/grievances.php?status=open\",\"method\":\"POST\",\"timestamp\":1751315296}', '2025-06-30 20:28:16'),
(57, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"grievances.php\",\"url\":\"\\/migoripmc\\/admin\\/grievances.php?status=open\",\"referrer\":\"http:\\/\\/localhost\\/migoripmc\\/admin\\/grievances.php?status=open\",\"method\":\"POST\",\"timestamp\":1751315299}', '2025-06-30 20:28:19'),
(58, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"grievances.php\",\"url\":\"\\/migoripmc\\/admin\\/grievances.php\",\"referrer\":\"http:\\/\\/localhost\\/migoripmc\\/admin\\/grievances.php?status=open\",\"method\":\"POST\",\"timestamp\":1751315301}', '2025-06-30 20:28:21'),
(59, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"grievances.php\",\"url\":\"\\/migoripmc\\/admin\\/grievances.php?status=open\",\"referrer\":\"http:\\/\\/localhost\\/migoripmc\\/admin\\/grievances.php?status=open\",\"method\":\"POST\",\"timestamp\":1751315303}', '2025-06-30 20:28:23'),
(60, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"grievances.php\",\"url\":\"\\/migoripmc\\/admin\\/grievances.php\",\"referrer\":\"http:\\/\\/localhost\\/migoripmc\\/admin\\/grievances.php?status=open\",\"method\":\"POST\",\"timestamp\":1751315305}', '2025-06-30 20:28:25'),
(61, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"grievances.php\",\"url\":\"\\/migoripmc\\/admin\\/grievances.php?status=open\",\"referrer\":\"http:\\/\\/localhost\\/migoripmc\\/admin\\/grievances.php?status=open\",\"method\":\"POST\",\"timestamp\":1751315307}', '2025-06-30 20:28:27'),
(62, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"grievances.php\",\"url\":\"\\/migoripmc\\/admin\\/grievances.php?status=open\",\"referrer\":\"http:\\/\\/localhost\\/migoripmc\\/admin\\/grievances.php?status=open\",\"method\":\"GET\",\"timestamp\":1751315343}', '2025-06-30 20:29:03'),
(63, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"grievances.php\",\"url\":\"\\/migoripmc\\/admin\\/grievances.php?status=open\",\"referrer\":\"http:\\/\\/localhost\\/migoripmc\\/admin\\/grievances.php?status=open\",\"method\":\"GET\",\"timestamp\":1751315344}', '2025-06-30 20:29:04'),
(64, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"grievances.php\",\"url\":\"\\/migoripmc\\/admin\\/grievances.php\",\"referrer\":\"http:\\/\\/localhost\\/migoripmc\\/admin\\/grievances.php?status=open\",\"method\":\"POST\",\"timestamp\":1751315350}', '2025-06-30 20:29:10'),
(65, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"grievances.php\",\"url\":\"\\/migoripmc\\/admin\\/grievances.php?status=open\",\"referrer\":\"http:\\/\\/localhost\\/migoripmc\\/admin\\/grievances.php?status=open\",\"method\":\"GET\",\"timestamp\":1751315352}', '2025-06-30 20:29:12'),
(66, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"grievances.php\",\"url\":\"\\/migoripmc\\/admin\\/grievances.php\",\"referrer\":\"http:\\/\\/localhost\\/migoripmc\\/admin\\/grievances.php?status=open\",\"method\":\"POST\",\"timestamp\":1751315358}', '2025-06-30 20:29:18'),
(67, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"grievances.php\",\"url\":\"\\/migoripmc\\/admin\\/grievances.php?status=open\",\"referrer\":\"http:\\/\\/localhost\\/migoripmc\\/admin\\/grievances.php?status=open\",\"method\":\"GET\",\"timestamp\":1751315360}', '2025-06-30 20:29:20'),
(68, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"feedback.php\",\"url\":\"\\/migoripmc\\/admin\\/feedback.php\",\"referrer\":\"http:\\/\\/localhost\\/migoripmc\\/admin\\/grievances.php?status=open\",\"method\":\"GET\",\"timestamp\":1751315377}', '2025-06-30 20:29:37'),
(69, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"roles_permissions.php\",\"url\":\"\\/migoripmc\\/admin\\/roles_permissions.php\",\"referrer\":\"http:\\/\\/localhost\\/migoripmc\\/admin\\/\",\"method\":\"GET\",\"timestamp\":1751388015}', '2025-07-01 16:40:15'),
(70, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"roles_permissions.php\",\"url\":\"\\/migoripmc\\/admin\\/roles_permissions.php\",\"referrer\":\"http:\\/\\/localhost\\/migoripmc\\/admin\\/roles_permissions.php\",\"method\":\"POST\",\"timestamp\":1751388033}', '2025-07-01 16:40:33'),
(71, 'permissions_updated', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"target_admin\":2,\"permissions\":[\"dashboard_access\",\"profile_access\",\"manage_feedback\"],\"permission_count\":3}', '2025-07-01 16:40:33'),
(72, 'page_access', 2, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"feedback.php\",\"url\":\"\\/migoripmc\\/admin\\/feedback.php\",\"referrer\":\"http:\\/\\/localhost\\/migoripmc\\/admin\\/\",\"method\":\"GET\",\"timestamp\":1751388061}', '2025-07-01 16:41:01'),
(73, 'page_access', 2, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"feedback.php\",\"url\":\"\\/migoripmc\\/admin\\/feedback.php\",\"referrer\":\"http:\\/\\/localhost\\/migoripmc\\/admin\\/index.php\",\"method\":\"GET\",\"timestamp\":1751388065}', '2025-07-01 16:41:05'),
(74, 'page_access', 2, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"feedback.php\",\"url\":\"\\/migoripmc\\/admin\\/feedback.php\",\"referrer\":\"http:\\/\\/localhost\\/migoripmc\\/admin\\/\",\"method\":\"GET\",\"timestamp\":1751395970}', '2025-07-01 18:52:50'),
(75, 'unauthorized_access_attempt', 2, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"pmc_reports.php\",\"url\":\"\\/migoripmc\\/admin\\/pmc_reports.php\",\"referrer\":\"http:\\/\\/localhost\\/migoripmc\\/admin\\/feedback.php\"}', '2025-07-01 19:01:19'),
(76, 'unauthorized_access_attempt', 2, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"projects.php\",\"url\":\"\\/migoripmc\\/admin\\/projects.php\",\"referrer\":\"http:\\/\\/localhost\\/migoripmc\\/index.php\"}', '2025-07-01 19:01:24'),
(77, 'unauthorized_access_attempt', 2, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"projects.php\",\"url\":\"\\/migoripmc\\/admin\\/projects.php\",\"referrer\":\"http:\\/\\/localhost\\/migoripmc\\/index.php\"}', '2025-07-01 19:01:36'),
(78, 'page_access', 2, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"feedback.php\",\"url\":\"\\/migoripmc\\/admin\\/feedback.php\",\"referrer\":\"http:\\/\\/localhost\\/migoripmc\\/index.php\",\"method\":\"GET\",\"timestamp\":1751396501}', '2025-07-01 19:01:41'),
(79, 'page_access', 2, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"feedback.php\",\"url\":\"\\/migoripmc\\/admin\\/feedback.php\",\"referrer\":\"http:\\/\\/localhost\\/migoripmc\\/admin\\/index.php\",\"method\":\"GET\",\"timestamp\":1751397457}', '2025-07-01 19:17:37'),
(80, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36 Edg/138.0.0.0', '{\"page\":\"roles_permissions.php\",\"url\":\"\\/Migoripmc\\/admin\\/roles_permissions.php\",\"referrer\":\"http:\\/\\/localhost\\/Migoripmc\\/admin\\/\",\"method\":\"GET\",\"timestamp\":1751397569}', '2025-07-01 19:19:29'),
(81, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36 Edg/138.0.0.0', '{\"page\":\"roles_permissions.php\",\"url\":\"\\/Migoripmc\\/admin\\/roles_permissions.php\",\"referrer\":\"http:\\/\\/localhost\\/Migoripmc\\/admin\\/roles_permissions.php\",\"method\":\"POST\",\"timestamp\":1751397611}', '2025-07-01 19:20:11'),
(82, 'permissions_updated', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36 Edg/138.0.0.0', '{\"target_admin\":2,\"permissions\":[\"profile_access\",\"view_projects\",\"create_projects\",\"edit_projects\",\"manage_projects\",\"manage_project_steps\",\"import_data\",\"manage_documents\",\"manage_budgets\",\"manage_feedback\",\"view_reports\",\"view_activity_logs\",\"manage_users\",\"manage_roles\",\"system_settings\"],\"permission_count\":15}', '2025-07-01 19:20:11'),
(83, 'page_access', 2, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"feedback.php\",\"url\":\"\\/migoripmc\\/admin\\/feedback.php\",\"referrer\":\"http:\\/\\/localhost\\/migoripmc\\/admin\\/index.php\",\"method\":\"GET\",\"timestamp\":1751397621}', '2025-07-01 19:20:21'),
(84, 'page_access', 2, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"import_csv.php\",\"url\":\"\\/migoripmc\\/admin\\/import_csv.php\",\"referrer\":\"http:\\/\\/localhost\\/migoripmc\\/admin\\/index.php\",\"method\":\"GET\",\"timestamp\":1751397629}', '2025-07-01 19:20:29'),
(85, 'undefined_page_access', 2, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"csv_import\",\"url\":\"\\/migoripmc\\/admin\\/import_csv.php\"}', '2025-07-01 19:20:29'),
(86, 'page_access', 2, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"create_project.php\",\"url\":\"\\/migoripmc\\/admin\\/create_project.php\",\"referrer\":\"http:\\/\\/localhost\\/migoripmc\\/admin\\/import_csv.php\",\"method\":\"GET\",\"timestamp\":1751397631}', '2025-07-01 19:20:31'),
(87, 'page_access', 2, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"projects.php\",\"url\":\"\\/migoripmc\\/admin\\/projects.php\",\"referrer\":\"http:\\/\\/localhost\\/migoripmc\\/admin\\/index.php?error=insufficient_permissions\",\"method\":\"GET\",\"timestamp\":1751397634}', '2025-07-01 19:20:34'),
(88, 'undefined_page_access', 2, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"manage_projects\",\"url\":\"\\/migoripmc\\/admin\\/projects.php\"}', '2025-07-01 19:20:34'),
(89, 'page_access', 2, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"create_project.php\",\"url\":\"\\/migoripmc\\/admin\\/create_project.php\",\"referrer\":\"http:\\/\\/localhost\\/migoripmc\\/admin\\/projects.php\",\"method\":\"GET\",\"timestamp\":1751397636}', '2025-07-01 19:20:36'),
(90, 'page_access', 2, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"projects.php\",\"url\":\"\\/migoripmc\\/admin\\/projects.php\",\"referrer\":\"http:\\/\\/localhost\\/migoripmc\\/admin\\/index.php?error=insufficient_permissions\",\"method\":\"GET\",\"timestamp\":1751397690}', '2025-07-01 19:21:30'),
(91, 'undefined_page_access', 2, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"manage_projects\",\"url\":\"\\/migoripmc\\/admin\\/projects.php\"}', '2025-07-01 19:21:30'),
(92, 'page_access', 2, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"pmc_reports.php\",\"url\":\"\\/migoripmc\\/admin\\/pmc_reports.php\",\"referrer\":\"http:\\/\\/localhost\\/migoripmc\\/admin\\/budget_management.php\",\"method\":\"GET\",\"timestamp\":1751397721}', '2025-07-01 19:22:01'),
(93, 'page_access', 2, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"feedback.php\",\"url\":\"\\/migoripmc\\/admin\\/feedback.php\",\"referrer\":\"http:\\/\\/localhost\\/migoripmc\\/admin\\/document_manager.php\",\"method\":\"GET\",\"timestamp\":1751397745}', '2025-07-01 19:22:25'),
(94, 'page_access', 2, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"roles_permissions.php\",\"url\":\"\\/migoripmc\\/admin\\/roles_permissions.php\",\"referrer\":\"http:\\/\\/localhost\\/migoripmc\\/admin\\/feedback.php\",\"method\":\"GET\",\"timestamp\":1751397750}', '2025-07-01 19:22:30'),
(95, 'page_access', 2, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"import_csv.php\",\"url\":\"\\/migoripmc\\/admin\\/import_csv.php\",\"referrer\":\"http:\\/\\/localhost\\/migoripmc\\/admin\\/\",\"method\":\"GET\",\"timestamp\":1751398291}', '2025-07-01 19:31:31'),
(96, 'undefined_page_access', 2, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"csv_import\",\"url\":\"\\/migoripmc\\/admin\\/import_csv.php\"}', '2025-07-01 19:31:31'),
(97, 'page_access', 2, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"import_csv.php\",\"url\":\"\\/migoripmc\\/admin\\/import_csv.php\",\"referrer\":\"http:\\/\\/localhost\\/migoripmc\\/admin\\/\",\"method\":\"GET\",\"timestamp\":1751398329}', '2025-07-01 19:32:09'),
(98, 'undefined_page_access', 2, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"csv_import\",\"url\":\"\\/migoripmc\\/admin\\/import_csv.php\"}', '2025-07-01 19:32:09'),
(99, 'page_access', 2, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"create_project.php\",\"url\":\"\\/migoripmc\\/admin\\/create_project.php\",\"referrer\":\"http:\\/\\/localhost\\/migoripmc\\/admin\\/import_csv.php\",\"method\":\"GET\",\"timestamp\":1751398330}', '2025-07-01 19:32:10'),
(100, 'page_access', 2, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"import_csv.php\",\"url\":\"\\/migoripmc\\/admin\\/import_csv.php\",\"referrer\":\"http:\\/\\/localhost\\/migoripmc\\/admin\\/index.php?error=insufficient_permissions\",\"method\":\"GET\",\"timestamp\":1751400556}', '2025-07-01 20:09:16'),
(101, 'undefined_page_access', 2, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"csv_import\",\"url\":\"\\/migoripmc\\/admin\\/import_csv.php\"}', '2025-07-01 20:09:16'),
(102, 'page_access', 2, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"create_project.php\",\"url\":\"\\/migoripmc\\/admin\\/create_project.php\",\"referrer\":\"http:\\/\\/localhost\\/migoripmc\\/admin\\/import_csv.php\",\"method\":\"GET\",\"timestamp\":1751400558}', '2025-07-01 20:09:18'),
(103, 'page_access', 2, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"create_project.php\",\"url\":\"\\/migoripmc\\/admin\\/create_project.php\",\"referrer\":\"http:\\/\\/localhost\\/migoripmc\\/admin\\/import_csv.php\",\"method\":\"GET\",\"timestamp\":1751400674}', '2025-07-01 20:11:14'),
(104, 'page_access', 2, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"projects.php\",\"url\":\"\\/migoripmc\\/admin\\/projects.php\",\"referrer\":\"http:\\/\\/localhost\\/migoripmc\\/admin\\/create_project.php\",\"method\":\"GET\",\"timestamp\":1751400681}', '2025-07-01 20:11:21'),
(105, 'page_access', 2, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"projects.php\",\"url\":\"\\/migoripmc\\/admin\\/projects.php\",\"referrer\":\"http:\\/\\/localhost\\/migoripmc\\/admin\\/create_project.php\",\"method\":\"GET\",\"timestamp\":1751400973}', '2025-07-01 20:16:13'),
(106, 'undefined_page_access', 2, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"manage_projects\",\"url\":\"\\/migoripmc\\/admin\\/projects.php\"}', '2025-07-01 20:16:13'),
(107, 'page_access', 2, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"pmc_reports.php\",\"url\":\"\\/migoripmc\\/admin\\/pmc_reports.php\",\"referrer\":\"http:\\/\\/localhost\\/migoripmc\\/admin\\/budget_management.php\",\"method\":\"GET\",\"timestamp\":1751400991}', '2025-07-01 20:16:31'),
(108, 'page_access', 2, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"feedback.php\",\"url\":\"\\/migoripmc\\/admin\\/feedback.php\",\"referrer\":\"http:\\/\\/localhost\\/migoripmc\\/admin\\/document_manager.php\",\"method\":\"GET\",\"timestamp\":1751401095}', '2025-07-01 20:18:15'),
(109, 'page_access', 2, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"roles_permissions.php\",\"url\":\"\\/migoripmc\\/admin\\/roles_permissions.php\",\"referrer\":\"http:\\/\\/localhost\\/migoripmc\\/admin\\/feedback.php\",\"method\":\"GET\",\"timestamp\":1751401100}', '2025-07-01 20:18:20'),
(110, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"import_csv.php\",\"url\":\"\\/migoripmc\\/admin\\/import_csv.php\",\"referrer\":\"http:\\/\\/localhost\\/migoripmc\\/admin\\/\",\"method\":\"GET\",\"timestamp\":1751401120}', '2025-07-01 20:18:40'),
(111, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"create_project.php\",\"url\":\"\\/migoripmc\\/admin\\/create_project.php\",\"referrer\":\"http:\\/\\/localhost\\/migoripmc\\/admin\\/import_csv.php\",\"method\":\"GET\",\"timestamp\":1751401122}', '2025-07-01 20:18:42'),
(112, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"projects.php\",\"url\":\"\\/migoripmc\\/admin\\/projects.php\",\"referrer\":\"http:\\/\\/localhost\\/migoripmc\\/admin\\/create_project.php\",\"method\":\"GET\",\"timestamp\":1751401123}', '2025-07-01 20:18:43'),
(113, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"pmc_reports.php\",\"url\":\"\\/migoripmc\\/admin\\/pmc_reports.php\",\"referrer\":\"http:\\/\\/localhost\\/migoripmc\\/admin\\/budget_management.php\",\"method\":\"GET\",\"timestamp\":1751401130}', '2025-07-01 20:18:50'),
(114, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"feedback.php\",\"url\":\"\\/migoripmc\\/admin\\/feedback.php\",\"referrer\":\"http:\\/\\/localhost\\/migoripmc\\/admin\\/document_manager.php\",\"method\":\"GET\",\"timestamp\":1751401134}', '2025-07-01 20:18:54'),
(115, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"grievances.php\",\"url\":\"\\/migoripmc\\/admin\\/grievances.php\",\"referrer\":\"http:\\/\\/localhost\\/migoripmc\\/admin\\/feedback.php\",\"method\":\"GET\",\"timestamp\":1751401147}', '2025-07-01 20:19:07'),
(116, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"roles_permissions.php\",\"url\":\"\\/migoripmc\\/admin\\/roles_permissions.php\",\"referrer\":\"http:\\/\\/localhost\\/migoripmc\\/admin\\/grievances.php\",\"method\":\"GET\",\"timestamp\":1751401152}', '2025-07-01 20:19:12'),
(117, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"activity_logs.php\",\"url\":\"\\/migoripmc\\/admin\\/activity_logs.php\",\"referrer\":\"http:\\/\\/localhost\\/migoripmc\\/admin\\/roles_permissions.php\",\"method\":\"GET\",\"timestamp\":1751401156}', '2025-07-01 20:19:16'),
(118, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"projects.php\",\"url\":\"\\/migoripmc\\/admin\\/projects.php\",\"referrer\":\"http:\\/\\/localhost\\/migoripmc\\/admin\\/roles_permissions.php\",\"method\":\"GET\",\"timestamp\":1751401178}', '2025-07-01 20:19:38'),
(119, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"import_csv.php\",\"url\":\"\\/migoripmc\\/admin\\/import_csv.php\",\"referrer\":\"http:\\/\\/localhost\\/migoripmc\\/admin\\/projects.php\",\"method\":\"GET\",\"timestamp\":1751401241}', '2025-07-01 20:20:41'),
(120, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"projects.php\",\"url\":\"\\/migoripmc\\/admin\\/projects.php\",\"referrer\":\"http:\\/\\/localhost\\/migoripmc\\/admin\\/import_csv.php\",\"method\":\"GET\",\"timestamp\":1751401243}', '2025-07-01 20:20:43'),
(121, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"system_settings.php\",\"url\":\"\\/migoripmc\\/admin\\/system_settings.php\",\"referrer\":\"http:\\/\\/localhost\\/migoripmc\\/admin\\/projects.php\",\"method\":\"GET\",\"timestamp\":1751401247}', '2025-07-01 20:20:47'),
(122, 'page_access', 2, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36 Edg/138.0.0.0', '{\"page\":\"import_csv.php\",\"url\":\"\\/Migoripmc\\/admin\\/import_csv.php\",\"referrer\":\"http:\\/\\/localhost\\/Migoripmc\\/admin\\/\",\"method\":\"GET\",\"timestamp\":1751401306}', '2025-07-01 20:21:46'),
(123, 'undefined_page_access', 2, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36 Edg/138.0.0.0', '{\"page\":\"csv_import\",\"url\":\"\\/Migoripmc\\/admin\\/import_csv.php\"}', '2025-07-01 20:21:46'),
(124, 'page_access', 2, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36 Edg/138.0.0.0', '{\"page\":\"create_project.php\",\"url\":\"\\/Migoripmc\\/admin\\/create_project.php\",\"referrer\":\"http:\\/\\/localhost\\/Migoripmc\\/admin\\/import_csv.php\",\"method\":\"GET\",\"timestamp\":1751401308}', '2025-07-01 20:21:48'),
(125, 'page_access', 2, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36 Edg/138.0.0.0', '{\"page\":\"projects.php\",\"url\":\"\\/Migoripmc\\/admin\\/projects.php\",\"referrer\":\"http:\\/\\/localhost\\/Migoripmc\\/admin\\/create_project.php\",\"method\":\"GET\",\"timestamp\":1751401311}', '2025-07-01 20:21:51'),
(126, 'undefined_page_access', 2, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36 Edg/138.0.0.0', '{\"page\":\"manage_projects\",\"url\":\"\\/Migoripmc\\/admin\\/projects.php\"}', '2025-07-01 20:21:51'),
(127, 'page_access', 2, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36 Edg/138.0.0.0', '{\"page\":\"pmc_reports.php\",\"url\":\"\\/Migoripmc\\/admin\\/pmc_reports.php\",\"referrer\":\"http:\\/\\/localhost\\/Migoripmc\\/admin\\/budget_management.php\",\"method\":\"GET\",\"timestamp\":1751401322}', '2025-07-01 20:22:02'),
(128, 'page_access', 2, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36 Edg/138.0.0.0', '{\"page\":\"projects.php\",\"url\":\"\\/Migoripmc\\/admin\\/projects.php\",\"referrer\":\"http:\\/\\/localhost\\/Migoripmc\\/admin\\/pmc_reports.php\",\"method\":\"GET\",\"timestamp\":1751401325}', '2025-07-01 20:22:05'),
(129, 'undefined_page_access', 2, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36 Edg/138.0.0.0', '{\"page\":\"manage_projects\",\"url\":\"\\/Migoripmc\\/admin\\/projects.php\"}', '2025-07-01 20:22:05'),
(130, 'page_access', 2, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36 Edg/138.0.0.0', '{\"page\":\"pmc_reports.php\",\"url\":\"\\/Migoripmc\\/admin\\/pmc_reports.php\",\"referrer\":\"http:\\/\\/localhost\\/Migoripmc\\/admin\\/budget_management.php\",\"method\":\"GET\",\"timestamp\":1751401339}', '2025-07-01 20:22:19'),
(131, 'page_access', 2, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36 Edg/138.0.0.0', '{\"page\":\"feedback.php\",\"url\":\"\\/Migoripmc\\/admin\\/feedback.php\",\"referrer\":\"http:\\/\\/localhost\\/Migoripmc\\/admin\\/document_manager.php\",\"method\":\"GET\",\"timestamp\":1751401345}', '2025-07-01 20:22:25'),
(132, 'page_access', 2, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36 Edg/138.0.0.0', '{\"page\":\"roles_permissions.php\",\"url\":\"\\/Migoripmc\\/admin\\/roles_permissions.php\",\"referrer\":\"http:\\/\\/localhost\\/Migoripmc\\/admin\\/feedback.php\",\"method\":\"GET\",\"timestamp\":1751401349}', '2025-07-01 20:22:29'),
(133, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"roles_permissions.php\",\"url\":\"\\/migoripmc\\/admin\\/roles_permissions.php?error=invalid_admin\",\"referrer\":null,\"method\":\"GET\",\"timestamp\":1751401611}', '2025-07-01 20:26:51'),
(134, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"projects.php\",\"url\":\"\\/migoripmc\\/admin\\/projects.php\",\"referrer\":\"http:\\/\\/localhost\\/migoripmc\\/admin\\/budget_management.php\",\"method\":\"GET\",\"timestamp\":1751401668}', '2025-07-01 20:27:48'),
(135, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"projects.php\",\"url\":\"\\/migoripmc\\/admin\\/projects.php\",\"referrer\":\"http:\\/\\/localhost\\/migoripmc\\/admin\\/budget_management.php\",\"method\":\"GET\",\"timestamp\":1751401675}', '2025-07-01 20:27:55'),
(136, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"projects.php\",\"url\":\"\\/migoripmc\\/admin\\/projects.php\",\"referrer\":\"http:\\/\\/localhost\\/migoripmc\\/admin\\/budget_management.php\",\"method\":\"GET\",\"timestamp\":1751401676}', '2025-07-01 20:27:56');
INSERT INTO `security_logs` (`id`, `event_type`, `admin_id`, `ip_address`, `user_agent`, `details`, `created_at`) VALUES
(137, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"projects.php\",\"url\":\"\\/migoripmc\\/admin\\/projects.php\",\"referrer\":\"http:\\/\\/localhost\\/migoripmc\\/admin\\/budget_management.php\",\"method\":\"GET\",\"timestamp\":1751401676}', '2025-07-01 20:27:56'),
(138, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"projects.php\",\"url\":\"\\/migoripmc\\/admin\\/projects.php\",\"referrer\":\"http:\\/\\/localhost\\/migoripmc\\/admin\\/budget_management.php\",\"method\":\"GET\",\"timestamp\":1751401676}', '2025-07-01 20:27:56'),
(139, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"roles_permissions.php\",\"url\":\"\\/migoripmc\\/admin\\/roles_permissions.php\",\"referrer\":\"http:\\/\\/localhost\\/migoripmc\\/admin\\/projects.php\",\"method\":\"GET\",\"timestamp\":1751401680}', '2025-07-01 20:28:00'),
(140, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"roles_permissions.php\",\"url\":\"\\/migoripmc\\/admin\\/roles_permissions.php\",\"referrer\":\"http:\\/\\/localhost\\/migoripmc\\/admin\\/roles_permissions.php\",\"method\":\"POST\",\"timestamp\":1751401700}', '2025-07-01 20:28:20'),
(141, 'permissions_updated', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"target_admin\":2,\"permissions\":[\"dashboard_access\",\"profile_access\",\"import_data\",\"manage_documents\",\"manage_budgets\",\"manage_feedback\",\"view_reports\",\"view_activity_logs\"],\"permission_count\":8}', '2025-07-01 20:28:20'),
(142, 'page_access', 2, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36 Edg/138.0.0.0', '{\"page\":\"activity_logs.php\",\"url\":\"\\/Migoripmc\\/admin\\/activity_logs.php\",\"referrer\":\"http:\\/\\/localhost\\/Migoripmc\\/admin\\/\",\"method\":\"GET\",\"timestamp\":1751401717}', '2025-07-01 20:28:37'),
(143, 'page_access', 2, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36 Edg/138.0.0.0', '{\"page\":\"activity_logs.php\",\"url\":\"\\/Migoripmc\\/admin\\/activity_logs.php\",\"referrer\":\"http:\\/\\/localhost\\/Migoripmc\\/admin\\/\",\"method\":\"GET\",\"timestamp\":1751401769}', '2025-07-01 20:29:29'),
(144, 'page_access', 2, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36 Edg/138.0.0.0', '{\"page\":\"activity_logs.php\",\"url\":\"\\/Migoripmc\\/admin\\/activity_logs.php\",\"referrer\":\"http:\\/\\/localhost\\/Migoripmc\\/admin\\/\",\"method\":\"GET\",\"timestamp\":1751401771}', '2025-07-01 20:29:31'),
(145, 'page_access', 2, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36 Edg/138.0.0.0', '{\"page\":\"activity_logs.php\",\"url\":\"\\/Migoripmc\\/admin\\/activity_logs.php\",\"referrer\":\"http:\\/\\/localhost\\/Migoripmc\\/admin\\/\",\"method\":\"GET\",\"timestamp\":1751401772}', '2025-07-01 20:29:32'),
(146, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"roles_permissions.php\",\"url\":\"\\/migoripmc\\/admin\\/roles_permissions.php\",\"referrer\":\"http:\\/\\/localhost\\/migoripmc\\/admin\\/roles_permissions.php\",\"method\":\"POST\",\"timestamp\":1751401794}', '2025-07-01 20:29:54'),
(147, 'permissions_updated', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"target_admin\":2,\"permissions\":[\"dashboard_access\",\"profile_access\",\"import_data\",\"manage_documents\",\"manage_budgets\",\"manage_feedback\",\"view_reports\"],\"permission_count\":7}', '2025-07-01 20:29:54'),
(148, 'unauthorized_access_attempt', 2, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36 Edg/138.0.0.0', '{\"page\":\"activity_logs.php\",\"url\":\"\\/Migoripmc\\/admin\\/activity_logs.php\",\"referrer\":\"http:\\/\\/localhost\\/Migoripmc\\/admin\\/\"}', '2025-07-01 20:30:34'),
(149, 'page_access', 2, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36 Edg/138.0.0.0', '{\"page\":\"pmc_reports.php\",\"url\":\"\\/migoripmc\\/admin\\/pmc_reports.php\",\"referrer\":\"http:\\/\\/localhost\\/migoripmc\\/admin\\/budget_management.php\",\"method\":\"GET\",\"timestamp\":1751401872}', '2025-07-01 20:31:12'),
(150, 'page_access', 2, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36 Edg/138.0.0.0', '{\"page\":\"feedback.php\",\"url\":\"\\/migoripmc\\/admin\\/feedback.php\",\"referrer\":\"http:\\/\\/localhost\\/migoripmc\\/admin\\/document_manager.php\",\"method\":\"GET\",\"timestamp\":1751401875}', '2025-07-01 20:31:15'),
(151, 'unauthorized_access_attempt', 2, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36 Edg/138.0.0.0', '{\"page\":\"activity_logs.php\",\"url\":\"\\/migoripmc\\/admin\\/activity_logs.php\",\"referrer\":\"http:\\/\\/localhost\\/migoripmc\\/admin\\/feedback.php\"}', '2025-07-01 20:31:17'),
(152, 'page_access', 2, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36 Edg/138.0.0.0', '{\"page\":\"feedback.php\",\"url\":\"\\/migoripmc\\/admin\\/feedback.php\",\"referrer\":\"http:\\/\\/localhost\\/migoripmc\\/admin\\/document_manager.php\",\"method\":\"GET\",\"timestamp\":1751401884}', '2025-07-01 20:31:24'),
(153, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"roles_permissions.php\",\"url\":\"\\/migoripmc\\/admin\\/roles_permissions.php\",\"referrer\":\"http:\\/\\/localhost\\/migoripmc\\/admin\\/roles_permissions.php\",\"method\":\"POST\",\"timestamp\":1751401902}', '2025-07-01 20:31:42'),
(154, 'permissions_updated', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"target_admin\":2,\"permissions\":[\"dashboard_access\",\"profile_access\",\"import_data\",\"manage_documents\",\"manage_budgets\",\"manage_feedback\"],\"permission_count\":6}', '2025-07-01 20:31:42'),
(155, 'page_access', 2, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36 Edg/138.0.0.0', '{\"page\":\"feedback.php\",\"url\":\"\\/migoripmc\\/admin\\/feedback.php\",\"referrer\":\"http:\\/\\/localhost\\/migoripmc\\/admin\\/document_manager.php\",\"method\":\"GET\",\"timestamp\":1751401906}', '2025-07-01 20:31:46'),
(156, 'page_access', 2, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36 Edg/138.0.0.0', '{\"page\":\"feedback.php\",\"url\":\"\\/migoripmc\\/admin\\/feedback.php\",\"referrer\":\"http:\\/\\/localhost\\/migoripmc\\/admin\\/document_manager.php\",\"method\":\"GET\",\"timestamp\":1751401907}', '2025-07-01 20:31:47'),
(157, 'page_access', 2, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36 Edg/138.0.0.0', '{\"page\":\"feedback.php\",\"url\":\"\\/migoripmc\\/admin\\/feedback.php\",\"referrer\":\"http:\\/\\/localhost\\/migoripmc\\/admin\\/document_manager.php\",\"method\":\"GET\",\"timestamp\":1751401908}', '2025-07-01 20:31:48'),
(158, 'page_access', 2, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36 Edg/138.0.0.0', '{\"page\":\"feedback.php\",\"url\":\"\\/migoripmc\\/admin\\/feedback.php\",\"referrer\":\"http:\\/\\/localhost\\/migoripmc\\/admin\\/document_manager.php\",\"method\":\"GET\",\"timestamp\":1751401908}', '2025-07-01 20:31:48'),
(159, 'page_access', 2, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36 Edg/138.0.0.0', '{\"page\":\"feedback.php\",\"url\":\"\\/migoripmc\\/admin\\/feedback.php\",\"referrer\":\"http:\\/\\/localhost\\/migoripmc\\/admin\\/document_manager.php\",\"method\":\"GET\",\"timestamp\":1751401909}', '2025-07-01 20:31:49'),
(160, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"roles_permissions.php\",\"url\":\"\\/migoripmc\\/admin\\/roles_permissions.php\",\"referrer\":\"http:\\/\\/localhost\\/migoripmc\\/admin\\/roles_permissions.php\",\"method\":\"POST\",\"timestamp\":1751402401}', '2025-07-01 20:40:01'),
(161, 'permissions_updated', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"target_admin\":2,\"permissions\":[\"manage_feedback\"],\"permission_count\":1}', '2025-07-01 20:40:01'),
(162, 'page_access', 2, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36 Edg/138.0.0.0', '{\"page\":\"feedback.php\",\"url\":\"\\/migoripmc\\/admin\\/feedback.php\",\"referrer\":\"http:\\/\\/localhost\\/migoripmc\\/admin\\/document_manager.php\",\"method\":\"GET\",\"timestamp\":1751402410}', '2025-07-01 20:40:10'),
(163, 'page_access', 2, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36 Edg/138.0.0.0', '{\"page\":\"feedback.php\",\"url\":\"\\/migoripmc\\/admin\\/feedback.php\",\"referrer\":\"http:\\/\\/localhost\\/migoripmc\\/admin\\/document_manager.php\",\"method\":\"GET\",\"timestamp\":1751402411}', '2025-07-01 20:40:11'),
(164, 'page_access', 2, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36 Edg/138.0.0.0', '{\"page\":\"feedback.php\",\"url\":\"\\/migoripmc\\/admin\\/feedback.php\",\"referrer\":\"http:\\/\\/localhost\\/migoripmc\\/admin\\/document_manager.php\",\"method\":\"GET\",\"timestamp\":1751402413}', '2025-07-01 20:40:13'),
(165, 'page_access', 2, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36 Edg/138.0.0.0', '{\"page\":\"feedback.php\",\"url\":\"\\/migoripmc\\/admin\\/feedback.php\",\"referrer\":\"http:\\/\\/localhost\\/migoripmc\\/admin\\/document_manager.php\",\"method\":\"GET\",\"timestamp\":1751402508}', '2025-07-01 20:41:48'),
(166, 'page_access', 2, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36 Edg/138.0.0.0', '{\"page\":\"feedback.php\",\"url\":\"\\/migoripmc\\/admin\\/feedback.php\",\"referrer\":\"http:\\/\\/localhost\\/migoripmc\\/admin\\/document_manager.php\",\"method\":\"GET\",\"timestamp\":1751402509}', '2025-07-01 20:41:49'),
(167, 'page_access', 2, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36 Edg/138.0.0.0', '{\"page\":\"feedback.php\",\"url\":\"\\/migoripmc\\/admin\\/feedback.php\",\"referrer\":\"http:\\/\\/localhost\\/migoripmc\\/admin\\/document_manager.php\",\"method\":\"GET\",\"timestamp\":1751402509}', '2025-07-01 20:41:49'),
(168, 'page_access', 2, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36 Edg/138.0.0.0', '{\"page\":\"feedback.php\",\"url\":\"\\/migoripmc\\/admin\\/feedback.php\",\"referrer\":\"http:\\/\\/localhost\\/migoripmc\\/admin\\/document_manager.php\",\"method\":\"GET\",\"timestamp\":1751402509}', '2025-07-01 20:41:49'),
(169, 'page_access', 2, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36 Edg/138.0.0.0', '{\"page\":\"feedback.php\",\"url\":\"\\/migoripmc\\/admin\\/feedback.php\",\"referrer\":\"http:\\/\\/localhost\\/migoripmc\\/admin\\/document_manager.php\",\"method\":\"GET\",\"timestamp\":1751402509}', '2025-07-01 20:41:49'),
(170, 'page_access', 2, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36 Edg/138.0.0.0', '{\"page\":\"feedback.php\",\"url\":\"\\/migoripmc\\/admin\\/feedback.php\",\"referrer\":\"http:\\/\\/localhost\\/migoripmc\\/admin\\/document_manager.php\",\"method\":\"GET\",\"timestamp\":1751402510}', '2025-07-01 20:41:50'),
(171, 'page_access', 2, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36 Edg/138.0.0.0', '{\"page\":\"feedback.php\",\"url\":\"\\/migoripmc\\/admin\\/feedback.php\",\"referrer\":\"http:\\/\\/localhost\\/migoripmc\\/admin\\/document_manager.php\",\"method\":\"GET\",\"timestamp\":1751402510}', '2025-07-01 20:41:50'),
(172, 'page_access', 2, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36 Edg/138.0.0.0', '{\"page\":\"feedback.php\",\"url\":\"\\/migoripmc\\/admin\\/feedback.php\",\"referrer\":\"http:\\/\\/localhost\\/migoripmc\\/admin\\/document_manager.php\",\"method\":\"GET\",\"timestamp\":1751402510}', '2025-07-01 20:41:50'),
(173, 'page_access', 2, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36 Edg/138.0.0.0', '{\"page\":\"feedback.php\",\"url\":\"\\/migoripmc\\/admin\\/feedback.php\",\"referrer\":\"http:\\/\\/localhost\\/migoripmc\\/admin\\/document_manager.php\",\"method\":\"GET\",\"timestamp\":1751402510}', '2025-07-01 20:41:50'),
(174, 'unauthorized_access_attempt', 2, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36 Edg/138.0.0.0', '{\"page\":\"pmc_reports.php\",\"url\":\"\\/migoripmc\\/admin\\/pmc_reports.php\",\"referrer\":\"http:\\/\\/localhost\\/migoripmc\\/admin\\/index.php\"}', '2025-07-01 20:41:53'),
(175, 'page_access', 2, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36 Edg/138.0.0.0', '{\"page\":\"feedback.php\",\"url\":\"\\/migoripmc\\/admin\\/feedback.php\",\"referrer\":\"http:\\/\\/localhost\\/migoripmc\\/admin\\/index.php\",\"method\":\"GET\",\"timestamp\":1751402518}', '2025-07-01 20:41:58'),
(176, 'unauthorized_access_attempt', 2, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36 Edg/138.0.0.0', '{\"page\":\"activity_logs.php\",\"url\":\"\\/migoripmc\\/admin\\/activity_logs.php\",\"referrer\":\"http:\\/\\/localhost\\/migoripmc\\/admin\\/feedback.php\"}', '2025-07-01 20:41:59'),
(177, 'unauthorized_access_attempt', 2, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36 Edg/138.0.0.0', '{\"page\":\"pmc_reports.php\",\"url\":\"\\/migoripmc\\/admin\\/pmc_reports.php\",\"referrer\":\"http:\\/\\/localhost\\/migoripmc\\/admin\\/feedback.php\"}', '2025-07-01 20:42:03'),
(178, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"roles_permissions.php\",\"url\":\"\\/migoripmc\\/admin\\/roles_permissions.php\",\"referrer\":\"http:\\/\\/localhost\\/migoripmc\\/admin\\/roles_permissions.php\",\"method\":\"POST\",\"timestamp\":1751402688}', '2025-07-01 20:44:48'),
(179, 'permissions_updated', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"target_admin\":2,\"permissions\":[\"manage_feedback\"],\"permission_count\":1}', '2025-07-01 20:44:48'),
(180, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"roles_permissions.php\",\"url\":\"\\/migoripmc\\/admin\\/roles_permissions.php\",\"referrer\":\"http:\\/\\/localhost\\/migoripmc\\/admin\\/roles_permissions.php\",\"method\":\"POST\",\"timestamp\":1751402743}', '2025-07-01 20:45:43'),
(181, 'permissions_updated', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"target_admin\":2,\"permissions\":[\"dashboard_access\",\"profile_access\",\"view_projects\",\"create_projects\",\"edit_projects\",\"manage_projects\",\"manage_project_steps\",\"import_data\",\"manage_documents\",\"manage_budgets\",\"manage_feedback\",\"view_reports\",\"view_activity_logs\",\"manage_users\",\"manage_roles\",\"system_settings\"],\"permission_count\":16}', '2025-07-01 20:45:43'),
(182, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"roles_permissions.php\",\"url\":\"\\/migoripmc\\/admin\\/roles_permissions.php\",\"referrer\":\"http:\\/\\/localhost\\/migoripmc\\/admin\\/roles_permissions.php\",\"method\":\"POST\",\"timestamp\":1751402786}', '2025-07-01 20:46:26'),
(183, 'permissions_updated', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"target_admin\":2,\"permissions\":[],\"permission_count\":0}', '2025-07-01 20:46:26'),
(184, 'unauthorized_access_attempt', 2, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36 Edg/138.0.0.0', '{\"page\":\"activity_logs.php\",\"url\":\"\\/migoripmc\\/admin\\/activity_logs.php\",\"referrer\":\"http:\\/\\/localhost\\/migoripmc\\/admin\\/budget_management.php\"}', '2025-07-01 20:48:52'),
(185, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"import_csv.php\",\"url\":\"\\/migoripmc\\/admin\\/import_csv.php\",\"referrer\":\"http:\\/\\/localhost\\/migoripmc\\/admin\\/index.php\",\"method\":\"GET\",\"timestamp\":1751403071}', '2025-07-01 20:51:11'),
(186, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"create_project.php\",\"url\":\"\\/migoripmc\\/admin\\/create_project.php\",\"referrer\":\"http:\\/\\/localhost\\/migoripmc\\/admin\\/import_csv.php\",\"method\":\"GET\",\"timestamp\":1751403073}', '2025-07-01 20:51:13'),
(187, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"projects.php\",\"url\":\"\\/migoripmc\\/admin\\/projects.php\",\"referrer\":\"http:\\/\\/localhost\\/migoripmc\\/admin\\/import_csv.php\",\"method\":\"GET\",\"timestamp\":1751403111}', '2025-07-01 20:51:51'),
(188, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"create_project.php\",\"url\":\"\\/migoripmc\\/admin\\/create_project.php\",\"referrer\":\"http:\\/\\/localhost\\/migoripmc\\/admin\\/projects.php\",\"method\":\"GET\",\"timestamp\":1751403112}', '2025-07-01 20:51:52'),
(189, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"pmc_reports.php\",\"url\":\"\\/migoripmc\\/admin\\/pmc_reports.php\",\"referrer\":\"http:\\/\\/localhost\\/migoripmc\\/admin\\/budget_management.php\",\"method\":\"GET\",\"timestamp\":1751403118}', '2025-07-01 20:51:58'),
(190, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"feedback.php\",\"url\":\"\\/migoripmc\\/admin\\/feedback.php\",\"referrer\":\"http:\\/\\/localhost\\/migoripmc\\/admin\\/pmc_reports.php\",\"method\":\"GET\",\"timestamp\":1751403120}', '2025-07-01 20:52:00'),
(191, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"grievances.php\",\"url\":\"\\/migoripmc\\/admin\\/grievances.php\",\"referrer\":\"http:\\/\\/localhost\\/migoripmc\\/admin\\/feedback.php\",\"method\":\"GET\",\"timestamp\":1751403199}', '2025-07-01 20:53:19'),
(192, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"roles_permissions.php\",\"url\":\"\\/migoripmc\\/admin\\/roles_permissions.php\",\"referrer\":\"http:\\/\\/localhost\\/migoripmc\\/admin\\/grievances.php\",\"method\":\"GET\",\"timestamp\":1751403202}', '2025-07-01 20:53:22'),
(193, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"activity_logs.php\",\"url\":\"\\/migoripmc\\/admin\\/activity_logs.php\",\"referrer\":\"http:\\/\\/localhost\\/migoripmc\\/admin\\/roles_permissions.php\",\"method\":\"GET\",\"timestamp\":1751403206}', '2025-07-01 20:53:26'),
(194, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"activity_logs.php\",\"url\":\"\\/migoripmc\\/admin\\/activity_logs.php\",\"referrer\":\"http:\\/\\/localhost\\/migoripmc\\/admin\\/roles_permissions.php\",\"method\":\"GET\",\"timestamp\":1751404062}', '2025-07-01 21:07:42'),
(195, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"grievances.php\",\"url\":\"\\/migoripmc\\/admin\\/grievances.php\",\"referrer\":\"http:\\/\\/localhost\\/migoripmc\\/admin\\/feedback.php\",\"method\":\"GET\",\"timestamp\":1751404065}', '2025-07-01 21:07:45'),
(196, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"grievances.php\",\"url\":\"\\/migoripmc\\/admin\\/grievances.php\",\"referrer\":\"http:\\/\\/localhost\\/migoripmc\\/admin\\/feedback.php\",\"method\":\"GET\",\"timestamp\":1751404066}', '2025-07-01 21:07:46'),
(197, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"activity_logs.php\",\"url\":\"\\/migoripmc\\/admin\\/activity_logs.php\",\"referrer\":\"http:\\/\\/localhost\\/migoripmc\\/admin\\/roles_permissions.php\",\"method\":\"GET\",\"timestamp\":1751404166}', '2025-07-01 21:09:26'),
(198, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"grievances.php\",\"url\":\"\\/migoripmc\\/admin\\/grievances.php\",\"referrer\":\"http:\\/\\/localhost\\/migoripmc\\/admin\\/feedback.php\",\"method\":\"GET\",\"timestamp\":1751404170}', '2025-07-01 21:09:30'),
(199, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"feedback.php\",\"url\":\"\\/migoripmc\\/admin\\/feedback.php\",\"referrer\":\"http:\\/\\/localhost\\/migoripmc\\/admin\\/pmc_reports.php\",\"method\":\"GET\",\"timestamp\":1751404171}', '2025-07-01 21:09:31'),
(200, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"pmc_reports.php\",\"url\":\"\\/migoripmc\\/admin\\/pmc_reports.php\",\"referrer\":\"http:\\/\\/localhost\\/migoripmc\\/admin\\/budget_management.php\",\"method\":\"GET\",\"timestamp\":1751404172}', '2025-07-01 21:09:32'),
(201, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"import_csv.php\",\"url\":\"\\/migoripmc\\/admin\\/import_csv.php\",\"referrer\":\"http:\\/\\/localhost\\/migoripmc\\/admin\\/index.php\",\"method\":\"GET\",\"timestamp\":1751404879}', '2025-07-01 21:21:19'),
(202, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"create_project.php\",\"url\":\"\\/migoripmc\\/admin\\/create_project.php\",\"referrer\":\"http:\\/\\/localhost\\/migoripmc\\/admin\\/import_csv.php\",\"method\":\"GET\",\"timestamp\":1751404881}', '2025-07-01 21:21:21'),
(203, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"create_project.php\",\"url\":\"\\/migoripmc\\/admin\\/create_project.php\",\"referrer\":\"http:\\/\\/localhost\\/migoripmc\\/admin\\/import_csv.php\",\"method\":\"GET\",\"timestamp\":1751404934}', '2025-07-01 21:22:14'),
(204, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"import_csv.php\",\"url\":\"\\/migoripmc\\/admin\\/import_csv.php\",\"referrer\":\"http:\\/\\/localhost\\/migoripmc\\/admin\\/create_project.php\",\"method\":\"GET\",\"timestamp\":1751404937}', '2025-07-01 21:22:17'),
(205, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"create_project.php\",\"url\":\"\\/migoripmc\\/admin\\/create_project.php\",\"referrer\":\"http:\\/\\/localhost\\/migoripmc\\/admin\\/import_csv.php\",\"method\":\"GET\",\"timestamp\":1751404938}', '2025-07-01 21:22:18'),
(206, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"projects.php\",\"url\":\"\\/migoripmc\\/admin\\/projects.php\",\"referrer\":\"http:\\/\\/localhost\\/migoripmc\\/admin\\/create_project.php\",\"method\":\"GET\",\"timestamp\":1751404940}', '2025-07-01 21:22:20'),
(207, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"pmc_reports.php\",\"url\":\"\\/migoripmc\\/admin\\/pmc_reports.php\",\"referrer\":\"http:\\/\\/localhost\\/migoripmc\\/admin\\/budget_management.php\",\"method\":\"GET\",\"timestamp\":1751404943}', '2025-07-01 21:22:23'),
(208, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"projects.php\",\"url\":\"\\/migoripmc\\/admin\\/projects.php\",\"referrer\":\"http:\\/\\/localhost\\/migoripmc\\/admin\\/document_manager.php\",\"method\":\"GET\",\"timestamp\":1751405068}', '2025-07-01 21:24:28'),
(209, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"projects.php\",\"url\":\"\\/migoripmc\\/admin\\/projects.php\",\"referrer\":\"http:\\/\\/localhost\\/migoripmc\\/admin\\/document_manager.php\",\"method\":\"GET\",\"timestamp\":1751405095}', '2025-07-01 21:24:55'),
(210, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"import_csv.php\",\"url\":\"\\/migoripmc\\/admin\\/import_csv.php\",\"referrer\":\"http:\\/\\/localhost\\/migoripmc\\/admin\\/index.php\",\"method\":\"GET\",\"timestamp\":1751405099}', '2025-07-01 21:24:59'),
(211, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"create_project.php\",\"url\":\"\\/migoripmc\\/admin\\/create_project.php\",\"referrer\":\"http:\\/\\/localhost\\/migoripmc\\/admin\\/import_csv.php\",\"method\":\"GET\",\"timestamp\":1751405100}', '2025-07-01 21:25:00'),
(212, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"projects.php\",\"url\":\"\\/migoripmc\\/admin\\/projects.php\",\"referrer\":\"http:\\/\\/localhost\\/migoripmc\\/admin\\/create_project.php\",\"method\":\"GET\",\"timestamp\":1751405102}', '2025-07-01 21:25:02'),
(213, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"pmc_reports.php\",\"url\":\"\\/migoripmc\\/admin\\/pmc_reports.php\",\"referrer\":\"http:\\/\\/localhost\\/migoripmc\\/admin\\/budget_management.php\",\"method\":\"GET\",\"timestamp\":1751405105}', '2025-07-01 21:25:05'),
(214, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"feedback.php\",\"url\":\"\\/migoripmc\\/admin\\/feedback.php\",\"referrer\":\"http:\\/\\/localhost\\/migoripmc\\/admin\\/document_manager.php\",\"method\":\"GET\",\"timestamp\":1751405111}', '2025-07-01 21:25:11'),
(215, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"roles_permissions.php\",\"url\":\"\\/migoripmc\\/admin\\/roles_permissions.php\",\"referrer\":\"http:\\/\\/localhost\\/migoripmc\\/admin\\/feedback.php\",\"method\":\"GET\",\"timestamp\":1751405119}', '2025-07-01 21:25:19'),
(216, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"activity_logs.php\",\"url\":\"\\/migoripmc\\/admin\\/activity_logs.php\",\"referrer\":\"http:\\/\\/localhost\\/migoripmc\\/admin\\/roles_permissions.php\",\"method\":\"GET\",\"timestamp\":1751405124}', '2025-07-01 21:25:24'),
(217, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"system_settings.php\",\"url\":\"\\/migoripmc\\/admin\\/system_settings.php\",\"referrer\":\"http:\\/\\/localhost\\/migoripmc\\/admin\\/activity_logs.php\",\"method\":\"GET\",\"timestamp\":1751405135}', '2025-07-01 21:25:35'),
(218, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"system_settings.php\",\"url\":\"\\/migoripmc\\/admin\\/system_settings.php\",\"referrer\":\"http:\\/\\/localhost\\/migoripmc\\/admin\\/activity_logs.php\",\"method\":\"GET\",\"timestamp\":1751407311}', '2025-07-01 22:01:51'),
(219, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"activity_logs.php\",\"url\":\"\\/migoripmc\\/admin\\/activity_logs.php\",\"referrer\":\"http:\\/\\/localhost\\/migoripmc\\/admin\\/system_settings.php\",\"method\":\"GET\",\"timestamp\":1751407340}', '2025-07-01 22:02:20'),
(220, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"grievances.php\",\"url\":\"\\/migoripmc\\/admin\\/grievances.php\",\"referrer\":\"http:\\/\\/localhost\\/migoripmc\\/admin\\/activity_logs.php\",\"method\":\"GET\",\"timestamp\":1751407361}', '2025-07-01 22:02:41'),
(221, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"roles_permissions.php\",\"url\":\"\\/migoripmc\\/admin\\/roles_permissions.php\",\"referrer\":\"http:\\/\\/localhost\\/migoripmc\\/admin\\/grievances.php\",\"method\":\"GET\",\"timestamp\":1751407367}', '2025-07-01 22:02:47'),
(222, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"roles_permissions.php\",\"url\":\"\\/migoripmc\\/admin\\/roles_permissions.php\",\"referrer\":\"http:\\/\\/localhost\\/migoripmc\\/admin\\/grievances.php\",\"method\":\"GET\",\"timestamp\":1751407501}', '2025-07-01 22:05:01'),
(223, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"roles_permissions.php\",\"url\":\"\\/migoripmc\\/admin\\/roles_permissions.php\",\"referrer\":\"http:\\/\\/localhost\\/migoripmc\\/admin\\/roles_permissions.php\",\"method\":\"POST\",\"timestamp\":1751407562}', '2025-07-01 22:06:02'),
(224, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"roles_permissions.php\",\"url\":\"\\/Migoripmc\\/admin\\/roles_permissions.php\",\"referrer\":null,\"method\":\"GET\",\"timestamp\":1751407566}', '2025-07-01 22:06:06'),
(225, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"roles_permissions.php\",\"url\":\"\\/Migoripmc\\/admin\\/roles_permissions.php\",\"referrer\":\"http:\\/\\/localhost\\/Migoripmc\\/admin\\/roles_permissions.php\",\"method\":\"POST\",\"timestamp\":1751407588}', '2025-07-01 22:06:28'),
(226, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"roles_permissions.php\",\"url\":\"\\/Migoripmc\\/admin\\/roles_permissions.php\",\"referrer\":null,\"method\":\"GET\",\"timestamp\":1751407590}', '2025-07-01 22:06:30'),
(227, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"roles_permissions.php\",\"url\":\"\\/Migoripmc\\/admin\\/roles_permissions.php\",\"referrer\":null,\"method\":\"GET\",\"timestamp\":1751407657}', '2025-07-01 22:07:37'),
(228, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"roles_permissions.php\",\"url\":\"\\/Migoripmc\\/admin\\/roles_permissions.php\",\"referrer\":\"http:\\/\\/localhost\\/Migoripmc\\/admin\\/roles_permissions.php\",\"method\":\"POST\",\"timestamp\":1751407668}', '2025-07-01 22:07:48'),
(229, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"roles_permissions.php\",\"url\":\"\\/Migoripmc\\/admin\\/roles_permissions.php\",\"referrer\":null,\"method\":\"GET\",\"timestamp\":1751407670}', '2025-07-01 22:07:50'),
(230, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"projects.php\",\"url\":\"\\/Migoripmc\\/admin\\/projects.php\",\"referrer\":\"http:\\/\\/localhost\\/Migoripmc\\/admin\\/roles_permissions.php\",\"method\":\"GET\",\"timestamp\":1751407690}', '2025-07-01 22:08:10'),
(231, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"projects.php\",\"url\":\"\\/Migoripmc\\/admin\\/projects.php\",\"referrer\":\"http:\\/\\/localhost\\/Migoripmc\\/admin\\/projects.php\",\"method\":\"GET\",\"timestamp\":1751407703}', '2025-07-01 22:08:23'),
(232, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"projects.php\",\"url\":\"\\/Migoripmc\\/admin\\/projects.php\",\"referrer\":\"http:\\/\\/localhost\\/Migoripmc\\/admin\\/projects.php\",\"method\":\"GET\",\"timestamp\":1751407705}', '2025-07-01 22:08:25'),
(233, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"projects.php\",\"url\":\"\\/Migoripmc\\/admin\\/projects.php\",\"referrer\":\"http:\\/\\/localhost\\/Migoripmc\\/admin\\/projects.php\",\"method\":\"GET\",\"timestamp\":1751407706}', '2025-07-01 22:08:26'),
(234, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"feedback.php\",\"url\":\"\\/Migoripmc\\/admin\\/feedback.php\",\"referrer\":\"http:\\/\\/localhost\\/Migoripmc\\/admin\\/projects.php\",\"method\":\"GET\",\"timestamp\":1751407716}', '2025-07-01 22:08:36'),
(235, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"roles_permissions.php\",\"url\":\"\\/Migoripmc\\/admin\\/roles_permissions.php\",\"referrer\":\"http:\\/\\/localhost\\/Migoripmc\\/admin\\/feedback.php\",\"method\":\"GET\",\"timestamp\":1751407744}', '2025-07-01 22:09:04'),
(236, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"roles_permissions.php\",\"url\":\"\\/Migoripmc\\/admin\\/roles_permissions.php\",\"referrer\":null,\"method\":\"GET\",\"timestamp\":1751408586}', '2025-07-01 22:23:06'),
(237, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"roles_permissions.php\",\"url\":\"\\/Migoripmc\\/admin\\/roles_permissions.php\",\"referrer\":\"http:\\/\\/localhost\\/Migoripmc\\/admin\\/roles_permissions.php\",\"method\":\"POST\",\"timestamp\":1751408623}', '2025-07-01 22:23:43'),
(238, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"feedback.php\",\"url\":\"\\/migoripmc\\/admin\\/feedback.php\",\"referrer\":\"http:\\/\\/localhost\\/migoripmc\\/admin\\/dashboard.php\",\"method\":\"GET\",\"timestamp\":1751441642}', '2025-07-02 07:34:02'),
(239, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"grievances.php\",\"url\":\"\\/migoripmc\\/admin\\/grievances.php\",\"referrer\":\"http:\\/\\/localhost\\/migoripmc\\/admin\\/feedback.php\",\"method\":\"GET\",\"timestamp\":1751441653}', '2025-07-02 07:34:13'),
(240, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"grievances.php\",\"url\":\"\\/migoripmc\\/admin\\/grievances.php\",\"referrer\":\"http:\\/\\/localhost\\/migoripmc\\/admin\\/grievances.php\",\"method\":\"POST\",\"timestamp\":1751441726}', '2025-07-02 07:35:26'),
(241, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"grievances.php\",\"url\":\"\\/migoripmc\\/admin\\/grievances.php\",\"referrer\":\"http:\\/\\/localhost\\/migoripmc\\/admin\\/grievances.php\",\"method\":\"GET\",\"timestamp\":1751441728}', '2025-07-02 07:35:28'),
(242, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"feedback.php\",\"url\":\"\\/migoripmc\\/admin\\/feedback.php?info=no_grievances\",\"referrer\":\"http:\\/\\/localhost\\/migoripmc\\/admin\\/grievances.php\",\"method\":\"GET\",\"timestamp\":1751441728}', '2025-07-02 07:35:28'),
(243, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"feedback.php\",\"url\":\"\\/migoripmc\\/admin\\/feedback.php\",\"referrer\":\"http:\\/\\/localhost\\/migoripmc\\/admin\\/feedback.php?info=no_grievances\",\"method\":\"POST\",\"timestamp\":1751441822}', '2025-07-02 07:37:02'),
(244, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"feedback.php\",\"url\":\"\\/migoripmc\\/admin\\/feedback.php?info=no_grievances\",\"referrer\":\"http:\\/\\/localhost\\/migoripmc\\/admin\\/feedback.php?info=no_grievances\",\"method\":\"GET\",\"timestamp\":1751441822}', '2025-07-02 07:37:02'),
(245, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"import_csv.php\",\"url\":\"\\/migoripmc\\/admin\\/import_csv.php\",\"referrer\":\"http:\\/\\/localhost\\/migoripmc\\/admin\\/feedback.php?info=no_grievances\",\"method\":\"GET\",\"timestamp\":1751442057}', '2025-07-02 07:40:57'),
(246, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"create_project.php\",\"url\":\"\\/migoripmc\\/admin\\/create_project.php\",\"referrer\":\"http:\\/\\/localhost\\/migoripmc\\/admin\\/import_csv.php\",\"method\":\"GET\",\"timestamp\":1751442060}', '2025-07-02 07:41:00'),
(247, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"create_project.php\",\"url\":\"\\/migoripmc\\/admin\\/create_project.php\",\"referrer\":\"http:\\/\\/localhost\\/migoripmc\\/admin\\/import_csv.php\",\"method\":\"GET\",\"timestamp\":1751442100}', '2025-07-02 07:41:40'),
(248, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"create_project.php\",\"url\":\"\\/migoripmc\\/admin\\/create_project.php\",\"referrer\":\"http:\\/\\/localhost\\/migoripmc\\/admin\\/create_project.php\",\"method\":\"GET\",\"timestamp\":1751442102}', '2025-07-02 07:41:42'),
(249, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"pmc_reports.php\",\"url\":\"\\/migoripmc\\/admin\\/pmc_reports.php\",\"referrer\":\"http:\\/\\/localhost\\/migoripmc\\/admin\\/budget_management.php\",\"method\":\"GET\",\"timestamp\":1751442120}', '2025-07-02 07:42:00'),
(250, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"document_manager.php\",\"url\":\"\\/migoripmc\\/admin\\/document_manager.php\",\"referrer\":\"http:\\/\\/localhost\\/migoripmc\\/admin\\/pmc_reports.php\",\"method\":\"GET\",\"timestamp\":1751442162}', '2025-07-02 07:42:42'),
(251, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"feedback.php\",\"url\":\"\\/migoripmc\\/admin\\/feedback.php\",\"referrer\":\"http:\\/\\/localhost\\/migoripmc\\/admin\\/document_manager.php\",\"method\":\"GET\",\"timestamp\":1751442191}', '2025-07-02 07:43:11'),
(252, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"grievances.php\",\"url\":\"\\/migoripmc\\/admin\\/grievances.php\",\"referrer\":\"http:\\/\\/localhost\\/migoripmc\\/admin\\/feedback.php\",\"method\":\"GET\",\"timestamp\":1751442198}', '2025-07-02 07:43:18'),
(253, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"grievances.php\",\"url\":\"\\/migoripmc\\/admin\\/grievances.php\",\"referrer\":\"http:\\/\\/localhost\\/migoripmc\\/admin\\/grievances.php\",\"method\":\"POST\",\"timestamp\":1751442208}', '2025-07-02 07:43:28'),
(254, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"grievances.php\",\"url\":\"\\/migoripmc\\/admin\\/grievances.php\",\"referrer\":\"http:\\/\\/localhost\\/migoripmc\\/admin\\/grievances.php\",\"method\":\"GET\",\"timestamp\":1751442209}', '2025-07-02 07:43:29'),
(255, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"feedback.php\",\"url\":\"\\/migoripmc\\/admin\\/feedback.php?info=no_grievances\",\"referrer\":\"http:\\/\\/localhost\\/migoripmc\\/admin\\/grievances.php\",\"method\":\"GET\",\"timestamp\":1751442209}', '2025-07-02 07:43:29'),
(256, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"roles_permissions.php\",\"url\":\"\\/migoripmc\\/admin\\/roles_permissions.php\",\"referrer\":\"http:\\/\\/localhost\\/migoripmc\\/admin\\/feedback.php?info=no_grievances\",\"method\":\"GET\",\"timestamp\":1751442248}', '2025-07-02 07:44:08'),
(257, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"activity_logs.php\",\"url\":\"\\/migoripmc\\/admin\\/activity_logs.php\",\"referrer\":\"http:\\/\\/localhost\\/migoripmc\\/admin\\/roles_permissions.php\",\"method\":\"GET\",\"timestamp\":1751442318}', '2025-07-02 07:45:18'),
(258, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"system_settings.php\",\"url\":\"\\/migoripmc\\/admin\\/system_settings.php\",\"referrer\":\"http:\\/\\/localhost\\/migoripmc\\/admin\\/activity_logs.php\",\"method\":\"GET\",\"timestamp\":1751442329}', '2025-07-02 07:45:29'),
(259, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"pmc_reports.php\",\"url\":\"\\/migoripmc\\/admin\\/pmc_reports.php\",\"referrer\":\"http:\\/\\/localhost\\/migoripmc\\/admin\\/budget_management.php\",\"method\":\"GET\",\"timestamp\":1751443194}', '2025-07-02 07:59:54'),
(260, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"import_csv.php\",\"url\":\"\\/migoripmc\\/admin\\/import_csv.php\",\"referrer\":\"http:\\/\\/localhost\\/migoripmc\\/admin\\/pmc_reports.php\",\"method\":\"GET\",\"timestamp\":1751443249}', '2025-07-02 08:00:49'),
(261, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"create_project.php\",\"url\":\"\\/migoripmc\\/admin\\/create_project.php\",\"referrer\":\"http:\\/\\/localhost\\/migoripmc\\/admin\\/import_csv.php\",\"method\":\"GET\",\"timestamp\":1751443252}', '2025-07-02 08:00:52'),
(262, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"projects.php\",\"url\":\"\\/migoripmc\\/admin\\/projects.php\",\"referrer\":\"http:\\/\\/localhost\\/migoripmc\\/admin\\/create_project.php\",\"method\":\"GET\",\"timestamp\":1751443255}', '2025-07-02 08:00:55'),
(263, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"projects.php\",\"url\":\"\\/migoripmc\\/admin\\/projects.php\",\"referrer\":\"http:\\/\\/localhost\\/migoripmc\\/admin\\/create_project.php\",\"method\":\"GET\",\"timestamp\":1751443282}', '2025-07-02 08:01:22'),
(264, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"document_manager.php\",\"url\":\"\\/migoripmc\\/admin\\/document_manager.php\",\"referrer\":\"http:\\/\\/localhost\\/migoripmc\\/admin\\/budget_management.php\",\"method\":\"GET\",\"timestamp\":1751443302}', '2025-07-02 08:01:42'),
(265, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"feedback.php\",\"url\":\"\\/migoripmc\\/admin\\/feedback.php\",\"referrer\":\"http:\\/\\/localhost\\/migoripmc\\/admin\\/document_manager.php\",\"method\":\"GET\",\"timestamp\":1751443395}', '2025-07-02 08:03:15'),
(266, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"roles_permissions.php\",\"url\":\"\\/migoripmc\\/admin\\/roles_permissions.php\",\"referrer\":\"http:\\/\\/localhost\\/migoripmc\\/admin\\/feedback.php\",\"method\":\"GET\",\"timestamp\":1751443430}', '2025-07-02 08:03:50'),
(267, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"activity_logs.php\",\"url\":\"\\/migoripmc\\/admin\\/activity_logs.php\",\"referrer\":\"http:\\/\\/localhost\\/migoripmc\\/admin\\/roles_permissions.php\",\"method\":\"GET\",\"timestamp\":1751443438}', '2025-07-02 08:03:58'),
(268, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"system_settings.php\",\"url\":\"\\/migoripmc\\/admin\\/system_settings.php\",\"referrer\":\"http:\\/\\/localhost\\/migoripmc\\/admin\\/activity_logs.php\",\"method\":\"GET\",\"timestamp\":1751443471}', '2025-07-02 08:04:31'),
(269, 'unauthorized_access_attempt', 2, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36 Edg/138.0.0.0', '{\"page\":\"projects.php\",\"url\":\"\\/Migoripmc\\/admin\\/projects.php\",\"referrer\":null}', '2025-07-02 08:05:34');
INSERT INTO `security_logs` (`id`, `event_type`, `admin_id`, `ip_address`, `user_agent`, `details`, `created_at`) VALUES
(270, 'unauthorized_access_attempt', 2, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36 Edg/138.0.0.0', '{\"page\":\"projects.php\",\"url\":\"\\/migoripmc\\/admin\\/projects.php\",\"referrer\":\"http:\\/\\/localhost\\/Migoripmc\\/index.php\"}', '2025-07-02 08:05:40'),
(271, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"roles_permissions.php\",\"url\":\"\\/migoripmc\\/admin\\/roles_permissions.php\",\"referrer\":\"http:\\/\\/localhost\\/migoripmc\\/admin\\/dashboard.php\",\"method\":\"GET\",\"timestamp\":1751443570}', '2025-07-02 08:06:10'),
(272, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"roles_permissions.php\",\"url\":\"\\/migoripmc\\/admin\\/roles_permissions.php\",\"referrer\":\"http:\\/\\/localhost\\/migoripmc\\/admin\\/roles_permissions.php\",\"method\":\"POST\",\"timestamp\":1751443622}', '2025-07-02 08:07:02'),
(273, 'permissions_updated', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"target_admin\":2,\"permissions\":[\"dashboard_access\",\"create_projects\",\"view_projects\"],\"permission_count\":3}', '2025-07-02 08:07:02'),
(274, 'unauthorized_access_attempt', 2, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36 Edg/138.0.0.0', '{\"page\":\"import_csv.php\",\"url\":\"\\/migoripmc\\/admin\\/import_csv.php\",\"referrer\":\"http:\\/\\/localhost\\/migoripmc\\/admin\\/index.php\"}', '2025-07-02 08:07:16'),
(275, 'page_access', 2, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36 Edg/138.0.0.0', '{\"page\":\"create_project.php\",\"url\":\"\\/migoripmc\\/admin\\/create_project.php\",\"referrer\":\"http:\\/\\/localhost\\/migoripmc\\/admin\\/index.php\",\"method\":\"GET\",\"timestamp\":1751443642}', '2025-07-02 08:07:22'),
(276, 'page_access', 2, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36 Edg/138.0.0.0', '{\"page\":\"projects.php\",\"url\":\"\\/migoripmc\\/admin\\/projects.php\",\"referrer\":\"http:\\/\\/localhost\\/migoripmc\\/admin\\/create_project.php\",\"method\":\"GET\",\"timestamp\":1751443646}', '2025-07-02 08:07:26'),
(277, 'unauthorized_access_attempt', 2, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36 Edg/138.0.0.0', '{\"page\":\"manage_project.php\",\"url\":\"\\/migoripmc\\/admin\\/manage_project.php?id=17&created=1\",\"referrer\":\"http:\\/\\/localhost\\/migoripmc\\/admin\\/create_project.php\"}', '2025-07-02 08:12:21'),
(278, 'page_access', 2, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36 Edg/138.0.0.0', '{\"page\":\"create_project.php\",\"url\":\"\\/migoripmc\\/admin\\/create_project.php\",\"referrer\":\"http:\\/\\/localhost\\/migoripmc\\/admin\\/index.php\",\"method\":\"GET\",\"timestamp\":1751444017}', '2025-07-02 08:13:37'),
(279, 'unauthorized_access_attempt', 2, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36 Edg/138.0.0.0', '{\"page\":\"import_csv.php\",\"url\":\"\\/migoripmc\\/admin\\/import_csv.php\",\"referrer\":\"http:\\/\\/localhost\\/migoripmc\\/admin\\/dashboard.php\"}', '2025-07-02 08:28:42'),
(280, 'unauthorized_access_attempt', 2, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36 Edg/138.0.0.0', '{\"page\":\"manage_project.php\",\"url\":\"\\/migoripmc\\/admin\\/manage_project.php?id=18&created=1\",\"referrer\":\"http:\\/\\/localhost\\/migoripmc\\/admin\\/create_project.php\"}', '2025-07-02 08:36:46'),
(281, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"import_csv.php\",\"url\":\"\\/migoripmc\\/admin\\/import_csv.php\",\"referrer\":\"http:\\/\\/localhost\\/migoripmc\\/admin\\/dashboard.php\",\"method\":\"GET\",\"timestamp\":1751450624}', '2025-07-02 10:03:44'),
(282, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"create_project.php\",\"url\":\"\\/migoripmc\\/admin\\/create_project.php\",\"referrer\":\"http:\\/\\/localhost\\/migoripmc\\/admin\\/import_csv.php\",\"method\":\"GET\",\"timestamp\":1751450628}', '2025-07-02 10:03:48'),
(283, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"projects.php\",\"url\":\"\\/migoripmc\\/admin\\/projects.php\",\"referrer\":\"http:\\/\\/localhost\\/migoripmc\\/admin\\/create_project.php\",\"method\":\"GET\",\"timestamp\":1751450630}', '2025-07-02 10:03:50'),
(284, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"projects.php\",\"url\":\"\\/migoripmc\\/admin\\/projects.php\",\"referrer\":\"http:\\/\\/localhost\\/migoripmc\\/admin\\/create_project.php\",\"method\":\"GET\",\"timestamp\":1751450672}', '2025-07-02 10:04:32'),
(285, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"projects.php\",\"url\":\"\\/migoripmc\\/admin\\/projects.php\",\"referrer\":\"http:\\/\\/localhost\\/migoripmc\\/admin\\/projects.php\",\"method\":\"GET\",\"timestamp\":1751450691}', '2025-07-02 10:04:51'),
(286, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"manage_project.php\",\"url\":\"\\/migoripmc\\/admin\\/manage_project.php?id=18\",\"referrer\":\"http:\\/\\/localhost\\/migoripmc\\/admin\\/projects.php\",\"method\":\"GET\",\"timestamp\":1751450700}', '2025-07-02 10:05:00'),
(287, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"manage_project.php\",\"url\":\"\\/migoripmc\\/admin\\/manage_project.php?id=18\",\"referrer\":\"http:\\/\\/localhost\\/migoripmc\\/admin\\/manage_project.php?id=18\",\"method\":\"POST\",\"timestamp\":1751450714}', '2025-07-02 10:05:14'),
(288, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"manage_project.php\",\"url\":\"\\/migoripmc\\/admin\\/manage_project.php?id=18\",\"referrer\":\"http:\\/\\/localhost\\/migoripmc\\/admin\\/manage_project.php?id=18\",\"method\":\"POST\",\"timestamp\":1751450724}', '2025-07-02 10:05:24'),
(289, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"manage_project.php\",\"url\":\"\\/migoripmc\\/admin\\/manage_project.php?id=18\",\"referrer\":\"http:\\/\\/localhost\\/migoripmc\\/admin\\/manage_project.php?id=18\",\"method\":\"POST\",\"timestamp\":1751450735}', '2025-07-02 10:05:35'),
(290, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"manage_project.php\",\"url\":\"\\/migoripmc\\/admin\\/manage_project.php?id=18\",\"referrer\":\"http:\\/\\/localhost\\/migoripmc\\/admin\\/manage_project.php?id=18\",\"method\":\"POST\",\"timestamp\":1751450744}', '2025-07-02 10:05:44'),
(291, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"manage_project.php\",\"url\":\"\\/migoripmc\\/admin\\/manage_project.php?id=18\",\"referrer\":\"http:\\/\\/localhost\\/migoripmc\\/admin\\/manage_project.php?id=18\",\"method\":\"POST\",\"timestamp\":1751450750}', '2025-07-02 10:05:50'),
(292, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"projects.php\",\"url\":\"\\/migoripmc\\/admin\\/projects.php\",\"referrer\":\"http:\\/\\/localhost\\/migoripmc\\/admin\\/manage_project.php?id=18\",\"method\":\"GET\",\"timestamp\":1751450762}', '2025-07-02 10:06:02'),
(293, 'unauthorized_access_attempt', 2, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36 Edg/138.0.0.0', '{\"page\":\"import_csv.php\",\"url\":\"\\/migoripmc\\/admin\\/import_csv.php\",\"referrer\":\"http:\\/\\/localhost\\/migoripmc\\/admin\\/\"}', '2025-07-02 10:07:00'),
(294, 'page_access', 2, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36 Edg/138.0.0.0', '{\"page\":\"create_project.php\",\"url\":\"\\/migoripmc\\/admin\\/create_project.php\",\"referrer\":\"http:\\/\\/localhost\\/migoripmc\\/admin\\/\",\"method\":\"GET\",\"timestamp\":1751450824}', '2025-07-02 10:07:04'),
(295, 'page_access', 2, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36 Edg/138.0.0.0', '{\"page\":\"projects.php\",\"url\":\"\\/migoripmc\\/admin\\/projects.php\",\"referrer\":\"http:\\/\\/localhost\\/migoripmc\\/admin\\/create_project.php\",\"method\":\"GET\",\"timestamp\":1751450826}', '2025-07-02 10:07:06'),
(296, 'unauthorized_access_attempt', 2, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36 Edg/138.0.0.0', '{\"page\":\"manage_project.php\",\"url\":\"\\/migoripmc\\/admin\\/manage_project.php?id=18\",\"referrer\":\"http:\\/\\/localhost\\/migoripmc\\/admin\\/projects.php\"}', '2025-07-02 10:07:14'),
(297, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"pmc_reports.php\",\"url\":\"\\/migoripmc\\/admin\\/pmc_reports.php\",\"referrer\":\"http:\\/\\/localhost\\/migoripmc\\/admin\\/budget_management.php\",\"method\":\"GET\",\"timestamp\":1751450853}', '2025-07-02 10:07:33'),
(298, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"document_manager.php\",\"url\":\"\\/migoripmc\\/admin\\/document_manager.php\",\"referrer\":\"http:\\/\\/localhost\\/migoripmc\\/admin\\/pmc_reports.php\",\"method\":\"GET\",\"timestamp\":1751450858}', '2025-07-02 10:07:38'),
(299, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"feedback.php\",\"url\":\"\\/migoripmc\\/admin\\/feedback.php\",\"referrer\":\"http:\\/\\/localhost\\/migoripmc\\/admin\\/document_manager.php\",\"method\":\"GET\",\"timestamp\":1751450867}', '2025-07-02 10:07:47'),
(300, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"feedback.php\",\"url\":\"\\/migoripmc\\/admin\\/feedback.php\",\"referrer\":\"http:\\/\\/localhost\\/migoripmc\\/admin\\/feedback.php\",\"method\":\"POST\",\"timestamp\":1751450881}', '2025-07-02 10:08:01'),
(301, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"feedback.php\",\"url\":\"\\/Migoripmc\\/admin\\/feedback.php\",\"referrer\":null,\"method\":\"GET\",\"timestamp\":1751450885}', '2025-07-02 10:08:05'),
(302, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"feedback.php\",\"url\":\"\\/Migoripmc\\/admin\\/feedback.php\",\"referrer\":\"http:\\/\\/localhost\\/Migoripmc\\/admin\\/feedback.php\",\"method\":\"POST\",\"timestamp\":1751450894}', '2025-07-02 10:08:14'),
(303, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"feedback.php\",\"url\":\"\\/Migoripmc\\/admin\\/feedback.php\",\"referrer\":\"http:\\/\\/localhost\\/Migoripmc\\/admin\\/feedback.php\",\"method\":\"GET\",\"timestamp\":1751450894}', '2025-07-02 10:08:14'),
(304, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"feedback.php\",\"url\":\"\\/Migoripmc\\/admin\\/feedback.php\",\"referrer\":\"http:\\/\\/localhost\\/Migoripmc\\/admin\\/feedback.php\",\"method\":\"POST\",\"timestamp\":1751450909}', '2025-07-02 10:08:29'),
(305, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"feedback.php\",\"url\":\"\\/Migoripmc\\/admin\\/feedback.php\",\"referrer\":\"http:\\/\\/localhost\\/Migoripmc\\/admin\\/feedback.php\",\"method\":\"GET\",\"timestamp\":1751450909}', '2025-07-02 10:08:29'),
(306, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"roles_permissions.php\",\"url\":\"\\/Migoripmc\\/admin\\/roles_permissions.php\",\"referrer\":\"http:\\/\\/localhost\\/Migoripmc\\/admin\\/feedback.php\",\"method\":\"GET\",\"timestamp\":1751450915}', '2025-07-02 10:08:35'),
(307, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"roles_permissions.php\",\"url\":\"\\/Migoripmc\\/admin\\/roles_permissions.php\",\"referrer\":\"http:\\/\\/localhost\\/Migoripmc\\/admin\\/feedback.php\",\"method\":\"GET\",\"timestamp\":1751450949}', '2025-07-02 10:09:09'),
(308, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"roles_permissions.php\",\"url\":\"\\/Migoripmc\\/admin\\/roles_permissions.php\",\"referrer\":\"http:\\/\\/localhost\\/Migoripmc\\/admin\\/roles_permissions.php\",\"method\":\"POST\",\"timestamp\":1751450990}', '2025-07-02 10:09:50'),
(309, 'permission_update_error', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"target_admin\":2,\"error\":\"SQLSTATE[23000]: Integrity constraint violation: 1062 Duplicate entry \'2-profile_access\' for key \'unique_admin_permission\'\"}', '2025-07-02 10:09:50'),
(310, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"roles_permissions.php\",\"url\":\"\\/Migoripmc\\/admin\\/roles_permissions.php\",\"referrer\":\"http:\\/\\/localhost\\/Migoripmc\\/admin\\/roles_permissions.php\",\"method\":\"POST\",\"timestamp\":1751451627}', '2025-07-02 10:20:27'),
(311, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"roles_permissions.php\",\"url\":\"\\/Migoripmc\\/admin\\/roles_permissions.php\",\"referrer\":\"http:\\/\\/localhost\\/Migoripmc\\/admin\\/roles_permissions.php\",\"method\":\"POST\",\"timestamp\":1751451651}', '2025-07-02 10:20:51'),
(312, 'permission_update_error', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"target_admin\":2,\"error\":\"SQLSTATE[23000]: Integrity constraint violation: 1062 Duplicate entry \'2-profile_access\' for key \'unique_admin_permission\'\"}', '2025-07-02 10:20:51'),
(313, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"roles_permissions.php\",\"url\":\"\\/Migoripmc\\/admin\\/roles_permissions.php\",\"referrer\":null,\"method\":\"GET\",\"timestamp\":1751452152}', '2025-07-02 10:29:12'),
(314, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"roles_permissions.php\",\"url\":\"\\/Migoripmc\\/admin\\/roles_permissions.php\",\"referrer\":\"http:\\/\\/localhost\\/Migoripmc\\/admin\\/roles_permissions.php\",\"method\":\"POST\",\"timestamp\":1751452166}', '2025-07-02 10:29:26'),
(315, 'permission_update_error', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"target_admin\":2,\"error\":\"SQLSTATE[23000]: Integrity constraint violation: 1062 Duplicate entry \'2-profile_access\' for key \'unique_admin_permission\'\"}', '2025-07-02 10:29:26'),
(316, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"roles_permissions.php\",\"url\":\"\\/Migoripmc\\/admin\\/roles_permissions.php\",\"referrer\":\"http:\\/\\/localhost\\/Migoripmc\\/admin\\/roles_permissions.php\",\"method\":\"POST\",\"timestamp\":1751452177}', '2025-07-02 10:29:37'),
(317, 'permissions_updated', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"target_admin\":2,\"final_permissions\":[],\"permissions_added\":[],\"permissions_removed\":[\"create_projects\",\"dashboard_access\",\"view_projects\"],\"total_permissions\":0}', '2025-07-02 10:29:37'),
(318, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"roles_permissions.php\",\"url\":\"\\/Migoripmc\\/admin\\/roles_permissions.php\",\"referrer\":null,\"method\":\"GET\",\"timestamp\":1751452208}', '2025-07-02 10:30:08'),
(319, 'unauthorized_access_attempt', 2, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36 Edg/138.0.0.0', '{\"page\":\"projects.php\",\"url\":\"\\/migoripmc\\/admin\\/projects.php\",\"referrer\":\"http:\\/\\/localhost\\/migoripmc\\/admin\\/create_project.php\"}', '2025-07-02 10:30:19'),
(320, 'unauthorized_access_attempt', 2, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36 Edg/138.0.0.0', '{\"page\":\"projects.php\",\"url\":\"\\/migoripmc\\/admin\\/projects.php\",\"referrer\":\"http:\\/\\/localhost\\/migoripmc\\/index.php\"}', '2025-07-02 10:30:23'),
(321, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"roles_permissions.php\",\"url\":\"\\/Migoripmc\\/admin\\/roles_permissions.php\",\"referrer\":\"http:\\/\\/localhost\\/Migoripmc\\/admin\\/roles_permissions.php\",\"method\":\"POST\",\"timestamp\":1751452274}', '2025-07-02 10:31:14'),
(322, 'permission_update_error', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"target_admin\":2,\"error\":\"SQLSTATE[23000]: Integrity constraint violation: 1062 Duplicate entry \'2-profile_access\' for key \'unique_admin_permission\'\"}', '2025-07-02 10:31:14'),
(323, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"roles_permissions.php\",\"url\":\"\\/Migoripmc\\/admin\\/roles_permissions.php\",\"referrer\":null,\"method\":\"GET\",\"timestamp\":1751454215}', '2025-07-02 11:03:35'),
(324, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"roles_permissions.php\",\"url\":\"\\/Migoripmc\\/admin\\/roles_permissions.php\",\"referrer\":\"http:\\/\\/localhost\\/Migoripmc\\/admin\\/roles_permissions.php\",\"method\":\"POST\",\"timestamp\":1751454245}', '2025-07-02 11:04:05'),
(325, 'permissions_updated', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"target_admin\":2,\"final_permissions\":[\"dashboard_access\",\"profile_access\",\"create_projects\",\"view_projects\",\"edit_projects\",\"manage_projects\",\"import_data\",\"manage_project_steps\",\"manage_budgets\",\"view_reports\",\"manage_feedback\",\"manage_documents\"],\"permissions_added\":[\"dashboard_access\",\"profile_access\",\"create_projects\",\"view_projects\",\"edit_projects\",\"manage_projects\",\"import_data\",\"manage_project_steps\",\"manage_budgets\",\"view_reports\",\"manage_feedback\",\"manage_documents\"],\"permissions_removed\":[],\"total_permissions\":12}', '2025-07-02 11:04:05'),
(326, 'page_access', 2, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36 Edg/138.0.0.0', '{\"page\":\"import_csv.php\",\"url\":\"\\/migoripmc\\/admin\\/import_csv.php\",\"referrer\":\"http:\\/\\/localhost\\/migoripmc\\/admin\\/index.php\",\"method\":\"GET\",\"timestamp\":1751454364}', '2025-07-02 11:06:04'),
(327, 'undefined_page_access', 2, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36 Edg/138.0.0.0', '{\"page\":\"csv_import\",\"url\":\"\\/migoripmc\\/admin\\/import_csv.php\"}', '2025-07-02 11:06:04'),
(328, 'page_access', 2, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36 Edg/138.0.0.0', '{\"page\":\"create_project.php\",\"url\":\"\\/migoripmc\\/admin\\/create_project.php\",\"referrer\":\"http:\\/\\/localhost\\/migoripmc\\/admin\\/import_csv.php\",\"method\":\"GET\",\"timestamp\":1751454368}', '2025-07-02 11:06:08'),
(329, 'page_access', 2, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36 Edg/138.0.0.0', '{\"page\":\"projects.php\",\"url\":\"\\/migoripmc\\/admin\\/projects.php\",\"referrer\":\"http:\\/\\/localhost\\/migoripmc\\/admin\\/create_project.php\",\"method\":\"GET\",\"timestamp\":1751454372}', '2025-07-02 11:06:12'),
(330, 'page_access', 2, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36 Edg/138.0.0.0', '{\"page\":\"pmc_reports.php\",\"url\":\"\\/migoripmc\\/admin\\/pmc_reports.php\",\"referrer\":\"http:\\/\\/localhost\\/migoripmc\\/admin\\/budget_management.php\",\"method\":\"GET\",\"timestamp\":1751454376}', '2025-07-02 11:06:16'),
(331, 'page_access', 2, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36 Edg/138.0.0.0', '{\"page\":\"document_manager.php\",\"url\":\"\\/migoripmc\\/admin\\/document_manager.php\",\"referrer\":\"http:\\/\\/localhost\\/migoripmc\\/admin\\/pmc_reports.php\",\"method\":\"GET\",\"timestamp\":1751454379}', '2025-07-02 11:06:19'),
(332, 'page_access', 2, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36 Edg/138.0.0.0', '{\"page\":\"feedback.php\",\"url\":\"\\/migoripmc\\/admin\\/feedback.php\",\"referrer\":\"http:\\/\\/localhost\\/migoripmc\\/admin\\/document_manager.php\",\"method\":\"GET\",\"timestamp\":1751454389}', '2025-07-02 11:06:29'),
(333, 'page_access', 2, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36 Edg/138.0.0.0', '{\"page\":\"pmc_reports.php\",\"url\":\"\\/migoripmc\\/admin\\/pmc_reports.php\",\"referrer\":\"http:\\/\\/localhost\\/migoripmc\\/admin\\/feedback.php\",\"method\":\"GET\",\"timestamp\":1751454393}', '2025-07-02 11:06:33'),
(334, 'page_access', 2, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36 Edg/138.0.0.0', '{\"page\":\"projects.php\",\"url\":\"\\/migoripmc\\/admin\\/projects.php\",\"referrer\":\"http:\\/\\/localhost\\/migoripmc\\/admin\\/budget_management.php\",\"method\":\"GET\",\"timestamp\":1751454405}', '2025-07-02 11:06:45'),
(335, 'page_access', 2, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36 Edg/138.0.0.0', '{\"page\":\"manage_project.php\",\"url\":\"\\/migoripmc\\/admin\\/manage_project.php?id=18\",\"referrer\":\"http:\\/\\/localhost\\/migoripmc\\/admin\\/projects.php\",\"method\":\"GET\",\"timestamp\":1751454413}', '2025-07-02 11:06:53'),
(336, 'page_access', 2, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36 Edg/138.0.0.0', '{\"page\":\"manage_project.php\",\"url\":\"\\/migoripmc\\/admin\\/manage_project.php?id=18\",\"referrer\":\"http:\\/\\/localhost\\/migoripmc\\/admin\\/manage_project.php?id=18\",\"method\":\"POST\",\"timestamp\":1751454426}', '2025-07-02 11:07:06'),
(337, 'page_access', 2, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36 Edg/138.0.0.0', '{\"page\":\"manage_project.php\",\"url\":\"\\/migoripmc\\/admin\\/manage_project.php?id=18\",\"referrer\":\"http:\\/\\/localhost\\/migoripmc\\/admin\\/manage_project.php?id=18\",\"method\":\"POST\",\"timestamp\":1751454439}', '2025-07-02 11:07:19'),
(338, 'page_access', 2, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36 Edg/138.0.0.0', '{\"page\":\"manage_project.php\",\"url\":\"\\/migoripmc\\/admin\\/manage_project.php?id=18\",\"referrer\":\"http:\\/\\/localhost\\/migoripmc\\/admin\\/manage_project.php?id=18\",\"method\":\"POST\",\"timestamp\":1751454446}', '2025-07-02 11:07:26'),
(339, 'page_access', 2, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36 Edg/138.0.0.0', '{\"page\":\"create_project.php\",\"url\":\"\\/migoripmc\\/admin\\/create_project.php\",\"referrer\":\"http:\\/\\/localhost\\/migoripmc\\/admin\\/manage_project.php?id=18\",\"method\":\"GET\",\"timestamp\":1751454464}', '2025-07-02 11:07:44'),
(340, 'page_access', 2, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36 Edg/138.0.0.0', '{\"page\":\"manage_project.php\",\"url\":\"\\/migoripmc\\/admin\\/manage_project.php?id=19&created=1\",\"referrer\":\"http:\\/\\/localhost\\/migoripmc\\/admin\\/create_project.php\",\"method\":\"GET\",\"timestamp\":1751454558}', '2025-07-02 11:09:18'),
(341, 'page_access', 2, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36 Edg/138.0.0.0', '{\"page\":\"manage_project.php\",\"url\":\"\\/migoripmc\\/admin\\/manage_project.php?id=19&created=1\",\"referrer\":\"http:\\/\\/localhost\\/migoripmc\\/admin\\/manage_project.php?id=19&created=1\",\"method\":\"POST\",\"timestamp\":1751454575}', '2025-07-02 11:09:35'),
(342, 'page_access', 2, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36 Edg/138.0.0.0', '{\"page\":\"manage_project.php\",\"url\":\"\\/migoripmc\\/admin\\/manage_project.php?id=19&created=1\",\"referrer\":\"http:\\/\\/localhost\\/migoripmc\\/admin\\/manage_project.php?id=19&created=1\",\"method\":\"POST\",\"timestamp\":1751454582}', '2025-07-02 11:09:42'),
(343, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"roles_permissions.php\",\"url\":\"\\/Migoripmc\\/admin\\/roles_permissions.php\",\"referrer\":\"http:\\/\\/localhost\\/Migoripmc\\/admin\\/roles_permissions.php\",\"method\":\"POST\",\"timestamp\":1751457068}', '2025-07-02 11:51:08'),
(344, 'permissions_updated', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"target_admin\":\"3\",\"final_permissions\":[\"dashboard_access\"],\"permissions_added\":[\"dashboard_access\"],\"permissions_removed\":[],\"total_permissions\":1}', '2025-07-02 11:51:08'),
(345, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"roles_permissions.php\",\"url\":\"\\/Migoripmc\\/admin\\/roles_permissions.php\",\"referrer\":\"http:\\/\\/localhost\\/Migoripmc\\/admin\\/roles_permissions.php\",\"method\":\"POST\",\"timestamp\":1751457091}', '2025-07-02 11:51:31'),
(346, 'permissions_updated', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"target_admin\":3,\"final_permissions\":[\"dashboard_access\",\"profile_access\"],\"permissions_added\":{\"1\":\"profile_access\"},\"permissions_removed\":[],\"total_permissions\":2}', '2025-07-02 11:51:31'),
(347, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"roles_permissions.php\",\"url\":\"\\/Migoripmc\\/admin\\/roles_permissions.php\",\"referrer\":\"http:\\/\\/localhost\\/Migoripmc\\/admin\\/roles_permissions.php\",\"method\":\"POST\",\"timestamp\":1751457225}', '2025-07-02 11:53:45'),
(348, 'permissions_updated', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"target_admin\":3,\"final_permissions\":[\"dashboard_access\"],\"permissions_added\":[],\"permissions_removed\":{\"1\":\"profile_access\"},\"total_permissions\":1}', '2025-07-02 11:53:45'),
(349, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"roles_permissions.php\",\"url\":\"\\/Migoripmc\\/admin\\/roles_permissions.php\",\"referrer\":\"http:\\/\\/localhost\\/Migoripmc\\/admin\\/roles_permissions.php\",\"method\":\"POST\",\"timestamp\":1751457262}', '2025-07-02 11:54:22'),
(350, 'permissions_updated', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"target_admin\":2,\"final_permissions\":[\"dashboard_access\"],\"permissions_added\":[],\"permissions_removed\":{\"1\":\"profile_access\",\"2\":\"create_projects\",\"3\":\"view_projects\",\"4\":\"edit_projects\",\"5\":\"manage_projects\",\"6\":\"import_data\",\"7\":\"manage_project_steps\",\"8\":\"manage_budgets\",\"9\":\"view_reports\",\"10\":\"manage_feedback\",\"11\":\"manage_documents\"},\"total_permissions\":1}', '2025-07-02 11:54:22'),
(351, 'unauthorized_access_attempt', 2, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36 Edg/138.0.0.0', '{\"page\":\"import_csv.php\",\"url\":\"\\/migoripmc\\/admin\\/import_csv.php\",\"referrer\":\"http:\\/\\/localhost\\/migoripmc\\/admin\\/index.php\"}', '2025-07-02 11:55:07'),
(352, 'unauthorized_access_attempt', 2, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36 Edg/138.0.0.0', '{\"page\":\"document_manager.php\",\"url\":\"\\/migoripmc\\/admin\\/document_manager.php\",\"referrer\":\"http:\\/\\/localhost\\/migoripmc\\/admin\\/dashboard.php\"}', '2025-07-02 11:56:30'),
(353, 'unauthorized_access_attempt', 2, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36 Edg/138.0.0.0', '{\"page\":\"feedback.php\",\"url\":\"\\/migoripmc\\/admin\\/feedback.php\",\"referrer\":\"http:\\/\\/localhost\\/migoripmc\\/index.php\"}', '2025-07-02 11:56:36'),
(354, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"roles_permissions.php\",\"url\":\"\\/Migoripmc\\/admin\\/roles_permissions.php\",\"referrer\":\"http:\\/\\/localhost\\/Migoripmc\\/admin\\/roles_permissions.php\",\"method\":\"POST\",\"timestamp\":1751457413}', '2025-07-02 11:56:53'),
(355, 'permissions_updated', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"target_admin\":2,\"final_permissions\":[\"dashboard_access\",\"manage_feedback\"],\"permissions_added\":{\"1\":\"manage_feedback\"},\"permissions_removed\":[],\"total_permissions\":2}', '2025-07-02 11:56:53'),
(356, 'page_access', 2, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36 Edg/138.0.0.0', '{\"page\":\"feedback.php\",\"url\":\"\\/migoripmc\\/admin\\/feedback.php\",\"referrer\":\"http:\\/\\/localhost\\/migoripmc\\/index.php\",\"method\":\"GET\",\"timestamp\":1751457426}', '2025-07-02 11:57:06'),
(357, 'unauthorized_access_attempt', 2, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36 Edg/138.0.0.0', '{\"page\":\"import_csv.php\",\"url\":\"\\/migoripmc\\/admin\\/import_csv.php\",\"referrer\":\"http:\\/\\/localhost\\/migoripmc\\/admin\\/index.php\"}', '2025-07-02 12:44:16'),
(358, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"projects.php\",\"url\":\"\\/Migoripmc\\/admin\\/projects.php\",\"referrer\":\"http:\\/\\/localhost\\/Migoripmc\\/admin\\/\",\"method\":\"GET\",\"timestamp\":1751469639}', '2025-07-02 15:20:39'),
(359, 'page_access', 2, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36 Edg/138.0.0.0', '{\"page\":\"feedback.php\",\"url\":\"\\/migoripmc\\/admin\\/feedback.php\",\"referrer\":\"http:\\/\\/localhost\\/migoripmc\\/admin\\/\",\"method\":\"GET\",\"timestamp\":1751469775}', '2025-07-02 15:22:55'),
(360, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"roles_permissions.php\",\"url\":\"\\/Migoripmc\\/admin\\/roles_permissions.php\",\"referrer\":\"http:\\/\\/localhost\\/Migoripmc\\/admin\\/projects.php\",\"method\":\"GET\",\"timestamp\":1751470065}', '2025-07-02 15:27:45'),
(361, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"import_csv.php\",\"url\":\"\\/Migoripmc\\/admin\\/import_csv.php\",\"referrer\":\"http:\\/\\/localhost\\/Migoripmc\\/admin\\/roles_permissions.php\",\"method\":\"GET\",\"timestamp\":1751470273}', '2025-07-02 15:31:13'),
(362, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"feedback.php\",\"url\":\"\\/Migoripmc\\/admin\\/feedback.php\",\"referrer\":\"http:\\/\\/localhost\\/Migoripmc\\/admin\\/index.php\",\"method\":\"GET\",\"timestamp\":1751471595}', '2025-07-02 15:53:15'),
(363, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"feedback.php\",\"url\":\"\\/Migoripmc\\/admin\\/feedback.php\",\"referrer\":\"http:\\/\\/localhost\\/Migoripmc\\/admin\\/feedback.php\",\"method\":\"GET\",\"timestamp\":1751471599}', '2025-07-02 15:53:19'),
(364, 'page_access', 2, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36 Edg/138.0.0.0', '{\"page\":\"feedback.php\",\"url\":\"\\/migoripmc\\/admin\\/feedback.php\",\"referrer\":\"http:\\/\\/localhost\\/migoripmc\\/admin\\/dashboard.php\",\"method\":\"GET\",\"timestamp\":1751472843}', '2025-07-02 16:14:03'),
(365, 'page_access', 2, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36 Edg/138.0.0.0', '{\"page\":\"feedback.php\",\"url\":\"\\/migoripmc\\/admin\\/feedback.php\",\"referrer\":\"http:\\/\\/localhost\\/migoripmc\\/admin\\/index.php\",\"method\":\"GET\",\"timestamp\":1751472848}', '2025-07-02 16:14:08'),
(366, 'page_access', 2, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36 Edg/138.0.0.0', '{\"page\":\"feedback.php\",\"url\":\"\\/migoripmc\\/admin\\/feedback.php\",\"referrer\":\"http:\\/\\/localhost\\/migoripmc\\/admin\\/index.php\",\"method\":\"GET\",\"timestamp\":1751472890}', '2025-07-02 16:14:50'),
(367, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"import_csv.php\",\"url\":\"\\/Migoripmc\\/admin\\/import_csv.php\",\"referrer\":\"http:\\/\\/localhost\\/Migoripmc\\/admin\\/index.php\",\"method\":\"GET\",\"timestamp\":1751472945}', '2025-07-02 16:15:45'),
(368, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"projects.php\",\"url\":\"\\/Migoripmc\\/admin\\/projects.php\",\"referrer\":\"http:\\/\\/localhost\\/Migoripmc\\/admin\\/import_csv.php\",\"method\":\"GET\",\"timestamp\":1751472998}', '2025-07-02 16:16:38'),
(369, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"projects.php\",\"url\":\"\\/Migoripmc\\/admin\\/projects.php\",\"referrer\":\"http:\\/\\/localhost\\/Migoripmc\\/admin\\/import_csv.php\",\"method\":\"GET\",\"timestamp\":1751473456}', '2025-07-02 16:24:16'),
(370, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"projects.php\",\"url\":\"\\/Migoripmc\\/admin\\/projects.php?search=&status=cancelled&visibility=\",\"referrer\":\"http:\\/\\/localhost\\/Migoripmc\\/admin\\/projects.php\",\"method\":\"GET\",\"timestamp\":1751473497}', '2025-07-02 16:24:57'),
(371, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"projects.php\",\"url\":\"\\/Migoripmc\\/admin\\/projects.php?search=&status=suspended&visibility=\",\"referrer\":\"http:\\/\\/localhost\\/Migoripmc\\/admin\\/projects.php?search=&status=cancelled&visibility=\",\"method\":\"GET\",\"timestamp\":1751473504}', '2025-07-02 16:25:04'),
(372, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"projects.php\",\"url\":\"\\/Migoripmc\\/admin\\/projects.php?search=&status=planning&visibility=\",\"referrer\":\"http:\\/\\/localhost\\/Migoripmc\\/admin\\/projects.php?search=&status=suspended&visibility=\",\"method\":\"GET\",\"timestamp\":1751473511}', '2025-07-02 16:25:11'),
(373, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"projects.php\",\"url\":\"\\/Migoripmc\\/admin\\/projects.php?search=&status=completed&visibility=\",\"referrer\":\"http:\\/\\/localhost\\/Migoripmc\\/admin\\/projects.php?search=&status=planning&visibility=\",\"method\":\"GET\",\"timestamp\":1751473518}', '2025-07-02 16:25:18'),
(374, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"projects.php\",\"url\":\"\\/Migoripmc\\/admin\\/projects.php?search=&status=completed&visibility=private\",\"referrer\":\"http:\\/\\/localhost\\/Migoripmc\\/admin\\/projects.php?search=&status=completed&visibility=\",\"method\":\"GET\",\"timestamp\":1751473523}', '2025-07-02 16:25:23'),
(375, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"projects.php\",\"url\":\"\\/Migoripmc\\/admin\\/projects.php?search=&status=completed&visibility=private\",\"referrer\":\"http:\\/\\/localhost\\/Migoripmc\\/admin\\/projects.php?search=&status=completed&visibility=private\",\"method\":\"GET\",\"timestamp\":1751473528}', '2025-07-02 16:25:28'),
(376, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"projects.php\",\"url\":\"\\/Migoripmc\\/admin\\/projects.php?search=&status=completed&visibility=published\",\"referrer\":\"http:\\/\\/localhost\\/Migoripmc\\/admin\\/projects.php?search=&status=completed&visibility=private\",\"method\":\"GET\",\"timestamp\":1751473534}', '2025-07-02 16:25:34'),
(377, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"create_project.php\",\"url\":\"\\/Migoripmc\\/admin\\/create_project.php\",\"referrer\":\"http:\\/\\/localhost\\/Migoripmc\\/admin\\/projects.php?search=&status=completed&visibility=published\",\"method\":\"GET\",\"timestamp\":1751473545}', '2025-07-02 16:25:45'),
(378, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"roles_permissions.php\",\"url\":\"\\/Migoripmc\\/admin\\/roles_permissions.php\",\"referrer\":\"http:\\/\\/localhost\\/Migoripmc\\/admin\\/create_project.php\",\"method\":\"GET\",\"timestamp\":1751473593}', '2025-07-02 16:26:33'),
(379, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"projects.php\",\"url\":\"\\/Migoripmc\\/admin\\/projects.php\",\"referrer\":\"http:\\/\\/localhost\\/Migoripmc\\/admin\\/index.php\",\"method\":\"GET\",\"timestamp\":1751473656}', '2025-07-02 16:27:36'),
(380, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"projects.php\",\"url\":\"\\/Migoripmc\\/admin\\/projects.php?search=&status=&visibility=private\",\"referrer\":\"http:\\/\\/localhost\\/Migoripmc\\/admin\\/projects.php\",\"method\":\"GET\",\"timestamp\":1751473665}', '2025-07-02 16:27:45'),
(381, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"projects.php\",\"url\":\"\\/Migoripmc\\/admin\\/projects.php?search=&status=&visibility=published\",\"referrer\":\"http:\\/\\/localhost\\/Migoripmc\\/admin\\/projects.php?search=&status=&visibility=private\",\"method\":\"GET\",\"timestamp\":1751473671}', '2025-07-02 16:27:51'),
(382, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"projects.php\",\"url\":\"\\/Migoripmc\\/admin\\/projects.php\",\"referrer\":\"http:\\/\\/localhost\\/Migoripmc\\/admin\\/projects.php?search=&status=&visibility=published\",\"method\":\"GET\",\"timestamp\":1751473682}', '2025-07-02 16:28:02'),
(383, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"create_project.php\",\"url\":\"\\/Migoripmc\\/admin\\/create_project.php\",\"referrer\":\"http:\\/\\/localhost\\/Migoripmc\\/admin\\/projects.php\",\"method\":\"GET\",\"timestamp\":1751473685}', '2025-07-02 16:28:05'),
(384, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"import_csv.php\",\"url\":\"\\/Migoripmc\\/admin\\/import_csv.php\",\"referrer\":\"http:\\/\\/localhost\\/Migoripmc\\/admin\\/create_project.php\",\"method\":\"GET\",\"timestamp\":1751473693}', '2025-07-02 16:28:13'),
(385, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"projects.php\",\"url\":\"\\/Migoripmc\\/admin\\/projects.php\",\"referrer\":\"http:\\/\\/localhost\\/Migoripmc\\/admin\\/import_csv.php\",\"method\":\"GET\",\"timestamp\":1751476843}', '2025-07-02 17:20:43'),
(386, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"feedback.php\",\"url\":\"\\/Migoripmc\\/admin\\/feedback.php\",\"referrer\":\"http:\\/\\/localhost\\/Migoripmc\\/admin\\/projects.php\",\"method\":\"GET\",\"timestamp\":1751476846}', '2025-07-02 17:20:46'),
(387, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"roles_permissions.php\",\"url\":\"\\/Migoripmc\\/admin\\/roles_permissions.php\",\"referrer\":\"http:\\/\\/localhost\\/Migoripmc\\/admin\\/feedback.php\",\"method\":\"GET\",\"timestamp\":1751476855}', '2025-07-02 17:20:55'),
(388, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"roles_permissions.php\",\"url\":\"\\/Migoripmc\\/admin\\/roles_permissions.php\",\"referrer\":\"http:\\/\\/localhost\\/Migoripmc\\/admin\\/feedback.php\",\"method\":\"GET\",\"timestamp\":1751477338}', '2025-07-02 17:28:58'),
(389, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"roles_permissions.php\",\"url\":\"\\/Migoripmc\\/admin\\/roles_permissions.php\",\"referrer\":\"http:\\/\\/localhost\\/Migoripmc\\/admin\\/feedback.php\",\"method\":\"GET\",\"timestamp\":1751477421}', '2025-07-02 17:30:21'),
(390, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"roles_permissions.php\",\"url\":\"\\/Migoripmc\\/admin\\/roles_permissions.php\",\"referrer\":\"http:\\/\\/localhost\\/Migoripmc\\/admin\\/feedback.php\",\"method\":\"GET\",\"timestamp\":1751477565}', '2025-07-02 17:32:45'),
(391, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"roles_permissions.php\",\"url\":\"\\/Migoripmc\\/admin\\/roles_permissions.php\",\"referrer\":\"http:\\/\\/localhost\\/Migoripmc\\/admin\\/feedback.php\",\"method\":\"GET\",\"timestamp\":1751477566}', '2025-07-02 17:32:46'),
(392, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"roles_permissions.php\",\"url\":\"\\/Migoripmc\\/admin\\/roles_permissions.php\",\"referrer\":\"http:\\/\\/localhost\\/Migoripmc\\/admin\\/feedback.php\",\"method\":\"GET\",\"timestamp\":1751478407}', '2025-07-02 17:46:47'),
(393, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"roles_permissions.php\",\"url\":\"\\/Migoripmc\\/admin\\/roles_permissions.php\",\"referrer\":\"http:\\/\\/localhost\\/Migoripmc\\/admin\\/index.php\",\"method\":\"GET\",\"timestamp\":1751478590}', '2025-07-02 17:49:50'),
(394, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"roles_permissions.php\",\"url\":\"\\/Migoripmc\\/admin\\/roles_permissions.php\",\"referrer\":\"http:\\/\\/localhost\\/Migoripmc\\/admin\\/roles_permissions.php\",\"method\":\"POST\",\"timestamp\":1751478625}', '2025-07-02 17:50:25'),
(395, 'permissions_updated', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"target_admin\":2,\"final_permissions\":[\"dashboard_access\",\"profile_access\",\"create_projects\",\"view_projects\",\"edit_projects\",\"manage_projects\",\"import_data\",\"manage_project_steps\",\"manage_budgets\",\"view_reports\",\"manage_feedback\",\"manage_documents\",\"manage_users\"],\"permissions_added\":{\"1\":\"profile_access\",\"2\":\"create_projects\",\"3\":\"view_projects\",\"4\":\"edit_projects\",\"5\":\"manage_projects\",\"6\":\"import_data\",\"7\":\"manage_project_steps\",\"8\":\"manage_budgets\",\"9\":\"view_reports\",\"11\":\"manage_documents\",\"12\":\"manage_users\"},\"permissions_removed\":[],\"total_permissions\":13}', '2025-07-02 17:50:25'),
(396, 'page_access', 2, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36 Edg/138.0.0.0', '{\"page\":\"import_csv.php\",\"url\":\"\\/migoripmc\\/admin\\/import_csv.php\",\"referrer\":\"http:\\/\\/localhost\\/migoripmc\\/admin\\/\",\"method\":\"GET\",\"timestamp\":1751478686}', '2025-07-02 17:51:26'),
(397, 'undefined_page_access', 2, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36 Edg/138.0.0.0', '{\"page\":\"csv_import\",\"url\":\"\\/migoripmc\\/admin\\/import_csv.php\"}', '2025-07-02 17:51:26'),
(398, 'page_access', 2, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36 Edg/138.0.0.0', '{\"page\":\"projects.php\",\"url\":\"\\/migoripmc\\/admin\\/projects.php\",\"referrer\":\"http:\\/\\/localhost\\/migoripmc\\/admin\\/import_csv.php\",\"method\":\"GET\",\"timestamp\":1751478839}', '2025-07-02 17:53:59');
INSERT INTO `security_logs` (`id`, `event_type`, `admin_id`, `ip_address`, `user_agent`, `details`, `created_at`) VALUES
(399, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"projects.php\",\"url\":\"\\/Migoripmc\\/admin\\/projects.php\",\"referrer\":\"http:\\/\\/localhost\\/Migoripmc\\/admin\\/roles_permissions.php\",\"method\":\"GET\",\"timestamp\":1751478857}', '2025-07-02 17:54:17'),
(400, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"manage_project.php\",\"url\":\"\\/Migoripmc\\/admin\\/manage_project.php?id=8\",\"referrer\":\"http:\\/\\/localhost\\/Migoripmc\\/admin\\/projects.php\",\"method\":\"GET\",\"timestamp\":1751478864}', '2025-07-02 17:54:24'),
(401, 'page_access', 2, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36 Edg/138.0.0.0', '{\"page\":\"manage_project.php\",\"url\":\"\\/Migoripmc\\/admin\\/manage_project.php?id=8\",\"referrer\":null,\"method\":\"GET\",\"timestamp\":1751478873}', '2025-07-02 17:54:33'),
(402, 'page_access', 2, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36 Edg/138.0.0.0', '{\"page\":\"projects.php\",\"url\":\"\\/migoripmc\\/admin\\/projects.php\",\"referrer\":\"http:\\/\\/localhost\\/migoripmc\\/admin\\/dashboard.php\",\"method\":\"GET\",\"timestamp\":1751478902}', '2025-07-02 17:55:02'),
(403, 'page_access', 2, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36 Edg/138.0.0.0', '{\"page\":\"manage_project.php\",\"url\":\"\\/migoripmc\\/admin\\/manage_project.php?id=19\",\"referrer\":\"http:\\/\\/localhost\\/migoripmc\\/admin\\/projects.php\",\"method\":\"GET\",\"timestamp\":1751478955}', '2025-07-02 17:55:55'),
(404, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"manage_project.php\",\"url\":\"\\/migoripmc\\/admin\\/manage_project.php?id=19\",\"referrer\":null,\"method\":\"GET\",\"timestamp\":1751478971}', '2025-07-02 17:56:11'),
(405, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"projects.php\",\"url\":\"\\/migoripmc\\/admin\\/projects.php\",\"referrer\":\"http:\\/\\/localhost\\/migoripmc\\/admin\\/manage_project.php?id=19\",\"method\":\"GET\",\"timestamp\":1751478978}', '2025-07-02 17:56:18'),
(406, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"manage_project.php\",\"url\":\"\\/migoripmc\\/admin\\/manage_project.php?id=2\",\"referrer\":\"http:\\/\\/localhost\\/migoripmc\\/admin\\/projects.php\",\"method\":\"GET\",\"timestamp\":1751478984}', '2025-07-02 17:56:24'),
(407, 'page_access', 2, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36 Edg/138.0.0.0', '{\"page\":\"manage_project.php\",\"url\":\"\\/migoripmc\\/admin\\/manage_project.php?id=2\",\"referrer\":null,\"method\":\"GET\",\"timestamp\":1751478992}', '2025-07-02 17:56:32'),
(408, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"feedback.php\",\"url\":\"\\/migoripmc\\/admin\\/feedback.php\",\"referrer\":\"http:\\/\\/localhost\\/migoripmc\\/admin\\/index.php\",\"method\":\"GET\",\"timestamp\":1751479641}', '2025-07-02 18:07:21'),
(409, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"system_settings.php\",\"url\":\"\\/migoripmc\\/admin\\/system_settings.php\",\"referrer\":\"http:\\/\\/localhost\\/migoripmc\\/admin\\/index.php\",\"method\":\"GET\",\"timestamp\":1751479696}', '2025-07-02 18:08:16'),
(410, 'unauthorized_access_attempt', 2, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36 Edg/138.0.0.0', '{\"page\":\"system_settings.php\",\"url\":\"\\/migoripmc\\/admin\\/system_settings.php\",\"referrer\":null}', '2025-07-02 18:08:29'),
(411, 'page_access', 2, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36 Edg/138.0.0.0', '{\"page\":\"feedback.php\",\"url\":\"\\/migoripmc\\/admin\\/feedback.php\",\"referrer\":\"http:\\/\\/localhost\\/migoripmc\\/admin\\/\",\"method\":\"GET\",\"timestamp\":1751479714}', '2025-07-02 18:08:34'),
(412, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"roles_permissions.php\",\"url\":\"\\/migoripmc\\/admin\\/roles_permissions.php\",\"referrer\":\"http:\\/\\/localhost\\/migoripmc\\/admin\\/system_settings.php\",\"method\":\"GET\",\"timestamp\":1751479724}', '2025-07-02 18:08:44'),
(413, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"roles_permissions.php\",\"url\":\"\\/migoripmc\\/admin\\/roles_permissions.php\",\"referrer\":\"http:\\/\\/localhost\\/migoripmc\\/admin\\/roles_permissions.php\",\"method\":\"POST\",\"timestamp\":1751479760}', '2025-07-02 18:09:20'),
(414, 'permissions_updated', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"target_admin\":2,\"final_permissions\":[\"dashboard_access\",\"profile_access\",\"create_projects\"],\"permissions_added\":[],\"permissions_removed\":{\"1\":\"manage_feedback\",\"4\":\"view_projects\",\"5\":\"edit_projects\",\"6\":\"manage_projects\",\"7\":\"import_data\",\"8\":\"manage_project_steps\",\"9\":\"manage_budgets\",\"10\":\"view_reports\",\"11\":\"manage_documents\",\"12\":\"manage_users\"},\"total_permissions\":3}', '2025-07-02 18:09:20'),
(415, 'unauthorized_access_attempt', 2, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36 Edg/138.0.0.0', '{\"page\":\"feedback.php\",\"url\":\"\\/migoripmc\\/admin\\/feedback.php\",\"referrer\":\"http:\\/\\/localhost\\/migoripmc\\/admin\\/\"}', '2025-07-02 18:09:27'),
(416, 'unauthorized_access_attempt', 2, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36 Edg/138.0.0.0', '{\"page\":\"import_csv.php\",\"url\":\"\\/migoripmc\\/admin\\/import_csv.php\",\"referrer\":\"http:\\/\\/localhost\\/migoripmc\\/admin\\/index.php\"}', '2025-07-02 18:09:42'),
(417, 'unauthorized_access_attempt', 2, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36 Edg/138.0.0.0', '{\"page\":\"import_csv.php\",\"url\":\"\\/migoripmc\\/admin\\/import_csv.php\",\"referrer\":\"http:\\/\\/localhost\\/migoripmc\\/admin\\/index.php\"}', '2025-07-02 18:11:26'),
(418, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"roles_permissions.php\",\"url\":\"\\/migoripmc\\/admin\\/roles_permissions.php\",\"referrer\":\"http:\\/\\/localhost\\/migoripmc\\/admin\\/roles_permissions.php\",\"method\":\"POST\",\"timestamp\":1751479919}', '2025-07-02 18:11:59'),
(419, 'page_access', 2, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36 Edg/138.0.0.0', '{\"page\":\"create_project.php\",\"url\":\"\\/migoripmc\\/admin\\/create_project.php\",\"referrer\":\"http:\\/\\/localhost\\/migoripmc\\/admin\\/index.php\",\"method\":\"GET\",\"timestamp\":1751480288}', '2025-07-02 18:18:08'),
(420, 'unauthorized_access_attempt', 2, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36 Edg/138.0.0.0', '{\"page\":\"import_csv.php\",\"url\":\"\\/migoripmc\\/admin\\/import_csv.php\",\"referrer\":\"http:\\/\\/localhost\\/migoripmc\\/admin\\/create_project.php\"}', '2025-07-02 18:18:12'),
(421, 'unauthorized_access_attempt', 2, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36 Edg/138.0.0.0', '{\"page\":\"projects.php\",\"url\":\"\\/migoripmc\\/admin\\/projects.php\",\"referrer\":\"http:\\/\\/localhost\\/migoripmc\\/admin\\/create_project.php\"}', '2025-07-02 18:18:16'),
(422, 'page_access', 2, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36 Edg/138.0.0.0', '{\"page\":\"create_project.php\",\"url\":\"\\/migoripmc\\/admin\\/create_project.php\",\"referrer\":\"http:\\/\\/localhost\\/migoripmc\\/admin\\/create_project.php\",\"method\":\"GET\",\"timestamp\":1751480300}', '2025-07-02 18:18:20'),
(423, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"roles_permissions.php\",\"url\":\"\\/migoripmc\\/admin\\/roles_permissions.php\",\"referrer\":\"http:\\/\\/localhost\\/migoripmc\\/admin\\/index.php\",\"method\":\"GET\",\"timestamp\":1751480512}', '2025-07-02 18:21:52'),
(424, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"roles_permissions.php\",\"url\":\"\\/migoripmc\\/admin\\/roles_permissions.php\",\"referrer\":\"http:\\/\\/localhost\\/migoripmc\\/admin\\/roles_permissions.php\",\"method\":\"POST\",\"timestamp\":1751480529}', '2025-07-02 18:22:09'),
(425, 'permissions_updated', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"target_admin\":2,\"final_permissions\":[\"dashboard_access\",\"profile_access\"],\"permissions_added\":[],\"permissions_removed\":{\"2\":\"create_projects\"},\"total_permissions\":2}', '2025-07-02 18:22:09'),
(426, 'unauthorized_access_attempt', 2, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36 Edg/138.0.0.0', '{\"page\":\"create_project.php\",\"url\":\"\\/migoripmc\\/admin\\/create_project.php\",\"referrer\":\"http:\\/\\/localhost\\/migoripmc\\/admin\\/create_project.php\"}', '2025-07-02 18:22:15'),
(427, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"create_project.php\",\"url\":\"\\/migoripmc\\/admin\\/create_project.php\",\"referrer\":\"http:\\/\\/localhost\\/migoripmc\\/admin\\/roles_permissions.php\",\"method\":\"GET\",\"timestamp\":1751481972}', '2025-07-02 18:46:12'),
(428, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"create_project.php\",\"url\":\"\\/migoripmc\\/admin\\/create_project.php\",\"referrer\":\"http:\\/\\/localhost\\/migoripmc\\/admin\\/roles_permissions.php\",\"method\":\"GET\",\"timestamp\":1751482043}', '2025-07-02 18:47:23'),
(429, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"create_project.php\",\"url\":\"\\/Migoripmc\\/admin\\/create_project.php\",\"referrer\":null,\"method\":\"GET\",\"timestamp\":1751482119}', '2025-07-02 18:48:39'),
(430, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"create_project.php\",\"url\":\"\\/Migoripmc\\/admin\\/create_project.php\",\"referrer\":null,\"method\":\"GET\",\"timestamp\":1751482144}', '2025-07-02 18:49:04'),
(431, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"create_project.php\",\"url\":\"\\/Migoripmc\\/admin\\/create_project.php\",\"referrer\":\"http:\\/\\/localhost\\/Migoripmc\\/admin\\/create_project.php\",\"method\":\"GET\",\"timestamp\":1751482166}', '2025-07-02 18:49:26'),
(432, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"create_project.php\",\"url\":\"\\/Migoripmc\\/admin\\/create_project.php\",\"referrer\":\"http:\\/\\/localhost\\/Migoripmc\\/admin\\/create_project.php\",\"method\":\"GET\",\"timestamp\":1751482205}', '2025-07-02 18:50:05'),
(433, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"create_project.php\",\"url\":\"\\/Migoripmc\\/admin\\/create_project.php\",\"referrer\":\"http:\\/\\/localhost\\/Migoripmc\\/admin\\/create_project.php\",\"method\":\"GET\",\"timestamp\":1751482306}', '2025-07-02 18:51:46'),
(434, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"create_project.php\",\"url\":\"\\/Migoripmc\\/admin\\/create_project.php\",\"referrer\":\"http:\\/\\/localhost\\/Migoripmc\\/admin\\/create_project.php\",\"method\":\"GET\",\"timestamp\":1751482332}', '2025-07-02 18:52:12'),
(435, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"create_project.php\",\"url\":\"\\/Migoripmc\\/admin\\/create_project.php\",\"referrer\":\"http:\\/\\/localhost\\/Migoripmc\\/admin\\/create_project.php\",\"method\":\"GET\",\"timestamp\":1751482400}', '2025-07-02 18:53:20'),
(436, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"create_project.php\",\"url\":\"\\/Migoripmc\\/admin\\/create_project.php\",\"referrer\":\"http:\\/\\/localhost\\/Migoripmc\\/admin\\/create_project.php\",\"method\":\"GET\",\"timestamp\":1751482464}', '2025-07-02 18:54:24'),
(437, 'unauthorized_access_attempt', 2, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36 Edg/138.0.0.0', '{\"page\":\"create_project.php\",\"url\":\"\\/migoripmc\\/admin\\/create_project.php\",\"referrer\":\"http:\\/\\/localhost\\/migoripmc\\/admin\\/dashboard.php\"}', '2025-07-02 18:57:03'),
(438, 'unauthorized_access_attempt', 2, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36 Edg/138.0.0.0', '{\"page\":\"import_csv.php\",\"url\":\"\\/migoripmc\\/admin\\/import_csv.php\",\"referrer\":\"http:\\/\\/localhost\\/migoripmc\\/admin\\/dashboard.php\"}', '2025-07-02 18:57:11'),
(439, 'unauthorized_access_attempt', 2, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36 Edg/138.0.0.0', '{\"page\":\"create_project.php\",\"url\":\"\\/migoripmc\\/admin\\/create_project.php\",\"referrer\":\"http:\\/\\/localhost\\/migoripmc\\/admin\\/dashboard.php\"}', '2025-07-02 18:57:17'),
(440, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"import_csv.php\",\"url\":\"\\/migoripmc\\/admin\\/import_csv.php\",\"referrer\":\"http:\\/\\/localhost\\/migoripmc\\/admin\\/budget_management.php?edit=9\",\"method\":\"GET\",\"timestamp\":1751484530}', '2025-07-02 19:28:50'),
(441, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"import_csv.php\",\"url\":\"\\/Migoripmc\\/admin\\/import_csv.php\",\"referrer\":\"http:\\/\\/localhost\\/Migoripmc\\/admin\\/\",\"method\":\"GET\",\"timestamp\":1751487680}', '2025-07-02 20:21:20'),
(442, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"import_csv.php\",\"url\":\"\\/Migoripmc\\/admin\\/import_csv.php\",\"referrer\":\"http:\\/\\/localhost\\/Migoripmc\\/admin\\/\",\"method\":\"GET\",\"timestamp\":1751487743}', '2025-07-02 20:22:23'),
(443, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"create_project.php\",\"url\":\"\\/Migoripmc\\/admin\\/create_project.php\",\"referrer\":\"http:\\/\\/localhost\\/Migoripmc\\/admin\\/import_csv.php\",\"method\":\"GET\",\"timestamp\":1751487754}', '2025-07-02 20:22:34'),
(444, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"projects.php\",\"url\":\"\\/Migoripmc\\/admin\\/projects.php\",\"referrer\":\"http:\\/\\/localhost\\/Migoripmc\\/admin\\/create_project.php\",\"method\":\"GET\",\"timestamp\":1751487758}', '2025-07-02 20:22:38'),
(445, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"pmc_reports.php\",\"url\":\"\\/Migoripmc\\/admin\\/pmc_reports.php\",\"referrer\":\"http:\\/\\/localhost\\/Migoripmc\\/admin\\/budget_management.php\",\"method\":\"GET\",\"timestamp\":1751487764}', '2025-07-02 20:22:44'),
(446, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36 Edg/138.0.0.0', '{\"page\":\"import_csv.php\",\"url\":\"\\/Migoripmc\\/admin\\/import_csv.php\",\"referrer\":\"http:\\/\\/localhost\\/Migoripmc\\/admin\\/\",\"method\":\"GET\",\"timestamp\":1751493132}', '2025-07-02 21:52:12'),
(447, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"import_csv.php\",\"url\":\"\\/Migoripmc\\/admin\\/import_csv.php\",\"referrer\":\"http:\\/\\/localhost\\/Migoripmc\\/admin\\/\",\"method\":\"GET\",\"timestamp\":1751498441}', '2025-07-02 23:20:41'),
(448, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"projects.php\",\"url\":\"\\/Migoripmc\\/admin\\/projects.php\",\"referrer\":\"http:\\/\\/localhost\\/Migoripmc\\/admin\\/import_csv.php\",\"method\":\"GET\",\"timestamp\":1751498444}', '2025-07-02 23:20:44'),
(449, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"manage_project.php\",\"url\":\"\\/Migoripmc\\/admin\\/manage_project.php?id=7\",\"referrer\":\"http:\\/\\/localhost\\/Migoripmc\\/admin\\/projects.php\",\"method\":\"GET\",\"timestamp\":1751498451}', '2025-07-02 23:20:51'),
(450, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"manage_project.php\",\"url\":\"\\/Migoripmc\\/admin\\/manage_project.php?id=7\",\"referrer\":\"http:\\/\\/localhost\\/Migoripmc\\/admin\\/manage_project.php?id=7\",\"method\":\"POST\",\"timestamp\":1751498454}', '2025-07-02 23:20:54'),
(451, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"projects.php\",\"url\":\"\\/Migoripmc\\/admin\\/projects.php?success=Project+deleted+successfully\",\"referrer\":\"http:\\/\\/localhost\\/Migoripmc\\/admin\\/manage_project.php?id=7\",\"method\":\"GET\",\"timestamp\":1751498454}', '2025-07-02 23:20:54'),
(452, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"import_csv.php\",\"url\":\"\\/Migoripmc\\/admin\\/import_csv.php\",\"referrer\":\"http:\\/\\/localhost\\/Migoripmc\\/admin\\/projects.php?success=Project+deleted+successfully\",\"method\":\"GET\",\"timestamp\":1751498459}', '2025-07-02 23:20:59'),
(453, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"create_project.php\",\"url\":\"\\/Migoripmc\\/admin\\/create_project.php\",\"referrer\":\"http:\\/\\/localhost\\/Migoripmc\\/admin\\/import_csv.php\",\"method\":\"GET\",\"timestamp\":1751498480}', '2025-07-02 23:21:20'),
(454, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"roles_permissions.php\",\"url\":\"\\/Migoripmc\\/admin\\/roles_permissions.php\",\"referrer\":\"http:\\/\\/localhost\\/Migoripmc\\/admin\\/budget_management.php\",\"method\":\"GET\",\"timestamp\":1751498536}', '2025-07-02 23:22:16'),
(455, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"roles_permissions.php\",\"url\":\"\\/Migoripmc\\/admin\\/roles_permissions.php\",\"referrer\":\"http:\\/\\/localhost\\/Migoripmc\\/admin\\/roles_permissions.php\",\"method\":\"POST\",\"timestamp\":1751498558}', '2025-07-02 23:22:38'),
(456, 'permissions_updated', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"target_admin\":2,\"final_permissions\":[\"dashboard_access\",\"profile_access\",\"create_projects\",\"view_projects\",\"edit_projects\",\"manage_projects\",\"import_data\",\"manage_project_steps\",\"manage_budgets\",\"view_reports\",\"manage_feedback\",\"manage_documents\"],\"permissions_added\":{\"2\":\"create_projects\",\"3\":\"view_projects\",\"4\":\"edit_projects\",\"5\":\"manage_projects\",\"6\":\"import_data\",\"7\":\"manage_project_steps\",\"8\":\"manage_budgets\",\"9\":\"view_reports\",\"10\":\"manage_feedback\",\"11\":\"manage_documents\"},\"permissions_removed\":[],\"total_permissions\":12}', '2025-07-02 23:22:39'),
(457, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"roles_permissions.php\",\"url\":\"\\/Migoripmc\\/admin\\/roles_permissions.php\",\"referrer\":\"http:\\/\\/localhost\\/Migoripmc\\/admin\\/roles_permissions.php\",\"method\":\"POST\",\"timestamp\":1751498599}', '2025-07-02 23:23:19'),
(458, 'permissions_updated', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"target_admin\":2,\"final_permissions\":[\"dashboard_access\",\"profile_access\",\"create_projects\"],\"permissions_added\":[],\"permissions_removed\":{\"3\":\"view_projects\",\"4\":\"edit_projects\",\"5\":\"manage_projects\",\"6\":\"import_data\",\"7\":\"manage_project_steps\",\"8\":\"manage_budgets\",\"9\":\"view_reports\",\"10\":\"manage_feedback\",\"11\":\"manage_documents\"},\"total_permissions\":3}', '2025-07-02 23:23:19'),
(459, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"roles_permissions.php\",\"url\":\"\\/Migoripmc\\/admin\\/roles_permissions.php\",\"referrer\":\"http:\\/\\/localhost\\/Migoripmc\\/admin\\/roles_permissions.php\",\"method\":\"POST\",\"timestamp\":1751498667}', '2025-07-02 23:24:27'),
(460, 'permissions_updated', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"target_admin\":2,\"final_permissions\":[\"dashboard_access\",\"profile_access\",\"create_projects\",\"view_projects\",\"edit_projects\",\"manage_projects\",\"import_data\",\"manage_project_steps\"],\"permissions_added\":{\"3\":\"view_projects\",\"4\":\"edit_projects\",\"5\":\"manage_projects\",\"6\":\"import_data\",\"7\":\"manage_project_steps\"},\"permissions_removed\":[],\"total_permissions\":8}', '2025-07-02 23:24:27'),
(461, 'page_access', 2, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36 Edg/138.0.0.0', '{\"page\":\"projects.php\",\"url\":\"\\/Migoripmc\\/admin\\/projects.php\",\"referrer\":\"http:\\/\\/localhost\\/Migoripmc\\/admin\\/\",\"method\":\"GET\",\"timestamp\":1751498673}', '2025-07-02 23:24:33'),
(462, 'page_access', 2, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36 Edg/138.0.0.0', '{\"page\":\"create_project.php\",\"url\":\"\\/Migoripmc\\/admin\\/create_project.php\",\"referrer\":\"http:\\/\\/localhost\\/Migoripmc\\/admin\\/projects.php\",\"method\":\"GET\",\"timestamp\":1751498675}', '2025-07-02 23:24:35'),
(463, 'page_access', 2, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36 Edg/138.0.0.0', '{\"page\":\"import_csv.php\",\"url\":\"\\/Migoripmc\\/admin\\/import_csv.php\",\"referrer\":\"http:\\/\\/localhost\\/Migoripmc\\/admin\\/create_project.php\",\"method\":\"GET\",\"timestamp\":1751498676}', '2025-07-02 23:24:36'),
(464, 'undefined_page_access', 2, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36 Edg/138.0.0.0', '{\"page\":\"csv_import\",\"url\":\"\\/Migoripmc\\/admin\\/import_csv.php\"}', '2025-07-02 23:24:36'),
(465, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"roles_permissions.php\",\"url\":\"\\/Migoripmc\\/admin\\/roles_permissions.php\",\"referrer\":\"http:\\/\\/localhost\\/Migoripmc\\/admin\\/roles_permissions.php\",\"method\":\"POST\",\"timestamp\":1751498728}', '2025-07-02 23:25:28'),
(466, 'permissions_updated', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"target_admin\":2,\"final_permissions\":[\"dashboard_access\"],\"permissions_added\":[],\"permissions_removed\":{\"1\":\"profile_access\",\"2\":\"create_projects\",\"3\":\"view_projects\",\"4\":\"edit_projects\",\"5\":\"manage_projects\",\"6\":\"import_data\",\"7\":\"manage_project_steps\"},\"total_permissions\":1}', '2025-07-02 23:25:28'),
(467, 'unauthorized_access_attempt', 2, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36 Edg/138.0.0.0', '{\"page\":\"import_csv.php\",\"url\":\"\\/Migoripmc\\/admin\\/import_csv.php\",\"referrer\":\"http:\\/\\/localhost\\/Migoripmc\\/admin\\/profile.php\"}', '2025-07-02 23:25:39'),
(468, 'unauthorized_access_attempt', 2, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36 Edg/138.0.0.0', '{\"page\":\"projects.php\",\"url\":\"\\/Migoripmc\\/admin\\/projects.php\",\"referrer\":\"http:\\/\\/localhost\\/Migoripmc\\/admin\\/profile.php\"}', '2025-07-02 23:25:43'),
(469, 'unauthorized_access_attempt', 2, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36 Edg/138.0.0.0', '{\"page\":\"projects.php\",\"url\":\"\\/Migoripmc\\/admin\\/projects.php\",\"referrer\":\"http:\\/\\/localhost\\/Migoripmc\\/admin\\/profile.php\"}', '2025-07-02 23:25:49'),
(470, 'unauthorized_access_attempt', 2, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36 Edg/138.0.0.0', '{\"page\":\"projects.php\",\"url\":\"\\/migoripmc\\/admin\\/projects.php\",\"referrer\":\"http:\\/\\/localhost\\/migoripmc\\/admin\\/dashboard.php\"}', '2025-07-02 23:25:56'),
(471, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"roles_permissions.php\",\"url\":\"\\/Migoripmc\\/admin\\/roles_permissions.php\",\"referrer\":\"http:\\/\\/localhost\\/Migoripmc\\/admin\\/roles_permissions.php\",\"method\":\"POST\",\"timestamp\":1751498770}', '2025-07-02 23:26:10'),
(472, 'permissions_updated', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"target_admin\":2,\"final_permissions\":[\"dashboard_access\",\"manage_roles\"],\"permissions_added\":{\"1\":\"manage_roles\"},\"permissions_removed\":[],\"total_permissions\":2}', '2025-07-02 23:26:10'),
(473, 'page_access', 2, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36 Edg/138.0.0.0', '{\"page\":\"roles_permissions.php\",\"url\":\"\\/migoripmc\\/admin\\/roles_permissions.php\",\"referrer\":\"http:\\/\\/localhost\\/migoripmc\\/admin\\/dashboard.php\",\"method\":\"GET\",\"timestamp\":1751498797}', '2025-07-02 23:26:37'),
(474, 'page_access', 2, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36 Edg/138.0.0.0', '{\"page\":\"roles_permissions.php\",\"url\":\"\\/migoripmc\\/admin\\/roles_permissions.php\",\"referrer\":\"http:\\/\\/localhost\\/migoripmc\\/admin\\/\",\"method\":\"GET\",\"timestamp\":1751498813}', '2025-07-02 23:26:53'),
(475, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"roles_permissions.php\",\"url\":\"\\/Migoripmc\\/admin\\/roles_permissions.php\",\"referrer\":\"http:\\/\\/localhost\\/Migoripmc\\/admin\\/roles_permissions.php\",\"method\":\"POST\",\"timestamp\":1751498835}', '2025-07-02 23:27:15'),
(476, 'permissions_updated', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"target_admin\":2,\"final_permissions\":[\"dashboard_access\"],\"permissions_added\":[],\"permissions_removed\":{\"1\":\"manage_roles\"},\"total_permissions\":1}', '2025-07-02 23:27:15'),
(477, 'unauthorized_access_attempt', 2, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36 Edg/138.0.0.0', '{\"page\":\"roles_permissions.php\",\"url\":\"\\/migoripmc\\/admin\\/roles_permissions.php\",\"referrer\":\"http:\\/\\/localhost\\/migoripmc\\/admin\\/\"}', '2025-07-02 23:27:24'),
(478, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"import_csv.php\",\"url\":\"\\/Migoripmc\\/admin\\/import_csv.php\",\"referrer\":\"http:\\/\\/localhost\\/Migoripmc\\/admin\\/\",\"method\":\"GET\",\"timestamp\":1751523158}', '2025-07-03 06:12:38'),
(479, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"create_project.php\",\"url\":\"\\/Migoripmc\\/admin\\/create_project.php\",\"referrer\":\"http:\\/\\/localhost\\/Migoripmc\\/admin\\/import_csv.php\",\"method\":\"GET\",\"timestamp\":1751523293}', '2025-07-03 06:14:53'),
(480, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"manage_project.php\",\"url\":\"\\/Migoripmc\\/admin\\/manage_project.php?id=21&created=1\",\"referrer\":\"http:\\/\\/localhost\\/Migoripmc\\/admin\\/create_project.php\",\"method\":\"GET\",\"timestamp\":1751523594}', '2025-07-03 06:19:54'),
(481, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"edit_project.php\",\"url\":\"\\/Migoripmc\\/admin\\/edit_project.php?id=21\",\"referrer\":\"http:\\/\\/localhost\\/Migoripmc\\/admin\\/manage_project.php?id=21&created=1\",\"method\":\"GET\",\"timestamp\":1751523598}', '2025-07-03 06:19:58'),
(482, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"projects.php\",\"url\":\"\\/Migoripmc\\/admin\\/projects.php?success=Project%20updated%20successfully\",\"referrer\":\"http:\\/\\/localhost\\/Migoripmc\\/admin\\/edit_project.php?id=21\",\"method\":\"GET\",\"timestamp\":1751523620}', '2025-07-03 06:20:20'),
(483, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"manage_project.php\",\"url\":\"\\/Migoripmc\\/admin\\/manage_project.php?id=21\",\"referrer\":\"http:\\/\\/localhost\\/Migoripmc\\/admin\\/projects.php?success=Project%20updated%20successfully\",\"method\":\"GET\",\"timestamp\":1751523637}', '2025-07-03 06:20:37'),
(484, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"manage_project.php\",\"url\":\"\\/Migoripmc\\/admin\\/manage_project.php?id=21\",\"referrer\":\"http:\\/\\/localhost\\/Migoripmc\\/admin\\/manage_project.php?id=21\",\"method\":\"POST\",\"timestamp\":1751523785}', '2025-07-03 06:23:05'),
(485, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"manage_project.php\",\"url\":\"\\/Migoripmc\\/admin\\/manage_project.php?id=21\",\"referrer\":\"http:\\/\\/localhost\\/Migoripmc\\/admin\\/manage_project.php?id=21\",\"method\":\"POST\",\"timestamp\":1751523827}', '2025-07-03 06:23:47'),
(486, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"manage_project.php\",\"url\":\"\\/Migoripmc\\/admin\\/manage_project.php?id=21\",\"referrer\":\"http:\\/\\/localhost\\/Migoripmc\\/admin\\/manage_project.php?id=21\",\"method\":\"POST\",\"timestamp\":1751523890}', '2025-07-03 06:24:50'),
(487, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"manage_project.php\",\"url\":\"\\/Migoripmc\\/admin\\/manage_project.php?id=21\",\"referrer\":\"http:\\/\\/localhost\\/Migoripmc\\/admin\\/manage_project.php?id=21\",\"method\":\"POST\",\"timestamp\":1751523902}', '2025-07-03 06:25:02'),
(488, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"manage_project.php\",\"url\":\"\\/Migoripmc\\/admin\\/manage_project.php?id=21\",\"referrer\":\"http:\\/\\/localhost\\/Migoripmc\\/admin\\/manage_project.php?id=21\",\"method\":\"POST\",\"timestamp\":1751523942}', '2025-07-03 06:25:42'),
(489, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"manage_project.php\",\"url\":\"\\/Migoripmc\\/admin\\/manage_project.php?id=21\",\"referrer\":\"http:\\/\\/localhost\\/Migoripmc\\/admin\\/manage_project.php?id=21\",\"method\":\"POST\",\"timestamp\":1751523956}', '2025-07-03 06:25:56'),
(490, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"manage_project.php\",\"url\":\"\\/Migoripmc\\/admin\\/manage_project.php?id=21\",\"referrer\":\"http:\\/\\/localhost\\/Migoripmc\\/admin\\/manage_project.php?id=21\",\"method\":\"POST\",\"timestamp\":1751523963}', '2025-07-03 06:26:03'),
(491, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"pmc_reports.php\",\"url\":\"\\/Migoripmc\\/admin\\/pmc_reports.php\",\"referrer\":\"http:\\/\\/localhost\\/Migoripmc\\/admin\\/budget_management.php\",\"method\":\"GET\",\"timestamp\":1751524395}', '2025-07-03 06:33:15'),
(492, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"document_manager.php\",\"url\":\"\\/Migoripmc\\/admin\\/document_manager.php\",\"referrer\":\"http:\\/\\/localhost\\/Migoripmc\\/admin\\/pmc_reports.php\",\"method\":\"GET\",\"timestamp\":1751524420}', '2025-07-03 06:33:40'),
(493, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"document_manager.php\",\"url\":\"\\/Migoripmc\\/admin\\/document_manager.php\",\"referrer\":\"http:\\/\\/localhost\\/Migoripmc\\/admin\\/pmc_reports.php\",\"method\":\"GET\",\"timestamp\":1751524608}', '2025-07-03 06:36:48'),
(494, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"feedback.php\",\"url\":\"\\/Migoripmc\\/admin\\/feedback.php\",\"referrer\":\"http:\\/\\/localhost\\/Migoripmc\\/admin\\/document_manager.php\",\"method\":\"GET\",\"timestamp\":1751524618}', '2025-07-03 06:36:58'),
(495, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"feedback.php\",\"url\":\"\\/Migoripmc\\/admin\\/feedback.php\",\"referrer\":\"http:\\/\\/localhost\\/Migoripmc\\/admin\\/feedback.php\",\"method\":\"POST\",\"timestamp\":1751524634}', '2025-07-03 06:37:14'),
(496, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"feedback.php\",\"url\":\"\\/Migoripmc\\/admin\\/feedback.php\",\"referrer\":\"http:\\/\\/localhost\\/Migoripmc\\/admin\\/feedback.php\",\"method\":\"GET\",\"timestamp\":1751524634}', '2025-07-03 06:37:14'),
(497, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"feedback.php\",\"url\":\"\\/Migoripmc\\/admin\\/feedback.php\",\"referrer\":\"http:\\/\\/localhost\\/Migoripmc\\/admin\\/feedback.php\",\"method\":\"POST\",\"timestamp\":1751524672}', '2025-07-03 06:37:52'),
(498, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"feedback.php\",\"url\":\"\\/Migoripmc\\/admin\\/feedback.php\",\"referrer\":\"http:\\/\\/localhost\\/Migoripmc\\/admin\\/feedback.php\",\"method\":\"GET\",\"timestamp\":1751524672}', '2025-07-03 06:37:52'),
(499, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"feedback.php\",\"url\":\"\\/Migoripmc\\/admin\\/feedback.php\",\"referrer\":\"http:\\/\\/localhost\\/Migoripmc\\/admin\\/feedback.php\",\"method\":\"GET\",\"timestamp\":1751524767}', '2025-07-03 06:39:27'),
(500, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"feedback.php\",\"url\":\"\\/Migoripmc\\/admin\\/feedback.php\",\"referrer\":\"http:\\/\\/localhost\\/Migoripmc\\/admin\\/feedback.php\",\"method\":\"GET\",\"timestamp\":1751524771}', '2025-07-03 06:39:31'),
(501, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"feedback.php\",\"url\":\"\\/Migoripmc\\/admin\\/feedback.php\",\"referrer\":\"http:\\/\\/localhost\\/Migoripmc\\/admin\\/feedback.php\",\"method\":\"POST\",\"timestamp\":1751524781}', '2025-07-03 06:39:41'),
(502, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"feedback.php\",\"url\":\"\\/Migoripmc\\/admin\\/feedback.php\",\"referrer\":\"http:\\/\\/localhost\\/Migoripmc\\/admin\\/feedback.php\",\"method\":\"GET\",\"timestamp\":1751524781}', '2025-07-03 06:39:41'),
(503, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"grievances.php\",\"url\":\"\\/Migoripmc\\/admin\\/grievances.php\",\"referrer\":\"http:\\/\\/localhost\\/Migoripmc\\/admin\\/feedback.php\",\"method\":\"GET\",\"timestamp\":1751524793}', '2025-07-03 06:39:53'),
(504, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"roles_permissions.php\",\"url\":\"\\/Migoripmc\\/admin\\/roles_permissions.php\",\"referrer\":\"http:\\/\\/localhost\\/Migoripmc\\/admin\\/grievances.php\",\"method\":\"GET\",\"timestamp\":1751524882}', '2025-07-03 06:41:22'),
(505, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"roles_permissions.php\",\"url\":\"\\/Migoripmc\\/admin\\/roles_permissions.php\",\"referrer\":\"http:\\/\\/localhost\\/Migoripmc\\/admin\\/roles_permissions.php\",\"method\":\"POST\",\"timestamp\":1751524995}', '2025-07-03 06:43:15'),
(506, 'permissions_updated', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"target_admin\":2,\"final_permissions\":[\"dashboard_access\",\"profile_access\",\"create_projects\",\"view_projects\",\"edit_projects\",\"manage_projects\",\"import_data\",\"manage_project_steps\",\"manage_budgets\",\"view_reports\",\"manage_feedback\",\"manage_documents\"],\"permissions_added\":{\"1\":\"profile_access\",\"2\":\"create_projects\",\"3\":\"view_projects\",\"4\":\"edit_projects\",\"5\":\"manage_projects\",\"6\":\"import_data\",\"7\":\"manage_project_steps\",\"8\":\"manage_budgets\",\"9\":\"view_reports\",\"10\":\"manage_feedback\",\"11\":\"manage_documents\"},\"permissions_removed\":[],\"total_permissions\":12}', '2025-07-03 06:43:15'),
(507, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"roles_permissions.php\",\"url\":\"\\/Migoripmc\\/admin\\/roles_permissions.php\",\"referrer\":\"http:\\/\\/localhost\\/Migoripmc\\/admin\\/roles_permissions.php\",\"method\":\"POST\",\"timestamp\":1751525284}', '2025-07-03 06:48:04'),
(508, 'permissions_updated', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"target_admin\":2,\"final_permissions\":[\"dashboard_access\"],\"permissions_added\":[],\"permissions_removed\":{\"1\":\"profile_access\",\"2\":\"create_projects\",\"3\":\"view_projects\",\"4\":\"edit_projects\",\"5\":\"manage_projects\",\"6\":\"import_data\",\"7\":\"manage_project_steps\",\"8\":\"manage_budgets\",\"9\":\"view_reports\",\"10\":\"manage_feedback\",\"11\":\"manage_documents\"},\"total_permissions\":1}', '2025-07-03 06:48:04'),
(509, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"roles_permissions.php\",\"url\":\"\\/Migoripmc\\/admin\\/roles_permissions.php\",\"referrer\":\"http:\\/\\/localhost\\/Migoripmc\\/admin\\/roles_permissions.php\",\"method\":\"POST\",\"timestamp\":1751525405}', '2025-07-03 06:50:05'),
(510, 'permissions_updated', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"target_admin\":2,\"final_permissions\":[\"dashboard_access\",\"profile_access\",\"create_projects\",\"view_projects\",\"edit_projects\",\"manage_projects\",\"import_data\",\"manage_project_steps\",\"manage_budgets\",\"view_reports\",\"manage_feedback\",\"manage_documents\",\"manage_users\"],\"permissions_added\":{\"1\":\"profile_access\",\"2\":\"create_projects\",\"3\":\"view_projects\",\"4\":\"edit_projects\",\"5\":\"manage_projects\",\"6\":\"import_data\",\"7\":\"manage_project_steps\",\"8\":\"manage_budgets\",\"9\":\"view_reports\",\"10\":\"manage_feedback\",\"11\":\"manage_documents\",\"12\":\"manage_users\"},\"permissions_removed\":[],\"total_permissions\":13}', '2025-07-03 06:50:05'),
(511, 'page_access', 2, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"import_csv.php\",\"url\":\"\\/Migoripmc\\/admin\\/import_csv.php\",\"referrer\":\"http:\\/\\/localhost\\/Migoripmc\\/admin\\/\",\"method\":\"GET\",\"timestamp\":1751525418}', '2025-07-03 06:50:18'),
(512, 'undefined_page_access', 2, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"csv_import\",\"url\":\"\\/Migoripmc\\/admin\\/import_csv.php\"}', '2025-07-03 06:50:18'),
(513, 'page_access', 2, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"create_project.php\",\"url\":\"\\/Migoripmc\\/admin\\/create_project.php\",\"referrer\":\"http:\\/\\/localhost\\/Migoripmc\\/admin\\/import_csv.php\",\"method\":\"GET\",\"timestamp\":1751525421}', '2025-07-03 06:50:21'),
(514, 'page_access', 2, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"projects.php\",\"url\":\"\\/Migoripmc\\/admin\\/projects.php\",\"referrer\":\"http:\\/\\/localhost\\/Migoripmc\\/admin\\/create_project.php\",\"method\":\"GET\",\"timestamp\":1751525422}', '2025-07-03 06:50:22'),
(515, 'page_access', 2, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"pmc_reports.php\",\"url\":\"\\/Migoripmc\\/admin\\/pmc_reports.php\",\"referrer\":\"http:\\/\\/localhost\\/Migoripmc\\/admin\\/budget_management.php\",\"method\":\"GET\",\"timestamp\":1751525448}', '2025-07-03 06:50:48'),
(516, 'page_access', 2, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"document_manager.php\",\"url\":\"\\/Migoripmc\\/admin\\/document_manager.php\",\"referrer\":\"http:\\/\\/localhost\\/Migoripmc\\/admin\\/pmc_reports.php\",\"method\":\"GET\",\"timestamp\":1751525454}', '2025-07-03 06:50:54'),
(517, 'page_access', 2, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"feedback.php\",\"url\":\"\\/Migoripmc\\/admin\\/feedback.php\",\"referrer\":\"http:\\/\\/localhost\\/Migoripmc\\/admin\\/document_manager.php\",\"method\":\"GET\",\"timestamp\":1751525493}', '2025-07-03 06:51:33'),
(518, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"create_project.php\",\"url\":\"\\/Migoripmc\\/admin\\/create_project.php\",\"referrer\":\"http:\\/\\/localhost\\/Migoripmc\\/admin\\/roles_permissions.php\",\"method\":\"GET\",\"timestamp\":1751525528}', '2025-07-03 06:52:08'),
(519, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"roles_permissions.php\",\"url\":\"\\/Migoripmc\\/admin\\/roles_permissions.php\",\"referrer\":\"http:\\/\\/localhost\\/Migoripmc\\/admin\\/create_project.php\",\"method\":\"GET\",\"timestamp\":1751525534}', '2025-07-03 06:52:14'),
(520, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"activity_logs.php\",\"url\":\"\\/Migoripmc\\/admin\\/activity_logs.php\",\"referrer\":\"http:\\/\\/localhost\\/Migoripmc\\/admin\\/roles_permissions.php\",\"method\":\"GET\",\"timestamp\":1751525545}', '2025-07-03 06:52:25'),
(521, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"activity_logs.php\",\"url\":\"\\/Migoripmc\\/admin\\/activity_logs.php?page=24\",\"referrer\":\"http:\\/\\/localhost\\/Migoripmc\\/admin\\/activity_logs.php\",\"method\":\"GET\",\"timestamp\":1751525659}', '2025-07-03 06:54:19'),
(522, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"activity_logs.php\",\"url\":\"\\/Migoripmc\\/admin\\/activity_logs.php?admin_id=&activity_type=&target_type=admin&date_from=&date_to=&search=\",\"referrer\":\"http:\\/\\/localhost\\/Migoripmc\\/admin\\/activity_logs.php?page=24\",\"method\":\"GET\",\"timestamp\":1751525680}', '2025-07-03 06:54:40'),
(523, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"activity_logs.php\",\"url\":\"\\/Migoripmc\\/admin\\/activity_logs.php?admin_id=&activity_type=csv_import_access&target_type=admin&date_from=&date_to=&search=\",\"referrer\":\"http:\\/\\/localhost\\/Migoripmc\\/admin\\/activity_logs.php?admin_id=&activity_type=&target_type=admin&date_from=&date_to=&search=\",\"method\":\"GET\",\"timestamp\":1751525697}', '2025-07-03 06:54:57'),
(524, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"feedback.php\",\"url\":\"\\/Migoripmc\\/admin\\/feedback.php\",\"referrer\":\"http:\\/\\/localhost\\/Migoripmc\\/admin\\/activity_logs.php?admin_id=&activity_type=csv_import_access&target_type=admin&date_from=&date_to=&search=\",\"method\":\"GET\",\"timestamp\":1751527321}', '2025-07-03 07:22:01');
INSERT INTO `security_logs` (`id`, `event_type`, `admin_id`, `ip_address`, `user_agent`, `details`, `created_at`) VALUES
(525, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"feedback.php\",\"url\":\"\\/Migoripmc\\/admin\\/feedback.php?search=&status=pending&project_id=\",\"referrer\":\"http:\\/\\/localhost\\/Migoripmc\\/admin\\/feedback.php\",\"method\":\"GET\",\"timestamp\":1751527351}', '2025-07-03 07:22:31'),
(526, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"feedback.php\",\"url\":\"\\/Migoripmc\\/admin\\/feedback.php?search=&status=&project_id=\",\"referrer\":\"http:\\/\\/localhost\\/Migoripmc\\/admin\\/feedback.php?search=&status=pending&project_id=\",\"method\":\"GET\",\"timestamp\":1751527366}', '2025-07-03 07:22:46'),
(527, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"feedback.php\",\"url\":\"\\/Migoripmc\\/admin\\/feedback.php\",\"referrer\":\"http:\\/\\/localhost\\/Migoripmc\\/admin\\/feedback.php?search=&status=&project_id=\",\"method\":\"GET\",\"timestamp\":1751527367}', '2025-07-03 07:22:47'),
(528, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"create_project.php\",\"url\":\"\\/migoripmc\\/admin\\/create_project.php\",\"referrer\":\"http:\\/\\/localhost\\/migoripmc\\/admin\\/\",\"method\":\"GET\",\"timestamp\":1751535327}', '2025-07-03 09:35:27'),
(529, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"projects.php\",\"url\":\"\\/migoripmc\\/admin\\/projects.php\",\"referrer\":\"http:\\/\\/localhost\\/migoripmc\\/admin\\/create_project.php\",\"method\":\"GET\",\"timestamp\":1751535363}', '2025-07-03 09:36:03'),
(530, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"manage_project.php\",\"url\":\"\\/migoripmc\\/admin\\/manage_project.php?id=19\",\"referrer\":\"http:\\/\\/localhost\\/migoripmc\\/admin\\/projects.php\",\"method\":\"GET\",\"timestamp\":1751535373}', '2025-07-03 09:36:13'),
(531, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"manage_project.php\",\"url\":\"\\/migoripmc\\/admin\\/manage_project.php?id=19\",\"referrer\":\"http:\\/\\/localhost\\/migoripmc\\/admin\\/manage_project.php?id=19\",\"method\":\"POST\",\"timestamp\":1751535780}', '2025-07-03 09:43:00'),
(532, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"importCsv.php\",\"url\":\"\\/migoripmcCamelV\\/admin\\/importCsv.php\",\"referrer\":\"http:\\/\\/localhost\\/migoripmcCamelV\\/admin\\/\",\"method\":\"GET\",\"timestamp\":1751558146}', '2025-07-03 15:55:46'),
(533, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"createProject.php\",\"url\":\"\\/migoripmcCamelV\\/admin\\/createProject.php\",\"referrer\":\"http:\\/\\/localhost\\/migoripmcCamelV\\/admin\\/importCsv.php\",\"method\":\"GET\",\"timestamp\":1751558149}', '2025-07-03 15:55:49'),
(534, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"projects.php\",\"url\":\"\\/migoripmcCamelV\\/admin\\/projects.php\",\"referrer\":\"http:\\/\\/localhost\\/migoripmcCamelV\\/admin\\/createProject.php\",\"method\":\"GET\",\"timestamp\":1751558151}', '2025-07-03 15:55:51'),
(535, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"pmcReports.php\",\"url\":\"\\/migoripmcCamelV\\/admin\\/pmcReports.php\",\"referrer\":\"http:\\/\\/localhost\\/migoripmcCamelV\\/admin\\/budgetManagement.php\",\"method\":\"GET\",\"timestamp\":1751558156}', '2025-07-03 15:55:56'),
(536, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"documentManager.php\",\"url\":\"\\/migoripmcCamelV\\/admin\\/documentManager.php\",\"referrer\":\"http:\\/\\/localhost\\/migoripmcCamelV\\/admin\\/pmcReports.php\",\"method\":\"GET\",\"timestamp\":1751558158}', '2025-07-03 15:55:58'),
(537, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"feedback.php\",\"url\":\"\\/migoripmcCamelV\\/admin\\/feedback.php\",\"referrer\":\"http:\\/\\/localhost\\/migoripmcCamelV\\/admin\\/documentManager.php\",\"method\":\"GET\",\"timestamp\":1751558160}', '2025-07-03 15:56:00'),
(538, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"grievances.php\",\"url\":\"\\/migoripmcCamelV\\/admin\\/grievances.php\",\"referrer\":\"http:\\/\\/localhost\\/migoripmcCamelV\\/admin\\/feedback.php\",\"method\":\"GET\",\"timestamp\":1751558166}', '2025-07-03 15:56:06'),
(539, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"grievances.php\",\"url\":\"\\/migoripmcCamelV\\/admin\\/grievances.php\",\"referrer\":\"http:\\/\\/localhost\\/migoripmcCamelV\\/admin\\/grievances.php\",\"method\":\"POST\",\"timestamp\":1751558187}', '2025-07-03 15:56:27'),
(540, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"grievances.php\",\"url\":\"\\/migoripmcCamelV\\/admin\\/grievances.php\",\"referrer\":\"http:\\/\\/localhost\\/migoripmcCamelV\\/admin\\/grievances.php\",\"method\":\"GET\",\"timestamp\":1751558189}', '2025-07-03 15:56:29'),
(541, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"feedback.php\",\"url\":\"\\/migoripmcCamelV\\/admin\\/feedback.php?info=no_grievances\",\"referrer\":\"http:\\/\\/localhost\\/migoripmcCamelV\\/admin\\/grievances.php\",\"method\":\"GET\",\"timestamp\":1751558189}', '2025-07-03 15:56:29'),
(542, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"rolesPermissions.php\",\"url\":\"\\/migoripmcCamelV\\/admin\\/rolesPermissions.php\",\"referrer\":\"http:\\/\\/localhost\\/migoripmcCamelV\\/admin\\/feedback.php?info=no_grievances\",\"method\":\"GET\",\"timestamp\":1751558198}', '2025-07-03 15:56:38'),
(543, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"rolesPermissions.php\",\"url\":\"\\/migoripmcCamelV\\/admin\\/rolesPermissions.php\",\"referrer\":\"http:\\/\\/localhost\\/migoripmcCamelV\\/admin\\/rolesPermissions.php\",\"method\":\"POST\",\"timestamp\":1751558216}', '2025-07-03 15:56:56'),
(544, 'permissions_updated', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"target_admin\":2,\"final_permissions\":[\"dashboard_access\",\"profile_access\",\"create_projects\",\"manage_users\"],\"permissions_added\":[],\"permissions_removed\":{\"3\":\"view_projects\",\"4\":\"edit_projects\",\"5\":\"manage_projects\",\"6\":\"import_data\",\"7\":\"manage_project_steps\",\"8\":\"manage_budgets\",\"9\":\"view_reports\",\"10\":\"manage_feedback\",\"11\":\"manage_documents\"},\"total_permissions\":4}', '2025-07-03 15:56:56'),
(545, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"activityLogs.php\",\"url\":\"\\/migoripmcCamelV\\/admin\\/activityLogs.php\",\"referrer\":\"http:\\/\\/localhost\\/migoripmcCamelV\\/admin\\/rolesPermissions.php\",\"method\":\"GET\",\"timestamp\":1751558221}', '2025-07-03 15:57:01'),
(546, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"importCsv.php\",\"url\":\"\\/migoripmcCamelV\\/admin\\/importCsv.php\",\"referrer\":\"http:\\/\\/localhost\\/migoripmcCamelV\\/admin\\/profile.php\",\"method\":\"GET\",\"timestamp\":1751559043}', '2025-07-03 16:10:43'),
(547, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"createProject.php\",\"url\":\"\\/migoripmcCamelV\\/admin\\/createProject.php\",\"referrer\":\"http:\\/\\/localhost\\/migoripmcCamelV\\/admin\\/importCsv.php\",\"method\":\"GET\",\"timestamp\":1751559068}', '2025-07-03 16:11:08'),
(548, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"importCsv.php\",\"url\":\"\\/migoripmcCamelV\\/admin\\/importCsv.php\",\"referrer\":\"http:\\/\\/localhost\\/migoripmcCamelV\\/admin\\/profile.php\",\"method\":\"GET\",\"timestamp\":1751562090}', '2025-07-03 17:01:30'),
(549, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"createProject.php\",\"url\":\"\\/migoripmcCamelV\\/admin\\/createProject.php\",\"referrer\":\"http:\\/\\/localhost\\/migoripmcCamelV\\/admin\\/importCsv.php\",\"method\":\"GET\",\"timestamp\":1751562095}', '2025-07-03 17:01:35'),
(550, 'unauthorized_access_attempt', 2, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"importCsv.php\",\"url\":\"\\/migoripmcCamelV\\/admin\\/importCsv.php\",\"referrer\":\"http:\\/\\/localhost\\/migoripmcCamelV\\/admin\\/\"}', '2025-07-04 04:57:51'),
(551, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"importCsv.php\",\"url\":\"\\/migoripmcCamelV\\/admin\\/importCsv.php\",\"referrer\":\"http:\\/\\/localhost\\/migoripmcCamelV\\/admin\\/\",\"method\":\"GET\",\"timestamp\":1751605090}', '2025-07-04 04:58:10'),
(552, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"rolesPermissions.php\",\"url\":\"\\/migoripmcCamelV\\/admin\\/rolesPermissions.php\",\"referrer\":\"http:\\/\\/localhost\\/migoripmcCamelV\\/admin\\/\",\"method\":\"GET\",\"timestamp\":1751605100}', '2025-07-04 04:58:20'),
(553, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"rolesPermissions.php\",\"url\":\"\\/migoripmcCamelV\\/admin\\/rolesPermissions.php\",\"referrer\":\"http:\\/\\/localhost\\/migoripmcCamelV\\/admin\\/rolesPermissions.php\",\"method\":\"POST\",\"timestamp\":1751605134}', '2025-07-04 04:58:54'),
(554, 'permissions_updated', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"target_admin\":2,\"final_permissions\":[\"dashboard_access\"],\"permissions_added\":[],\"permissions_removed\":{\"1\":\"profile_access\",\"2\":\"create_projects\",\"3\":\"manage_users\"},\"total_permissions\":1}', '2025-07-04 04:58:54'),
(555, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"rolesPermissions.php\",\"url\":\"\\/migoripmcCamelV\\/admin\\/rolesPermissions.php\",\"referrer\":\"http:\\/\\/localhost\\/migoripmcCamelV\\/admin\\/rolesPermissions.php\",\"method\":\"POST\",\"timestamp\":1751605196}', '2025-07-04 04:59:56'),
(556, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"rolesPermissions.php\",\"url\":\"\\/migoripmcCamelV\\/admin\\/rolesPermissions.php\",\"referrer\":\"http:\\/\\/localhost\\/migoripmcCamelV\\/admin\\/rolesPermissions.php\",\"method\":\"POST\",\"timestamp\":1751605202}', '2025-07-04 05:00:02'),
(557, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"rolesPermissions.php\",\"url\":\"\\/migoripmcCamelV\\/admin\\/rolesPermissions.php\",\"referrer\":null,\"method\":\"GET\",\"timestamp\":1751605207}', '2025-07-04 05:00:07'),
(558, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"rolesPermissions.php\",\"url\":\"\\/migoripmcCamelV\\/admin\\/rolesPermissions.php\",\"referrer\":\"http:\\/\\/localhost\\/migoripmcCamelV\\/admin\\/rolesPermissions.php\",\"method\":\"POST\",\"timestamp\":1751605238}', '2025-07-04 05:00:38'),
(559, 'permissions_updated', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"target_admin\":2,\"final_permissions\":[\"dashboard_access\",\"profile_access\",\"create_projects\",\"view_projects\",\"edit_projects\",\"manage_projects\",\"import_data\",\"manage_project_steps\",\"manage_budgets\",\"view_reports\",\"manage_feedback\",\"manage_documents\"],\"permissions_added\":{\"1\":\"profile_access\",\"2\":\"create_projects\",\"3\":\"view_projects\",\"4\":\"edit_projects\",\"5\":\"manage_projects\",\"6\":\"import_data\",\"7\":\"manage_project_steps\",\"8\":\"manage_budgets\",\"9\":\"view_reports\",\"10\":\"manage_feedback\",\"11\":\"manage_documents\"},\"permissions_removed\":[],\"total_permissions\":12}', '2025-07-04 05:00:38'),
(560, 'page_access', 2, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"importCsv.php\",\"url\":\"\\/migoripmccamelv\\/admin\\/importCsv.php\",\"referrer\":\"http:\\/\\/localhost\\/migoripmccamelv\\/admin\\/\",\"method\":\"GET\",\"timestamp\":1751605249}', '2025-07-04 05:00:49'),
(561, 'undefined_page_access', 2, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"csv_import\",\"url\":\"\\/migoripmccamelv\\/admin\\/importCsv.php\"}', '2025-07-04 05:00:49'),
(562, 'page_access', 2, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"createProject.php\",\"url\":\"\\/migoripmccamelv\\/admin\\/createProject.php\",\"referrer\":\"http:\\/\\/localhost\\/migoripmccamelv\\/admin\\/profile.php\",\"method\":\"GET\",\"timestamp\":1751605276}', '2025-07-04 05:01:16'),
(563, 'page_access', 2, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"projects.php\",\"url\":\"\\/migoripmccamelv\\/admin\\/projects.php\",\"referrer\":\"http:\\/\\/localhost\\/migoripmccamelv\\/admin\\/createProject.php\",\"method\":\"GET\",\"timestamp\":1751605286}', '2025-07-04 05:01:26'),
(564, 'page_access', 2, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"manageProject.php\",\"url\":\"\\/migoripmccamelv\\/admin\\/manageProject.php?id=17\",\"referrer\":\"http:\\/\\/localhost\\/migoripmccamelv\\/admin\\/projects.php\",\"method\":\"GET\",\"timestamp\":1751605291}', '2025-07-04 05:01:31'),
(565, 'page_access', 2, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"manageProject.php\",\"url\":\"\\/migoripmccamelv\\/admin\\/manageProject.php?id=17\",\"referrer\":\"http:\\/\\/localhost\\/migoripmccamelv\\/admin\\/manageProject.php?id=17\",\"method\":\"POST\",\"timestamp\":1751605298}', '2025-07-04 05:01:38'),
(566, 'page_access', 2, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"manageProject.php\",\"url\":\"\\/migoripmccamelv\\/admin\\/manageProject.php?id=17\",\"referrer\":\"http:\\/\\/localhost\\/migoripmccamelv\\/admin\\/manageProject.php?id=17\",\"method\":\"POST\",\"timestamp\":1751605308}', '2025-07-04 05:01:48'),
(567, 'page_access', 2, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"pmcReports.php\",\"url\":\"\\/migoripmccamelv\\/admin\\/pmcReports.php\",\"referrer\":\"http:\\/\\/localhost\\/migoripmccamelv\\/admin\\/budgetManagement.php\",\"method\":\"GET\",\"timestamp\":1751605356}', '2025-07-04 05:02:36'),
(568, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"importCsv.php\",\"url\":\"\\/migoripmccamelv2\\/admin\\/importCsv.php\",\"referrer\":\"http:\\/\\/localhost\\/migoripmccamelv2\\/admin\\/\",\"method\":\"GET\",\"timestamp\":1751652525}', '2025-07-04 18:08:45'),
(569, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"projects.php\",\"url\":\"\\/migoripmccamelv2\\/admin\\/projects.php\",\"referrer\":\"http:\\/\\/localhost\\/migoripmccamelv2\\/admin\\/importCsv.php\",\"method\":\"GET\",\"timestamp\":1751653092}', '2025-07-04 18:18:12'),
(570, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"manageProject.php\",\"url\":\"\\/migoripmccamelv2\\/admin\\/manageProject.php?id=21\",\"referrer\":\"http:\\/\\/localhost\\/migoripmccamelv2\\/admin\\/projects.php\",\"method\":\"GET\",\"timestamp\":1751653095}', '2025-07-04 18:18:15'),
(571, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"projects.php\",\"url\":\"\\/migoripmccamelv2\\/admin\\/projects.php\",\"referrer\":\"http:\\/\\/localhost\\/migoripmccamelv2\\/admin\\/importCsv.php\",\"method\":\"GET\",\"timestamp\":1751653099}', '2025-07-04 18:18:19'),
(572, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"projects.php\",\"url\":\"\\/migoripmccamelv2\\/admin\\/projects.php?search=&status=&visibility=private\",\"referrer\":\"http:\\/\\/localhost\\/migoripmccamelv2\\/admin\\/projects.php\",\"method\":\"GET\",\"timestamp\":1751653108}', '2025-07-04 18:18:28'),
(573, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"manageProject.php\",\"url\":\"\\/migoripmccamelv2\\/admin\\/manageProject.php?id=20\",\"referrer\":\"http:\\/\\/localhost\\/migoripmccamelv2\\/admin\\/projects.php?search=&status=&visibility=private\",\"method\":\"GET\",\"timestamp\":1751653111}', '2025-07-04 18:18:31'),
(574, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"manageProject.php\",\"url\":\"\\/migoripmccamelv2\\/admin\\/manageProject.php?id=20\",\"referrer\":\"http:\\/\\/localhost\\/migoripmccamelv2\\/admin\\/manageProject.php?id=20\",\"method\":\"POST\",\"timestamp\":1751653115}', '2025-07-04 18:18:35'),
(575, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"projects.php\",\"url\":\"\\/migoripmccamelv2\\/admin\\/projects.php?success=Project+deleted+successfully\",\"referrer\":\"http:\\/\\/localhost\\/migoripmccamelv2\\/admin\\/manageProject.php?id=20\",\"method\":\"GET\",\"timestamp\":1751653115}', '2025-07-04 18:18:35'),
(576, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"manageProject.php\",\"url\":\"\\/migoripmccamelv2\\/admin\\/manageProject.php?id=21\",\"referrer\":\"http:\\/\\/localhost\\/migoripmccamelv2\\/admin\\/projects.php?success=Project+deleted+successfully\",\"method\":\"GET\",\"timestamp\":1751653117}', '2025-07-04 18:18:37'),
(577, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"manageProject.php\",\"url\":\"\\/migoripmccamelv2\\/admin\\/manageProject.php?id=21\",\"referrer\":\"http:\\/\\/localhost\\/migoripmccamelv2\\/admin\\/manageProject.php?id=21\",\"method\":\"POST\",\"timestamp\":1751653120}', '2025-07-04 18:18:40'),
(578, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"projects.php\",\"url\":\"\\/migoripmccamelv2\\/admin\\/projects.php?success=Project+deleted+successfully\",\"referrer\":\"http:\\/\\/localhost\\/migoripmccamelv2\\/admin\\/manageProject.php?id=21\",\"method\":\"GET\",\"timestamp\":1751653120}', '2025-07-04 18:18:40'),
(579, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"manageProject.php\",\"url\":\"\\/migoripmccamelv2\\/admin\\/manageProject.php?id=19\",\"referrer\":\"http:\\/\\/localhost\\/migoripmccamelv2\\/admin\\/projects.php?success=Project+deleted+successfully\",\"method\":\"GET\",\"timestamp\":1751653122}', '2025-07-04 18:18:42'),
(580, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"manageProject.php\",\"url\":\"\\/migoripmccamelv2\\/admin\\/manageProject.php?id=19\",\"referrer\":\"http:\\/\\/localhost\\/migoripmccamelv2\\/admin\\/manageProject.php?id=19\",\"method\":\"POST\",\"timestamp\":1751653126}', '2025-07-04 18:18:46'),
(581, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"projects.php\",\"url\":\"\\/migoripmccamelv2\\/admin\\/projects.php?success=Project+deleted+successfully\",\"referrer\":\"http:\\/\\/localhost\\/migoripmccamelv2\\/admin\\/manageProject.php?id=19\",\"method\":\"GET\",\"timestamp\":1751653126}', '2025-07-04 18:18:46'),
(582, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"manageProject.php\",\"url\":\"\\/migoripmccamelv2\\/admin\\/manageProject.php?id=18\",\"referrer\":\"http:\\/\\/localhost\\/migoripmccamelv2\\/admin\\/projects.php?success=Project+deleted+successfully\",\"method\":\"GET\",\"timestamp\":1751653128}', '2025-07-04 18:18:48'),
(583, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"manageProject.php\",\"url\":\"\\/migoripmccamelv2\\/admin\\/manageProject.php?id=18\",\"referrer\":\"http:\\/\\/localhost\\/migoripmccamelv2\\/admin\\/manageProject.php?id=18\",\"method\":\"POST\",\"timestamp\":1751653132}', '2025-07-04 18:18:52'),
(584, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"projects.php\",\"url\":\"\\/migoripmccamelv2\\/admin\\/projects.php?success=Project+deleted+successfully\",\"referrer\":\"http:\\/\\/localhost\\/migoripmccamelv2\\/admin\\/manageProject.php?id=18\",\"method\":\"GET\",\"timestamp\":1751653132}', '2025-07-04 18:18:52'),
(585, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"manageProject.php\",\"url\":\"\\/migoripmccamelv2\\/admin\\/manageProject.php?id=17\",\"referrer\":\"http:\\/\\/localhost\\/migoripmccamelv2\\/admin\\/projects.php?success=Project+deleted+successfully\",\"method\":\"GET\",\"timestamp\":1751653134}', '2025-07-04 18:18:54'),
(586, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"manageProject.php\",\"url\":\"\\/migoripmccamelv2\\/admin\\/manageProject.php?id=17\",\"referrer\":\"http:\\/\\/localhost\\/migoripmccamelv2\\/admin\\/manageProject.php?id=17\",\"method\":\"POST\",\"timestamp\":1751653137}', '2025-07-04 18:18:57'),
(587, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"projects.php\",\"url\":\"\\/migoripmccamelv2\\/admin\\/projects.php?success=Project+deleted+successfully\",\"referrer\":\"http:\\/\\/localhost\\/migoripmccamelv2\\/admin\\/manageProject.php?id=17\",\"method\":\"GET\",\"timestamp\":1751653138}', '2025-07-04 18:18:58'),
(588, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"manageProject.php\",\"url\":\"\\/migoripmccamelv2\\/admin\\/manageProject.php?id=3\",\"referrer\":\"http:\\/\\/localhost\\/migoripmccamelv2\\/admin\\/projects.php?success=Project+deleted+successfully\",\"method\":\"GET\",\"timestamp\":1751653140}', '2025-07-04 18:19:00'),
(589, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"manageProject.php\",\"url\":\"\\/migoripmccamelv2\\/admin\\/manageProject.php?id=3\",\"referrer\":\"http:\\/\\/localhost\\/migoripmccamelv2\\/admin\\/manageProject.php?id=3\",\"method\":\"POST\",\"timestamp\":1751653144}', '2025-07-04 18:19:04'),
(590, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"projects.php\",\"url\":\"\\/migoripmccamelv2\\/admin\\/projects.php?success=Project+deleted+successfully\",\"referrer\":\"http:\\/\\/localhost\\/migoripmccamelv2\\/admin\\/manageProject.php?id=3\",\"method\":\"GET\",\"timestamp\":1751653144}', '2025-07-04 18:19:04'),
(591, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"manageProject.php\",\"url\":\"\\/migoripmccamelv2\\/admin\\/manageProject.php?id=9\",\"referrer\":\"http:\\/\\/localhost\\/migoripmccamelv2\\/admin\\/projects.php?success=Project+deleted+successfully\",\"method\":\"GET\",\"timestamp\":1751653148}', '2025-07-04 18:19:08'),
(592, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"manageProject.php\",\"url\":\"\\/migoripmccamelv2\\/admin\\/manageProject.php?id=9\",\"referrer\":\"http:\\/\\/localhost\\/migoripmccamelv2\\/admin\\/manageProject.php?id=9\",\"method\":\"POST\",\"timestamp\":1751653151}', '2025-07-04 18:19:11'),
(593, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"projects.php\",\"url\":\"\\/migoripmccamelv2\\/admin\\/projects.php?success=Project+deleted+successfully\",\"referrer\":\"http:\\/\\/localhost\\/migoripmccamelv2\\/admin\\/manageProject.php?id=9\",\"method\":\"GET\",\"timestamp\":1751653151}', '2025-07-04 18:19:11'),
(594, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"manageProject.php\",\"url\":\"\\/migoripmccamelv2\\/admin\\/manageProject.php?id=2\",\"referrer\":\"http:\\/\\/localhost\\/migoripmccamelv2\\/admin\\/projects.php?success=Project+deleted+successfully\",\"method\":\"GET\",\"timestamp\":1751653154}', '2025-07-04 18:19:14'),
(595, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"manageProject.php\",\"url\":\"\\/migoripmccamelv2\\/admin\\/manageProject.php?id=2\",\"referrer\":\"http:\\/\\/localhost\\/migoripmccamelv2\\/admin\\/manageProject.php?id=2\",\"method\":\"POST\",\"timestamp\":1751653157}', '2025-07-04 18:19:17'),
(596, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"projects.php\",\"url\":\"\\/migoripmccamelv2\\/admin\\/projects.php?success=Project+deleted+successfully\",\"referrer\":\"http:\\/\\/localhost\\/migoripmccamelv2\\/admin\\/manageProject.php?id=2\",\"method\":\"GET\",\"timestamp\":1751653158}', '2025-07-04 18:19:18'),
(597, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"manageProject.php\",\"url\":\"\\/migoripmccamelv2\\/admin\\/manageProject.php?id=5\",\"referrer\":\"http:\\/\\/localhost\\/migoripmccamelv2\\/admin\\/projects.php?success=Project+deleted+successfully\",\"method\":\"GET\",\"timestamp\":1751653160}', '2025-07-04 18:19:20'),
(598, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"manageProject.php\",\"url\":\"\\/migoripmccamelv2\\/admin\\/manageProject.php?id=5\",\"referrer\":\"http:\\/\\/localhost\\/migoripmccamelv2\\/admin\\/manageProject.php?id=5\",\"method\":\"POST\",\"timestamp\":1751653163}', '2025-07-04 18:19:23'),
(599, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"projects.php\",\"url\":\"\\/migoripmccamelv2\\/admin\\/projects.php?success=Project+deleted+successfully\",\"referrer\":\"http:\\/\\/localhost\\/migoripmccamelv2\\/admin\\/manageProject.php?id=5\",\"method\":\"GET\",\"timestamp\":1751653163}', '2025-07-04 18:19:23'),
(600, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"manageProject.php\",\"url\":\"\\/migoripmccamelv2\\/admin\\/manageProject.php?id=6\",\"referrer\":\"http:\\/\\/localhost\\/migoripmccamelv2\\/admin\\/projects.php?success=Project+deleted+successfully\",\"method\":\"GET\",\"timestamp\":1751653165}', '2025-07-04 18:19:25'),
(601, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"manageProject.php\",\"url\":\"\\/migoripmccamelv2\\/admin\\/manageProject.php?id=6\",\"referrer\":\"http:\\/\\/localhost\\/migoripmccamelv2\\/admin\\/manageProject.php?id=6\",\"method\":\"POST\",\"timestamp\":1751653169}', '2025-07-04 18:19:29'),
(602, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"projects.php\",\"url\":\"\\/migoripmccamelv2\\/admin\\/projects.php?success=Project+deleted+successfully\",\"referrer\":\"http:\\/\\/localhost\\/migoripmccamelv2\\/admin\\/manageProject.php?id=6\",\"method\":\"GET\",\"timestamp\":1751653169}', '2025-07-04 18:19:29'),
(603, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"manageProject.php\",\"url\":\"\\/migoripmccamelv2\\/admin\\/manageProject.php?id=1\",\"referrer\":\"http:\\/\\/localhost\\/migoripmccamelv2\\/admin\\/projects.php?success=Project+deleted+successfully\",\"method\":\"GET\",\"timestamp\":1751653171}', '2025-07-04 18:19:31'),
(604, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"manageProject.php\",\"url\":\"\\/migoripmccamelv2\\/admin\\/manageProject.php?id=1\",\"referrer\":\"http:\\/\\/localhost\\/migoripmccamelv2\\/admin\\/manageProject.php?id=1\",\"method\":\"POST\",\"timestamp\":1751653175}', '2025-07-04 18:19:35'),
(605, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"projects.php\",\"url\":\"\\/migoripmccamelv2\\/admin\\/projects.php?success=Project+deleted+successfully\",\"referrer\":\"http:\\/\\/localhost\\/migoripmccamelv2\\/admin\\/manageProject.php?id=1\",\"method\":\"GET\",\"timestamp\":1751653175}', '2025-07-04 18:19:35'),
(606, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"manageProject.php\",\"url\":\"\\/migoripmccamelv2\\/admin\\/manageProject.php?id=4\",\"referrer\":\"http:\\/\\/localhost\\/migoripmccamelv2\\/admin\\/projects.php?success=Project+deleted+successfully\",\"method\":\"GET\",\"timestamp\":1751653177}', '2025-07-04 18:19:37'),
(607, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"manageProject.php\",\"url\":\"\\/migoripmccamelv2\\/admin\\/manageProject.php?id=4\",\"referrer\":\"http:\\/\\/localhost\\/migoripmccamelv2\\/admin\\/manageProject.php?id=4\",\"method\":\"POST\",\"timestamp\":1751653180}', '2025-07-04 18:19:40'),
(608, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"projects.php\",\"url\":\"\\/migoripmccamelv2\\/admin\\/projects.php?success=Project+deleted+successfully\",\"referrer\":\"http:\\/\\/localhost\\/migoripmccamelv2\\/admin\\/manageProject.php?id=4\",\"method\":\"GET\",\"timestamp\":1751653180}', '2025-07-04 18:19:40'),
(609, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"manageProject.php\",\"url\":\"\\/migoripmccamelv2\\/admin\\/manageProject.php?id=8\",\"referrer\":\"http:\\/\\/localhost\\/migoripmccamelv2\\/admin\\/projects.php?success=Project+deleted+successfully\",\"method\":\"GET\",\"timestamp\":1751653182}', '2025-07-04 18:19:42'),
(610, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"manageProject.php\",\"url\":\"\\/migoripmccamelv2\\/admin\\/manageProject.php?id=8\",\"referrer\":\"http:\\/\\/localhost\\/migoripmccamelv2\\/admin\\/manageProject.php?id=8\",\"method\":\"POST\",\"timestamp\":1751653185}', '2025-07-04 18:19:45'),
(611, 'suspicious_activity', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"reason\":\"rapid_page_access\",\"access_count\":31,\"page\":\"projects.php\",\"time_window\":\"1_minute\"}', '2025-07-04 18:19:45'),
(612, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"projects.php\",\"url\":\"\\/migoripmccamelv2\\/admin\\/projects.php?success=Project+deleted+successfully\",\"referrer\":\"http:\\/\\/localhost\\/migoripmccamelv2\\/admin\\/manageProject.php?id=8\",\"method\":\"GET\",\"timestamp\":1751653185}', '2025-07-04 18:19:45'),
(613, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"manageProject.php\",\"url\":\"\\/migoripmccamelv2\\/admin\\/manageProject.php?id=10\",\"referrer\":\"http:\\/\\/localhost\\/migoripmccamelv2\\/admin\\/projects.php?success=Project+deleted+successfully\",\"method\":\"GET\",\"timestamp\":1751653187}', '2025-07-04 18:19:47'),
(614, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"manageProject.php\",\"url\":\"\\/migoripmccamelv2\\/admin\\/manageProject.php?id=10\",\"referrer\":\"http:\\/\\/localhost\\/migoripmccamelv2\\/admin\\/manageProject.php?id=10\",\"method\":\"POST\",\"timestamp\":1751653191}', '2025-07-04 18:19:51'),
(615, 'suspicious_activity', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"reason\":\"rapid_page_access\",\"access_count\":31,\"page\":\"projects.php\",\"time_window\":\"1_minute\"}', '2025-07-04 18:19:51'),
(616, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"projects.php\",\"url\":\"\\/migoripmccamelv2\\/admin\\/projects.php?success=Project+deleted+successfully\",\"referrer\":\"http:\\/\\/localhost\\/migoripmccamelv2\\/admin\\/manageProject.php?id=10\",\"method\":\"GET\",\"timestamp\":1751653191}', '2025-07-04 18:19:51'),
(617, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"manageProject.php\",\"url\":\"\\/migoripmccamelv2\\/admin\\/manageProject.php?id=11\",\"referrer\":\"http:\\/\\/localhost\\/migoripmccamelv2\\/admin\\/projects.php?success=Project+deleted+successfully\",\"method\":\"GET\",\"timestamp\":1751653195}', '2025-07-04 18:19:55'),
(618, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"manageProject.php\",\"url\":\"\\/migoripmccamelv2\\/admin\\/manageProject.php?id=11\",\"referrer\":\"http:\\/\\/localhost\\/migoripmccamelv2\\/admin\\/manageProject.php?id=11\",\"method\":\"POST\",\"timestamp\":1751653198}', '2025-07-04 18:19:58'),
(619, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"projects.php\",\"url\":\"\\/migoripmccamelv2\\/admin\\/projects.php?success=Project+deleted+successfully\",\"referrer\":\"http:\\/\\/localhost\\/migoripmccamelv2\\/admin\\/manageProject.php?id=11\",\"method\":\"GET\",\"timestamp\":1751653198}', '2025-07-04 18:19:58'),
(620, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"manageProject.php\",\"url\":\"\\/migoripmccamelv2\\/admin\\/manageProject.php?id=12\",\"referrer\":\"http:\\/\\/localhost\\/migoripmccamelv2\\/admin\\/projects.php?success=Project+deleted+successfully\",\"method\":\"GET\",\"timestamp\":1751653201}', '2025-07-04 18:20:01'),
(621, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"manageProject.php\",\"url\":\"\\/migoripmccamelv2\\/admin\\/manageProject.php?id=12\",\"referrer\":\"http:\\/\\/localhost\\/migoripmccamelv2\\/admin\\/manageProject.php?id=12\",\"method\":\"POST\",\"timestamp\":1751653205}', '2025-07-04 18:20:05'),
(622, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"projects.php\",\"url\":\"\\/migoripmccamelv2\\/admin\\/projects.php?success=Project+deleted+successfully\",\"referrer\":\"http:\\/\\/localhost\\/migoripmccamelv2\\/admin\\/manageProject.php?id=12\",\"method\":\"GET\",\"timestamp\":1751653205}', '2025-07-04 18:20:05'),
(623, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"manageProject.php\",\"url\":\"\\/migoripmccamelv2\\/admin\\/manageProject.php?id=13\",\"referrer\":\"http:\\/\\/localhost\\/migoripmccamelv2\\/admin\\/projects.php?success=Project+deleted+successfully\",\"method\":\"GET\",\"timestamp\":1751653207}', '2025-07-04 18:20:07'),
(624, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"editProject.php\",\"url\":\"\\/migoripmccamelv2\\/admin\\/editProject.php?id=13\",\"referrer\":\"http:\\/\\/localhost\\/migoripmccamelv2\\/admin\\/manageProject.php?id=13\",\"method\":\"GET\",\"timestamp\":1751653210}', '2025-07-04 18:20:10'),
(625, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"manageProject.php\",\"url\":\"\\/migoripmccamelv2\\/admin\\/manageProject.php?id=13\",\"referrer\":\"http:\\/\\/localhost\\/migoripmccamelv2\\/admin\\/manageProject.php?id=13\",\"method\":\"POST\",\"timestamp\":1751653228}', '2025-07-04 18:20:28'),
(626, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"projects.php\",\"url\":\"\\/migoripmccamelv2\\/admin\\/projects.php?success=Project+deleted+successfully\",\"referrer\":\"http:\\/\\/localhost\\/migoripmccamelv2\\/admin\\/manageProject.php?id=13\",\"method\":\"GET\",\"timestamp\":1751653228}', '2025-07-04 18:20:28'),
(627, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"manageProject.php\",\"url\":\"\\/migoripmccamelv2\\/admin\\/manageProject.php?id=14\",\"referrer\":\"http:\\/\\/localhost\\/migoripmccamelv2\\/admin\\/projects.php?success=Project+deleted+successfully\",\"method\":\"GET\",\"timestamp\":1751653232}', '2025-07-04 18:20:32'),
(628, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"manageProject.php\",\"url\":\"\\/migoripmccamelv2\\/admin\\/manageProject.php?id=14\",\"referrer\":\"http:\\/\\/localhost\\/migoripmccamelv2\\/admin\\/manageProject.php?id=14\",\"method\":\"POST\",\"timestamp\":1751653235}', '2025-07-04 18:20:35'),
(629, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"projects.php\",\"url\":\"\\/migoripmccamelv2\\/admin\\/projects.php?success=Project+deleted+successfully\",\"referrer\":\"http:\\/\\/localhost\\/migoripmccamelv2\\/admin\\/manageProject.php?id=14\",\"method\":\"GET\",\"timestamp\":1751653235}', '2025-07-04 18:20:35'),
(630, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"manageProject.php\",\"url\":\"\\/migoripmccamelv2\\/admin\\/manageProject.php?id=15\",\"referrer\":\"http:\\/\\/localhost\\/migoripmccamelv2\\/admin\\/projects.php?success=Project+deleted+successfully\",\"method\":\"GET\",\"timestamp\":1751653237}', '2025-07-04 18:20:37'),
(631, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"manageProject.php\",\"url\":\"\\/migoripmccamelv2\\/admin\\/manageProject.php?id=15\",\"referrer\":\"http:\\/\\/localhost\\/migoripmccamelv2\\/admin\\/manageProject.php?id=15\",\"method\":\"POST\",\"timestamp\":1751653241}', '2025-07-04 18:20:41'),
(632, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"projects.php\",\"url\":\"\\/migoripmccamelv2\\/admin\\/projects.php?success=Project+deleted+successfully\",\"referrer\":\"http:\\/\\/localhost\\/migoripmccamelv2\\/admin\\/manageProject.php?id=15\",\"method\":\"GET\",\"timestamp\":1751653241}', '2025-07-04 18:20:41'),
(633, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"importCsv.php\",\"url\":\"\\/migoripmccamelv2\\/admin\\/importCsv.php\",\"referrer\":\"http:\\/\\/localhost\\/migoripmccamelv2\\/admin\\/index.php\",\"method\":\"GET\",\"timestamp\":1751653322}', '2025-07-04 18:22:02'),
(634, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"importCsv.php\",\"url\":\"\\/migoripmccamelv2\\/admin\\/importCsv.php\",\"referrer\":\"http:\\/\\/localhost\\/migoripmccamelv2\\/admin\\/index.php\",\"method\":\"GET\",\"timestamp\":1751653732}', '2025-07-04 18:28:52'),
(635, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"projects.php\",\"url\":\"\\/migoripmccamelv2\\/admin\\/projects.php\",\"referrer\":\"http:\\/\\/localhost\\/migoripmccamelv2\\/admin\\/importCsv.php\",\"method\":\"GET\",\"timestamp\":1751653751}', '2025-07-04 18:29:11'),
(636, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"manageProject.php\",\"url\":\"\\/migoripmccamelv2\\/admin\\/manageProject.php?id=22\",\"referrer\":\"http:\\/\\/localhost\\/migoripmccamelv2\\/admin\\/projects.php\",\"method\":\"GET\",\"timestamp\":1751653759}', '2025-07-04 18:29:19'),
(637, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"createProject.php\",\"url\":\"\\/migoripmccamelv2\\/admin\\/createProject.php\",\"referrer\":\"http:\\/\\/localhost\\/migoripmccamelv2\\/admin\\/manageProject.php?id=22\",\"method\":\"GET\",\"timestamp\":1751653833}', '2025-07-04 18:30:33'),
(638, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"projects.php\",\"url\":\"\\/migoripmccamelv2\\/admin\\/projects.php\",\"referrer\":\"http:\\/\\/localhost\\/migoripmccamelv2\\/admin\\/createProject.php\",\"method\":\"GET\",\"timestamp\":1751653881}', '2025-07-04 18:31:21'),
(639, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"manageProject.php\",\"url\":\"\\/migoripmccamelv2\\/admin\\/manageProject.php?id=22\",\"referrer\":\"http:\\/\\/localhost\\/migoripmccamelv2\\/admin\\/projects.php\",\"method\":\"GET\",\"timestamp\":1751653884}', '2025-07-04 18:31:24'),
(640, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"manageProject.php\",\"url\":\"\\/migoripmccamelv2\\/admin\\/manageProject.php?id=22\",\"referrer\":\"http:\\/\\/localhost\\/migoripmccamelv2\\/admin\\/manageProject.php?id=22\",\"method\":\"POST\",\"timestamp\":1751653891}', '2025-07-04 18:31:31'),
(641, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"manageProject.php\",\"url\":\"\\/migoripmccamelv2\\/admin\\/manageProject.php?id=22\",\"referrer\":\"http:\\/\\/localhost\\/migoripmccamelv2\\/admin\\/manageProject.php?id=22\",\"method\":\"POST\",\"timestamp\":1751654680}', '2025-07-04 18:44:40'),
(642, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"manageProject.php\",\"url\":\"\\/migoripmccamelv2\\/admin\\/manageProject.php?id=22\",\"referrer\":\"http:\\/\\/localhost\\/migoripmccamelv2\\/admin\\/manageProject.php?id=22\",\"method\":\"POST\",\"timestamp\":1751654688}', '2025-07-04 18:44:48'),
(643, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"createProject.php\",\"url\":\"\\/migoripmccamelv2\\/admin\\/createProject.php\",\"referrer\":\"http:\\/\\/localhost\\/migoripmccamelv2\\/admin\\/manageProject.php?id=22\",\"method\":\"GET\",\"timestamp\":1751654696}', '2025-07-04 18:44:56'),
(644, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"manageProject.php\",\"url\":\"\\/migoripmccamelv2\\/admin\\/manageProject.php?id=31&created=1\",\"referrer\":\"http:\\/\\/localhost\\/migoripmccamelv2\\/admin\\/createProject.php\",\"method\":\"GET\",\"timestamp\":1751655562}', '2025-07-04 18:59:22'),
(645, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"projects.php\",\"url\":\"\\/migoripmccamelv2\\/admin\\/projects.php\",\"referrer\":\"http:\\/\\/localhost\\/migoripmccamelv2\\/admin\\/manageProject.php?id=31&created=1\",\"method\":\"GET\",\"timestamp\":1751655575}', '2025-07-04 18:59:35'),
(646, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"dashboard.php\",\"url\":\"\\/migoripmccamelv2\\/admin\\/dashboard.php\",\"referrer\":\"http:\\/\\/localhost\\/migoripmccamelv2\\/admin\\/index.php\",\"method\":\"GET\",\"timestamp\":1751657151}', '2025-07-04 19:25:51'),
(647, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"importCsv.php\",\"url\":\"\\/migoripmccamelv2\\/admin\\/importCsv.php\",\"referrer\":\"http:\\/\\/localhost\\/migoripmccamelv2\\/admin\\/dashboard.php\",\"method\":\"GET\",\"timestamp\":1751657169}', '2025-07-04 19:26:09');
INSERT INTO `security_logs` (`id`, `event_type`, `admin_id`, `ip_address`, `user_agent`, `details`, `created_at`) VALUES
(648, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"createProject.php\",\"url\":\"\\/migoripmccamelv2\\/admin\\/createProject.php\",\"referrer\":\"http:\\/\\/localhost\\/migoripmccamelv2\\/admin\\/\",\"method\":\"GET\",\"timestamp\":1751657287}', '2025-07-04 19:28:07'),
(649, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"projects.php\",\"url\":\"\\/migoripmccamelv2\\/admin\\/projects.php\",\"referrer\":\"http:\\/\\/localhost\\/migoripmccamelv2\\/admin\\/createProject.php\",\"method\":\"GET\",\"timestamp\":1751657291}', '2025-07-04 19:28:11'),
(650, 'page_access', 1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"importCsv.php\",\"url\":\"\\/migoripmccamelv2\\/admin\\/importCsv.php\",\"referrer\":\"http:\\/\\/localhost\\/migoripmccamelv2\\/admin\\/budgetManagement.php\",\"method\":\"GET\",\"timestamp\":1751659112}', '2025-07-04 19:58:32'),
(651, 'page_access', 2, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"projects.php\",\"url\":\"\\/migoripmccamelv2\\/admin\\/projects.php\",\"referrer\":\"http:\\/\\/localhost\\/migoripmccamelv2\\/admin\\/budgetManagement.php\",\"method\":\"GET\",\"timestamp\":1751659578}', '2025-07-04 20:06:18'),
(652, 'page_access', 2, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"createProject.php\",\"url\":\"\\/migoripmccamelv2\\/admin\\/createProject.php\",\"referrer\":\"http:\\/\\/localhost\\/migoripmccamelv2\\/admin\\/projects.php\",\"method\":\"GET\",\"timestamp\":1751659582}', '2025-07-04 20:06:22'),
(653, 'page_access', 2, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"importCsv.php\",\"url\":\"\\/migoripmccamelv2\\/admin\\/importCsv.php\",\"referrer\":\"http:\\/\\/localhost\\/migoripmccamelv2\\/admin\\/createProject.php\",\"method\":\"GET\",\"timestamp\":1751659585}', '2025-07-04 20:06:25'),
(654, 'undefined_page_access', 2, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '{\"page\":\"csv_import\",\"url\":\"\\/migoripmccamelv2\\/admin\\/importCsv.php\"}', '2025-07-04 20:06:25');

-- --------------------------------------------------------

--
-- Table structure for table `sub_counties`
--

CREATE TABLE `sub_counties` (
  `id` int(11) NOT NULL,
  `name` varchar(100) NOT NULL,
  `county_id` int(11) NOT NULL,
  `created_at` timestamp NOT NULL DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Dumping data for table `sub_counties`
--

INSERT INTO `sub_counties` (`id`, `name`, `county_id`, `created_at`) VALUES
(1, 'Rongo', 1, '2025-06-21 09:39:15'),
(2, 'Awendo', 1, '2025-06-21 09:39:15'),
(3, 'Suna East', 1, '2025-06-21 09:39:15'),
(4, 'Suna West', 1, '2025-06-21 09:39:15'),
(5, 'Uriri', 1, '2025-06-21 09:39:15'),
(6, 'Kuria East', 1, '2025-06-21 09:39:15'),
(7, 'Nyatike', 1, '2025-06-21 09:39:15'),
(8, 'Kuria West', 1, '2025-06-21 09:39:15');

-- --------------------------------------------------------

--
-- Table structure for table `total_budget`
--

CREATE TABLE `total_budget` (
  `id` int(11) NOT NULL,
  `project_id` int(11) NOT NULL,
  `budget_amount` decimal(15,2) NOT NULL DEFAULT 0.00,
  `budget_type` enum('initial','revised','supplementary') DEFAULT 'initial',
  `budget_source` varchar(255) DEFAULT NULL,
  `fiscal_year` varchar(10) NOT NULL,
  `approval_status` enum('pending','approved','rejected','under_review') DEFAULT 'pending',
  `approved_by` int(11) DEFAULT NULL,
  `approved_at` timestamp NULL DEFAULT NULL,
  `approval_comments` text DEFAULT NULL,
  `budget_breakdown` longtext CHARACTER SET utf8mb4 COLLATE utf8mb4_bin DEFAULT NULL CHECK (json_valid(`budget_breakdown`)),
  `supporting_documents` longtext CHARACTER SET utf8mb4 COLLATE utf8mb4_bin DEFAULT NULL CHECK (json_valid(`supporting_documents`)),
  `created_by` int(11) DEFAULT NULL,
  `created_at` timestamp NOT NULL DEFAULT current_timestamp(),
  `updated_at` timestamp NOT NULL DEFAULT current_timestamp() ON UPDATE current_timestamp(),
  `is_active` tinyint(1) DEFAULT 1,
  `version` int(11) DEFAULT 1,
  `previous_version_id` int(11) DEFAULT NULL,
  `fund_source` varchar(255) DEFAULT 'County Development Fund',
  `funding_category` enum('development','recurrent','emergency','donor') DEFAULT 'development',
  `disbursement_schedule` text DEFAULT NULL,
  `allocated_amount` decimal(15,2) DEFAULT 0.00,
  `disbursed_amount` decimal(15,2) DEFAULT 0.00,
  `remaining_amount` decimal(15,2) DEFAULT 0.00,
  `budget_notes` text DEFAULT NULL,
  `financial_year` varchar(20) DEFAULT NULL,
  `budget_line_item` varchar(255) DEFAULT NULL,
  `funding_agency` varchar(255) DEFAULT NULL,
  `disbursement_conditions` text DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci COMMENT='Stores project budget information with approval workflow and version control';

--
-- Dumping data for table `total_budget`
--

INSERT INTO `total_budget` (`id`, `project_id`, `budget_amount`, `budget_type`, `budget_source`, `fiscal_year`, `approval_status`, `approved_by`, `approved_at`, `approval_comments`, `budget_breakdown`, `supporting_documents`, `created_by`, `created_at`, `updated_at`, `is_active`, `version`, `previous_version_id`, `fund_source`, `funding_category`, `disbursement_schedule`, `allocated_amount`, `disbursed_amount`, `remaining_amount`, `budget_notes`, `financial_year`, `budget_line_item`, `funding_agency`, `disbursement_conditions`) VALUES
(4, 22, 25000000.00, 'initial', 'County Development Fund', '2024/2025', 'approved', NULL, NULL, NULL, NULL, NULL, 1, '2025-07-04 18:29:01', '2025-07-04 18:29:01', 1, 1, NULL, 'County Development Fund', 'development', NULL, 0.00, 0.00, 0.00, NULL, NULL, NULL, NULL, NULL),
(5, 23, 15000000.00, 'initial', 'County Development Fund', '2024/2025', 'approved', NULL, NULL, NULL, NULL, NULL, 1, '2025-07-04 18:29:01', '2025-07-04 18:29:01', 1, 1, NULL, 'County Development Fund', 'development', NULL, 0.00, 0.00, 0.00, NULL, NULL, NULL, NULL, NULL),
(6, 24, 5000000.00, 'initial', 'County Development Fund', '2024/2025', 'approved', NULL, NULL, NULL, NULL, NULL, 1, '2025-07-04 18:29:01', '2025-07-04 18:29:01', 1, 1, NULL, 'County Development Fund', 'development', NULL, 0.00, 0.00, 0.00, NULL, NULL, NULL, NULL, NULL),
(7, 25, 12000000.00, 'initial', 'County Development Fund', '2024/2025', 'approved', NULL, NULL, NULL, NULL, NULL, 1, '2025-07-04 18:29:01', '2025-07-04 18:29:01', 1, 1, NULL, 'County Development Fund', 'development', NULL, 0.00, 0.00, 0.00, NULL, NULL, NULL, NULL, NULL),
(8, 26, 17500000.00, 'initial', 'County Development Fund', '2025/2026', 'approved', NULL, NULL, NULL, NULL, NULL, 1, '2025-07-04 18:29:01', '2025-07-04 18:29:01', 1, 1, NULL, 'County Development Fund', 'development', NULL, 0.00, 0.00, 0.00, NULL, NULL, NULL, NULL, NULL),
(9, 27, 13000500.00, 'initial', 'County Development Fund', '2026/2027', 'approved', NULL, NULL, NULL, NULL, NULL, 1, '2025-07-04 18:29:01', '2025-07-04 18:29:01', 1, 1, NULL, 'County Development Fund', 'development', NULL, 0.00, 0.00, 0.00, NULL, NULL, NULL, NULL, NULL),
(10, 28, 50900000.00, 'initial', 'County Development Fund', '2024/2025', 'approved', NULL, NULL, NULL, NULL, NULL, 1, '2025-07-04 18:29:01', '2025-07-04 18:29:01', 1, 1, NULL, 'County Development Fund', 'development', NULL, 0.00, 0.00, 0.00, NULL, NULL, NULL, NULL, NULL),
(11, 29, 44000000.00, 'initial', 'County Development Fund', '2023/2024', 'approved', NULL, NULL, NULL, NULL, NULL, 1, '2025-07-04 18:29:01', '2025-07-04 18:29:01', 1, 1, NULL, 'County Development Fund', 'development', NULL, 0.00, 0.00, 0.00, NULL, NULL, NULL, NULL, NULL),
(12, 30, 19000000.00, 'initial', 'County Development Fund', '2025/2026', 'approved', NULL, NULL, NULL, NULL, NULL, 1, '2025-07-04 18:29:01', '2025-07-04 18:29:01', 1, 1, NULL, 'County Development Fund', 'development', NULL, 0.00, 0.00, 0.00, NULL, NULL, NULL, NULL, NULL),
(13, 31, 2000000.00, 'initial', 'County Development Fund', '2025/2026', 'approved', NULL, NULL, NULL, NULL, NULL, 1, '2025-07-04 18:59:22', '2025-07-04 18:59:22', 1, 1, NULL, 'County Development Fund', 'development', NULL, 0.00, 0.00, 0.00, NULL, NULL, NULL, NULL, NULL);

-- --------------------------------------------------------

--
-- Table structure for table `wards`
--

CREATE TABLE `wards` (
  `id` int(11) NOT NULL,
  `name` varchar(100) NOT NULL,
  `sub_county_id` int(11) NOT NULL,
  `created_at` timestamp NOT NULL DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Dumping data for table `wards`
--

INSERT INTO `wards` (`id`, `name`, `sub_county_id`, `created_at`) VALUES
(1, 'North Kamagambo', 1, '2025-06-21 09:39:15'),
(2, 'Central Kamagambo', 1, '2025-06-21 09:39:15'),
(3, 'East Kamagambo', 1, '2025-06-21 09:39:15'),
(4, 'South Kamagambo', 1, '2025-06-21 09:39:15'),
(5, 'North East Sakwa', 2, '2025-06-21 09:39:15'),
(6, 'South Sakwa', 2, '2025-06-21 09:39:15'),
(7, 'West Sakwa', 2, '2025-06-21 09:39:15'),
(8, 'Central Sakwa', 2, '2025-06-21 09:39:15'),
(9, 'God Jope', 3, '2025-06-21 09:39:15'),
(10, 'Suna Central', 3, '2025-06-21 09:39:15'),
(11, 'Kakrao', 3, '2025-06-21 09:39:15'),
(12, 'Kwa', 3, '2025-06-21 09:39:15'),
(13, 'Wiga', 4, '2025-06-21 09:39:15'),
(14, 'Wasweta II', 4, '2025-06-21 09:39:15'),
(15, 'Ragana-Oruba', 4, '2025-06-21 09:39:15'),
(16, 'Wasimbete', 4, '2025-06-21 09:39:15'),
(17, 'West Kanyamkago', 5, '2025-06-21 09:39:15'),
(18, 'North Kanyamkago', 5, '2025-06-21 09:39:15'),
(19, 'Central Kanyamkago', 5, '2025-06-21 09:39:15'),
(20, 'South Kanyamkago', 5, '2025-06-21 09:39:15'),
(21, 'East Kanyamkago', 5, '2025-06-21 09:39:15'),
(22, 'Gokeharaka/Getamwega', 6, '2025-06-21 09:39:15'),
(23, 'Ntimaru West', 6, '2025-06-21 09:39:15'),
(24, 'Ntimaru East', 6, '2025-06-21 09:39:15'),
(25, 'Nyabasi East', 6, '2025-06-21 09:39:15'),
(26, 'Nyabasi West', 6, '2025-06-21 09:39:15'),
(27, 'Kachieng', 7, '2025-06-21 09:39:15'),
(28, 'Kanyasa', 7, '2025-06-21 09:39:15'),
(29, 'North Kadem', 7, '2025-06-21 09:39:15'),
(30, 'Macalder/Kanyarwanda', 7, '2025-06-21 09:39:15'),
(31, 'Kaler', 7, '2025-06-21 09:39:15'),
(32, 'Got Kachola', 7, '2025-06-21 09:39:15'),
(33, 'Muhuru', 7, '2025-06-21 09:39:15'),
(34, 'Bukira East', 8, '2025-06-21 09:39:15'),
(35, 'Bukira Central/Ikerege', 8, '2025-06-21 09:39:15'),
(36, 'Isibania', 8, '2025-06-21 09:39:15'),
(37, 'Makerero', 8, '2025-06-21 09:39:15'),
(38, 'Masaba', 8, '2025-06-21 09:39:15'),
(39, 'Tagare', 8, '2025-06-21 09:39:15'),
(40, 'Nyamosense/Komosoko', 8, '2025-06-21 09:39:15');

-- --------------------------------------------------------

--
-- Structure for view `project_financial_summary`
--
DROP TABLE IF EXISTS `project_financial_summary`;

CREATE ALGORITHM=UNDEFINED DEFINER=`root`@`localhost` SQL SECURITY DEFINER VIEW `project_financial_summary`  AS SELECT `p`.`id` AS `project_id`, `p`.`project_name` AS `project_name`, `p`.`total_budget` AS `approved_budget`, coalesce(sum(case when `pt`.`transaction_type` = 'budget_increase' and `pt`.`transaction_status` = 'active' then `pt`.`amount` else 0 end),0) AS `budget_increases`, coalesce(sum(case when `pt`.`transaction_type` = 'disbursement' and `pt`.`transaction_status` = 'active' then `pt`.`amount` else 0 end),0) AS `total_disbursed`, coalesce(sum(case when `pt`.`transaction_type` = 'expenditure' and `pt`.`transaction_status` = 'active' then `pt`.`amount` else 0 end),0) AS `total_spent`, `p`.`total_budget`+ coalesce(sum(case when `pt`.`transaction_type` = 'budget_increase' and `pt`.`transaction_status` = 'active' then `pt`.`amount` else 0 end),0) AS `total_allocated`, coalesce(sum(case when `pt`.`transaction_type` = 'disbursement' and `pt`.`transaction_status` = 'active' then `pt`.`amount` else 0 end),0) - coalesce(sum(case when `pt`.`transaction_type` = 'expenditure' and `pt`.`transaction_status` = 'active' then `pt`.`amount` else 0 end),0) AS `remaining_balance` FROM (`projects` `p` left join `project_transactions` `pt` on(`p`.`id` = `pt`.`project_id`)) GROUP BY `p`.`id`, `p`.`project_name`, `p`.`total_budget` ;

--
-- Indexes for dumped tables
--

--
-- Indexes for table `admins`
--
ALTER TABLE `admins`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `email` (`email`),
  ADD KEY `idx_admins_role` (`role`),
  ADD KEY `idx_admins_active` (`is_active`);

--
-- Indexes for table `admin_activity_log`
--
ALTER TABLE `admin_activity_log`
  ADD PRIMARY KEY (`id`),
  ADD KEY `idx_admin_id` (`admin_id`),
  ADD KEY `idx_activity_type` (`activity_type`),
  ADD KEY `idx_target` (`target_type`,`target_id`),
  ADD KEY `idx_created_at` (`created_at`);

--
-- Indexes for table `admin_permissions`
--
ALTER TABLE `admin_permissions`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `unique_admin_permission` (`admin_id`,`permission_key`),
  ADD KEY `idx_admin_id` (`admin_id`),
  ADD KEY `idx_permission_key` (`permission_key`),
  ADD KEY `idx_is_active` (`is_active`),
  ADD KEY `granted_by` (`granted_by`);

--
-- Indexes for table `budget_allocations`
--
ALTER TABLE `budget_allocations`
  ADD PRIMARY KEY (`id`),
  ADD KEY `budget_id` (`budget_id`),
  ADD KEY `allocated_by` (`allocated_by`),
  ADD KEY `approved_by` (`approved_by`),
  ADD KEY `idx_project_budget` (`project_id`,`budget_id`),
  ADD KEY `idx_financial_year` (`financial_year`),
  ADD KEY `idx_fund_source` (`fund_source`);

--
-- Indexes for table `counties`
--
ALTER TABLE `counties`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `name` (`name`);

--
-- Indexes for table `departments`
--
ALTER TABLE `departments`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `name` (`name`);

--
-- Indexes for table `feedback`
--
ALTER TABLE `feedback`
  ADD PRIMARY KEY (`id`),
  ADD KEY `responded_by` (`responded_by`),
  ADD KEY `moderated_by` (`moderated_by`),
  ADD KEY `idx_project_id` (`project_id`),
  ADD KEY `idx_parent_comment_id` (`parent_comment_id`),
  ADD KEY `idx_status` (`status`),
  ADD KEY `idx_user_ip` (`user_ip`),
  ADD KEY `idx_created_at` (`created_at`),
  ADD KEY `idx_project_status` (`project_id`,`status`);

--
-- Indexes for table `feedback_notifications`
--
ALTER TABLE `feedback_notifications`
  ADD PRIMARY KEY (`id`),
  ADD KEY `idx_feedback_notifications_feedback_id` (`feedback_id`),
  ADD KEY `idx_feedback_notifications_status` (`delivery_status`);

--
-- Indexes for table `fund_sources`
--
ALTER TABLE `fund_sources`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `source_name` (`source_name`),
  ADD UNIQUE KEY `source_code` (`source_code`);

--
-- Indexes for table `import_logs`
--
ALTER TABLE `import_logs`
  ADD PRIMARY KEY (`id`),
  ADD KEY `imported_by` (`imported_by`);

--
-- Indexes for table `login_attempts`
--
ALTER TABLE `login_attempts`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `username` (`email`);

--
-- Indexes for table `prepared_responses`
--
ALTER TABLE `prepared_responses`
  ADD PRIMARY KEY (`id`);

--
-- Indexes for table `projects`
--
ALTER TABLE `projects`
  ADD PRIMARY KEY (`id`),
  ADD KEY `department_id` (`department_id`),
  ADD KEY `county_id` (`county_id`),
  ADD KEY `sub_county_id` (`sub_county_id`),
  ADD KEY `ward_id` (`ward_id`),
  ADD KEY `created_by` (`created_by`),
  ADD KEY `idx_projects_status` (`status`),
  ADD KEY `idx_projects_visibility` (`visibility`),
  ADD KEY `idx_projects_year` (`project_year`);

--
-- Indexes for table `project_documents`
--
ALTER TABLE `project_documents`
  ADD PRIMARY KEY (`id`),
  ADD KEY `project_id` (`project_id`),
  ADD KEY `uploaded_by` (`uploaded_by`);

--
-- Indexes for table `project_steps`
--
ALTER TABLE `project_steps`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `unique_project_step` (`project_id`,`step_number`),
  ADD KEY `idx_project_steps_status` (`status`);

--
-- Indexes for table `project_transactions`
--
ALTER TABLE `project_transactions`
  ADD PRIMARY KEY (`id`),
  ADD KEY `project_id` (`project_id`),
  ADD KEY `transaction_date` (`transaction_date`),
  ADD KEY `idx_transaction_status` (`transaction_status`),
  ADD KEY `idx_transaction_project_admin` (`project_id`,`created_by`),
  ADD KEY `idx_transaction_type_status` (`transaction_type`,`transaction_status`),
  ADD KEY `fk_pt_approved_by` (`approved_by`),
  ADD KEY `fk_pt_modified_by` (`modified_by`);

--
-- Indexes for table `project_transaction_documents`
--
ALTER TABLE `project_transaction_documents`
  ADD PRIMARY KEY (`id`),
  ADD KEY `transaction_id` (`transaction_id`),
  ADD KEY `uploaded_by` (`uploaded_by`);

--
-- Indexes for table `security_logs`
--
ALTER TABLE `security_logs`
  ADD PRIMARY KEY (`id`),
  ADD KEY `idx_event_type` (`event_type`),
  ADD KEY `idx_admin_id` (`admin_id`),
  ADD KEY `idx_created_at` (`created_at`);

--
-- Indexes for table `sub_counties`
--
ALTER TABLE `sub_counties`
  ADD PRIMARY KEY (`id`),
  ADD KEY `county_id` (`county_id`);

--
-- Indexes for table `total_budget`
--
ALTER TABLE `total_budget`
  ADD PRIMARY KEY (`id`),
  ADD KEY `idx_project_id` (`project_id`),
  ADD KEY `idx_approval_status` (`approval_status`),
  ADD KEY `idx_fiscal_year` (`fiscal_year`),
  ADD KEY `idx_created_by` (`created_by`),
  ADD KEY `idx_approved_by` (`approved_by`),
  ADD KEY `idx_is_active` (`is_active`),
  ADD KEY `fk_total_budget_previous_version` (`previous_version_id`),
  ADD KEY `idx_total_budget_project_active` (`project_id`,`is_active`),
  ADD KEY `idx_total_budget_version_active` (`project_id`,`version`,`is_active`);

--
-- Indexes for table `wards`
--
ALTER TABLE `wards`
  ADD PRIMARY KEY (`id`),
  ADD KEY `sub_county_id` (`sub_county_id`);

--
-- AUTO_INCREMENT for dumped tables
--

--
-- AUTO_INCREMENT for table `admins`
--
ALTER TABLE `admins`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=4;

--
-- AUTO_INCREMENT for table `admin_activity_log`
--
ALTER TABLE `admin_activity_log`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=604;

--
-- AUTO_INCREMENT for table `admin_permissions`
--
ALTER TABLE `admin_permissions`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=77;

--
-- AUTO_INCREMENT for table `budget_allocations`
--
ALTER TABLE `budget_allocations`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT for table `counties`
--
ALTER TABLE `counties`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=2;

--
-- AUTO_INCREMENT for table `departments`
--
ALTER TABLE `departments`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=14;

--
-- AUTO_INCREMENT for table `feedback`
--
ALTER TABLE `feedback`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=6;

--
-- AUTO_INCREMENT for table `feedback_notifications`
--
ALTER TABLE `feedback_notifications`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT for table `fund_sources`
--
ALTER TABLE `fund_sources`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=16;

--
-- AUTO_INCREMENT for table `import_logs`
--
ALTER TABLE `import_logs`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=2;

--
-- AUTO_INCREMENT for table `login_attempts`
--
ALTER TABLE `login_attempts`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=10;

--
-- AUTO_INCREMENT for table `prepared_responses`
--
ALTER TABLE `prepared_responses`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=11;

--
-- AUTO_INCREMENT for table `projects`
--
ALTER TABLE `projects`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=32;

--
-- AUTO_INCREMENT for table `project_documents`
--
ALTER TABLE `project_documents`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=2;

--
-- AUTO_INCREMENT for table `project_steps`
--
ALTER TABLE `project_steps`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=32;

--
-- AUTO_INCREMENT for table `project_transactions`
--
ALTER TABLE `project_transactions`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=20;

--
-- AUTO_INCREMENT for table `project_transaction_documents`
--
ALTER TABLE `project_transaction_documents`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=15;

--
-- AUTO_INCREMENT for table `security_logs`
--
ALTER TABLE `security_logs`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=655;

--
-- AUTO_INCREMENT for table `total_budget`
--
ALTER TABLE `total_budget`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=14;

--
-- Constraints for dumped tables
--

--
-- Constraints for table `admin_activity_log`
--
ALTER TABLE `admin_activity_log`
  ADD CONSTRAINT `admin_activity_log_ibfk_1` FOREIGN KEY (`admin_id`) REFERENCES `admins` (`id`) ON DELETE CASCADE;

--
-- Constraints for table `admin_permissions`
--
ALTER TABLE `admin_permissions`
  ADD CONSTRAINT `admin_permissions_ibfk_1` FOREIGN KEY (`admin_id`) REFERENCES `admins` (`id`) ON DELETE CASCADE,
  ADD CONSTRAINT `admin_permissions_ibfk_2` FOREIGN KEY (`granted_by`) REFERENCES `admins` (`id`) ON DELETE CASCADE;

--
-- Constraints for table `budget_allocations`
--
ALTER TABLE `budget_allocations`
  ADD CONSTRAINT `budget_allocations_ibfk_1` FOREIGN KEY (`project_id`) REFERENCES `projects` (`id`) ON DELETE CASCADE,
  ADD CONSTRAINT `budget_allocations_ibfk_2` FOREIGN KEY (`budget_id`) REFERENCES `total_budget` (`id`) ON DELETE CASCADE,
  ADD CONSTRAINT `budget_allocations_ibfk_3` FOREIGN KEY (`allocated_by`) REFERENCES `admins` (`id`),
  ADD CONSTRAINT `budget_allocations_ibfk_4` FOREIGN KEY (`approved_by`) REFERENCES `admins` (`id`);

--
-- Constraints for table `project_documents`
--
ALTER TABLE `project_documents`
  ADD CONSTRAINT `project_documents_ibfk_1` FOREIGN KEY (`project_id`) REFERENCES `projects` (`id`) ON DELETE CASCADE,
  ADD CONSTRAINT `project_documents_ibfk_2` FOREIGN KEY (`uploaded_by`) REFERENCES `admins` (`id`) ON DELETE SET NULL;

--
-- Constraints for table `project_transactions`
--
ALTER TABLE `project_transactions`
  ADD CONSTRAINT `fk_pt_approved_by` FOREIGN KEY (`approved_by`) REFERENCES `admins` (`id`) ON DELETE SET NULL,
  ADD CONSTRAINT `fk_pt_modified_by` FOREIGN KEY (`modified_by`) REFERENCES `admins` (`id`) ON DELETE SET NULL,
  ADD CONSTRAINT `fk_transactions_approved_by_new` FOREIGN KEY (`approved_by`) REFERENCES `admins` (`id`) ON DELETE SET NULL,
  ADD CONSTRAINT `fk_transactions_modified_by_new` FOREIGN KEY (`modified_by`) REFERENCES `admins` (`id`) ON DELETE SET NULL,
  ADD CONSTRAINT `project_transactions_ibfk_1` FOREIGN KEY (`project_id`) REFERENCES `projects` (`id`) ON DELETE CASCADE;

--
-- Constraints for table `project_transaction_documents`
--
ALTER TABLE `project_transaction_documents`
  ADD CONSTRAINT `project_transaction_documents_ibfk_1` FOREIGN KEY (`transaction_id`) REFERENCES `project_transactions` (`id`) ON DELETE CASCADE,
  ADD CONSTRAINT `project_transaction_documents_ibfk_2` FOREIGN KEY (`uploaded_by`) REFERENCES `admins` (`id`) ON DELETE SET NULL;

--
-- Constraints for table `security_logs`
--
ALTER TABLE `security_logs`
  ADD CONSTRAINT `security_logs_ibfk_1` FOREIGN KEY (`admin_id`) REFERENCES `admins` (`id`) ON DELETE SET NULL;

--
-- Constraints for table `total_budget`
--
ALTER TABLE `total_budget`
  ADD CONSTRAINT `fk_total_budget_approved_by` FOREIGN KEY (`approved_by`) REFERENCES `admins` (`id`) ON DELETE SET NULL ON UPDATE CASCADE,
  ADD CONSTRAINT `fk_total_budget_created_by` FOREIGN KEY (`created_by`) REFERENCES `admins` (`id`) ON DELETE SET NULL ON UPDATE CASCADE,
  ADD CONSTRAINT `fk_total_budget_previous_version` FOREIGN KEY (`previous_version_id`) REFERENCES `total_budget` (`id`) ON DELETE SET NULL ON UPDATE CASCADE,
  ADD CONSTRAINT `fk_total_budget_project` FOREIGN KEY (`project_id`) REFERENCES `projects` (`id`) ON DELETE CASCADE ON UPDATE CASCADE;
COMMIT;

/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
