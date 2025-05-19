-- phpMyAdmin SQL Dump
-- version 5.2.1
-- https://www.phpmyadmin.net/
--
-- Host: 127.0.0.1
-- Generation Time: May 19, 2025 at 10:15 AM
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
-- Database: `flask_auth`
--

-- --------------------------------------------------------

--
-- Table structure for table `admin_action_history`
--

CREATE TABLE `admin_action_history` (
  `id` int(11) NOT NULL,
  `admin_id` int(11) NOT NULL,
  `action_type` varchar(50) NOT NULL,
  `description` text NOT NULL,
  `target_id` int(11) DEFAULT NULL,
  `target_type` varchar(50) DEFAULT NULL,
  `performed_at` datetime DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- --------------------------------------------------------

--
-- Table structure for table `published_theses`
--

CREATE TABLE `published_theses` (
  `id` int(11) NOT NULL,
  `submission_id` int(11) NOT NULL,
  `file_path` varchar(255) NOT NULL,
  `title` varchar(255) NOT NULL,
  `authors` text NOT NULL,
  `school` varchar(255) NOT NULL,
  `year_made` varchar(4) NOT NULL,
  `keywords` text NOT NULL,
  `published_by` int(11) NOT NULL,
  `published_at` timestamp NOT NULL DEFAULT current_timestamp(),
  `num_pages` int(11) DEFAULT NULL,
  `is_deleted` tinyint(1) DEFAULT 0,
  `deleted_at` datetime DEFAULT NULL,
  `deletion_scheduled` datetime DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- --------------------------------------------------------

--
-- Table structure for table `thesis_pages`
--

CREATE TABLE `thesis_pages` (
  `id` int(11) NOT NULL,
  `thesis_id` int(11) NOT NULL,
  `page_number` int(11) NOT NULL,
  `page_text` text DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- --------------------------------------------------------

--
-- Table structure for table `thesis_submissions`
--

CREATE TABLE `thesis_submissions` (
  `id` int(11) NOT NULL,
  `admin_id` int(11) NOT NULL,
  `file_path` varchar(255) DEFAULT NULL,
  `original_filename` varchar(255) DEFAULT NULL,
  `title` varchar(255) DEFAULT NULL,
  `authors` text DEFAULT NULL,
  `school` varchar(255) DEFAULT NULL,
  `year_made` varchar(4) DEFAULT NULL,
  `keywords` text DEFAULT NULL,
  `extracted_text` longtext DEFAULT NULL,
  `status` enum('pending','approved','rejected') DEFAULT 'pending',
  `created_at` timestamp NOT NULL DEFAULT current_timestamp(),
  `updated_at` timestamp NOT NULL DEFAULT current_timestamp() ON UPDATE current_timestamp(),
  `revised_file_path` varchar(255) DEFAULT NULL,
  `num_pages` int(11) DEFAULT NULL,
  `deleted_at` datetime DEFAULT NULL,
  `file_persisted` tinyint(1) DEFAULT 0,
  `file_reuploaded` tinyint(1) DEFAULT 0
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- --------------------------------------------------------

--
-- Table structure for table `thesis_versions`
--

CREATE TABLE `thesis_versions` (
  `id` int(11) NOT NULL,
  `thesis_id` int(11) NOT NULL,
  `edited_title` varchar(255) DEFAULT NULL,
  `edited_authors` text DEFAULT NULL,
  `edited_school` varchar(255) DEFAULT NULL,
  `edited_year_made` varchar(4) DEFAULT NULL,
  `edited_keywords` text DEFAULT NULL,
  `notes` text DEFAULT NULL,
  `edited_by` int(11) NOT NULL,
  `created_at` timestamp NOT NULL DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- --------------------------------------------------------

--
-- Table structure for table `users`
--

CREATE TABLE `users` (
  `id` int(11) NOT NULL,
  `username` varchar(80) NOT NULL,
  `password` varchar(255) NOT NULL,
  `role` enum('user','admin') NOT NULL DEFAULT 'user',
  `email` text NOT NULL,
  `is_verified` tinyint(1) DEFAULT 0,
  `verification_code` text DEFAULT NULL,
  `code_expires` datetime DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Dumping data for table `users`
--

INSERT INTO `users` (`id`, `username`, `password`, `role`, `email`, `is_verified`, `verification_code`, `code_expires`) VALUES
(8, 'admin2025', 'scrypt:32768:8:1$ioJg56s33nLFUA2N$61c3ce9bbc863b712bc2ee697685f9dcdbb63688c4aedfc43a2a501fe0174c74bd77d59c8f78f740a0a69598889a2e399650481f3a403fe6b24118efaa91765f', 'admin', '', 1, NULL, NULL),
(23, 'user123', 'scrypt:32768:8:1$z2RMd25FqRkcdSI8$a953040c40bb469a8509b82e2b199e196a2b0d2f26af90f0e1df75866f192f913ce66e5ddd163d7c35d59f33d1fad2c99ce528bf798a40c15e026399912ccf13', 'user', 'ryanchristian.robles@cvsu.edu.ph', 1, NULL, NULL);

-- --------------------------------------------------------

--
-- Table structure for table `user_bookmarks`
--

CREATE TABLE `user_bookmarks` (
  `id` int(11) NOT NULL,
  `user_id` int(11) NOT NULL,
  `thesis_id` int(11) NOT NULL,
  `created_at` timestamp NOT NULL DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- --------------------------------------------------------

--
-- Table structure for table `user_view_history`
--

CREATE TABLE `user_view_history` (
  `id` int(11) NOT NULL,
  `user_id` int(11) NOT NULL,
  `thesis_id` int(11) NOT NULL,
  `viewed_at` timestamp NOT NULL DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Indexes for dumped tables
--

--
-- Indexes for table `admin_action_history`
--
ALTER TABLE `admin_action_history`
  ADD PRIMARY KEY (`id`),
  ADD KEY `admin_id` (`admin_id`);

--
-- Indexes for table `published_theses`
--
ALTER TABLE `published_theses`
  ADD PRIMARY KEY (`id`),
  ADD KEY `submission_id` (`submission_id`),
  ADD KEY `published_by` (`published_by`);
ALTER TABLE `published_theses` ADD FULLTEXT KEY `ft_title` (`title`);
ALTER TABLE `published_theses` ADD FULLTEXT KEY `ft_authors` (`authors`);
ALTER TABLE `published_theses` ADD FULLTEXT KEY `ft_keywords` (`keywords`);

--
-- Indexes for table `thesis_pages`
--
ALTER TABLE `thesis_pages`
  ADD PRIMARY KEY (`id`),
  ADD KEY `thesis_id` (`thesis_id`);
ALTER TABLE `thesis_pages` ADD FULLTEXT KEY `ft_page_text` (`page_text`);
ALTER TABLE `thesis_pages` ADD FULLTEXT KEY `page_text` (`page_text`);

--
-- Indexes for table `thesis_submissions`
--
ALTER TABLE `thesis_submissions`
  ADD PRIMARY KEY (`id`),
  ADD KEY `admin_id` (`admin_id`);

--
-- Indexes for table `thesis_versions`
--
ALTER TABLE `thesis_versions`
  ADD PRIMARY KEY (`id`),
  ADD KEY `thesis_id` (`thesis_id`),
  ADD KEY `edited_by` (`edited_by`);

--
-- Indexes for table `users`
--
ALTER TABLE `users`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `username` (`username`);

--
-- Indexes for table `user_bookmarks`
--
ALTER TABLE `user_bookmarks`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `unique_bookmark` (`user_id`,`thesis_id`),
  ADD KEY `thesis_id` (`thesis_id`);

--
-- Indexes for table `user_view_history`
--
ALTER TABLE `user_view_history`
  ADD PRIMARY KEY (`id`),
  ADD KEY `user_id` (`user_id`),
  ADD KEY `thesis_id` (`thesis_id`);

--
-- AUTO_INCREMENT for dumped tables
--

--
-- AUTO_INCREMENT for table `admin_action_history`
--
ALTER TABLE `admin_action_history`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT for table `published_theses`
--
ALTER TABLE `published_theses`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=68;

--
-- AUTO_INCREMENT for table `thesis_pages`
--
ALTER TABLE `thesis_pages`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT for table `thesis_submissions`
--
ALTER TABLE `thesis_submissions`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=126;

--
-- AUTO_INCREMENT for table `thesis_versions`
--
ALTER TABLE `thesis_versions`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT for table `users`
--
ALTER TABLE `users`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=24;

--
-- AUTO_INCREMENT for table `user_bookmarks`
--
ALTER TABLE `user_bookmarks`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=7;

--
-- AUTO_INCREMENT for table `user_view_history`
--
ALTER TABLE `user_view_history`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT;

--
-- Constraints for dumped tables
--

--
-- Constraints for table `admin_action_history`
--
ALTER TABLE `admin_action_history`
  ADD CONSTRAINT `admin_action_history_ibfk_1` FOREIGN KEY (`admin_id`) REFERENCES `users` (`id`);

--
-- Constraints for table `published_theses`
--
ALTER TABLE `published_theses`
  ADD CONSTRAINT `fk_published_submission` FOREIGN KEY (`submission_id`) REFERENCES `thesis_submissions` (`id`),
  ADD CONSTRAINT `published_theses_ibfk_1` FOREIGN KEY (`submission_id`) REFERENCES `thesis_submissions` (`id`),
  ADD CONSTRAINT `published_theses_ibfk_2` FOREIGN KEY (`published_by`) REFERENCES `users` (`id`);

--
-- Constraints for table `thesis_pages`
--
ALTER TABLE `thesis_pages`
  ADD CONSTRAINT `thesis_pages_ibfk_1` FOREIGN KEY (`thesis_id`) REFERENCES `published_theses` (`id`);

--
-- Constraints for table `thesis_submissions`
--
ALTER TABLE `thesis_submissions`
  ADD CONSTRAINT `thesis_submissions_ibfk_1` FOREIGN KEY (`admin_id`) REFERENCES `users` (`id`);

--
-- Constraints for table `thesis_versions`
--
ALTER TABLE `thesis_versions`
  ADD CONSTRAINT `thesis_versions_ibfk_2` FOREIGN KEY (`edited_by`) REFERENCES `users` (`id`);

--
-- Constraints for table `user_bookmarks`
--
ALTER TABLE `user_bookmarks`
  ADD CONSTRAINT `user_bookmarks_ibfk_1` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`) ON DELETE CASCADE,
  ADD CONSTRAINT `user_bookmarks_ibfk_2` FOREIGN KEY (`thesis_id`) REFERENCES `published_theses` (`id`) ON DELETE CASCADE;

--
-- Constraints for table `user_view_history`
--
ALTER TABLE `user_view_history`
  ADD CONSTRAINT `user_view_history_ibfk_1` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`) ON DELETE CASCADE,
  ADD CONSTRAINT `user_view_history_ibfk_2` FOREIGN KEY (`thesis_id`) REFERENCES `published_theses` (`id`) ON DELETE CASCADE;
COMMIT;

/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
