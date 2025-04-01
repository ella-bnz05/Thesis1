-- phpMyAdmin SQL Dump
-- version 5.2.1
-- https://www.phpmyadmin.net/
--
-- Host: 127.0.0.1
-- Generation Time: Apr 01, 2025 at 05:05 PM
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
  `published_at` timestamp NOT NULL DEFAULT current_timestamp()
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
  `updated_at` timestamp NOT NULL DEFAULT current_timestamp() ON UPDATE current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Dumping data for table `thesis_submissions`
--

INSERT INTO `thesis_submissions` (`id`, `admin_id`, `file_path`, `original_filename`, `title`, `authors`, `school`, `year_made`, `keywords`, `extracted_text`, `status`, `created_at`, `updated_at`) VALUES
(10, 8, 'uploads\\submissions\\Thesis.jpg', 'Thesis.jpg', 'DEVELOPING A SPAN-BASED NAMED-ENTITY RECOGNITION METHOD FOR THESES INFORMATION-EXTRACTION ON COMPUTER, SCIENCE STUDIES USING OCR TESSERACT', 'RAFAELLA R. BANEZ, AALIHYA M. RIVERO., RYAN CHRISTIAN M. ROBLES', 'Cavite State University, Department of Computer Studies, Imus Campus', '2025', 'A SPAN-BASED NAMED-ENTITY RECOGNITION METHOD, COMPUTER, ENTITY, NAMED, OCR, OCR TESSERACT, RECOGNITION, SCIENCE STUDIES, SPAN, TESSERACT, THESES, THESES INFORMATION-EXTRACTION ON COMPUTER', 'DEVELOPING A SPAN-BASED NAMED-ENTITY RECOGNITION\nMETHOD FOR THESES INFORMATION-EXTRACTION ON COMPUTER,\nSCIENCE STUDIES USING OCR TESSERACT\n\nUndergraduate Thesis\nSubmitted to the Faculty of the\nDepartment of Computer Studies\nCavite State University ~ Imus Campus\nCity of mus, Cavite\n\nIn partial fullment\nof the requirements for the degree\nBachelor of Science in Computer Science\n\nRAFAELLA R. BANEZ\n‘AALIHYA M. RIVERO.\nRYAN CHRISTIAN M. ROBLES\nJanuary 2025\n\n', 'approved', '2025-04-01 12:50:21', '2025-04-01 12:50:32'),
(11, 8, 'uploads\\submissions\\thesis1.png', 'thesis1.png', 'DEVELOPMENT OF A WLFI SECURITY APPLICATION FOR DETECTING AND. MITIGATING EVIL TWIN ATTACKS', 'CZAR JOHN VILLAREAL, LOUISE MARK BANDOJA, VON PHILIPPE ACERO', 'Cavite State University, Department of Computer Studies, Imus Campus', '2025', 'A WLFI SECURITY APPLICATION, APPLICATION, ATTACKS, DETECTING, DEVELOPMENT, EVIL, MITIGATING, MITIGATING EVIL TWIN ATTACKS, SECURITY, TWIN, WLFI', 'DEVELOPMENT OF A WLFI SECURITY APPLICATION FOR DETECTING AND.\nMITIGATING EVIL TWIN ATTACKS\n\nUndergraduate Thesis\n‘Submitted to the Faculty of the\nDepartment of Computer Studies\nCavite State University - Imus Campus\nCity of Imus, Cavite\n\nIn partial fulfilment\nof the requirements for the degree\nBachelor of Science in Computer Science\n\nCZAR JOHN VILLAREAL\nLOUISE MARK BANDOJA\nVON PHILIPPE ACERO\nJanuary 2025\n\n', 'approved', '2025-04-01 13:19:48', '2025-04-01 13:20:12'),
(12, 8, 'uploads\\submissions\\thesis1.png', 'thesis1.png', 'DEVELOPMENT OF A WLFI SECURITY APPLICATION FOR DETECTING AND. MITIGATING EVIL TWIN ATTACKS', 'CZAR JOHN VILLAREAL, LOUISE MARK BANDOJA, VON PHILIPPE ACERO', 'Cavite State University, Department of Computer Studies, Imus Campus', '2025', 'A WLFI SECURITY APPLICATION, APPLICATION, ATTACKS, DETECTING, DEVELOPMENT, EVIL, MITIGATING, MITIGATING EVIL TWIN ATTACKS, SECURITY, TWIN, WLFI', 'DEVELOPMENT OF A WLFI SECURITY APPLICATION FOR DETECTING AND.\nMITIGATING EVIL TWIN ATTACKS\n\nUndergraduate Thesis\n‘Submitted to the Faculty of the\nDepartment of Computer Studies\nCavite State University - Imus Campus\nCity of Imus, Cavite\n\nIn partial fulfilment\nof the requirements for the degree\nBachelor of Science in Computer Science\n\nCZAR JOHN VILLAREAL\nLOUISE MARK BANDOJA\nVON PHILIPPE ACERO\nJanuary 2025\n\n', 'approved', '2025-04-01 14:02:36', '2025-04-01 14:03:39'),
(13, 8, 'uploads\\submissions\\thesis1.png', 'thesis1.png', 'DEVELOPMENT OF A WLFI SECURITY APPLICATION FOR DETECTING AND. MITIGATING EVIL TWIN ATTACKS', 'CZAR JOHN VILLAREAL, LOUISE MARK BANDOJA, VON PHILIPPE ACERO', 'Cavite State University, Department of Computer Studies, Imus Campus', '2025', 'A WLFI SECURITY APPLICATION, APPLICATION, ATTACKS, DETECTING, DEVELOPMENT, EVIL, MITIGATING, MITIGATING EVIL TWIN ATTACKS, SECURITY, TWIN, WLFI', 'DEVELOPMENT OF A WLFI SECURITY APPLICATION FOR DETECTING AND.\nMITIGATING EVIL TWIN ATTACKS\n\nUndergraduate Thesis\n‘Submitted to the Faculty of the\nDepartment of Computer Studies\nCavite State University - Imus Campus\nCity of Imus, Cavite\n\nIn partial fulfilment\nof the requirements for the degree\nBachelor of Science in Computer Science\n\nCZAR JOHN VILLAREAL\nLOUISE MARK BANDOJA\nVON PHILIPPE ACERO\nJanuary 2025\n\n', 'rejected', '2025-04-01 14:03:50', '2025-04-01 14:05:00');

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

--
-- Dumping data for table `thesis_versions`
--

INSERT INTO `thesis_versions` (`id`, `thesis_id`, `edited_title`, `edited_authors`, `edited_school`, `edited_year_made`, `edited_keywords`, `notes`, `edited_by`, `created_at`) VALUES
(11, 10, 'DEVELOPING A SPAN-BASED NAMED-ENTITY RECOGNITION METHOD FOR THESES INFORMATION-EXTRACTION ON COMPUTER, SCIENCE STUDIES USING OCR TESSERACT', 'RAFAELLA R. BANEZ, AALIHYA M. RIVERO., RYAN CHRISTIAN M. ROBLES', 'Cavite State University, Department of Computer Studies, Imus Campus', '2025', 'A SPAN-BASED NAMED-ENTITY RECOGNITION METHOD, COMPUTER, ENTITY, NAMED, OCR, OCR TESSERACT, RECOGNITION, SCIENCE STUDIES, SPAN, TESSERACT, THESES, THESES INFORMATION-EXTRACTION ON COMPUTER', '', 8, '2025-04-01 12:50:32'),
(12, 11, 'DEVELOPMENT OF A WLFI SECURITY APPLICATION FOR DETECTING AND. MITIGATING EVIL TWIN ATTACKS', 'CZAR JOHN VILLAREAL, LOUISE MARK BANDOJA, VON PHILIPPE ACERO', 'Cavite State University, Department of Computer Studies, Imus Campus', '2025', 'A WLFI SECURITY APPLICATION, APPLICATION, ATTACKS, DETECTING, DEVELOPMENT, EVIL, MITIGATING, MITIGATING EVIL TWIN ATTACKS, SECURITY, TWIN, WLFI', '', 8, '2025-04-01 13:20:02'),
(13, 11, 'DEVELOPMENT OF A WLFI SECURITY APPLICATION FOR DETECTING AND. MITIGATING EVIL TWIN ATTACKS', 'CZAR JOHN VILLAREAL, LOUISE MARK BANDOJA, VON PHILIPPE ACERO', 'Cavite State University, Department of Computer Studies, Imus Campus', '2025', 'A WLFI SECURITY APPLICATION, APPLICATION, ATTACKS, DETECTING, DEVELOPMENT, EVIL, MITIGATING, MITIGATING EVIL TWIN ATTACKS, SECURITY, TWIN, WLFI', '', 8, '2025-04-01 13:20:12'),
(14, 12, 'DEVELOPMENT OF A WLFI SECURITY APPLICATION FOR DETECTING AND. MITIGATING EVIL TWIN ATTACKS', 'CZAR JOHN VILLAREAL, LOUISE MARK BANDOJA, VON PHILIPPE ACERO', 'Cavite State University, Department of Computer Studies, Imus Campus', '2025', 'A WLFI SECURITY APPLICATION, APPLICATION, ATTACKS, DETECTING, DEVELOPMENT, EVIL, MITIGATING, MITIGATING EVIL TWIN ATTACKS, SECURITY, TWIN, WLFI', '', 8, '2025-04-01 14:03:39'),
(15, 13, 'DEVELOPMENT OF A WLFI SECURITY APPLICATION FOR DETECTING AND. MITIGATING EVIL TWIN ATTACKS', 'CZAR JOHN VILLAREAL, LOUISE MARK BANDOJA, VON PHILIPPE ACERO', 'Cavite State University, Department of Computer Studies, Imus Campus', '2025', 'A WLFI SECURITY APPLICATION, APPLICATION, ATTACKS, DETECTING, DEVELOPMENT, EVIL, MITIGATING, MITIGATING EVIL TWIN ATTACKS, SECURITY, TWIN, WLFI', '', 8, '2025-04-01 14:05:00');

-- --------------------------------------------------------

--
-- Table structure for table `users`
--

CREATE TABLE `users` (
  `id` int(11) NOT NULL,
  `username` varchar(80) NOT NULL,
  `password` varchar(255) NOT NULL,
  `role` enum('user','admin') NOT NULL DEFAULT 'user'
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Dumping data for table `users`
--

INSERT INTO `users` (`id`, `username`, `password`, `role`) VALUES
(8, 'admin', 'scrypt:32768:8:1$HD13SiK3xNEOgB4Q$8f9cef7b04f8979711202ec3baea8502975507eaaf11802866887837f1e76da75ad024a16e185349c66343fd922b3a7103322dd59a813c3933c583d5d7e176b7', 'admin'),
(9, 'test123', 'scrypt:32768:8:1$HfY8VnN3kECdDeHZ$0a36ecbcfbcae5f10e6bf604f4b3983cf5a73e0662a381ea8b5e23805f13ca693f59d4ced55dc62309338a4898e44576d90b353ff1773c579dece79595a9d827', 'user');

--
-- Indexes for dumped tables
--

--
-- Indexes for table `published_theses`
--
ALTER TABLE `published_theses`
  ADD PRIMARY KEY (`id`),
  ADD KEY `submission_id` (`submission_id`),
  ADD KEY `published_by` (`published_by`);

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
-- AUTO_INCREMENT for dumped tables
--

--
-- AUTO_INCREMENT for table `published_theses`
--
ALTER TABLE `published_theses`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT for table `thesis_submissions`
--
ALTER TABLE `thesis_submissions`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=14;

--
-- AUTO_INCREMENT for table `thesis_versions`
--
ALTER TABLE `thesis_versions`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=16;

--
-- AUTO_INCREMENT for table `users`
--
ALTER TABLE `users`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=10;

--
-- Constraints for dumped tables
--

--
-- Constraints for table `published_theses`
--
ALTER TABLE `published_theses`
  ADD CONSTRAINT `published_theses_ibfk_1` FOREIGN KEY (`submission_id`) REFERENCES `thesis_submissions` (`id`),
  ADD CONSTRAINT `published_theses_ibfk_2` FOREIGN KEY (`published_by`) REFERENCES `users` (`id`);

--
-- Constraints for table `thesis_submissions`
--
ALTER TABLE `thesis_submissions`
  ADD CONSTRAINT `thesis_submissions_ibfk_1` FOREIGN KEY (`admin_id`) REFERENCES `users` (`id`);

--
-- Constraints for table `thesis_versions`
--
ALTER TABLE `thesis_versions`
  ADD CONSTRAINT `thesis_versions_ibfk_1` FOREIGN KEY (`thesis_id`) REFERENCES `thesis_submissions` (`id`),
  ADD CONSTRAINT `thesis_versions_ibfk_2` FOREIGN KEY (`edited_by`) REFERENCES `users` (`id`);
COMMIT;

/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
