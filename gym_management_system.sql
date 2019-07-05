-- phpMyAdmin SQL Dump
-- version 4.1.14
-- http://www.phpmyadmin.net
--
-- Host: 127.0.0.1
-- Generation Time: Apr 28, 2016 at 05:57 PM
-- Server version: 5.6.17
-- PHP Version: 5.5.12

SET SQL_MODE = "NO_AUTO_VALUE_ON_ZERO";
SET time_zone = "+00:00";


/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8 */;

--
-- Database: `gym_management_system`
--

-- --------------------------------------------------------

--
-- Table structure for table `attendace`
--

CREATE TABLE IF NOT EXISTS `attendace` (
  `attendance_id` int(11) NOT NULL AUTO_INCREMENT,
  `attendance_user_id` varchar(255) NOT NULL,
  `attendance_date` varchar(255) NOT NULL,
  `attendance_description` varchar(255) NOT NULL,
  PRIMARY KEY (`attendance_id`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1 AUTO_INCREMENT=1 ;

-- --------------------------------------------------------

--
-- Table structure for table `attendance`
--

CREATE TABLE IF NOT EXISTS `attendance` (
  `attendance_id` int(11) NOT NULL AUTO_INCREMENT,
  `attendance_user_id` varchar(255) NOT NULL,
  `attendance_date` varchar(255) NOT NULL,
  `attendance_description` varchar(255) NOT NULL,
  PRIMARY KEY (`attendance_id`)
) ENGINE=InnoDB  DEFAULT CHARSET=latin1 AUTO_INCREMENT=7 ;

--
-- Dumping data for table `attendance`
--

INSERT INTO `attendance` (`attendance_id`, `attendance_user_id`, `attendance_date`, `attendance_description`) VALUES
(2, '7', '1 March,2016', 'Present'),
(3, '7', '2 March,2016', 'Present'),
(4, '7', '3 March,2016', 'Present'),
(5, '7', '4 March,2016', 'Present'),
(6, '7', '5 March,2016', 'Present');

-- --------------------------------------------------------

--
-- Table structure for table `city`
--

CREATE TABLE IF NOT EXISTS `city` (
  `city_id` int(11) NOT NULL AUTO_INCREMENT,
  `city_name` varchar(255) NOT NULL,
  PRIMARY KEY (`city_id`)
) ENGINE=InnoDB  DEFAULT CHARSET=latin1 AUTO_INCREMENT=3 ;

--
-- Dumping data for table `city`
--

INSERT INTO `city` (`city_id`, `city_name`) VALUES
(1, 'Allahabad'),
(2, 'Varanasi');

-- --------------------------------------------------------

--
-- Table structure for table `country`
--

CREATE TABLE IF NOT EXISTS `country` (
  `country_id` int(11) NOT NULL AUTO_INCREMENT,
  `country_name` varchar(255) NOT NULL,
  PRIMARY KEY (`country_id`)
) ENGINE=InnoDB  DEFAULT CHARSET=latin1 AUTO_INCREMENT=3 ;

--
-- Dumping data for table `country`
--

INSERT INTO `country` (`country_id`, `country_name`) VALUES
(1, 'India'),
(2, 'USA');

-- --------------------------------------------------------

--
-- Table structure for table `login`
--

CREATE TABLE IF NOT EXISTS `login` (
  `login_id` int(11) NOT NULL AUTO_INCREMENT,
  `login_user` varchar(255) NOT NULL,
  `login_password` varchar(255) NOT NULL,
  `login_level` varchar(255) NOT NULL,
  `login_date` int(11) DEFAULT NULL,
  PRIMARY KEY (`login_id`)
) ENGINE=InnoDB  DEFAULT CHARSET=latin1 AUTO_INCREMENT=2 ;

--
-- Dumping data for table `login`
--

INSERT INTO `login` (`login_id`, `login_user`, `login_password`, `login_level`, `login_date`) VALUES
(1, 'admin', 'test', '', NULL);

-- --------------------------------------------------------

--
-- Table structure for table `month`
--

CREATE TABLE IF NOT EXISTS `month` (
  `month_id` int(11) NOT NULL AUTO_INCREMENT,
  `month_name` varchar(100) NOT NULL,
  PRIMARY KEY (`month_id`)
) ENGINE=InnoDB  DEFAULT CHARSET=latin1 AUTO_INCREMENT=13 ;

--
-- Dumping data for table `month`
--

INSERT INTO `month` (`month_id`, `month_name`) VALUES
(1, 'January'),
(2, 'February'),
(3, 'March'),
(4, 'April'),
(5, 'May'),
(6, 'June'),
(7, 'July'),
(8, 'August'),
(9, 'September'),
(10, 'October'),
(11, 'November'),
(12, 'December');

-- --------------------------------------------------------

--
-- Table structure for table `package`
--

CREATE TABLE IF NOT EXISTS `package` (
  `package_id` int(11) NOT NULL AUTO_INCREMENT,
  `package_title` varchar(255) NOT NULL,
  `package_fees` varchar(255) NOT NULL,
  `package_description` varchar(255) NOT NULL,
  PRIMARY KEY (`package_id`)
) ENGINE=InnoDB  DEFAULT CHARSET=latin1 AUTO_INCREMENT=7 ;

--
-- Dumping data for table `package`
--

INSERT INTO `package` (`package_id`, `package_title`, `package_fees`, `package_description`) VALUES
(2, 'Quaterly Package', '1400', 'Quaterly Package'),
(3, 'Monthly Package', '1000', 'Monthl Package'),
(4, '6 Month Package', '5000', '6 Months Package'),
(5, '9 Month Package ', '7000', '9 Month Package '),
(6, 'Yearly Package', '9000', 'Yearly Package');

-- --------------------------------------------------------

--
-- Table structure for table `payment`
--

CREATE TABLE IF NOT EXISTS `payment` (
  `payment_id` int(11) NOT NULL AUTO_INCREMENT,
  `payment_user_id` varchar(255) NOT NULL,
  `payment_for_month` varchar(255) NOT NULL,
  `payment_date` varchar(255) NOT NULL,
  `payment_amount` varchar(255) NOT NULL,
  `payment_description` varchar(255) NOT NULL,
  PRIMARY KEY (`payment_id`)
) ENGINE=InnoDB  DEFAULT CHARSET=latin1 AUTO_INCREMENT=5 ;

--
-- Dumping data for table `payment`
--

INSERT INTO `payment` (`payment_id`, `payment_user_id`, `payment_for_month`, `payment_date`, `payment_amount`, `payment_description`) VALUES
(2, '7', '4', '17 March,2016', '1000', 'Payment for april'),
(3, '4', '2', '1 March,2016', '1200', 'Payment for fenruary'),
(4, '8', '9', '19 March,2016', '1000', 'Payment for Suman');

-- --------------------------------------------------------

--
-- Table structure for table `role`
--

CREATE TABLE IF NOT EXISTS `role` (
  `role_id` int(11) NOT NULL AUTO_INCREMENT,
  `role_name` varchar(255) NOT NULL,
  PRIMARY KEY (`role_id`)
) ENGINE=InnoDB  DEFAULT CHARSET=latin1 AUTO_INCREMENT=4 ;

--
-- Dumping data for table `role`
--

INSERT INTO `role` (`role_id`, `role_name`) VALUES
(1, 'Super Admin'),
(2, 'Head Of Department'),
(3, 'Faculty');

-- --------------------------------------------------------

--
-- Table structure for table `shift`
--

CREATE TABLE IF NOT EXISTS `shift` (
  `shift_id` int(11) NOT NULL AUTO_INCREMENT,
  `shift_title` varchar(255) NOT NULL,
  `shift_from_time` varchar(255) NOT NULL,
  `shift_to_time` varchar(255) NOT NULL,
  `shift_description` varchar(255) NOT NULL,
  PRIMARY KEY (`shift_id`)
) ENGINE=InnoDB  DEFAULT CHARSET=latin1 AUTO_INCREMENT=5 ;

--
-- Dumping data for table `shift`
--

INSERT INTO `shift` (`shift_id`, `shift_title`, `shift_from_time`, `shift_to_time`, `shift_description`) VALUES
(2, 'Morning Shift - 1', '06:00 AM', '07:00 AM', 'Morning Shift - 1'),
(3, 'Morning Shift - 2', '07:00 AM', '08:00 AM', 'Morning Shift - 2'),
(4, 'Morning Shift - 3', '08:00 AM', '09:00 AM', 'Morning Shift - 3');

-- --------------------------------------------------------

--
-- Table structure for table `state`
--

CREATE TABLE IF NOT EXISTS `state` (
  `state_id` int(11) NOT NULL AUTO_INCREMENT,
  `state_name` varchar(255) NOT NULL,
  PRIMARY KEY (`state_id`)
) ENGINE=InnoDB  DEFAULT CHARSET=latin1 AUTO_INCREMENT=3 ;

--
-- Dumping data for table `state`
--

INSERT INTO `state` (`state_id`, `state_name`) VALUES
(1, 'UP'),
(2, 'MP');

-- --------------------------------------------------------

--
-- Table structure for table `trainer`
--

CREATE TABLE IF NOT EXISTS `trainer` (
  `trainer_id` int(11) NOT NULL AUTO_INCREMENT,
  `trainer_trainername` varchar(255) DEFAULT NULL,
  `trainer_name` varchar(255) NOT NULL,
  `trainer_add1` varchar(255) NOT NULL,
  `trainer_add2` varchar(255) NOT NULL,
  `trainer_city` varchar(255) NOT NULL,
  `trainer_state` varchar(255) NOT NULL,
  `trainer_country` varchar(255) NOT NULL,
  `trainer_email` varchar(255) NOT NULL,
  `trainer_mobile` varchar(255) NOT NULL,
  `trainer_gender` varchar(255) NOT NULL,
  `trainer_dob` varchar(255) NOT NULL,
  `trainer_image` varchar(255) NOT NULL,
  PRIMARY KEY (`trainer_id`)
) ENGINE=InnoDB  DEFAULT CHARSET=latin1 AUTO_INCREMENT=2 ;

--
-- Dumping data for table `trainer`
--

INSERT INTO `trainer` (`trainer_id`, `trainer_trainername`, `trainer_name`, `trainer_add1`, `trainer_add2`, `trainer_city`, `trainer_state`, `trainer_country`, `trainer_email`, `trainer_mobile`, `trainer_gender`, `trainer_dob`, `trainer_image`) VALUES
(1, NULL, 'Kaushal Kishore', 'Mumbai', 'Mumbai', '1', '2', '2', 'kaushal@gmail.com', '9876765654', '', '5 March,1971', 'Image.jpg');

-- --------------------------------------------------------

--
-- Table structure for table `type`
--

CREATE TABLE IF NOT EXISTS `type` (
  `type_id` int(11) NOT NULL AUTO_INCREMENT,
  `type_name` varchar(255) NOT NULL,
  PRIMARY KEY (`type_id`)
) ENGINE=InnoDB  DEFAULT CHARSET=latin1 AUTO_INCREMENT=5 ;

--
-- Dumping data for table `type`
--

INSERT INTO `type` (`type_id`, `type_name`) VALUES
(1, 'Sedan'),
(2, 'Hatchback '),
(3, 'SUV'),
(4, 'MUV');

-- --------------------------------------------------------

--
-- Table structure for table `user`
--

CREATE TABLE IF NOT EXISTS `user` (
  `user_id` int(11) NOT NULL AUTO_INCREMENT,
  `user_package_id` varchar(255) NOT NULL,
  `user_shift_id` varchar(255) NOT NULL,
  `user_level_id` varchar(255) DEFAULT NULL,
  `user_username` varchar(255) DEFAULT NULL,
  `user_password` varchar(255) DEFAULT NULL,
  `user_name` varchar(255) NOT NULL,
  `user_add1` varchar(255) NOT NULL,
  `user_add2` varchar(255) NOT NULL,
  `user_city` varchar(255) NOT NULL,
  `user_state` varchar(255) NOT NULL,
  `user_country` varchar(255) NOT NULL,
  `user_email` varchar(255) NOT NULL,
  `user_mobile` varchar(255) NOT NULL,
  `user_gender` varchar(255) NOT NULL,
  `user_dob` varchar(255) NOT NULL,
  `user_image` varchar(255) NOT NULL,
  PRIMARY KEY (`user_id`)
) ENGINE=InnoDB  DEFAULT CHARSET=latin1 AUTO_INCREMENT=12 ;

--
-- Dumping data for table `user`
--

INSERT INTO `user` (`user_id`, `user_package_id`, `user_shift_id`, `user_level_id`, `user_username`, `user_password`, `user_name`, `user_add1`, `user_add2`, `user_city`, `user_state`, `user_country`, `user_email`, `user_mobile`, `user_gender`, `user_dob`, `user_image`) VALUES
(4, '4', '2', '1', 'admin', 'test', 'Kaushal Kishore', 'House no : 768', 'Sector 2B', '1', '1', '2', 'kaushal.rahuljaiswal@gmail.com', '987654321', '', '12 january, 2013', 'IMG_5739.JPG'),
(7, '1', '1', '3', 'faculty', 'test', 'Amit Kumar', 'House no : 768', 'Sector 2B', '2', '1', '2', 'amit@gmail.com', '9324324546', '', '26 December,2015', 'IMG_5746.JPG'),
(8, '2', '3', '3', 'suman', 'test', 'Suman Singh', 'House no : 768', 'Sector 2A', '1', '2', '1', 'suman@gmail.com', '987654321', '', '13 January,1961', 'IMG_5748.jpg'),
(9, '1', '3', '2', 'ece_hod', 'test', 'Arun Kumar', 'House no : 768', 'Sector 2A', '1', '1', '1', 'arun@gmail.com', '987654321', '', '12 january, 2013', 'IMG_5740.jpg'),
(10, '1', '1', '3', 'manasa', 'test', 'Manasa', 'New Delhi', 'India', '2', '2', '1', 'manasa@gmail.com', '9876543212', '', '18 January,1968', 'IMG_5746.jpg'),
(11, '5', '2', NULL, NULL, NULL, 'asdf', 'fd', 'fd', '1', '2', '1', 'dsf@dsaf.com', 'sdf', '', 'dsf', '');

/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
