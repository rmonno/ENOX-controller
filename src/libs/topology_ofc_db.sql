-- phpMyAdmin SQL Dump
-- version 3.3.2deb1ubuntu1
-- http://www.phpmyadmin.net
--
-- Host: localhost
-- Generation Time: Feb 20, 2013 at 12:33 PM
-- Server version: 5.1.67
-- PHP Version: 5.3.2-1ubuntu4.18

SET SQL_MODE="NO_AUTO_VALUE_ON_ZERO";
SET time_zone = "+00:00";

/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8 */;

--
-- Database: `topology_ofc_db`
--
CREATE DATABASE IF NOT EXISTS topology_ofc_db;
GRANT ALL ON topology_ofc_db.* TO 'topology_user'@'%' IDENTIFIED BY 'topology_pwd';
USE topology_ofc_db;
-- --------------------------------------------------------

--
-- Table structure for table `datapaths`
--

CREATE TABLE IF NOT EXISTS `datapaths` (
  `id` bigint(20) unsigned NOT NULL COMMENT 'datapath identifier',
  `name` varchar(20) COLLATE utf8_unicode_ci DEFAULT NULL COMMENT 'datapath name',
  `ofp_capabilities` int(11) unsigned DEFAULT NULL,
  `ofp_actions` int(11) unsigned DEFAULT NULL,
  `buffers` int(11) unsigned DEFAULT NULL COMMENT 'Max packets buffered at once',
  `tables` int(11) unsigned DEFAULT NULL COMMENT 'Number of tables supported by datapath',
  `dID` tinyint(3) unsigned NOT NULL AUTO_INCREMENT COMMENT 'unique datapath ID',
  PRIMARY KEY (`id`),
  UNIQUE KEY `dID` (`dID`)
) ENGINE=InnoDB  DEFAULT CHARSET=utf8 COLLATE=utf8_unicode_ci COMMENT='datapaths details' AUTO_INCREMENT=91 ;

-- --------------------------------------------------------

--
-- Table structure for table `hosts`
--

CREATE TABLE IF NOT EXISTS `hosts` (
  `mac_addr` varchar(18) CHARACTER SET latin1 NOT NULL,
  `ip_addr` varchar(18) CHARACTER SET latin1 NOT NULL,
  `in_port` smallint(8) unsigned NOT NULL,
  `dpid` bigint(20) unsigned NOT NULL,
  `hostID` smallint(5) unsigned NOT NULL AUTO_INCREMENT,
  PRIMARY KEY (`dpid`,`mac_addr`),
  UNIQUE KEY `id` (`hostID`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8 COLLATE=utf8_unicode_ci COMMENT='hosts info' AUTO_INCREMENT=1 ;

-- --------------------------------------------------------

--
-- Table structure for table `ports`
--

CREATE TABLE IF NOT EXISTS `ports` (
  `datapath_id` bigint(20) unsigned NOT NULL COMMENT 'datapath identifier',
  `port_no` mediumint(8) unsigned NOT NULL COMMENT 'port number',
  `hw_addr` varchar(18) COLLATE utf8_unicode_ci DEFAULT NULL COMMENT 'mac address (typically)',
  `name` varchar(16) COLLATE utf8_unicode_ci DEFAULT NULL COMMENT 'port human name',
  `config` int(11) unsigned DEFAULT NULL COMMENT 'spanning tree and administrative settings',
  `state` int(11) unsigned DEFAULT NULL COMMENT 'spanning tree state',
  `curr` int(11) unsigned DEFAULT NULL COMMENT 'current features',
  `advertised` int(11) unsigned DEFAULT NULL COMMENT 'Features being advertised by the port',
  `supported` int(11) unsigned DEFAULT NULL COMMENT 'Features supported by the port',
  `peer` int(11) unsigned DEFAULT NULL COMMENT 'Features advertised by peer',
  `nodeID` smallint(5) unsigned NOT NULL AUTO_INCREMENT COMMENT 'unique node identifier',
  PRIMARY KEY (`datapath_id`,`port_no`),
  UNIQUE KEY `nodeID` (`nodeID`)
) ENGINE=InnoDB  DEFAULT CHARSET=utf8 COLLATE=utf8_unicode_ci COMMENT='port details' AUTO_INCREMENT=112 ;

--
-- Table structure for table `links`
--

CREATE TABLE IF NOT EXISTS `links` (
  `src_dpid` bigint(20) unsigned NOT NULL COMMENT 'source datapath identifier',
  `src_pno` mediumint(8) unsigned NOT NULL COMMENT 'source port number',
  `dst_dpid` bigint(20) unsigned NOT NULL COMMENT 'destination datapath identifier',
  `dst_pno` mediumint(8) unsigned NOT NULL COMMENT 'destination port number',
  PRIMARY KEY (`src_dpid`,`src_pno`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8 COLLATE=utf8_unicode_ci COMMENT='links info' ;

-- --------------------------------------------------------

--
-- Constraints for dumped tables
--

--
-- Constraints for table `hosts`
--
ALTER TABLE `hosts`
  ADD CONSTRAINT `hosts_ibfk_1` FOREIGN KEY (`dpid`) REFERENCES `datapaths` (`id`) ON DELETE CASCADE ON UPDATE CASCADE;

--
-- Constraints for table `ports`
--
ALTER TABLE `ports`
  ADD CONSTRAINT `ports_ibfk_1` FOREIGN KEY (`datapath_id`) REFERENCES `datapaths` (`id`) ON DELETE CASCADE ON UPDATE CASCADE;

--
-- Constraints for table `links`
--
ALTER TABLE `links`
  ADD CONSTRAINT `links_ibfk_1` FOREIGN KEY (`src_dpid`,`src_pno`) REFERENCES `ports` (`datapath_id`,`port_no`) ON DELETE CASCADE ON UPDATE CASCADE;

ALTER TABLE `links`
  ADD CONSTRAINT `links_ibfk_2` FOREIGN KEY (`dst_dpid`,`dst_pno`) REFERENCES `ports` (`datapath_id`,`port_no`) ON DELETE CASCADE ON UPDATE CASCADE;
