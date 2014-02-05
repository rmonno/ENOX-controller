-- phpMyAdmin SQL Dump
-- version 3.3.2deb1ubuntu1
-- http://www.phpmyadmin.net
--
-- Host: localhost
-- Generation Time: Mar 11, 2013 at 06:30 PM
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
  `id` varchar(25) COLLATE utf8_unicode_ci NOT NULL COMMENT 'datapath identifier',
  `name` varchar(20) COLLATE utf8_unicode_ci DEFAULT NULL COMMENT 'datapath name',
  `ofp_capabilities` int(11) unsigned DEFAULT NULL,
  `ofp_actions` int(11) unsigned DEFAULT NULL,
  `buffers` int(11) unsigned DEFAULT NULL COMMENT 'Max packets buffered at once',
  `tables` tinyint(3) unsigned DEFAULT NULL COMMENT 'Number of tables supported by datapath',
  `cports` tinyint(3) unsigned DEFAULT NULL COMMENT 'Number of circuit ports',
  `dID` tinyint(3) unsigned NOT NULL AUTO_INCREMENT COMMENT 'unique datapath ID',
  PRIMARY KEY (`id`),
  UNIQUE KEY (`dID`)
) ENGINE=InnoDB  DEFAULT CHARSET=utf8 COLLATE=utf8_unicode_ci COMMENT='datapaths details';

ALTER TABLE `datapaths` AUTO_INCREMENT=1;

-- --------------------------------------------------------

--
-- Table structure for table `ports`
--
CREATE TABLE IF NOT EXISTS `ports` (
  `datapath_id` varchar(25) COLLATE utf8_unicode_ci NOT NULL COMMENT 'datapath identifier',
  `port_no` smallint(8) unsigned NOT NULL COMMENT 'port number',
  `hw_addr` varchar(18) COLLATE utf8_unicode_ci DEFAULT NULL COMMENT 'mac address (typically)',
  `name` varchar(16) COLLATE utf8_unicode_ci DEFAULT NULL COMMENT 'port human name',
  `config` int(11) unsigned DEFAULT NULL COMMENT 'spanning tree and administrative settings',
  `state` int(11) unsigned DEFAULT NULL COMMENT 'spanning tree state',
  `curr` int(11) unsigned DEFAULT NULL COMMENT 'current features',
  `advertised` int(11) unsigned DEFAULT NULL COMMENT 'Features being advertised by the port',
  `supported` int(11) unsigned DEFAULT NULL COMMENT 'Features supported by the port',
  `peer` int(11) unsigned DEFAULT NULL COMMENT 'Features advertised by peer',
  `sw_tdm_gran` int(11) unsigned DEFAULT NULL COMMENT 'TDM switching granularity flags',
  `sw_type` smallint(8) unsigned DEFAULT NULL COMMENT 'bitmap of switching type flags',
  `peer_port_no` smallint(8) unsigned DEFAULT NULL COMMENT 'discovered peer switching port number',
  `peer_dpath_id` varchar(25) COLLATE utf8_unicode_ci DEFAULT NULL COMMENT 'discovered peer switching datapath identifier',
  `nodeID` smallint(5) unsigned NOT NULL AUTO_INCREMENT COMMENT 'unique node identifier',
  PRIMARY KEY (`datapath_id`,`port_no`),
  UNIQUE KEY (`nodeID`)
) ENGINE=InnoDB  DEFAULT CHARSET=utf8 COLLATE=utf8_unicode_ci COMMENT='port details';

--
-- Constraints for table `ports`
--
ALTER TABLE `ports` AUTO_INCREMENT=1;

ALTER TABLE `ports`
  ADD CONSTRAINT `ports_ibfk_1` FOREIGN KEY (`datapath_id`)
        REFERENCES `datapaths` (`id`) ON DELETE CASCADE ON UPDATE CASCADE;

-- --------------------------------------------------------

--
-- Table structure for table `cports_bandwidth`
--
CREATE TABLE IF NOT EXISTS `cports_bandwidth` (
  `dpid` varchar(25) COLLATE utf8_unicode_ci NOT NULL COMMENT 'datapath identifier',
  `port_no` smallint(8) unsigned NOT NULL COMMENT 'circuit switch port number',
  `num_bandwidth` smallint(8) unsigned NOT NULL COMMENT 'identifies number of bandwidth array elements',
  `bandwidth` bigint(20) unsigned DEFAULT NULL COMMENT 'bandwidth value',
  PRIMARY KEY (`dpid`,`port_no`,`num_bandwidth`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8 COLLATE=utf8_unicode_ci COMMENT='circuit ports bandwidth info';

--
-- Constraints for table `cports_bandwidth`
--
ALTER TABLE `cports_bandwidth`
  ADD CONSTRAINT `cports_bandwidth_ibfk_1` FOREIGN KEY (`dpid`, `port_no`)
    REFERENCES `ports` (`datapath_id`, `port_no`) ON DELETE CASCADE ON UPDATE CASCADE;

-- --------------------------------------------------------

--
-- Table structure for table `hosts`
--
CREATE TABLE IF NOT EXISTS `hosts` (
  `dpid` varchar(25) COLLATE utf8_unicode_ci NOT NULL,
  `mac_addr` varchar(18) CHARACTER SET latin1 NOT NULL,
  `ip_addr` varchar(18) CHARACTER SET latin1 NOT NULL,
  `in_port` smallint(8) unsigned NOT NULL,
  `hostID` smallint(5) unsigned NOT NULL AUTO_INCREMENT,
  PRIMARY KEY (`dpid`,`mac_addr`),
  UNIQUE KEY (`hostID`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8 COLLATE=utf8_unicode_ci COMMENT='hosts info';

--
-- Constraints for table `hosts`
--
ALTER TABLE `hosts` AUTO_INCREMENT=1;

ALTER TABLE `hosts`
  ADD CONSTRAINT `hosts_ibfk_1` FOREIGN KEY (`dpid`)
    REFERENCES `datapaths` (`id`) ON DELETE CASCADE ON UPDATE CASCADE;

-- --------------------------------------------------------

--
-- Table structure for table `links`
--
CREATE TABLE IF NOT EXISTS `links` (
  `src_dpid` varchar(25) COLLATE utf8_unicode_ci NOT NULL COMMENT 'source datapath identifier',
  `src_pno` smallint(8) unsigned NOT NULL COMMENT 'source port number',
  `dst_dpid` varchar(25) COLLATE utf8_unicode_ci DEFAULT NULL COMMENT 'destination datapath identifier',
  `dst_pno` smallint(8) unsigned DEFAULT NULL COMMENT 'destination port number',
  `available_bw` bigint(20) unsigned DEFAULT NULL COMMENT 'available bandwidth',
  PRIMARY KEY (`src_dpid`,`src_pno`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8 COLLATE=utf8_unicode_ci COMMENT='links info';

--
-- Constraints for table `links`
--
ALTER TABLE `links`
  ADD CONSTRAINT `links_ibfk_1` FOREIGN KEY (`src_dpid`, `src_pno`)
    REFERENCES `ports` (`datapath_id`, `port_no`) ON DELETE CASCADE ON UPDATE CASCADE;

ALTER TABLE `links`
  ADD CONSTRAINT `links_ibfk_2` FOREIGN KEY (`dst_dpid`, `dst_pno`)
    REFERENCES `ports` (`datapath_id`, `port_no`) ON DELETE CASCADE ON UPDATE CASCADE;

-- --------------------------------------------------------

--
-- Table structure for table `flow_entries`
--
CREATE TABLE IF NOT EXISTS `flow_entries` (
  `flow_id` int(11) unsigned NOT NULL AUTO_INCREMENT,
  `dpid` varchar(25) COLLATE utf8_unicode_ci NOT NULL,
  `table_id` int(8) unsigned DEFAULT NULL,
  `in_port` int(16) unsigned DEFAULT NULL,
  `idle_timeout` int(16) unsigned DEFAULT NULL,
  `hard_timeout` int(16) unsigned DEFAULT NULL,
  `priority` int(16) unsigned DEFAULT NULL,
  `action` varchar(18) CHARACTER SET latin1 NOT NULL,
  `cookie` bigint(64) unsigned DEFAULT NULL,
  `dl_type` int(16) unsigned DEFAULT NULL,
  `dl_vlan` int(16) unsigned DEFAULT NULL,
  `dl_vlan_pcp` int(8) unsigned DEFAULT NULL,
  `dl_src` varchar(18) CHARACTER SET latin1 DEFAULT NULL,
  `dl_dst` varchar(18) CHARACTER SET latin1 DEFAULT NULL,
  `nw_src` varchar(18) CHARACTER SET latin1 DEFAULT NULL,
  `nw_dst` varchar(18) CHARACTER SET latin1 DEFAULT NULL,
  `nw_src_n_wild` int(11) DEFAULT NULL,
  `nw_dst_n_wild` int(11) DEFAULT NULL,
  `nw_proto` int(8) unsigned DEFAULT NULL,
  `tp_src` int(16) unsigned DEFAULT NULL,
  `tp_dst` int(16) unsigned DEFAULT NULL,
  PRIMARY KEY (`flow_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8 COLLATE=utf8_unicode_ci;

--
-- Constraints for table `flow_entries`
--
ALTER TABLE `flow_entries` AUTO_INCREMENT=1;

ALTER TABLE `flow_entries`
  ADD CONSTRAINT `flow_entries_ibfk_1` FOREIGN KEY (`dpid`)
    REFERENCES `datapaths` (`id`) ON DELETE CASCADE ON UPDATE CASCADE;

-- --------------------------------------------------------

--
-- Table structure for table `port_stats'
--
CREATE TABLE IF NOT EXISTS `port_stats` (
  `datapath_id` varchar(25) COLLATE utf8_unicode_ci NOT NULL,
  `port_no` smallint(8) unsigned NOT NULL,
  `rx_pkts` bigint(64) unsigned DEFAULT NULL,
  `tx_pkts` bigint(64) unsigned DEFAULT NULL,
  `rx_bytes` bigint(64) unsigned DEFAULT NULL,
  `tx_bytes` bigint(64) unsigned DEFAULT NULL,
  `rx_dropped` bigint(64) unsigned DEFAULT NULL,
  `tx_dropped` bigint(64) unsigned DEFAULT NULL,
  `rx_errors` bigint(64) unsigned DEFAULT NULL,
  `tx_errors` bigint(64) unsigned DEFAULT NULL,
  `rx_frame_err` bigint(64) unsigned DEFAULT NULL,
  `rx_over_err` bigint(64) unsigned DEFAULT NULL,
  `rx_crc_err` bigint(64) unsigned DEFAULT NULL,
  `collisions` bigint(64) unsigned DEFAULT NULL,
  PRIMARY KEY (`datapath_id`,`port_no`)
) ENGINE=InnoDB  DEFAULT CHARSET=utf8 COLLATE=utf8_unicode_ci COMMENT='port_stats details';

--
-- Constraints for table `port_stats`
--
ALTER TABLE `port_stats`
  ADD CONSTRAINT `port_stats_ibfk_1` FOREIGN KEY (`datapath_id`, `port_no`)
    REFERENCES `ports` (`datapath_id`, `port_no`) ON DELETE CASCADE ON UPDATE CASCADE;

-- --------------------------------------------------------

--
-- Table structure for table `table_stats'
--
CREATE TABLE IF NOT EXISTS `table_stats` (
  `datapath_id` varchar(25) COLLATE utf8_unicode_ci NOT NULL,
  `table_id` smallint(8) unsigned NOT NULL,
  `max_entries` bigint(32) unsigned DEFAULT NULL,
  `active_count` bigint(64) unsigned DEFAULT NULL,
  `lookup_count` bigint(64) unsigned DEFAULT NULL,
  `matched_count` bigint(64) unsigned DEFAULT NULL,
  PRIMARY KEY (`datapath_id`,`table_id`)
) ENGINE=InnoDB  DEFAULT CHARSET=utf8 COLLATE=utf8_unicode_ci COMMENT='table_stats details';

--
-- Constraints for table `table_stats`
--
ALTER TABLE `table_stats`
  ADD CONSTRAINT `table_stats_ibfk_1` FOREIGN KEY (`datapath_id`)
    REFERENCES `datapaths` (`id`) ON DELETE CASCADE ON UPDATE CASCADE;

-- --------------------------------------------------------

--
-- Table structure for table `requests'
--
CREATE TABLE IF NOT EXISTS `requests` (
  `ip_src` varchar(18) CHARACTER SET latin1 NOT NULL COMMENT 'source ip address',
  `ip_dst` varchar(18) CHARACTER SET latin1 NOT NULL COMMENT 'destination ip address',
  `port_src` smallint(8) unsigned NOT NULL COMMENT 'sorce (tcp/udp) port number',
  `port_dst` smallint(8) unsigned NOT NULL COMMENT 'destination (tcp/udp) port number',
  `ip_proto` int(8) unsigned NOT NULL COMMENT 'ip protocol number',
  `vlan_id` int(16) unsigned NOT NULL COMMENT 'vlan identifier',
  `bw` bigint(20) unsigned DEFAULT NULL COMMENT 'requested bandwidth',
  `status` varchar(18) CHARACTER SET latin1 DEFAULT NULL COMMENT 'request status',
  `comments` varchar(100) CHARACTER SET latin1 DEFAULT NULL COMMENT 'request comments',
  `start_time` timestamp NULL COMMENT 'request start time',
  `end_time` timestamp NULL COMMENT 'request end time',
  `serviceID` smallint(5) unsigned NOT NULL AUTO_INCREMENT COMMENT 'unique service identifier',
  PRIMARY KEY (`ip_src`, `ip_dst`, `port_src`, `port_dst`, `ip_proto`, `vlan_id`),
  UNIQUE KEY (`serviceID`)
) ENGINE=InnoDB  DEFAULT CHARSET=utf8 COLLATE=utf8_unicode_ci COMMENT='services requests';

--
-- Constraints for tables `requests`
--
ALTER TABLE `requests` AUTO_INCREMENT=1;

-- --------------------------------------------------------

--
-- Table structure for table `services'
--
CREATE TABLE IF NOT EXISTS `services` (
  `serviceID` smallint(5) unsigned NOT NULL COMMENT 'unique service identifier',
  `src_dpid` varchar(25) COLLATE utf8_unicode_ci NOT NULL COMMENT 'source datapath identifier',
  `src_portno` smallint(8) unsigned NOT NULL COMMENT 'source port number',
  `dst_dpid` varchar(25) COLLATE utf8_unicode_ci NOT NULL COMMENT 'destination datapath identifier',
  `dst_portno` smallint(8) unsigned NOT NULL COMMENT 'destination port number',
  `bw` bigint(20) unsigned DEFAULT NULL COMMENT 'bandwidth',
  `sequenceID` smallint(5) unsigned NOT NULL AUTO_INCREMENT COMMENT 'unique sequence identifier',
  PRIMARY KEY (`serviceID`, `src_dpid`, `src_portno`, `dst_dpid`, `dst_portno`),
  UNIQUE KEY (`sequenceID`)
) ENGINE=InnoDB  DEFAULT CHARSET=utf8 COLLATE=utf8_unicode_ci COMMENT='services details';

--
-- Constraints for table `services`
--
ALTER TABLE `services` AUTO_INCREMENT=1;

ALTER TABLE `services`
  ADD CONSTRAINT `services_ibfk_1` FOREIGN KEY (`serviceID`)
    REFERENCES `requests` (`serviceID`) ON DELETE CASCADE ON UPDATE CASCADE;

ALTER TABLE `services`
  ADD CONSTRAINT `services_ibfk_2` FOREIGN KEY (`src_dpid`, `src_portno`)
    REFERENCES `ports` (`datapath_id`, `port_no`) ON DELETE CASCADE ON UPDATE CASCADE;

ALTER TABLE `services`
  ADD CONSTRAINT `services_ibfk_3` FOREIGN KEY (`dst_dpid`, `dst_portno`)
    REFERENCES `ports` (`datapath_id`, `port_no`) ON DELETE CASCADE ON UPDATE CASCADE;

--
-- Trigger for table `datapaths` + `services` + `requests`
--
delimiter |

CREATE TRIGGER `after_datapath_delete` AFTER DELETE ON `datapaths`
FOR EACH ROW BEGIN
    DELETE FROM services WHERE services.src_dpid=OLD.id OR services.dst_dpid=OLD.id;
END;

CREATE TRIGGER `after_service_delete` AFTER DELETE ON `services`
FOR EACH ROW BEGIN
    DELETE FROM requests WHERE requests.serviceID=OLD.serviceID;
END;

CREATE TRIGGER `after_request_delete` AFTER DELETE ON `requests`
FOR EACH ROW BEGIN
    DELETE FROM services WHERE services.serviceID=OLD.serviceID;
END;

CREATE TRIGGER `after_host_delete` AFTER DELETE ON `hosts`
FOR EACH ROW BEGIN
    DELETE FROM requests WHERE requests.ip_src=OLD.ip_addr OR requests.ip_dst=OLD.ip_addr;
END;
|

delimiter ;
