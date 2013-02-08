-- phpMyAdmin SQL Dump
-- version 3.4.11.1deb1
-- http://www.phpmyadmin.net
--
-- Host: localhost
-- Generato il: Feb 07, 2013 alle 16:04
-- Versione del server: 5.5.29
-- Versione PHP: 5.4.6-1ubuntu1.1

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
USE topology_ofc_db;
-- --------------------------------------------------------

--
-- Struttura della tabella `datapaths`
--
-- Creazione: Feb 07, 2013 alle 15:04
--

CREATE TABLE IF NOT EXISTS `datapaths` (
  `id` bigint(20) unsigned NOT NULL COMMENT 'datapath identifier',
  `name` varchar(20) COLLATE utf8_unicode_ci DEFAULT NULL COMMENT 'datapath name',
  `ofp_capabilities` int(11) unsigned DEFAULT NULL,
  `ofp_actions` int(11) unsigned DEFAULT NULL,
  `buffers` int(11) unsigned DEFAULT NULL COMMENT 'Max packets buffered at once',
  `tables` int(11) unsigned DEFAULT NULL COMMENT 'Number of tables supported by datapath',
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8 COLLATE=utf8_unicode_ci COMMENT='datapaths details';

-- --------------------------------------------------------

--
-- Struttura della tabella `ports`
--
-- Creazione: Feb 07, 2013 alle 13:47
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
  PRIMARY KEY (`datapath_id`,`port_no`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8 COLLATE=utf8_unicode_ci COMMENT='port details';

--
-- RELATIONS FOR TABLE `ports`:
--   `datapath_id`
--       `datapaths` -> `id`
--

--
-- Limiti per le tabelle scaricate
--

--
-- Limiti per la tabella `ports`
--
ALTER TABLE `ports`
  ADD CONSTRAINT `ports_ibfk_1` FOREIGN KEY (`datapath_id`) REFERENCES `datapaths` (`id`) ON DELETE CASCADE ON UPDATE CASCADE;

/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
