-- table schema for MySQL
CREATE TABLE `urlalias` (
  `source` varchar(200) NOT NULL,
  `redirect_to` varchar(200) DEFAULT NULL,
  `http_code` char(3) NOT NULL DEFAULT '301',
  `target` varchar(100) NOT NULL DEFAULT '/',
  `parameters` varchar(200) CHARACTER SET ascii NOT NULL,
-- this flag makes it possible to define a URL alias as
-- a generic route. If so it will be treated like a regular
-- expression and will be applied to any incoming URI
  `generic_route` tinyint(1) NOT NULL DEFAULT '0',
-- the routes will be called in ascending order
-- a priority of 1 is the highest and a priotiry of 100 
-- is the lowest
-- it is only useful for the generic routes sytem
-- and will not be used for the standard URL alias mapping system
  `route_priority` tinyint(4) DEFAULT NULL,
  PRIMARY KEY (`source`),
  UNIQUE KEY `route_priority` (`route_priority`)
) ENGINE=MyISAM DEFAULT CHARSET=utf8;