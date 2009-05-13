-- table schema for MySQL
CREATE TABLE urlalias (
	source varchar(200) NOT NULL,
	module varchar(30) CHARACTER SET ascii NOT NULL,
	view varchar(30) CHARACTER SET ascii NOT NULL,
	parameters varchar(200) CHARACTER SET ascii NOT NULL,
	useregex tinyint(1) NOT NULL DEFAULT '0',
	PRIMARY KEY (source)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;