LOAD DATA LOCAL INFILE 'tests/data/data.csv' REPLACE INTO TABLE `urlalias`
FIELDS TERMINATED BY ','
ENCLOSED BY '"'
ESCAPED BY '\\'
LINES TERMINATED BY '\n'