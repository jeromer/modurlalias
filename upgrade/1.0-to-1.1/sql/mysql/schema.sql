ALTER TABLE urlalias ADD http_code CHAR( 3 ) NOT NULL DEFAULT '301' AFTER redirect_to;