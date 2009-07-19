ALTER TABLE urlalias ADD http_code CHAR( 3 ) NOT NULL DEFAULT '301' AFTER redirect_to;
ALTER TABLE urlalias ADD target VARCHAR( 100 ) NOT NULL DEFAULT '/' AFTER http_code ;
UPDATE urlalias SET target = (SELECT CONCAT_WS( '/', module, VIEW ) AS target);
ALTER TABLE urlalias DROP module, DROP view;