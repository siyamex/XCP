-- PHP version per account (ADM-WEB-04, USR-WEB-01). '' = the server default
-- (the newest installed PHP-FPM).
ALTER TABLE accounts ADD COLUMN php_version TEXT NOT NULL DEFAULT '';
