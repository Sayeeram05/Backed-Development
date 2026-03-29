-- Emergency Notifier Database Migration: Remove Phone Fields
-- This script removes all phone-related columns from the database

-- 1. Remove phone column from users table (check if exists first)
SET @exist := (SELECT count(*) FROM information_schema.COLUMNS WHERE TABLE_SCHEMA='emergency_notifier' AND TABLE_NAME='users' AND COLUMN_NAME='phone');
SET @sqlstmt := IF(@exist>0,'ALTER TABLE users DROP COLUMN phone','SELECT ''Column phone does not exist in users table''');
PREPARE stmt FROM @sqlstmt;
EXECUTE stmt;

-- 2. Remove contact_phone column from contacts table (check if exists first)
SET @exist := (SELECT count(*) FROM information_schema.COLUMNS WHERE TABLE_SCHEMA='emergency_notifier' AND TABLE_NAME='contacts' AND COLUMN_NAME='contact_phone');
SET @sqlstmt := IF(@exist>0,'ALTER TABLE contacts DROP COLUMN contact_phone','SELECT ''Column contact_phone does not exist in contacts table''');
PREPARE stmt FROM @sqlstmt;
EXECUTE stmt;

-- 3. Verify the updated table structures
DESCRIBE users;
DESCRIBE contacts;