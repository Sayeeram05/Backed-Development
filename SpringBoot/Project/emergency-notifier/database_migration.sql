-- Database Migration Script: Remove Phone Number Requirements
-- Execute this script to update the database schema

-- Step 1: Make contact_phone column nullable and contact_email not null
ALTER TABLE contacts MODIFY COLUMN contact_phone VARCHAR(15) NULL;
ALTER TABLE contacts MODIFY COLUMN contact_email VARCHAR(255) NOT NULL;

-- Step 2: Make user phone column nullable  
ALTER TABLE users MODIFY COLUMN phone VARCHAR(15) NULL;

-- Step 3: Clean up any existing data that doesn't have email
-- Update any contacts that don't have email addresses
UPDATE contacts SET contact_email = CONCAT(contact_name, '@example.com') 
WHERE contact_email IS NULL OR contact_email = '';

-- Step 4: Add indexes for better performance
CREATE INDEX idx_contacts_email ON contacts(contact_email);
CREATE INDEX idx_users_email ON users(email);

-- Verification queries
SELECT 'Users table structure:' as info;
DESCRIBE users;

SELECT 'Contacts table structure:' as info;
DESCRIBE contacts;

SELECT 'Sample data verification:' as info;
SELECT u.name, u.email, u.phone, c.contact_name, c.contact_email 
FROM users u 
LEFT JOIN contacts c ON u.id = c.user_id 
LIMIT 5;