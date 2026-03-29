-- Emergency Contact Notifier Database Schema
-- This script creates the database and tables required for the Emergency Contact Notifier application

-- Create database (if using this script in MySQL Workbench or similar tool)
CREATE DATABASE IF NOT EXISTS emergency_notifier;
USE emergency_notifier;

-- Users table
CREATE TABLE IF NOT EXISTS users (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    email VARCHAR(255) NOT NULL UNIQUE,
    phone VARCHAR(15) NOT NULL,
    password VARCHAR(255) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);

-- Contacts table
CREATE TABLE IF NOT EXISTS contacts (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    user_id BIGINT NOT NULL,
    contact_name VARCHAR(100) NOT NULL,
    contact_phone VARCHAR(15) NOT NULL,
    contact_email VARCHAR(255),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Create indexes for better performance
CREATE INDEX idx_users_email ON users(email);
CREATE INDEX idx_users_phone ON users(phone);
CREATE INDEX idx_contacts_user_id ON contacts(user_id);
CREATE INDEX idx_contacts_phone ON contacts(contact_phone);
CREATE INDEX idx_contacts_email ON contacts(contact_email);

-- Insert sample data for testing (optional)
-- You can uncomment these lines to insert test data

/*
INSERT INTO users (name, email, phone, password) VALUES 
('John Doe', 'john.doe@example.com', '+1234567890', 'password123'),
('Jane Smith', 'jane.smith@example.com', '+0987654321', 'password456');

INSERT INTO contacts (user_id, contact_name, contact_phone, contact_email) VALUES 
(1, 'Emergency Contact 1', '+1111111111', 'emergency1@example.com'),
(1, 'Emergency Contact 2', '+2222222222', 'emergency2@example.com'),
(2, 'Family Member', '+3333333333', 'family@example.com'),
(2, 'Close Friend', '+4444444444', 'friend@example.com');
*/