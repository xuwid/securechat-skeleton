#!/bin/bash
# MySQL Database Setup Script

echo "═══════════════════════════════════════════════════════════"
echo "  Secure Chat - MySQL Database Setup"
echo "═══════════════════════════════════════════════════════════"

# Database configuration
DB_NAME="securechat"
DB_USER="scuser"
DB_PASS="scpass123"
DB_HOST="localhost"

echo ""
echo "This script will:"
echo "1. Create database: $DB_NAME"
echo "2. Create user: $DB_USER"
echo "3. Grant privileges"
echo ""
echo "You will need to enter your MySQL root password."
echo ""
read -p "Press Enter to continue or Ctrl+C to cancel..."

# Create database and user
mysql -u root -p <<MYSQL_SCRIPT
-- Create database
CREATE DATABASE IF NOT EXISTS $DB_NAME CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- Create user
CREATE USER IF NOT EXISTS '$DB_USER'@'$DB_HOST' IDENTIFIED BY '$DB_PASS';

-- Grant privileges
GRANT ALL PRIVILEGES ON $DB_NAME.* TO '$DB_USER'@'$DB_HOST';

-- Flush privileges
FLUSH PRIVILEGES;

-- Show databases
SHOW DATABASES;

-- Use the database
USE $DB_NAME;

-- Create users table
CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    email VARCHAR(255) UNIQUE NOT NULL,
    username VARCHAR(255) UNIQUE NOT NULL,
    salt VARBINARY(16) NOT NULL,
    pwd_hash CHAR(64) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_email (email),
    INDEX idx_username (username)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Show tables
SHOW TABLES;

-- Describe users table
DESCRIBE users;
MYSQL_SCRIPT

if [ $? -eq 0 ]; then
    echo ""
    echo "═══════════════════════════════════════════════════════════"
    echo "✓ Database setup completed successfully!"
    echo "═══════════════════════════════════════════════════════════"
    echo ""
    echo "Database credentials:"
    echo "  Host: $DB_HOST"
    echo "  Database: $DB_NAME"
    echo "  User: $DB_USER"
    echo "  Password: $DB_PASS"
    echo ""
    echo "These are already configured in your .env file."
else
    echo ""
    echo "✗ Database setup failed. Please check your MySQL configuration."
fi
