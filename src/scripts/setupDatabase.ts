import mysql from 'mysql2/promise';
import dotenv from 'dotenv';
import { logger } from '../utils/logger';
import { config } from '../config';

dotenv.config();

const createUsersTableMySQL = `
CREATE TABLE IF NOT EXISTS users (
  id INT AUTO_INCREMENT PRIMARY KEY,
  api_user VARCHAR(255) NOT NULL UNIQUE,
  api_secret VARCHAR(255) NOT NULL,
  full_name VARCHAR(255) NOT NULL,
  email VARCHAR(255) NOT NULL UNIQUE,
  total_logins INT DEFAULT 0,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  modified_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
`;

const createKeyValuesTable = `
CREATE TABLE IF NOT EXISTS key_values (
  id INT AUTO_INCREMENT PRIMARY KEY,
  uuid VARCHAR(36) NOT NULL UNIQUE,
  key_name VARCHAR(255) NOT NULL,
  encrypted_value TEXT NOT NULL,
  retrieved INT DEFAULT 0,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  modified_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  INDEX idx_uuid (uuid)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
`;

async function setupMySQLDatabase() {
  try {
    const connection = await mysql.createConnection({
      host: config.database.mysql.host,
      user: config.database.mysql.user,
      password: config.database.mysql.password,
      database: config.database.mysql.database
    });

    logger.info('Connected to MySQL database');

    // Create users table
    await connection.execute(createUsersTableMySQL);
    logger.info('MySQL users table created successfully');

    // Create key_values table
    await connection.execute(createKeyValuesTable);
    logger.info('MySQL key-values table created successfully');

    await connection.end();
    logger.info('MySQL database setup completed');
  } catch (error) {
    logger.error('Error setting up MySQL database:', error);
    process.exit(1);
  }
}

async function setupSupabaseDatabase() {
  logger.info('For Supabase setup, please ensure the following tables exist:');
  logger.info('');
  logger.info('1. Table: node1_users');
  logger.info('   Columns:');
  logger.info('   - id (bigint, primary key, auto-increment)');
  logger.info('   - api_user (text, unique)');
  logger.info('   - api_secret (text)');
  logger.info('   - full_name (text)');
  logger.info('   - email (text, unique)');
  logger.info('   - total_logins (integer, default 0)');
  logger.info('   - created_at (timestamp with time zone, default now())');
  logger.info('   - modified_at (timestamp with time zone, default now())');
  logger.info('');
  logger.info('2. Table: key_values');
  logger.info('   Columns:');
  logger.info('   - id (bigint, primary key, auto-increment)');
  logger.info('   - uuid (text, unique)');
  logger.info('   - key_name (text)');
  logger.info('   - encrypted_value (text)');
  logger.info('   - retrieved (integer, default 0)');
  logger.info('   - created_at (timestamp with time zone, default now())');
  logger.info('   - modified_at (timestamp with time zone, default now())');
  logger.info('');
  logger.info('You can create these tables in the Supabase dashboard SQL editor.');
  logger.info('');
  logger.info('SQL for node1_users table:');
  logger.info(`
CREATE TABLE IF NOT EXISTS node1_users (
  id BIGSERIAL PRIMARY KEY,
  api_user TEXT UNIQUE NOT NULL,
  api_secret TEXT NOT NULL,
  full_name TEXT NOT NULL,
  email TEXT UNIQUE NOT NULL,
  total_logins INTEGER DEFAULT 0,
  created_at TIMESTAMPTZ DEFAULT NOW(),
  modified_at TIMESTAMPTZ DEFAULT NOW()
);

-- Create updated_at trigger
CREATE OR REPLACE FUNCTION update_modified_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.modified_at = NOW();
    RETURN NEW;
END;
$$ language 'plpgsql';

CREATE TRIGGER update_node1_users_modified_at BEFORE UPDATE
    ON node1_users FOR EACH ROW EXECUTE FUNCTION update_modified_at_column();
  `);
  
  logger.info('');
  logger.info('SQL for key_values table:');
  logger.info(`
CREATE TABLE IF NOT EXISTS key_values (
  id BIGSERIAL PRIMARY KEY,
  uuid TEXT UNIQUE NOT NULL,
  key_name TEXT NOT NULL,
  encrypted_value TEXT NOT NULL,
  retrieved INTEGER DEFAULT 0,
  created_at TIMESTAMPTZ DEFAULT NOW(),
  modified_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_key_values_uuid ON key_values(uuid);

CREATE TRIGGER update_key_values_modified_at BEFORE UPDATE
    ON key_values FOR EACH ROW EXECUTE FUNCTION update_modified_at_column();
  `);
}

async function setupDatabase() {
  if (config.database.type === 'mysql') {
    logger.info('Setting up MySQL database...');
    await setupMySQLDatabase();
  } else if (config.database.type === 'postgres') {
    logger.info('Setting up Supabase (PostgreSQL) database...');
    await setupSupabaseDatabase();
  } else {
    logger.error(`Unsupported database type: ${config.database.type}`);
    process.exit(1);
  }
}

setupDatabase();