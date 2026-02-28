import mysql from 'mysql2/promise';
import { createClient } from '@supabase/supabase-js';
import dotenv from 'dotenv';
import { logger } from '../utils/logger';
import { config } from '../config';

dotenv.config();

// MySQL table creation queries
const createUsersTableMySQL = (tableName: string) => `
CREATE TABLE IF NOT EXISTS ${tableName} (
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

const createKeyValuesTableMySQL = (tableName: string) => `
CREATE TABLE IF NOT EXISTS ${tableName} (
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

const createKeychainAppsTableMySQL = (tableName: string) => `
CREATE TABLE IF NOT EXISTS ${tableName} (
  id INT AUTO_INCREMENT PRIMARY KEY,
  account_id VARCHAR(255) NOT NULL,
  account_secret VARCHAR(255) NOT NULL,
  app_name VARCHAR(255) NOT NULL,
  active BOOLEAN DEFAULT TRUE,
  encrypt_type ENUM('default', 'passphrase', 'public_key') DEFAULT 'default',
  encrypt_public_key INT NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  modified_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  UNIQUE KEY unique_account (account_id),
  INDEX idx_account_id (account_id),
  INDEX idx_active (active)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
`;

const createKeychainAppPublicKeysTableMySQL = (tableName: string) => `
CREATE TABLE IF NOT EXISTS ${tableName} (
  id INT AUTO_INCREMENT PRIMARY KEY,
  status ENUM('active', 'previous_key', 'deleted') DEFAULT 'active',
  app_id INT NOT NULL,
  key_name VARCHAR(255) NOT NULL,
  \`key\` TEXT NOT NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  modified_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  INDEX idx_app_id (app_id),
  INDEX idx_status (status)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
`;

const createKeychainAppPrivateKeysTableMySQL = (tableName: string) => `
CREATE TABLE IF NOT EXISTS ${tableName} (
  id INT AUTO_INCREMENT PRIMARY KEY,
  app_id INT NOT NULL,
  retrieval_id VARCHAR(255) NOT NULL,
  private_key TEXT NOT NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  modified_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  INDEX idx_app_id (app_id),
  INDEX idx_retrieval_id (retrieval_id),
  UNIQUE KEY unique_app_retrieval (app_id, retrieval_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
`;

const createUserKeychainAppsTableMySQL = (tableName: string) => `
CREATE TABLE IF NOT EXISTS ${tableName} (
  id INT AUTO_INCREMENT PRIMARY KEY,
  user_id INT NOT NULL,
  keychain_app_id INT NOT NULL,
  role ENUM('owner', 'admin', 'viewer') DEFAULT 'owner',
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  modified_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  UNIQUE KEY unique_user_app (user_id, keychain_app_id),
  INDEX idx_user_id (user_id),
  INDEX idx_keychain_app_id (keychain_app_id),
  INDEX idx_role (role)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
`;

const createApiRequestLogsTableMySQL = (tableName: string) => `
CREATE TABLE IF NOT EXISTS ${tableName} (
  id INT AUTO_INCREMENT PRIMARY KEY,
  request_uuid VARCHAR(36) NOT NULL UNIQUE,
  user_id INT NULL,
  method VARCHAR(10) NOT NULL,
  url VARCHAR(2048) NOT NULL,
  status_code INT NULL,
  encrypted_headers TEXT NOT NULL,
  encrypted_request_body TEXT NULL,
  encrypted_response_body TEXT NULL,
  ip_address VARCHAR(45) NOT NULL,
  user_agent TEXT NULL,
  response_time_ms INT NULL,
  error_message TEXT NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  INDEX idx_request_uuid (request_uuid),
  INDEX idx_user_id (user_id),
  INDEX idx_method (method),
  INDEX idx_status_code (status_code),
  INDEX idx_created_at (created_at),
  INDEX idx_ip_address (ip_address)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
`;

// PostgreSQL table creation queries
const createUsersTablePostgreSQL = (tableName: string) => `
CREATE TABLE IF NOT EXISTS ${tableName} (
  id SERIAL PRIMARY KEY,
  api_user VARCHAR(255) NOT NULL UNIQUE,
  api_secret VARCHAR(255) NOT NULL,
  full_name VARCHAR(255) NOT NULL,
  email VARCHAR(255) NOT NULL UNIQUE,
  total_logins INTEGER DEFAULT 0,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  modified_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Create trigger for modified_at update
CREATE OR REPLACE FUNCTION update_modified_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.modified_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ language 'plpgsql';

DROP TRIGGER IF EXISTS update_${tableName}_modified_at ON ${tableName};
CREATE TRIGGER update_${tableName}_modified_at
    BEFORE UPDATE ON ${tableName}
    FOR EACH ROW
    EXECUTE FUNCTION update_modified_at_column();
`;

const createKeyValuesTablePostgreSQL = (tableName: string) => `
CREATE TABLE IF NOT EXISTS ${tableName} (
  id SERIAL PRIMARY KEY,
  uuid VARCHAR(36) NOT NULL UNIQUE,
  key_name VARCHAR(255) NOT NULL,
  encrypted_value TEXT NOT NULL,
  retrieved INTEGER DEFAULT 0,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  modified_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_${tableName}_uuid ON ${tableName} (uuid);

DROP TRIGGER IF EXISTS update_${tableName}_modified_at ON ${tableName};
CREATE TRIGGER update_${tableName}_modified_at
    BEFORE UPDATE ON ${tableName}
    FOR EACH ROW
    EXECUTE FUNCTION update_modified_at_column();
`;

const createKeychainAppsTablePostgreSQL = (tableName: string) => `
DO $$ BEGIN
    CREATE TYPE encrypt_type_enum AS ENUM ('default', 'passphrase', 'public_key');
EXCEPTION
    WHEN duplicate_object THEN null;
END $$;

CREATE TABLE IF NOT EXISTS ${tableName} (
  id SERIAL PRIMARY KEY,
  account_id VARCHAR(255) NOT NULL,
  account_secret VARCHAR(255) NOT NULL,
  app_name VARCHAR(255) NOT NULL,
  active BOOLEAN DEFAULT TRUE,
  encrypt_type encrypt_type_enum DEFAULT 'default',
  encrypt_public_key INTEGER NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  modified_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT unique_account_${tableName} UNIQUE (account_id)
);

CREATE INDEX IF NOT EXISTS idx_${tableName}_account_id ON ${tableName} (account_id);
CREATE INDEX IF NOT EXISTS idx_${tableName}_active ON ${tableName} (active);

DROP TRIGGER IF EXISTS update_${tableName}_modified_at ON ${tableName};
CREATE TRIGGER update_${tableName}_modified_at
    BEFORE UPDATE ON ${tableName}
    FOR EACH ROW
    EXECUTE FUNCTION update_modified_at_column();
`;

const createKeychainAppPublicKeysTablePostgreSQL = (tableName: string) => `
DO $$ BEGIN
    CREATE TYPE key_status_enum AS ENUM ('active', 'previous_key', 'deleted');
EXCEPTION
    WHEN duplicate_object THEN null;
END $$;

CREATE TABLE IF NOT EXISTS ${tableName} (
  id SERIAL PRIMARY KEY,
  status key_status_enum DEFAULT 'active',
  app_id INTEGER NOT NULL,
  key_name VARCHAR(255) NOT NULL,
  key TEXT NOT NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  modified_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_${tableName}_app_id ON ${tableName} (app_id);
CREATE INDEX IF NOT EXISTS idx_${tableName}_status ON ${tableName} (status);

DROP TRIGGER IF EXISTS update_${tableName}_modified_at ON ${tableName};
CREATE TRIGGER update_${tableName}_modified_at
    BEFORE UPDATE ON ${tableName}
    FOR EACH ROW
    EXECUTE FUNCTION update_modified_at_column();
`;

const createKeychainAppPrivateKeysTablePostgreSQL = (tableName: string) => `
CREATE TABLE IF NOT EXISTS ${tableName} (
  id SERIAL PRIMARY KEY,
  app_id INTEGER NOT NULL,
  retrieval_id VARCHAR(255) NOT NULL,
  private_key TEXT NOT NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  modified_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT unique_app_retrieval_${tableName} UNIQUE (app_id, retrieval_id)
);

CREATE INDEX IF NOT EXISTS idx_${tableName}_app_id ON ${tableName} (app_id);
CREATE INDEX IF NOT EXISTS idx_${tableName}_retrieval_id ON ${tableName} (retrieval_id);

DROP TRIGGER IF EXISTS update_${tableName}_modified_at ON ${tableName};
CREATE TRIGGER update_${tableName}_modified_at
    BEFORE UPDATE ON ${tableName}
    FOR EACH ROW
    EXECUTE FUNCTION update_modified_at_column();
`;

const createUserKeychainAppsTablePostgreSQL = (tableName: string) => `
DO $$ BEGIN
    CREATE TYPE user_app_role_enum AS ENUM ('owner', 'admin', 'viewer');
EXCEPTION
    WHEN duplicate_object THEN null;
END $$;

CREATE TABLE IF NOT EXISTS ${tableName} (
  id SERIAL PRIMARY KEY,
  user_id INTEGER NOT NULL,
  keychain_app_id INTEGER NOT NULL,
  role user_app_role_enum DEFAULT 'owner',
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  modified_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT unique_user_app_${tableName} UNIQUE (user_id, keychain_app_id)
);

CREATE INDEX IF NOT EXISTS idx_${tableName}_user_id ON ${tableName} (user_id);
CREATE INDEX IF NOT EXISTS idx_${tableName}_keychain_app_id ON ${tableName} (keychain_app_id);
CREATE INDEX IF NOT EXISTS idx_${tableName}_role ON ${tableName} (role);

DROP TRIGGER IF EXISTS update_${tableName}_modified_at ON ${tableName};
CREATE TRIGGER update_${tableName}_modified_at
    BEFORE UPDATE ON ${tableName}
    FOR EACH ROW
    EXECUTE FUNCTION update_modified_at_column();
`;

const createApiRequestLogsTablePostgreSQL = (tableName: string) => `
CREATE TABLE IF NOT EXISTS ${tableName} (
  id SERIAL PRIMARY KEY,
  request_uuid VARCHAR(36) NOT NULL UNIQUE,
  user_id INTEGER NULL,
  method VARCHAR(10) NOT NULL,
  url VARCHAR(2048) NOT NULL,
  status_code INTEGER NULL,
  encrypted_headers TEXT NOT NULL,
  encrypted_request_body TEXT NULL,
  encrypted_response_body TEXT NULL,
  ip_address VARCHAR(45) NOT NULL,
  user_agent TEXT NULL,
  response_time_ms INTEGER NULL,
  error_message TEXT NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_${tableName}_request_uuid ON ${tableName} (request_uuid);
CREATE INDEX IF NOT EXISTS idx_${tableName}_user_id ON ${tableName} (user_id);
CREATE INDEX IF NOT EXISTS idx_${tableName}_method ON ${tableName} (method);
CREATE INDEX IF NOT EXISTS idx_${tableName}_status_code ON ${tableName} (status_code);
CREATE INDEX IF NOT EXISTS idx_${tableName}_created_at ON ${tableName} (created_at);
CREATE INDEX IF NOT EXISTS idx_${tableName}_ip_address ON ${tableName} (ip_address);
`;

async function setupMySQLDatabase() {
  try {
    const connection = await mysql.createConnection({
      host: process.env.DB_HOST,
      user: process.env.DB_USER,
      password: process.env.DB_PASSWORD,
      database: process.env.DB_NAME,
      port: parseInt(process.env.DB_PORT || '3306')
    });

    logger.info('Connected to MySQL database');

    const tablePrefix = config.database.tablePrefix;

    // Create core tables
    await connection.execute(createUsersTableMySQL(`${tablePrefix}users`));
    logger.info('Users table created successfully');

    await connection.execute(createKeyValuesTableMySQL(`${tablePrefix}key_values`));
    logger.info('Key-values table created successfully');

    // Create keychain tables
    await connection.execute(createKeychainAppsTableMySQL(`${tablePrefix}keychain_apps`));
    logger.info('Keychain apps table created successfully');

    await connection.execute(createKeychainAppPublicKeysTableMySQL(`${tablePrefix}keychain_app_public_keys`));
    logger.info('Keychain app public keys table created successfully');

    await connection.execute(createKeychainAppPrivateKeysTableMySQL(`${tablePrefix}keychain_app_private_keys`));
    logger.info('Keychain app private keys table created successfully');

    // Create user-keychain apps lookup table
    await connection.execute(createUserKeychainAppsTableMySQL(`${tablePrefix}user_keychain_apps`));
    logger.info('User keychain apps lookup table created successfully');

    // Create API request logs table
    await connection.execute(createApiRequestLogsTableMySQL(`${tablePrefix}api_request_logs`));
    logger.info('API request logs table created successfully');

    // Add foreign key constraints
    await connection.execute(`
      ALTER TABLE ${tablePrefix}keychain_app_public_keys 
      ADD CONSTRAINT fk_public_keys_app_id 
      FOREIGN KEY (app_id) REFERENCES ${tablePrefix}keychain_apps(id) 
      ON DELETE CASCADE;
    `).catch(() => {
      // Constraint might already exist
      logger.info('Foreign key constraint for public keys already exists or failed to create');
    });

    await connection.execute(`
      ALTER TABLE ${tablePrefix}keychain_app_private_keys 
      ADD CONSTRAINT fk_private_keys_app_id 
      FOREIGN KEY (app_id) REFERENCES ${tablePrefix}keychain_apps(id) 
      ON DELETE CASCADE;
    `).catch(() => {
      // Constraint might already exist
      logger.info('Foreign key constraint for private keys already exists or failed to create');
    });

    await connection.execute(`
      ALTER TABLE ${tablePrefix}keychain_apps 
      ADD CONSTRAINT fk_apps_encrypt_public_key 
      FOREIGN KEY (encrypt_public_key) REFERENCES ${tablePrefix}keychain_app_public_keys(id) 
      ON DELETE SET NULL;
    `).catch(() => {
      // Constraint might already exist
      logger.info('Foreign key constraint for encrypt public key already exists or failed to create');
    });

    // Add foreign key constraints for user-keychain apps lookup table
    await connection.execute(`
      ALTER TABLE ${tablePrefix}user_keychain_apps 
      ADD CONSTRAINT fk_user_keychain_apps_user_id 
      FOREIGN KEY (user_id) REFERENCES ${tablePrefix}users(id) 
      ON DELETE CASCADE;
    `).catch(() => {
      // Constraint might already exist
      logger.info('Foreign key constraint for user_keychain_apps user_id already exists or failed to create');
    });

    await connection.execute(`
      ALTER TABLE ${tablePrefix}user_keychain_apps 
      ADD CONSTRAINT fk_user_keychain_apps_keychain_app_id 
      FOREIGN KEY (keychain_app_id) REFERENCES ${tablePrefix}keychain_apps(id) 
      ON DELETE CASCADE;
    `).catch(() => {
      // Constraint might already exist
      logger.info('Foreign key constraint for user_keychain_apps keychain_app_id already exists or failed to create');
    });

    // Add foreign key constraint for API request logs
    await connection.execute(`
      ALTER TABLE ${tablePrefix}api_request_logs 
      ADD CONSTRAINT fk_api_request_logs_user_id 
      FOREIGN KEY (user_id) REFERENCES ${tablePrefix}users(id) 
      ON DELETE SET NULL;
    `).catch(() => {
      // Constraint might already exist
      logger.info('Foreign key constraint for api_request_logs user_id already exists or failed to create');
    });

    await connection.end();
    logger.info('MySQL database setup completed');
  } catch (error) {
    logger.error('Error setting up MySQL database:', error);
    throw error;
  }
}

function generateSupabaseSQL() {
  const tablePrefix = config.database.tablePrefix;
  
  const allQueries = [
    createUsersTablePostgreSQL(`${tablePrefix}users`),
    createKeyValuesTablePostgreSQL(`${tablePrefix}key_values`),
    createKeychainAppsTablePostgreSQL(`${tablePrefix}keychain_apps`),
    createKeychainAppPublicKeysTablePostgreSQL(`${tablePrefix}keychain_app_public_keys`),
    createKeychainAppPrivateKeysTablePostgreSQL(`${tablePrefix}keychain_app_private_keys`),
    createUserKeychainAppsTablePostgreSQL(`${tablePrefix}user_keychain_apps`),
    createApiRequestLogsTablePostgreSQL(`${tablePrefix}api_request_logs`)
  ];

  const constraintQueries = [
    `ALTER TABLE ${tablePrefix}keychain_app_public_keys 
     ADD CONSTRAINT fk_public_keys_app_id 
     FOREIGN KEY (app_id) REFERENCES ${tablePrefix}keychain_apps(id) 
     ON DELETE CASCADE;`,
    
    `ALTER TABLE ${tablePrefix}keychain_app_private_keys 
     ADD CONSTRAINT fk_private_keys_app_id 
     FOREIGN KEY (app_id) REFERENCES ${tablePrefix}keychain_apps(id) 
     ON DELETE CASCADE;`,
    
    `ALTER TABLE ${tablePrefix}keychain_apps 
     ADD CONSTRAINT fk_apps_encrypt_public_key 
     FOREIGN KEY (encrypt_public_key) REFERENCES ${tablePrefix}keychain_app_public_keys(id) 
     ON DELETE SET NULL;`,

    `ALTER TABLE ${tablePrefix}user_keychain_apps 
     ADD CONSTRAINT fk_user_keychain_apps_user_id 
     FOREIGN KEY (user_id) REFERENCES ${tablePrefix}users(id) 
     ON DELETE CASCADE;`,

    `ALTER TABLE ${tablePrefix}user_keychain_apps 
     ADD CONSTRAINT fk_user_keychain_apps_keychain_app_id 
     FOREIGN KEY (keychain_app_id) REFERENCES ${tablePrefix}keychain_apps(id) 
     ON DELETE CASCADE;`,

    `ALTER TABLE ${tablePrefix}api_request_logs 
     ADD CONSTRAINT fk_api_request_logs_user_id 
     FOREIGN KEY (user_id) REFERENCES ${tablePrefix}users(id) 
     ON DELETE SET NULL;`
  ];

  return [...allQueries, ...constraintQueries].join('\n\n');
}

async function setupSupabaseDatabase() {
  try {
    if (!process.env.SUPABASE_URL || !process.env.SUPABASE_PUBLISHABLE_KEY) {
      throw new Error('Supabase configuration missing');
    }

    logger.info('='.repeat(80));
    logger.info('SUPABASE DATABASE SETUP REQUIRED');
    logger.info('='.repeat(80));
    logger.info('');
    logger.info('Supabase does not allow programmatic table creation through the API.');
    logger.info('You need to manually create the database tables using the Supabase SQL Editor.');
    logger.info('');
    logger.info('Please follow these steps:');
    logger.info('');
    logger.info('1. Go to your Supabase project dashboard');
    logger.info('2. Navigate to the SQL Editor');
    logger.info('3. Copy and paste the following SQL commands:');
    logger.info('');
    logger.info('-'.repeat(80));
    logger.info('SQL COMMANDS TO EXECUTE:');
    logger.info('-'.repeat(80));
    logger.info('');
    
    const sqlCommands = generateSupabaseSQL();
    console.log(sqlCommands);
    
    logger.info('');
    logger.info('-'.repeat(80));
    logger.info('');
    logger.info('4. Execute the SQL commands in the Supabase SQL Editor');
    logger.info('5. Verify that all tables have been created successfully');
    logger.info('');
    logger.info('After completing these steps, your Supabase database will be ready to use.');
    logger.info('='.repeat(80));

    // Test connection to verify Supabase is accessible
    const supabase = createClient(
      process.env.SUPABASE_URL,
      process.env.SUPABASE_PUBLISHABLE_KEY
    );

    // Simple connection test
    const { error } = await supabase.from('information_schema.tables').select('table_name').limit(1);
    if (error && !error.message.includes('relation "information_schema.tables" does not exist')) {
      logger.error('Supabase connection test failed:', error);
      throw error;
    }

    logger.info('Supabase connection verified successfully');
  } catch (error) {
    logger.error('Error with Supabase setup:', error);
    throw error;
  }
}

async function setupDatabase() {
  try {
    if (config.database.type === 'mysql') {
      await setupMySQLDatabase();
    } else if (config.database.type === 'postgres') {
      await setupSupabaseDatabase();
    } else {
      throw new Error(`Unsupported database type: ${config.database.type}`);
    }
    
    logger.info('Database setup process completed successfully');
  } catch (error) {
    logger.error('Error setting up database:', error);
    process.exit(1);
  }
}

setupDatabase();