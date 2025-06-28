import mysql from 'mysql2/promise';
import dotenv from 'dotenv';
import { logger } from './logger';

dotenv.config();

// Database configuration with explicit type conversion and defaults
const dbConfig = {
  host: process.env.DB_HOST || 'localhost',
  user: process.env.DB_USER || 'root',
  password: process.env.DB_PASSWORD || '',
  database: process.env.DB_NAME || '',
  port: parseInt(process.env.DB_PORT || '3306', 10),
  connectTimeout: 20000, // 20 seconds
  acquireTimeout: 20000, // 20 seconds
  timeout: 20000, // 20 seconds
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0,
  reconnect: true,
  charset: 'utf8mb4'
};

// Create connection pool
export const pool = mysql.createPool(dbConfig);

// Track database connection status
let isDbConnected = false;

// Helper function to safely log connection info (without password)
const getConnectionInfo = () => {
  return {
    host: dbConfig.host,
    user: dbConfig.user,
    database: dbConfig.database,
    port: dbConfig.port,
    hasPassword: !!dbConfig.password,
    passwordLength: dbConfig.password ? dbConfig.password.length : 0
  };
};

// Test database connection with detailed error logging
export const testDatabaseConnection = async (): Promise<boolean> => {
  const connectionInfo = getConnectionInfo();
  
  try {
    logger.info('Attempting database connection with config:', connectionInfo);
    
    // Log environment variables (safely)
    logger.info('Environment variables check:', {
      DB_HOST: process.env.DB_HOST ? 'SET' : 'NOT SET',
      DB_USER: process.env.DB_USER ? 'SET' : 'NOT SET', 
      DB_PASSWORD: process.env.DB_PASSWORD ? 'SET' : 'NOT SET',
      DB_NAME: process.env.DB_NAME ? 'SET' : 'NOT SET',
      DB_PORT: process.env.DB_PORT ? process.env.DB_PORT : 'NOT SET (using default 3306)'
    });
    
    // Test with a simple connection first
    logger.info('Creating test connection...');
    const connection = await pool.getConnection();
    
    logger.info('Connection established, testing query...');
    const [rows] = await connection.execute('SELECT 1 as test');
    logger.info('Test query successful:', rows);
    
    connection.release();
    logger.info('Successfully connected to MySQL database');
    isDbConnected = true;
    return true;
  } catch (error: any) {
    isDbConnected = false;
    
    // Log detailed connection attempt info
    logger.error('Database connection failed');
    logger.error('Connection attempted with:', connectionInfo);
    
    // Log specific error details
    if (error) {
      logger.error('Error details:', {
        message: error.message || 'No error message',
        code: error.code || 'No error code',
        errno: error.errno || 'No errno',
        syscall: error.syscall || 'No syscall',
        fatal: error.fatal || false,
        sqlState: error.sqlState || 'No SQL state',
        sqlMessage: error.sqlMessage || 'No SQL message'
      });
      
      // Provide helpful error interpretation
      if (error.code === 'ETIMEDOUT') {
        logger.error('Connection timed out - check if database server is running and accessible');
        logger.error('Possible causes:');
        logger.error('- Database server is not running');
        logger.error('- Firewall blocking connection');
        logger.error('- Wrong host/port configuration');
        logger.error('- Network connectivity issues');
      } else if (error.code === 'ECONNREFUSED') {
        logger.error('Connection refused - database server may not be running on the specified host/port');
      } else if (error.code === 'ER_ACCESS_DENIED_ERROR') {
        logger.error('Access denied - check username and password');
      } else if (error.code === 'ER_BAD_DB_ERROR') {
        logger.error('Database does not exist - check database name');
      } else if (error.code === 'ENOTFOUND') {
        logger.error('Host not found - check if the hostname is correct');
      }
      
      // Log the full stack trace for debugging
      if (error.stack) {
        logger.error('Full error stack:', error.stack);
      }
    }
    
    logger.warn('Server will continue without database connectivity');
    return false;
  }
};

// Alternative connection test using direct mysql connection (not pool)
export const testDirectConnection = async (): Promise<boolean> => {
  const connectionInfo = getConnectionInfo();
  
  try {
    logger.info('Testing direct MySQL connection (not pool)...');
    
    const connection = await mysql.createConnection({
      host: dbConfig.host,
      user: dbConfig.user,
      password: dbConfig.password,
      database: dbConfig.database,
      port: dbConfig.port,
      connectTimeout: 10000
    });
    
    logger.info('Direct connection successful');
    await connection.end();
    return true;
  } catch (error: any) {
    logger.error('Direct connection also failed:', {
      message: error.message,
      code: error.code
    });
    return false;
  }
};

// Export database connection status
export const isDatabaseConnected = (): boolean => isDbConnected;

// Initialize connection test (non-blocking)
testDatabaseConnection()
  .then(async (success) => {
    if (!success) {
      logger.info('Attempting direct connection test...');
      await testDirectConnection();
    }
  })
  .catch(() => {
    // Error already logged in testDatabaseConnection
  });