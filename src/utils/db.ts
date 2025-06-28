import mysql from 'mysql2/promise';
import dotenv from 'dotenv';
import { logger } from './logger';

dotenv.config();

// Database configuration
const dbConfig = {
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  port:3306,
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0
};

// Create connection pool
export const pool = mysql.createPool(dbConfig);

// Track database connection status
let isDbConnected = false;

// Helper function to safely log connection info (without password)
const getConnectionInfo = () => {
  return {
    host: dbConfig.host || 'undefined',
    user: dbConfig.user || 'undefined',
    database: dbConfig.database || 'undefined',
    port: dbConfig.port || 3306
  };
};

// Test database connection with detailed error logging
export const testDatabaseConnection = async (): Promise<boolean> => {
  const connectionInfo = getConnectionInfo();
  
  try {
    logger.info('Attempting database connection with config:', connectionInfo);
    
    const connection = await pool.getConnection();
    logger.info('Successfully connected to MySQL database');
    connection.release();
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
        stack: error.stack || 'No stack trace'
      });
      
      // Provide helpful error interpretation
      if (error.code === 'ETIMEDOUT') {
        logger.error('Connection timed out - check if database server is running and accessible');
      } else if (error.code === 'ECONNREFUSED') {
        logger.error('Connection refused - database server may not be running on the specified host/port');
      } else if (error.code === 'ER_ACCESS_DENIED_ERROR') {
        logger.error('Access denied - check username and password');
      } else if (error.code === 'ER_BAD_DB_ERROR') {
        logger.error('Database does not exist - check database name');
      }
    }
    
    logger.warn('Server will continue without database connectivity');
    return false;
  }
};

// Export database connection status
export const isDatabaseConnected = (): boolean => isDbConnected;

// Initialize connection test (non-blocking)
testDatabaseConnection().catch(() => {
  // Error already logged in testDatabaseConnection
});