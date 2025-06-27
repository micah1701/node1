import mysql from 'mysql2/promise';
import dotenv from 'dotenv';
import { logger } from './logger';

dotenv.config();

// Create connection pool
export const pool = mysql.createPool({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0,
  acquireTimeout: 5000, // 5 second timeout
  timeout: 5000 // 5 second query timeout
});

// Track database connection status
let isDbConnected = false;

// Test database connection with proper error handling
export const testDatabaseConnection = async (): Promise<boolean> => {
  try {
    const connection = await pool.getConnection();
    logger.info('Successfully connected to MySQL database');
    connection.release();
    isDbConnected = true;
    return true;
  } catch (error) {
    logger.warn('Database connection failed:', error instanceof Error ? error.message : 'Unknown error');
    logger.warn('Server will continue without database connectivity');
    isDbConnected = false;
    return false;
  }
};

// Export database connection status
export const isDatabaseConnected = (): boolean => isDbConnected;

// Initialize connection test (non-blocking)
testDatabaseConnection().catch(() => {
  // Error already logged in testDatabaseConnection
});