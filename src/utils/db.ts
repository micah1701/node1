import mysql from 'mysql2/promise';
import { createClient } from '@supabase/supabase-js';
import dotenv from 'dotenv';
import { logger } from './logger';
import { config } from '../config';

dotenv.config();

// Database abstraction interface
export interface DatabaseAdapter {
  query(sql: string, params?: any[]): Promise<any>;
  execute(sql: string, params?: any[]): Promise<any>;
  close(): Promise<void>;
  isConnected(): boolean;
  getTableName(baseName: string): string;
}

// MySQL adapter
class MySQLAdapter implements DatabaseAdapter {
  private pool: mysql.Pool;
  private connected: boolean = false;

  constructor() {
    const dbConfig = {
      host: config.database.mysql.host,
      user: config.database.mysql.user,
      password: config.database.mysql.password,
      database: config.database.mysql.database,
      port: config.database.mysql.port,
      connectTimeout: 20000,
      acquireTimeout: 20000,
      timeout: 20000,
      waitForConnections: true,
      connectionLimit: 10,
      queueLimit: 0,
      reconnect: true,
      charset: 'utf8mb4'
    };

    this.pool = mysql.createPool(dbConfig);
    this.testConnection();
  }

  private async testConnection(): Promise<void> {
    try {
      logger.info('Testing MySQL connection...');
      const connection = await this.pool.getConnection();
      await connection.execute('SELECT 1 as test');
      connection.release();
      this.connected = true;
      logger.info('Successfully connected to MySQL database');
    } catch (error: any) {
      this.connected = false;
      logger.error('MySQL connection failed:', error.message);
    }
  }

  getTableName(baseName: string): string {
    return `${config.database.tablePrefix}${baseName}`;
  }

  async query(sql: string, params?: any[]): Promise<any> {
    const [rows] = await this.pool.execute(sql, params);
    return rows;
  }

  async execute(sql: string, params?: any[]): Promise<any> {
    return await this.pool.execute(sql, params);
  }

  async close(): Promise<void> {
    await this.pool.end();
  }

  isConnected(): boolean {
    return this.connected;
  }
}

// Supabase adapter
class SupabaseAdapter implements DatabaseAdapter {
  private client: any;
  private connected: boolean = false;

  constructor() {
    if (!config.database.supabase.url || !config.database.supabase.anonKey) {
      logger.error('Supabase URL and anon key are required for PostgreSQL connection');
      return;
    }

    this.client = createClient(
      config.database.supabase.url,
      config.database.supabase.anonKey
    );
    
    this.testConnection();
  }

  private async testConnection(): Promise<void> {
    try {
      logger.info('Testing Supabase connection...');
      const { data, error } = await this.client.from(this.getTableName('users')).select('count').limit(1);
      
      if (error && error.code !== 'PGRST116') { // PGRST116 is "table not found" which is OK
        throw error;
      }
      
      this.connected = true;
      logger.info('Successfully connected to Supabase (PostgreSQL)');
    } catch (error: any) {
      this.connected = false;
      logger.error('Supabase connection failed:', error.message);
    }
  }

  getTableName(baseName: string): string {
    return `${config.database.tablePrefix}${baseName}`;
  }

  async query(sql: string, params?: any[]): Promise<any> {
    // For Supabase, we'll need to convert SQL to Supabase queries
    // This is a simplified implementation - you might need more sophisticated SQL parsing
    throw new Error('Raw SQL queries not directly supported with Supabase adapter. Use execute() for specific operations.');
  }

  async execute(sql: string, params?: any[]): Promise<any> {
    // This method will handle specific database operations
    // For now, we'll implement the most common operations
    throw new Error('Execute method needs to be implemented for specific operations');
  }

  // Supabase-specific methods
  async insertUser(userData: any): Promise<any> {
    const { data, error } = await this.client
      .from(this.getTableName('users'))
      .insert(userData)
      .select()
      .single();
    
    if (error) throw error;
    return data;
  }

  async findUserByEmail(email: string): Promise<any> {
    const { data, error } = await this.client
      .from(this.getTableName('users'))
      .select('*')
      .eq('api_user', email)
      .single();
    
    if (error && error.code !== 'PGRST116') throw error;
    return data;
  }

  async findUserById(id: string): Promise<any> {
    const { data, error } = await this.client
      .from(this.getTableName('users'))
      .select('id, api_user, full_name, email, total_logins, created_at')
      .eq('id', id)
      .single();
    
    if (error) throw error;
    return data;
  }

  async updateUserLogins(id: string): Promise<void> {
    // First get current total_logins
    const { data: currentUser, error: fetchError } = await this.client
      .from(this.getTableName('users'))
      .select('total_logins')
      .eq('id', id)
      .single();
    
    if (fetchError) throw fetchError;
    
    const newTotal = (currentUser.total_logins || 0) + 1;
    
    const { error } = await this.client
      .from(this.getTableName('users'))
      .update({ total_logins: newTotal })
      .eq('id', id);
    
    if (error) throw error;
  }

  async insertKeyValue(uuid: string, keyName: string, encryptedValue: string): Promise<void> {
    const { error } = await this.client
      .from(this.getTableName('key_values'))
      .insert({
        uuid,
        key_name: keyName,
        encrypted_value: encryptedValue
      });
    
    if (error) throw error;
  }

  async updateKeyValue(uuid: string, encryptedValue: string): Promise<any> {
    const { data, error } = await this.client
      .from(this.getTableName('key_values'))
      .update({ encrypted_value: encryptedValue })
      .eq('uuid', uuid)
      .select();
    
    if (error) throw error;
    return data;
  }

  async getKeyValue(uuid: string): Promise<any> {
    const { data, error } = await this.client
      .from(this.getTableName('key_values'))
      .select('key_name, encrypted_value')
      .eq('uuid', uuid)
      .single();
    
    if (error) throw error;
    return data;
  }

  async incrementKeyValueRetrieved(uuid: string): Promise<void> {
    // First get current retrieved count
    const { data: currentData, error: fetchError } = await this.client
      .from(this.getTableName('key_values'))
      .select('retrieved')
      .eq('uuid', uuid)
      .single();
    
    if (fetchError) throw fetchError;
    
    const newCount = (currentData.retrieved || 0) + 1;
    
    const { error } = await this.client
      .from(this.getTableName('key_values'))
      .update({ retrieved: newCount })
      .eq('uuid', uuid);
    
    if (error) throw error;
  }

  async close(): Promise<void> {
    // Supabase client doesn't need explicit closing
  }

  isConnected(): boolean {
    return this.connected;
  }

  getClient() {
    return this.client;
  }
}

// Create the appropriate database adapter based on configuration
let dbAdapter: DatabaseAdapter;

if (config.database.type === 'mysql') {
  logger.info('Initializing MySQL database adapter');
  dbAdapter = new MySQLAdapter();
} else if (config.database.type === 'postgres') {
  logger.info('Initializing Supabase (PostgreSQL) database adapter');
  dbAdapter = new SupabaseAdapter();
} else {
  throw new Error(`Unsupported database type: ${config.database.type}`);
}

// Export the database adapter and legacy pool for backward compatibility
export const db = dbAdapter;
export const pool = dbAdapter; // For backward compatibility with existing code
export const isDatabaseConnected = () => dbAdapter.isConnected();
export const testDatabaseConnection = async () => dbAdapter.isConnected();

// Export Supabase client if using Supabase
export const supabase = config.database.type === 'postgres' ? (dbAdapter as SupabaseAdapter).getClient() : null;

logger.info(`Database adapter initialized: ${config.database.type} with table prefix: "${config.database.tablePrefix}"`);