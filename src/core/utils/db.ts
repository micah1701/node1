import mysql from 'mysql2/promise';
import { createClient, SupabaseClient } from '@supabase/supabase-js';
import { logger } from './logger';
import { config } from '../config';

interface DatabaseInterface {
  execute(query: string, params?: any[]): Promise<any>;
  getTableName(tableName: string): string;
}

class MySQLDatabase implements DatabaseInterface {
  private pool: mysql.Pool;

  constructor() {
    this.pool = mysql.createPool({
      host: config.database.mysql.host,
      user: config.database.mysql.user,
      password: config.database.mysql.password,
      database: config.database.mysql.database,
      port: config.database.mysql.port,
      waitForConnections: true,
      connectionLimit: 10,
      queueLimit: 0
    });
  }

  async execute(query: string, params?: any[]): Promise<any> {
    return this.pool.execute(query, params);
  }

  getTableName(tableName: string): string {
    return `${config.database.tablePrefix}${tableName}`;
  }

  async testConnection(): Promise<boolean> {
    try {
      const connection = await this.pool.getConnection();
      connection.release();
      return true;
    } catch (error) {
      logger.error('MySQL connection test failed:', error);
      return false;
    }
  }
}

class SupabaseDatabase implements DatabaseInterface {
  private client: SupabaseClient;

  constructor() {
    if (!config.database.supabase.url || !config.database.supabase.anonKey) {
      throw new Error('Supabase configuration is missing');
    }
    
    this.client = createClient(
      config.database.supabase.url,
      config.database.supabase.anonKey
    );
  }

  async execute(query: string, params?: any[]): Promise<any> {
    // This is a simplified implementation
    // In practice, you'd need to convert SQL queries to Supabase operations
    throw new Error('Direct SQL execution not supported with Supabase. Use specific methods.');
  }

  getTableName(tableName: string): string {
    return `${config.database.tablePrefix}${tableName}`;
  }

  // Supabase-specific methods
  async insertUser(userData: any) {
    const tableName = this.getTableName('users');
    const { data, error } = await this.client
      .from(tableName)
      .insert(userData)
      .select('id, api_user, full_name, email, created_at')
      .single();
    
    if (error) throw error;
    return data;
  }

  async findUserByEmail(email: string) {
    const tableName = this.getTableName('users');
    const { data, error } = await this.client
      .from(tableName)
      .select('*')
      .eq('api_user', email)
      .single();
    
    if (error && error.code !== 'PGRST116') throw error; // PGRST116 = no rows returned
    return data;
  }

  async findUserById(id: string) {
    const tableName = this.getTableName('users');
    const { data, error } = await this.client
      .from(tableName)
      .select('id, api_user, full_name, email, total_logins, created_at')
      .eq('id', id)
      .single();
    
    if (error && error.code !== 'PGRST116') throw error;
    return data;
  }

  async updateUserLogins(id: string) {
    const tableName = this.getTableName('users');
    const { error } = await this.client
      .from(tableName)
      .update({ total_logins: this.client.sql`.total_logins + 1` })
      .eq('id', id);
    
    if (error) throw error;
  }

  async insertKeyValue(uuid: string, key: string, encryptedValue: string) {
    const tableName = this.getTableName('key_values');
    const { error } = await this.client
      .from(tableName)
      .insert({
        uuid,
        key_name: key,
        encrypted_value: encryptedValue
      });
    
    if (error) throw error;
  }

  async updateKeyValue(uuid: string, encryptedValue: string) {
    const tableName = this.getTableName('key_values');
    const { data, error } = await this.client
      .from(tableName)
      .update({ encrypted_value: encryptedValue })
      .eq('uuid', uuid)
      .select();
    
    if (error) throw error;
    return data;
  }

  async getKeyValue(uuid: string) {
    const tableName = this.getTableName('key_values');
    const { data, error } = await this.client
      .from(tableName)
      .select('key_name, encrypted_value')
      .eq('uuid', uuid)
      .single();
    
    if (error && error.code !== 'PGRST116') throw error;
    return data;
  }

  async incrementKeyValueRetrieved(uuid: string) {
    const tableName = this.getTableName('key_values');
    const { error } = await this.client
      .from(tableName)
      .update({ retrieved: this.client.sql`.retrieved + 1` })
      .eq('uuid', uuid);
    
    if (error) throw error;
  }

  async testConnection(): Promise<boolean> {
    try {
      const { data, error } = await this.client
        .from('_health')
        .select('*')
        .limit(1);
      
      // If the table doesn't exist, that's still a valid connection
      return !error || error.code === 'PGRST106'; // PGRST106 = table not found
    } catch (error) {
      logger.error('Supabase connection test failed:', error);
      return false;
    }
  }
}

// Create database instance based on configuration
let db: DatabaseInterface;
let isConnected = false;

try {
  if (config.database.type === 'mysql') {
    db = new MySQLDatabase();
  } else if (config.database.type === 'postgres') {
    db = new SupabaseDatabase();
  } else {
    throw new Error(`Unsupported database type: ${config.database.type}`);
  }
} catch (error) {
  logger.error('Failed to initialize database:', error);
  // Create a mock database that throws errors
  db = {
    execute: async () => { throw new Error('Database not properly configured'); },
    getTableName: (name: string) => name
  };
}

// Test database connection
export const testDatabaseConnection = async (): Promise<boolean> => {
  try {
    if ('testConnection' in db) {
      isConnected = await (db as any).testConnection();
      if (isConnected) {
        logger.info(`Successfully connected to ${config.database.type} database`);
      } else {
        logger.error(`Failed to connect to ${config.database.type} database`);
      }
    } else {
      logger.warn('Database connection test not available');
      isConnected = false;
    }
  } catch (error) {
    logger.error('Error testing database connection:', error);
    isConnected = false;
  }
  return isConnected;
};

export const isDatabaseConnected = (): boolean => {
  return isConnected;
};

export { db };