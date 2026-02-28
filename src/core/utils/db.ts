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
    if (!config.database.supabase.url || !config.database.supabase.publishableKey) {
      throw new Error('Supabase configuration is missing. Please check SUPABASE_URL and SUPABASE_PUBLISHABLE_KEY in your .env file');
    }

    this.client = createClient(
      config.database.supabase.url,
      config.database.supabase.publishableKey
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

  // Helper method to normalize nested response data
  private normalizeKeychainAppResponse(data: any): any {
    if (!data) return data;
    
    const keychainAppsTable = this.getTableName('keychain_apps');
    
    // If the data has the prefixed table name, normalize it to 'keychain_apps'
    if (data[keychainAppsTable]) {
      return {
        ...data,
        keychain_apps: data[keychainAppsTable],
        // Remove the prefixed version to avoid confusion
        // [keychainAppsTable]: undefined
      };
    }
    
    return data;
  }

  // Core user methods
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
    
    // First get current value
    const { data, error: selectError } = await this.client
      .from(tableName)
      .select('total_logins')
      .eq('id', id)
      .single();
    
    if (selectError) throw selectError;
    
    const newTotalLogins = (data?.total_logins ?? 0) + 1;
    
    // Update with new value
    const { error } = await this.client
      .from(tableName)
      .update({ total_logins: newTotalLogins })
      .eq('id', id);
    
    if (error) throw error;
  }

  // Key-value methods
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

    // First get current value
    const { data, error: selectError } = await this.client
      .from(tableName)
      .select('retrieved')
      .eq('uuid', uuid)
      .single();
    
    if (selectError) throw selectError;
    
    const newRetrievedCount = (data?.retrieved ?? 0) + 1;
    
    // Update with new value
    const { error } = await this.client
      .from(tableName)
      .update({ retrieved: newRetrievedCount })
      .eq('uuid', uuid);
    
    if (error) throw error;
  }

  // Keychain app methods
  async insertKeychainApp(appData: any) {
    const tableName = this.getTableName('keychain_apps');
    const { data, error } = await this.client
      .from(tableName)
      .insert(appData)
      .select('id, account_id, app_name, active, encrypt_type, encrypt_public_key, created_at, modified_at')
      .single();
    
    if (error) throw error;
    return data;
  }

  async findKeychainAppByAccountId(accountId: string) {
    const tableName = this.getTableName('keychain_apps');
    const { data, error } = await this.client
      .from(tableName)
      .select('id, account_id, app_name, active, encrypt_type, encrypt_public_key, created_at, modified_at')
      .eq('account_id', accountId)
      .single();
    
    if (error && error.code !== 'PGRST116') throw error;
    return data;
  }

  async findKeychainAppWithSecretByAccountId(accountId: string) {
    const tableName = this.getTableName('keychain_apps');
    const { data, error } = await this.client
      .from(tableName)
      .select('id, account_id, account_secret, app_name, active')
      .eq('account_id', accountId)
      .single();
    
    if (error && error.code !== 'PGRST116') throw error;
    return data;
  }

  async updateKeychainApp(accountId: string, updateData: any) {
    const tableName = this.getTableName('keychain_apps');
    const { data, error } = await this.client
      .from(tableName)
      .update(updateData)
      .eq('account_id', accountId)
      .select();
    
    if (error) throw error;
    return data;
  }

  // User-specific keychain app methods
  async findKeychainAppsByUserId(userId: string) {
    const keychainAppsTable = this.getTableName('keychain_apps');
    const userKeychainAppsTable = this.getTableName('user_keychain_apps');
    
    const { data, error } = await this.client
      .from(userKeychainAppsTable)
      .select(`
        role,
        ${keychainAppsTable} (
          id,
          account_id,
          app_name,
          active,
          encrypt_type,
          encrypt_public_key,
          created_at,
          modified_at
        )
      `)
      .eq('user_id', userId);
    
    if (error) throw error;
    
    // Normalize the response to use consistent key names
    const normalizedData = (data || []).map(item => this.normalizeKeychainAppResponse(item));
    return normalizedData;
  }

  async findKeychainAppByAccountIdAndUserId(accountId: string, userId: string) {
    const keychainAppsTable = this.getTableName('keychain_apps');
    const userKeychainAppsTable = this.getTableName('user_keychain_apps');
    
    // First, find the keychain app by account_id
    const { data: appData, error: appError } = await this.client
      .from(keychainAppsTable)
      .select('id, account_id, app_name, active, encrypt_type, encrypt_public_key, created_at, modified_at')
      .eq('account_id', accountId)
      .single();
    
    if (appError) {
      console.log('App lookup error:', appError);
      if (appError.code === 'PGRST116') return null; // No app found
      throw appError;
    }
    
    // Then, check if the user has access to this app
    const { data: userAppData, error: userAppError } = await this.client
      .from(userKeychainAppsTable)
      .select('role')
      .eq('user_id', userId)
      .eq('keychain_app_id', appData.id)
      .single();
    
    if (userAppError) {
      console.log('User app access lookup error:', userAppError);
      if (userAppError.code === 'PGRST116') return null; // User doesn't have access
      throw userAppError;
    }
    
    console.log('User has access with role:', userAppData.role);
    
    // Combine the data in the expected format
    const combinedData = {
      role: userAppData.role,
      keychain_apps: appData
    };
    
    console.log('Combined data:', combinedData);
    
    return combinedData;
  }

  async insertUserKeychainApp(userId: string, keychainAppId: number, role: string = 'owner') {
    const tableName = this.getTableName('user_keychain_apps');
    const { error } = await this.client
      .from(tableName)
      .insert({
        user_id: userId,
        keychain_app_id: keychainAppId,
        role
      });
    
    if (error) throw error;
  }

  // Public key methods
  async insertPublicKey(keyData: any) {
    const tableName = this.getTableName('keychain_app_public_keys');
    const { data, error } = await this.client
      .from(tableName)
      .insert(keyData)
      .select('id, status, app_id, key_name, key, created_at, modified_at')
      .single();
    
    if (error) throw error;
    return data;
  }

  async updatePublicKeysStatus(appId: number, currentStatus: string, newStatus: string) {
    const tableName = this.getTableName('keychain_app_public_keys');
    const { error } = await this.client
      .from(tableName)
      .update({ status: newStatus })
      .eq('app_id', appId)
      .eq('status', currentStatus);
    
    if (error) throw error;
  }

  async findPublicKeysByAppId(appId: number, status?: string) {
    const tableName = this.getTableName('keychain_app_public_keys');
    let query = this.client
      .from(tableName)
      .select('id, status, app_id, key_name, key, created_at, modified_at')
      .eq('app_id', appId);

    if (status) {
      query = query.eq('status', status);
    }

    const { data, error } = await query.order('created_at', { ascending: false });
    
    if (error) throw error;
    return data || [];
  }

  // Private key methods
  async upsertPrivateKey(keyData: any) {
    const tableName = this.getTableName('keychain_app_private_keys');
    const { error } = await this.client
      .from(tableName)
      .upsert(keyData, { 
        onConflict: 'app_id,retrieval_id',
        ignoreDuplicates: false 
      });
    
    if (error) throw error;
  }

  async findPrivateKey(appId: number, retrievalId: string) {
    const tableName = this.getTableName('keychain_app_private_keys');
    const { data, error } = await this.client
      .from(tableName)
      .select('retrieval_id, private_key, created_at')
      .eq('app_id', appId)
      .eq('retrieval_id', retrievalId)
      .single();
    
    if (error && error.code !== 'PGRST116') throw error;
    return data;
  }

  async findPrivateKeysByAppId(appId: number) {
    const tableName = this.getTableName('keychain_app_private_keys');
    const { data, error } = await this.client
      .from(tableName)
      .select('retrieval_id, created_at, modified_at')
      .eq('app_id', appId)
      .order('created_at', { ascending: false });
    
    if (error) throw error;
    return data || [];
  }

  // API Request Logs methods
  async insertApiRequestLog(logData: any) {
    const tableName = this.getTableName('api_request_logs');
    const { error } = await this.client
      .from(tableName)
      .insert(logData);
    
    if (error) throw error;
  }

  async findApiLogByUuid(uuid: string) {
    const tableName = this.getTableName('api_request_logs');
    const { data, error } = await this.client
      .from(tableName)
      .select('*')
      .eq('request_uuid', uuid)
      .single();
    
    if (error && error.code !== 'PGRST116') throw error;
    return data;
  }

  async testConnection(): Promise<boolean> {
    try {
      // Try a simple query to test the connection using a user-defined table
      const { error } = await this.client
        .from(this.getTableName('users'))
        .select('id')
        .limit(1);
      
      // If we get here without an error, connection is working
      return !error || error.code === 'PGRST106'; // PGRST106 = table not found (still a valid connection)
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