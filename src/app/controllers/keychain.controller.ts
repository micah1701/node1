import { Request, Response, NextFunction } from 'express';
import bcrypt from 'bcryptjs';
import { ApiError } from '../../core/middlewares/error.middleware';
import { HttpStatus, ApiResponse } from '../../core/types';
import { db } from '../../core/utils/db';
import { encryptWithMasterKey, decryptWithMasterKey } from '../../core/utils/encryption';
import { logger } from '../../core/utils/logger';
import { config } from '../../core/config';
import {
  CreateKeychainAppRequest,
  UpdateKeychainAppRequest,
  CreatePublicKeyRequest,
  UpdatePublicKeyRequest,
  StorePrivateKeyRequest,
  KeychainAppResponse,
  PublicKeyResponse,
  PrivateKeyResponse
} from '../types/keychain.types';

/**
 * Create a new keychain application
 */
export const createKeychainApp = async (req: Request, res: Response, next: NextFunction) => {
  try {
    const { account_id, account_secret, app_name, encrypt_type = 'default', encrypt_public_key = null} = req.body as CreateKeychainAppRequest;

    if (!account_id || !account_secret || !app_name) {
      throw new ApiError(HttpStatus.BAD_REQUEST, 'account_id, account_secret, and app_name are required');
    }

    // Hash the account secret
    const salt = await bcrypt.genSalt(10);
    const hashedSecret = await bcrypt.hash(account_secret, salt);

    if (config.database.type === 'mysql') {
      const keychainAppsTable = db.getTableName('keychain_apps');
      const [result] = await db.execute(
        `INSERT INTO ${keychainAppsTable} (account_id, account_secret, app_name, encrypt_type, encrypt_public_key) VALUES (?, ?, ?, ?, ?)`,
        [account_id, hashedSecret, app_name, encrypt_type, encrypt_public_key]
      );

      const insertResult = result as { insertId: number };

      // Get the created app
      const [apps] = await db.execute(
        `SELECT id, account_id, app_name, active, encrypt_type, encrypt_public_key, created_at, modified_at FROM ${keychainAppsTable} WHERE id = ?`,
        [insertResult.insertId]
      ) as [any[], any];

      const app = apps[0];

      logger.info(`Keychain app created: ${app_name} (ID: ${app.id})`);

      const response: ApiResponse<KeychainAppResponse> = {
        success: true,
        data: app,
        message: 'Keychain application created successfully'
      };

      res.status(HttpStatus.CREATED).json(response);
    } else {
      // Supabase implementation
      const appData = {
        account_id,
        account_secret: hashedSecret,
        app_name,
        encrypt_type,
        encrypt_public_key
      };

      const app = await (db as any).insertKeychainApp(appData);

      logger.info(`Keychain app created: ${app_name} (ID: ${app.id})`);

      const response: ApiResponse<KeychainAppResponse> = {
        success: true,
        data: app,
        message: 'Keychain application created successfully'
      };

      res.status(HttpStatus.CREATED).json(response);
    }
  } catch (error: any) {
    if (error.code === 'ER_DUP_ENTRY' || error.code === '23505') {
      next(new ApiError(HttpStatus.BAD_REQUEST, 'Account ID already exists'));
    } else {
      next(error);
    }
  }
};

/**
 * Get keychain application by account ID
 */
export const getKeychainApp = async (req: Request, res: Response, next: NextFunction) => {
  try {
    const { account_id } = req.params;

    if (!account_id) {
      throw new ApiError(HttpStatus.BAD_REQUEST, 'Account ID is required');
    }

    if (config.database.type === 'mysql') {
      const keychainAppsTable = db.getTableName('keychain_apps');
      const [apps] = await db.execute(
        `SELECT id, account_id, app_name, active, encrypt_type, encrypt_public_key, created_at, modified_at FROM ${keychainAppsTable} WHERE account_id = ?`,
        [account_id]
      ) as [any[], any];

      if (apps.length === 0) {
        throw new ApiError(HttpStatus.NOT_FOUND, 'Keychain application not found');
      }

      const app = apps[0];

      const response: ApiResponse<KeychainAppResponse> = {
        success: true,
        data: app
      };

      res.status(HttpStatus.OK).json(response);
    } else {
      // Supabase implementation
      const app = await (db as any).findKeychainAppByAccountId(account_id);

      if (!app) {
        throw new ApiError(HttpStatus.NOT_FOUND, 'Keychain application not found');
      }

      const response: ApiResponse<KeychainAppResponse> = {
        success: true,
        data: app
      };

      res.status(HttpStatus.OK).json(response);
    }
  } catch (error) {
    next(error);
  }
};

/**
 * Update keychain application
 */
export const updateKeychainApp = async (req: Request, res: Response, next: NextFunction) => {
  try {
    const { account_id } = req.params;
    const { app_name, active, encrypt_type, encrypt_public_key } = req.body as UpdateKeychainAppRequest;

    if (!account_id) {
      throw new ApiError(HttpStatus.BAD_REQUEST, 'Account ID is required');
    }

    // Build update data
    const updateData: any = {};
    if (app_name !== undefined) updateData.app_name = app_name;
    if (active !== undefined) updateData.active = active;
    if (encrypt_type !== undefined) updateData.encrypt_type = encrypt_type;
    if (encrypt_public_key !== undefined) updateData.encrypt_public_key = encrypt_public_key;

    if (Object.keys(updateData).length === 0) {
      throw new ApiError(HttpStatus.BAD_REQUEST, 'No fields to update');
    }

    if (config.database.type === 'mysql') {
      const keychainAppsTable = db.getTableName('keychain_apps');

      // Build update query dynamically
      const updateFields: string[] = [];
      const updateValues: any[] = [];

      Object.entries(updateData).forEach(([key, value]) => {
        updateFields.push(`${key} = ?`);
        updateValues.push(value);
      });

      updateValues.push(account_id);

      const [result] = await db.execute(
        `UPDATE ${keychainAppsTable} SET ${updateFields.join(', ')} WHERE account_id = ?`,
        updateValues
      ) as [any, any];

      if (result.affectedRows === 0) {
        throw new ApiError(HttpStatus.NOT_FOUND, 'Keychain application not found');
      }

      logger.info(`Keychain app updated: ${account_id}`);

      const response: ApiResponse<{ account_id: string }> = {
        success: true,
        data: { account_id },
        message: 'Keychain application updated successfully'
      };

      res.status(HttpStatus.OK).json(response);
    } else {
      // Supabase implementation
      const result = await (db as any).updateKeychainApp(account_id, updateData);

      if (!result || result.length === 0) {
        throw new ApiError(HttpStatus.NOT_FOUND, 'Keychain application not found');
      }

      logger.info(`Keychain app updated: ${account_id}`);

      const response: ApiResponse<{ account_id: string }> = {
        success: true,
        data: { account_id },
        message: 'Keychain application updated successfully'
      };

      res.status(HttpStatus.OK).json(response);
    }
  } catch (error) {
    next(error);
  }
};

/**
 * Add a public key to a keychain application
 */
export const addPublicKey = async (req: Request, res: Response, next: NextFunction) => {
  try {
    const { account_id } = req.params;
    const { key_name, key } = req.body as CreatePublicKeyRequest;

    if (!account_id || !key_name || !key) {
      throw new ApiError(HttpStatus.BAD_REQUEST, 'account_id, key_name, and key are required');
    }

    if (config.database.type === 'mysql') {
      const keychainAppsTable = db.getTableName('keychain_apps');
      const publicKeysTable = db.getTableName('keychain_app_public_keys');

      // First, get the app ID
      const [apps] = await db.execute(
        `SELECT id FROM ${keychainAppsTable} WHERE account_id = ? AND active = TRUE`,
        [account_id]
      ) as [any[], any];

      if (apps.length === 0) {
        throw new ApiError(HttpStatus.NOT_FOUND, 'Active keychain application not found');
      }

      const app_id = apps[0].id;

      // Mark existing active keys as previous
      await db.execute(
        `UPDATE ${publicKeysTable} SET status = 'previous_key' WHERE app_id = ? AND status = 'active'`,
        [app_id]
      );

      // Insert new public key
      const [result] = await db.execute(
        `INSERT INTO ${publicKeysTable} (app_id, key_name, \`key\`, status) VALUES (?, ?, ?, 'active')`,
        [app_id, key_name, key]
      );

      const insertResult = result as { insertId: number };

      // Get the created public key
      const [publicKeys] = await db.execute(
        `SELECT id, status, app_id, key_name, \`key\`, created_at, modified_at FROM ${publicKeysTable} WHERE id = ?`,
        [insertResult.insertId]
      ) as [any[], any];

      const publicKey = publicKeys[0];

      logger.info(`Public key added for app: ${account_id} (Key ID: ${publicKey.id})`);

      const response: ApiResponse<PublicKeyResponse> = {
        success: true,
        data: publicKey,
        message: 'Public key added successfully'
      };

      res.status(HttpStatus.CREATED).json(response);
    } else {
      // Supabase implementation
      // First, get the app ID
      const app = await (db as any).findKeychainAppByAccountId(account_id);

      if (!app || !app.active) {
        throw new ApiError(HttpStatus.NOT_FOUND, 'Active keychain application not found');
      }

      const app_id = app.id;

      // Mark existing active keys as previous
      await (db as any).updatePublicKeysStatus(app_id, 'active', 'previous_key');

      // Insert new public key
      const keyData = {
        app_id,
        key_name,
        key,
        status: 'active'
      };

      const publicKey = await (db as any).insertPublicKey(keyData);

      logger.info(`Public key added for app: ${account_id} (Key ID: ${publicKey.id})`);

      const response: ApiResponse<PublicKeyResponse> = {
        success: true,
        data: publicKey,
        message: 'Public key added successfully'
      };

      res.status(HttpStatus.CREATED).json(response);
    }
  } catch (error) {
    next(error);
  }
};

/**
 * Get public keys for a keychain application
 */
export const getPublicKeys = async (req: Request, res: Response, next: NextFunction) => {
  try {
    const { account_id } = req.params;
    const { status } = req.query;

    if (!account_id) {
      throw new ApiError(HttpStatus.BAD_REQUEST, 'Account ID is required');
    }

    if (config.database.type === 'mysql') {
      const keychainAppsTable = db.getTableName('keychain_apps');
      const publicKeysTable = db.getTableName('keychain_app_public_keys');

      // First, get the app ID
      const [apps] = await db.execute(
        `SELECT id FROM ${keychainAppsTable} WHERE account_id = ?`,
        [account_id]
      ) as [any[], any];

      if (apps.length === 0) {
        throw new ApiError(HttpStatus.NOT_FOUND, 'Keychain application not found');
      }

      const app_id = apps[0].id;

      // Build query with optional status filter
      let query = `SELECT id, status, app_id, key_name, \`key\`, created_at, modified_at FROM ${publicKeysTable} WHERE app_id = ?`;
      const queryParams = [app_id];

      if (status && ['active', 'previous_key', 'deleted'].includes(status as string)) {
        query += ' AND status = ?';
        queryParams.push(status as string);
      }

      query += ' ORDER BY created_at DESC';

      const [publicKeys] = await db.execute(query, queryParams) as [any[], any];

      const response: ApiResponse<PublicKeyResponse[]> = {
        success: true,
        data: publicKeys
      };

      res.status(HttpStatus.OK).json(response);
    } else {
      // Supabase implementation
      // First, get the app ID
      const app = await (db as any).findKeychainAppByAccountId(account_id);

      if (!app) {
        throw new ApiError(HttpStatus.NOT_FOUND, 'Keychain application not found');
      }

      const app_id = app.id;

      // Get public keys with optional status filter
      const validStatus = status && ['active', 'previous_key', 'deleted'].includes(status as string) ? status as string : undefined;
      const publicKeys = await (db as any).findPublicKeysByAppId(app_id, validStatus);

      const response: ApiResponse<PublicKeyResponse[]> = {
        success: true,
        data: publicKeys
      };

      res.status(HttpStatus.OK).json(response);
    }
  } catch (error) {
    next(error);
  }
};

/**
 * Store an encrypted private key
 */
export const storePrivateKey = async (req: Request, res: Response, next: NextFunction) => {
  try {
    const { account_id } = req.params;
    const { retrieval_id, private_key } = req.body as StorePrivateKeyRequest;

    if (!account_id || !retrieval_id || !private_key) {
      throw new ApiError(HttpStatus.BAD_REQUEST, 'account_id, retrieval_id, and private_key are required');
    }

    // Encrypt the private key
    const encryptedPrivateKey = encryptWithMasterKey(private_key);

    if (config.database.type === 'mysql') {
      const keychainAppsTable = db.getTableName('keychain_apps');
      const privateKeysTable = db.getTableName('keychain_app_private_keys');

      // First, get the app ID and verify it's active
      const [apps] = await db.execute(
        `SELECT id FROM ${keychainAppsTable} WHERE account_id = ? AND active = TRUE`,
        [account_id]
      ) as [any[], any];

      if (apps.length === 0) {
        throw new ApiError(HttpStatus.NOT_FOUND, 'Active keychain application not found');
      }

      const app_id = apps[0].id;

      // Store the encrypted private key
      await db.execute(
        `INSERT INTO ${privateKeysTable} (app_id, retrieval_id, private_key) VALUES (?, ?, ?)
         ON DUPLICATE KEY UPDATE private_key = VALUES(private_key), modified_at = CURRENT_TIMESTAMP`,
        [app_id, retrieval_id, encryptedPrivateKey]
      );

      logger.info(`Private key stored for app: ${account_id}, retrieval_id: ${retrieval_id}`);

      const response: ApiResponse<{ retrieval_id: string }> = {
        success: true,
        data: { retrieval_id },
        message: 'Private key stored successfully'
      };

      res.status(HttpStatus.CREATED).json(response);
    } else {
      // Supabase implementation
      // First, get the app ID and verify it's active
      const app = await (db as any).findKeychainAppByAccountId(account_id);

      if (!app || !app.active) {
        throw new ApiError(HttpStatus.NOT_FOUND, 'Active keychain application not found');
      }

      const app_id = app.id;

      // Store the encrypted private key (upsert)
      const keyData = {
        app_id,
        retrieval_id,
        private_key: encryptedPrivateKey
      };

      await (db as any).upsertPrivateKey(keyData);

      logger.info(`Private key stored for app: ${account_id}, retrieval_id: ${retrieval_id}`);

      const response: ApiResponse<{ retrieval_id: string }> = {
        success: true,
        data: { retrieval_id },
        message: 'Private key stored successfully'
      };

      res.status(HttpStatus.CREATED).json(response);
    }
  } catch (error) {
    next(error);
  }
};

/**
 * Retrieve and decrypt a private key
 */
export const getPrivateKey = async (req: Request, res: Response, next: NextFunction) => {
  try {
    const { account_id, retrieval_id } = req.params;

    if (!account_id || !retrieval_id) {
      throw new ApiError(HttpStatus.BAD_REQUEST, 'Account ID and retrieval ID are required');
    }

    if (config.database.type === 'mysql') {
      const keychainAppsTable = db.getTableName('keychain_apps');
      const privateKeysTable = db.getTableName('keychain_app_private_keys');

      // Get the private key with app verification
      const [privateKeys] = await db.execute(
        `SELECT pk.retrieval_id, pk.private_key, pk.created_at 
         FROM ${privateKeysTable} pk
         JOIN ${keychainAppsTable} ka ON pk.app_id = ka.id
         WHERE ka.account_id = ? AND pk.retrieval_id = ? AND ka.active = TRUE`,
        [account_id, retrieval_id]
      ) as [any[], any];

      if (privateKeys.length === 0) {
        throw new ApiError(HttpStatus.NOT_FOUND, 'Private key not found');
      }

      const privateKeyData = privateKeys[0];

      // Decrypt the private key
      const decryptedPrivateKey = decryptWithMasterKey(privateKeyData.private_key);

      logger.info(`Private key retrieved for app: ${account_id}, retrieval_id: ${retrieval_id}`);

      const response: ApiResponse<PrivateKeyResponse> = {
        success: true,
        data: {
          retrieval_id: privateKeyData.retrieval_id,
          private_key: decryptedPrivateKey,
          created_at: privateKeyData.created_at
        }
      };

      res.status(HttpStatus.OK).json(response);
    } else {
      // Supabase implementation
      // First, get the app ID and verify it's active
      const app = await (db as any).findKeychainAppByAccountId(account_id);

      if (!app || !app.active) {
        throw new ApiError(HttpStatus.NOT_FOUND, 'Active keychain application not found');
      }

      const app_id = app.id;

      // Get the private key
      const privateKeyData = await (db as any).findPrivateKey(app_id, retrieval_id);

      if (!privateKeyData) {
        throw new ApiError(HttpStatus.NOT_FOUND, 'Private key not found');
      }

      // Decrypt the private key
      const decryptedPrivateKey = decryptWithMasterKey(privateKeyData.private_key);

      logger.info(`Private key retrieved for app: ${account_id}, retrieval_id: ${retrieval_id}`);

      const response: ApiResponse<PrivateKeyResponse> = {
        success: true,
        data: {
          retrieval_id: privateKeyData.retrieval_id,
          private_key: decryptedPrivateKey,
          created_at: privateKeyData.created_at
        }
      };

      res.status(HttpStatus.OK).json(response);
    }
  } catch (error) {
    next(error);
  }
};

/**
 * List all private key retrieval IDs for an app (without the actual keys)
 */
export const listPrivateKeys = async (req: Request, res: Response, next: NextFunction) => {
  try {
    const { account_id } = req.params;

    if (!account_id) {
      throw new ApiError(HttpStatus.BAD_REQUEST, 'Account ID is required');
    }

    if (config.database.type === 'mysql') {
      const keychainAppsTable = db.getTableName('keychain_apps');
      const privateKeysTable = db.getTableName('keychain_app_private_keys');

      // Get list of retrieval IDs without the actual private keys
      const [privateKeys] = await db.execute(
        `SELECT pk.retrieval_id, pk.created_at, pk.modified_at
         FROM ${privateKeysTable} pk
         JOIN ${keychainAppsTable} ka ON pk.app_id = ka.id
         WHERE ka.account_id = ? AND ka.active = TRUE
         ORDER BY pk.created_at DESC`,
        [account_id]
      ) as [any[], any];

      const response: ApiResponse<Array<{ retrieval_id: string; created_at: Date; modified_at: Date }>> = {
        success: true,
        data: privateKeys
      };

      res.status(HttpStatus.OK).json(response);
    } else {
      // Supabase implementation
      // First, get the app ID and verify it's active
      const app = await (db as any).findKeychainAppByAccountId(account_id);

      if (!app || !app.active) {
        throw new ApiError(HttpStatus.NOT_FOUND, 'Active keychain application not found');
      }

      const app_id = app.id;

      // Get list of retrieval IDs without the actual private keys
      const privateKeys = await (db as any).findPrivateKeysByAppId(app_id);

      const response: ApiResponse<Array<{ retrieval_id: string; created_at: Date; modified_at: Date }>> = {
        success: true,
        data: privateKeys
      };

      res.status(HttpStatus.OK).json(response);
    }
  } catch (error) {
    next(error);
  }
};

/**
 * Authenticate keychain app (verify account_id and account_secret)
 */
export const authenticateKeychainApp = async (req: Request, res: Response, next: NextFunction) => {
  try {
    const { account_id, account_secret } = req.body;

    if (!account_id || !account_secret) {
      throw new ApiError(HttpStatus.BAD_REQUEST, 'account_id and account_secret are required');
    }

    if (config.database.type === 'mysql') {
      const keychainAppsTable = db.getTableName('keychain_apps');
      const [apps] = await db.execute(
        `SELECT id, account_id, account_secret, app_name, active FROM ${keychainAppsTable} WHERE account_id = ?`,
        [account_id]
      ) as [any[], any];

      if (apps.length === 0) {
        throw new ApiError(HttpStatus.UNAUTHORIZED, 'Invalid credentials');
      }

      const app = apps[0];

      if (!app.active) {
        throw new ApiError(HttpStatus.UNAUTHORIZED, 'Application is inactive');
      }

      // Verify the account secret
      const isSecretValid = await bcrypt.compare(account_secret, app.account_secret);
      if (!isSecretValid) {
        throw new ApiError(HttpStatus.UNAUTHORIZED, 'Invalid credentials');
      }

      logger.info(`Keychain app authenticated: ${account_id}`);

      const response: ApiResponse<{ account_id: string; app_name: string }> = {
        success: true,
        data: {
          account_id: app.account_id,
          app_name: app.app_name
        },
        message: 'Authentication successful'
      };

      res.status(HttpStatus.OK).json(response);
    } else {
      // Supabase implementation
      const app = await (db as any).findKeychainAppWithSecretByAccountId(account_id);

      if (!app) {
        throw new ApiError(HttpStatus.UNAUTHORIZED, 'Invalid credentials');
      }

      if (!app.active) {
        throw new ApiError(HttpStatus.UNAUTHORIZED, 'Application is inactive');
      }

      // Verify the account secret
      const isSecretValid = await bcrypt.compare(account_secret, app.account_secret);
      if (!isSecretValid) {
        throw new ApiError(HttpStatus.UNAUTHORIZED, 'Invalid credentials');
      }

      logger.info(`Keychain app authenticated: ${account_id}`);

      const response: ApiResponse<{ account_id: string; app_name: string }> = {
        success: true,
        data: {
          account_id: app.account_id,
          app_name: app.app_name
        },
        message: 'Authentication successful'
      };

      res.status(HttpStatus.OK).json(response);
    }
  } catch (error) {
    next(error);
  }
};