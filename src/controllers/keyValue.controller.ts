import { Request, Response, NextFunction } from 'express';
import { v4 as uuidv4 } from 'uuid';
import { ApiError } from '../middlewares/error.middleware';
import { HttpStatus, ApiResponse } from '../types';
import { pool } from '../utils/db';
import { encryptWithMasterKey, decryptWithMasterKey } from '../utils/encryption';
import { logger } from '../utils/logger';

interface KeyValuePair {
  key: string;
  value: string;
}

/**
 * Store a new key-value pair
 */
export const storeKeyValue = async (req: Request, res: Response, next: NextFunction) => {
  try {
    const { key, value } = req.body as KeyValuePair;
    
    if (!key || !value) {
      throw new ApiError(HttpStatus.BAD_REQUEST, 'Key and value are required');
    }

    const uuid = uuidv4();
    const encryptedValue = encryptWithMasterKey(value);

    await pool.execute(
      'INSERT INTO key_values (uuid, key_name, encrypted_value) VALUES (?, ?, ?)',
      [uuid, key, encryptedValue]
    );

    logger.info(`Stored new key-value pair with UUID: ${uuid}`);

    const response: ApiResponse<{ uuid: string }> = {
      success: true,
      data: { uuid },
      message: 'Key-value pair stored successfully'
    };

    res.status(HttpStatus.CREATED).json(response);
  } catch (error) {
    next(error);
  }
};

/**
 * Update an existing key-value pair
 */
export const updateKeyValue = async (req: Request, res: Response, next: NextFunction) => {
  try {
    const { uuid } = req.params;
    const { value } = req.body as Partial<KeyValuePair>;

    if (!value) {
      throw new ApiError(HttpStatus.BAD_REQUEST, 'Value is required');
    }

    const encryptedValue = encryptWithMasterKey(value);

    const [result] = await pool.execute(
      'UPDATE key_values SET encrypted_value = ? WHERE uuid = ?',
      [encryptedValue, uuid]
    ) as [any, any];

    if (result.affectedRows === 0) {
      throw new ApiError(HttpStatus.NOT_FOUND, 'Key-value pair not found');
    }

    logger.info(`Updated key-value pair with UUID: ${uuid}`);

    const response: ApiResponse<{ uuid: string }> = {
      success: true,
      data: { uuid },
      message: 'Key-value pair updated successfully'
    };

    res.status(HttpStatus.OK).json(response);
  } catch (error) {
    next(error);
  }
};

/**
 * Retrieve a key-value pair
 */
export const getKeyValue = async (req: Request, res: Response, next: NextFunction) => {
  try {
    const { uuid } = req.params;

    const [rows] = await pool.execute(
      'SELECT key_name, encrypted_value FROM key_values WHERE uuid = ?',
      [uuid]
    ) as [any[], any];

    if (rows.length === 0) {
      throw new ApiError(HttpStatus.NOT_FOUND, 'Key-value pair not found');
    }

    const { key_name, encrypted_value } = rows[0];
    const decryptedValue = decryptWithMasterKey(encrypted_value);

    // Increment retrieved counter
    await pool.execute(
      'UPDATE key_values SET retrieved = retrieved + 1 WHERE uuid = ?',
      [uuid]
    );

    logger.info(`Retrieved key-value pair with UUID: ${uuid}`);

    const response: ApiResponse<{ key: string; value: string }> = {
      success: true,
      data: {
        key: key_name,
        value: decryptedValue
      }
    };

    res.status(HttpStatus.OK).json(response);
  } catch (error) {
    next(error);
  }
};