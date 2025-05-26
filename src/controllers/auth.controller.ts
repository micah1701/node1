import { Request, Response, NextFunction } from 'express';
import bcrypt from 'bcryptjs';
import { ApiError } from '../middlewares/error.middleware';
import { HttpStatus, LoginRequest, RegisterRequest, ApiResponse, TokenResponse } from '../types';
import { generateToken, generateRefreshToken } from '../utils/jwt.utils';
import { logger } from '../utils/logger';
import { pool } from '../utils/db';

/**
 * Register a new user
 */
export const register = async (req: Request, res: Response, next: NextFunction) => {
  try {
    const { email, password, name } = req.body as RegisterRequest;
    
    // Hash password
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);
    
    // Create user
    const [result] = await pool.execute(
      'INSERT INTO users (api_user, api_secret, full_name, email) VALUES (?, ?, ?, ?)',
      [email, hashedPassword, name, email]
    );
    
    const insertResult = result as { insertId: number };
    
    logger.info(`User registered: ${email}`);
    
    // Get the created user
    const [users] = await pool.execute(
      'SELECT id, api_user, full_name, email, created_at FROM users WHERE id = ?',
      [insertResult.insertId]
    ) as [any[], any];
    
    const user = users[0];
    
    const response: ApiResponse<typeof user> = {
      success: true,
      data: user,
      message: 'User registered successfully'
    };
    
    res.status(HttpStatus.CREATED).json(response);
  } catch (error: any) {
    if (error.code === 'ER_DUP_ENTRY') {
      next(new ApiError(HttpStatus.BAD_REQUEST, 'User already exists'));
    } else {
      next(error);
    }
  }
};

/**
 * Login user
 */
export const login = async (req: Request, res: Response, next: NextFunction) => {
  try {
    const { email, password } = req.body as LoginRequest;
    
    // Find user
    const [users] = await pool.execute(
      'SELECT * FROM users WHERE api_user = ?',
      [email]
    ) as [any[], any];
    
    const user = users[0];
    if (!user) {
      throw new ApiError(HttpStatus.UNAUTHORIZED, 'Invalid credentials');
    }
    
    // Verify password
    const isPasswordValid = await bcrypt.compare(password, user.api_secret);
    if (!isPasswordValid) {
      throw new ApiError(HttpStatus.UNAUTHORIZED, 'Invalid credentials');
    }
    
    // Increment total_logins
    await pool.execute(
      'UPDATE users SET total_logins = total_logins + 1 WHERE id = ?',
      [user.id]
    );
    
    // Generate tokens
    const payload = { id: user.id.toString(), email: user.email, role: 'user' };
    const accessToken = generateToken(payload);
    const refreshToken = generateRefreshToken(payload);
    
    logger.info(`User logged in: ${email}`);
    
    const response: ApiResponse<TokenResponse> = {
      success: true,
      data: { accessToken, refreshToken },
      message: 'Login successful'
    };
    
    res.status(HttpStatus.OK).json(response);
  } catch (error) {
    next(error);
  }
};

/**
 * Get current user profile
 */
export const getProfile = async (req: Request, res: Response, next: NextFunction) => {
  try {
    if (!req.user) {
      throw new ApiError(HttpStatus.UNAUTHORIZED, 'Not authenticated');
    }
    
    // Find user by id
    const [users] = await pool.execute(
      'SELECT id, api_user, full_name, email, total_logins, created_at FROM users WHERE id = ?',
      [req.user.id]
    ) as [any[], any];
    
    const user = users[0];
    if (!user) {
      throw new ApiError(HttpStatus.NOT_FOUND, 'User not found');
    }
    
    const response: ApiResponse<typeof user> = {
      success: true,
      data: user
    };
    
    res.status(HttpStatus.OK).json(response);
  } catch (error) {
    next(error);
  }
};

/**
 * Refresh access token
 */
export const refreshToken = (req: Request, res: Response, next: NextFunction) => {
  try {
    if (!req.user) {
      throw new ApiError(HttpStatus.UNAUTHORIZED, 'Not authenticated');
    }
    
    const payload = { 
      id: req.user.id, 
      email: req.user.email, 
      role: req.user.role 
    };
    
    const accessToken = generateToken(payload);
    
    const response: ApiResponse<{ accessToken: string }> = {
      success: true,
      data: { accessToken },
      message: 'Token refreshed successfully'
    };
    
    res.status(HttpStatus.OK).json(response);
  } catch (error) {
    next(error);
  }
};