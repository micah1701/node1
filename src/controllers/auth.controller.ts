import { Request, Response, NextFunction } from 'express';
import bcrypt from 'bcryptjs';
import { ApiError } from '../middlewares/error.middleware';
import { HttpStatus, LoginRequest, RegisterRequest, ApiResponse, TokenResponse } from '../types';
import { generateToken, generateRefreshToken } from '../utils/jwt.utils';
import { logger } from '../utils/logger';

// In-memory user store (replace with database in production)
const users: any[] = [];

/**
 * Register a new user
 */
export const register = async (req: Request, res: Response, next: NextFunction) => {
  try {
    const { email, password, name } = req.body as RegisterRequest;
    
    // Check if user already exists
    const userExists = users.find(user => user.email === email);
    if (userExists) {
      throw new ApiError(HttpStatus.BAD_REQUEST, 'User already exists');
    }
    
    // Hash password
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);
    
    // Create user
    const newUser = {
      id: Date.now().toString(),
      email,
      password: hashedPassword,
      name,
      role: 'user',
      createdAt: new Date(),
      updatedAt: new Date()
    };
    
    // Save user
    users.push(newUser);
    
    logger.info(`User registered: ${email}`);
    
    // Create response without password
    const { password: _, ...userWithoutPassword } = newUser;
    
    const response: ApiResponse<typeof userWithoutPassword> = {
      success: true,
      data: userWithoutPassword,
      message: 'User registered successfully'
    };
    
    res.status(HttpStatus.CREATED).json(response);
  } catch (error) {
    next(error);
  }
};

/**
 * Login user
 */
export const login = async (req: Request, res: Response, next: NextFunction) => {
  try {
    const { email, password } = req.body as LoginRequest;
    
    // Find user
    const user = users.find(user => user.email === email);
    if (!user) {
      throw new ApiError(HttpStatus.UNAUTHORIZED, 'Invalid credentials');
    }
    
    // Verify password
    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      throw new ApiError(HttpStatus.UNAUTHORIZED, 'Invalid credentials');
    }
    
    // Generate tokens
    const payload = { id: user.id, email: user.email, role: user.role };
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
export const getProfile = (req: Request, res: Response, next: NextFunction) => {
  try {
    // User is attached to request by auth middleware
    if (!req.user) {
      throw new ApiError(HttpStatus.UNAUTHORIZED, 'Not authenticated');
    }
    
    // Find user by id
    const user = users.find(user => user.id === req.user?.id);
    if (!user) {
      throw new ApiError(HttpStatus.NOT_FOUND, 'User not found');
    }
    
    // Remove password from response
    const { password: _, ...userWithoutPassword } = user;
    
    const response: ApiResponse<typeof userWithoutPassword> = {
      success: true,
      data: userWithoutPassword
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
    // User is attached to request by auth middleware
    if (!req.user) {
      throw new ApiError(HttpStatus.UNAUTHORIZED, 'Not authenticated');
    }
    
    // Generate new access token
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