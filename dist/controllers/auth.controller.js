"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.refreshToken = exports.getProfile = exports.login = exports.register = void 0;
const bcryptjs_1 = __importDefault(require("bcryptjs"));
const error_middleware_1 = require("../middlewares/error.middleware");
const types_1 = require("../types");
const jwt_utils_1 = require("../utils/jwt.utils");
const logger_1 = require("../utils/logger");
// In-memory user store (replace with database in production)
const users = [];
/**
 * Register a new user
 */
const register = async (req, res, next) => {
    try {
        const { email, password, name } = req.body;
        // Check if user already exists
        const userExists = users.find(user => user.email === email);
        if (userExists) {
            throw new error_middleware_1.ApiError(types_1.HttpStatus.BAD_REQUEST, 'User already exists');
        }
        // Hash password
        const salt = await bcryptjs_1.default.genSalt(10);
        const hashedPassword = await bcryptjs_1.default.hash(password, salt);
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
        logger_1.logger.info(`User registered: ${email}`);
        // Create response without password
        const { password: _, ...userWithoutPassword } = newUser;
        const response = {
            success: true,
            data: userWithoutPassword,
            message: 'User registered successfully'
        };
        res.status(types_1.HttpStatus.CREATED).json(response);
    }
    catch (error) {
        next(error);
    }
};
exports.register = register;
/**
 * Login user
 */
const login = async (req, res, next) => {
    try {
        const { email, password } = req.body;
        // Find user
        const user = users.find(user => user.email === email);
        if (!user) {
            throw new error_middleware_1.ApiError(types_1.HttpStatus.UNAUTHORIZED, 'Invalid credentials');
        }
        // Verify password
        const isPasswordValid = await bcryptjs_1.default.compare(password, user.password);
        if (!isPasswordValid) {
            throw new error_middleware_1.ApiError(types_1.HttpStatus.UNAUTHORIZED, 'Invalid credentials');
        }
        // Generate tokens
        const payload = { id: user.id, email: user.email, role: user.role };
        const accessToken = (0, jwt_utils_1.generateToken)(payload);
        const refreshToken = (0, jwt_utils_1.generateRefreshToken)(payload);
        logger_1.logger.info(`User logged in: ${email}`);
        const response = {
            success: true,
            data: { accessToken, refreshToken },
            message: 'Login successful'
        };
        res.status(types_1.HttpStatus.OK).json(response);
    }
    catch (error) {
        next(error);
    }
};
exports.login = login;
/**
 * Get current user profile
 */
const getProfile = (req, res, next) => {
    try {
        // User is attached to request by auth middleware
        if (!req.user) {
            throw new error_middleware_1.ApiError(types_1.HttpStatus.UNAUTHORIZED, 'Not authenticated');
        }
        // Find user by id
        const user = users.find(user => user.id === req.user?.id);
        if (!user) {
            throw new error_middleware_1.ApiError(types_1.HttpStatus.NOT_FOUND, 'User not found');
        }
        // Remove password from response
        const { password: _, ...userWithoutPassword } = user;
        const response = {
            success: true,
            data: userWithoutPassword
        };
        res.status(types_1.HttpStatus.OK).json(response);
    }
    catch (error) {
        next(error);
    }
};
exports.getProfile = getProfile;
/**
 * Refresh access token
 */
const refreshToken = (req, res, next) => {
    try {
        // User is attached to request by auth middleware
        if (!req.user) {
            throw new error_middleware_1.ApiError(types_1.HttpStatus.UNAUTHORIZED, 'Not authenticated');
        }
        // Generate new access token
        const payload = {
            id: req.user.id,
            email: req.user.email,
            role: req.user.role
        };
        const accessToken = (0, jwt_utils_1.generateToken)(payload);
        const response = {
            success: true,
            data: { accessToken },
            message: 'Token refreshed successfully'
        };
        res.status(types_1.HttpStatus.OK).json(response);
    }
    catch (error) {
        next(error);
    }
};
exports.refreshToken = refreshToken;
