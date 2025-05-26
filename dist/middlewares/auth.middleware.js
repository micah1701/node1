"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.authorize = exports.authenticate = void 0;
const error_middleware_1 = require("./error.middleware");
const types_1 = require("../types");
const jwt_utils_1 = require("../utils/jwt.utils");
/**
 * Authentication middleware to protect routes
 */
const authenticate = (req, res, next) => {
    try {
        const authHeader = req.headers.authorization;
        if (!authHeader || !authHeader.startsWith('Bearer ')) {
            throw new error_middleware_1.ApiError(types_1.HttpStatus.UNAUTHORIZED, 'Authentication required');
        }
        const token = authHeader.split(' ')[1];
        if (!token) {
            throw new error_middleware_1.ApiError(types_1.HttpStatus.UNAUTHORIZED, 'Authentication token missing');
        }
        // Verify token
        const decoded = (0, jwt_utils_1.verifyToken)(token);
        // Attach user to request
        req.user = decoded;
        next();
    }
    catch (error) {
        if (error instanceof error_middleware_1.ApiError) {
            next(error);
        }
        else {
            next(new error_middleware_1.ApiError(types_1.HttpStatus.UNAUTHORIZED, 'Invalid authentication token'));
        }
    }
};
exports.authenticate = authenticate;
/**
 * Authorization middleware to check user roles
 */
const authorize = (roles) => {
    return (req, res, next) => {
        if (!req.user) {
            return next(new error_middleware_1.ApiError(types_1.HttpStatus.UNAUTHORIZED, 'Authentication required'));
        }
        if (!roles.includes(req.user.role)) {
            return next(new error_middleware_1.ApiError(types_1.HttpStatus.FORBIDDEN, 'Insufficient permissions'));
        }
        next();
    };
};
exports.authorize = authorize;
