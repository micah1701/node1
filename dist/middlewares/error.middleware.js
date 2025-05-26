"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.errorHandler = exports.ApiError = void 0;
const types_1 = require("../types");
const logger_1 = require("../utils/logger");
// Custom error class for API errors
class ApiError extends Error {
    constructor(statusCode, message) {
        super(message);
        this.statusCode = statusCode;
        this.name = this.constructor.name;
        Error.captureStackTrace(this, this.constructor);
    }
}
exports.ApiError = ApiError;
// Error handling middleware
const errorHandler = (err, req, res, 
// eslint-disable-next-line @typescript-eslint/no-unused-vars
next) => {
    let statusCode = types_1.HttpStatus.INTERNAL_SERVER_ERROR;
    let message = 'Internal Server Error';
    if (err instanceof ApiError) {
        statusCode = err.statusCode;
        message = err.message;
    }
    // Log error
    logger_1.logger.error(`${statusCode} - ${message} - ${req.originalUrl} - ${req.method} - ${req.ip}`);
    // Send error response
    const errorResponse = {
        success: false,
        error: message
    };
    return res.status(statusCode).json(errorResponse);
};
exports.errorHandler = errorHandler;
