"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.validate = void 0;
const express_validator_1 = require("express-validator");
const error_middleware_1 = require("./error.middleware");
const types_1 = require("../types");
/**
 * Middleware to validate request data
 */
const validate = (validations) => {
    return async (req, res, next) => {
        // Run all validations
        await Promise.all(validations.map(validation => validation.run(req)));
        // Check for validation errors
        const errors = (0, express_validator_1.validationResult)(req);
        if (!errors.isEmpty()) {
            // Extract error messages
            const errorMessages = errors.array().map(error => `${error.type === 'field' ? error.path : 'value'}: ${error.msg}`);
            return next(new error_middleware_1.ApiError(types_1.HttpStatus.BAD_REQUEST, errorMessages.join(', ')));
        }
        next();
    };
};
exports.validate = validate;
