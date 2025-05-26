import { Request, Response, NextFunction } from 'express';
import { validationResult, ValidationChain } from 'express-validator';
import { ApiError } from './error.middleware';
import { HttpStatus } from '../types';

/**
 * Middleware to validate request data
 */
export const validate = (validations: ValidationChain[]) => {
  return async (req: Request, res: Response, next: NextFunction) => {
    // Run all validations
    await Promise.all(validations.map(validation => validation.run(req)));
    
    // Check for validation errors
    const errors = validationResult(req);
    
    if (!errors.isEmpty()) {
      // Extract error messages
      const errorMessages = errors.array().map(error => 
        `${error.type === 'field' ? error.path : 'value'}: ${error.msg}`
      );
      
      return next(new ApiError(HttpStatus.BAD_REQUEST, errorMessages.join(', ')));
    }
    
    next();
  };
};