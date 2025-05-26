"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const express_1 = require("express");
const express_validator_1 = require("express-validator");
const controllers_1 = require("../controllers");
const validation_middleware_1 = require("../middlewares/validation.middleware");
const auth_middleware_1 = require("../middlewares/auth.middleware");
const router = (0, express_1.Router)();
// Register validation rules
const registerValidation = [
    (0, express_validator_1.body)('email').isEmail().withMessage('Must be a valid email'),
    (0, express_validator_1.body)('password')
        .isLength({ min: 6 })
        .withMessage('Password must be at least 6 characters long'),
    (0, express_validator_1.body)('name').notEmpty().withMessage('Name is required')
];
// Login validation rules
const loginValidation = [
    (0, express_validator_1.body)('email').isEmail().withMessage('Must be a valid email'),
    (0, express_validator_1.body)('password').notEmpty().withMessage('Password is required')
];
// Routes
router.post('/register', (0, validation_middleware_1.validate)(registerValidation), controllers_1.authController.register);
router.post('/login', (0, validation_middleware_1.validate)(loginValidation), controllers_1.authController.login);
router.get('/profile', auth_middleware_1.authenticate, controllers_1.authController.getProfile);
router.post('/refresh-token', auth_middleware_1.authenticate, controllers_1.authController.refreshToken);
exports.default = router;
