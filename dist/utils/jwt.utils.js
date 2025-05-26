"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.verifyToken = exports.generateRefreshToken = exports.generateToken = void 0;
const jsonwebtoken_1 = __importDefault(require("jsonwebtoken"));
const config_1 = require("../config");
/**
 * Generate a JWT token
 */
const generateToken = (payload) => {
    return jsonwebtoken_1.default.sign(payload, config_1.config.jwt.secret, {
        expiresIn: config_1.config.jwt.expiresIn
    });
};
exports.generateToken = generateToken;
/**
 * Generate a refresh token
 */
const generateRefreshToken = (payload) => {
    return jsonwebtoken_1.default.sign(payload, config_1.config.jwt.secret, {
        expiresIn: config_1.config.jwt.refreshExpiresIn
    });
};
exports.generateRefreshToken = generateRefreshToken;
/**
 * Verify a JWT token
 */
const verifyToken = (token) => {
    return jsonwebtoken_1.default.verify(token, config_1.config.jwt.secret);
};
exports.verifyToken = verifyToken;
