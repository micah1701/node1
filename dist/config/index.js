"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.config = void 0;
const dotenv_1 = __importDefault(require("dotenv"));
// Load environment variables from .env file
dotenv_1.default.config();
if (!process.env.JWT_SECRET) {
    throw new Error('JWT_SECRET environment variable must be defined');
}
exports.config = {
    port: process.env.PORT || 3000,
    environment: process.env.NODE_ENV || 'development',
    jwt: {
        secret: process.env.JWT_SECRET,
        expiresIn: process.env.JWT_EXPIRATION || '1h',
        refreshExpiresIn: process.env.JWT_REFRESH_EXPIRATION || '7d'
    },
    logging: {
        level: process.env.LOG_LEVEL || 'info'
    }
};
