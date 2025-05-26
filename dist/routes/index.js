"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const express_1 = require("express");
const auth_routes_1 = __importDefault(require("./auth.routes"));
const router = (0, express_1.Router)();
// Health check endpoint
router.get('/health', (req, res) => {
    res.json({ status: 'ok', timestamp: new Date() });
});
// Routes
router.use('/auth', auth_routes_1.default);
// Handle 404 - API endpoint not found
router.use('*', (req, res) => {
    res.status(404).json({
        success: false,
        error: 'API endpoint not found'
    });
});
exports.default = router;
