"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const express_1 = __importDefault(require("express"));
const helmet_1 = __importDefault(require("helmet"));
const cors_1 = __importDefault(require("cors"));
const morgan_1 = __importDefault(require("morgan"));
const config_1 = require("./config");
const error_middleware_1 = require("./middlewares/error.middleware");
const routes_1 = __importDefault(require("./routes"));
const logger_1 = require("./utils/logger");
// Initialize express app
const app = (0, express_1.default)();
// Apply middlewares
app.use((0, helmet_1.default)()); // Security headers
app.use((0, cors_1.default)()); // Enable CORS
app.use(express_1.default.json()); // Parse JSON bodies
app.use(express_1.default.urlencoded({ extended: true })); // Parse URL-encoded bodies
app.use((0, morgan_1.default)('dev')); // Request logging
// Apply routes
app.use('/api', routes_1.default);
// Error handling middleware
app.use(error_middleware_1.errorHandler);
// Start server
const server = app.listen(config_1.config.port, () => {
    logger_1.logger.info(`Server running on port ${config_1.config.port} in ${config_1.config.environment} mode`);
});
process.on('SIGTERM', () => {
    logger_1.logger.info('SIGTERM signal received: closing HTTP server');
    server.close(() => {
        logger_1.logger.info('HTTP server closed');
    });
});
exports.default = app;
