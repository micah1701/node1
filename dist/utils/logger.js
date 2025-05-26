"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.logger = void 0;
const winston_1 = __importDefault(require("winston"));
const config_1 = require("../config");
// Create winston logger instance
exports.logger = winston_1.default.createLogger({
    level: config_1.config.logging.level,
    format: winston_1.default.format.combine(winston_1.default.format.timestamp(), winston_1.default.format.json()),
    defaultMeta: { service: 'api-service' },
    transports: [
        new winston_1.default.transports.Console({
            format: winston_1.default.format.combine(winston_1.default.format.colorize(), winston_1.default.format.simple())
        })
    ]
});
// Add file transports in production
if (config_1.config.environment === 'production') {
    exports.logger.add(new winston_1.default.transports.File({ filename: 'error.log', level: 'error' }));
    exports.logger.add(new winston_1.default.transports.File({ filename: 'combined.log' }));
}
