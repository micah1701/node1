"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.ApiRouter = void 0;
const express_1 = require("express");
const logger_1 = require("../utils/logger");
/**
 * A class to simplify route handling with support for all HTTP methods
 */
class ApiRouter {
    constructor(basePath = '') {
        this.router = (0, express_1.Router)();
        this.basePath = basePath;
        // Log all requests
        this.router.use((req, res, next) => {
            logger_1.logger.info(`${req.method} ${req.originalUrl}`);
            next();
        });
    }
    /**
     * Register a GET route
     */
    get(path, ...handlers) {
        this.router.get(path, handlers);
        return this;
    }
    /**
     * Register a POST route
     */
    post(path, ...handlers) {
        this.router.post(path, handlers);
        return this;
    }
    /**
     * Register a PUT route
     */
    put(path, ...handlers) {
        this.router.put(path, handlers);
        return this;
    }
    /**
     * Register a DELETE route
     */
    delete(path, ...handlers) {
        this.router.delete(path, handlers);
        return this;
    }
    /**
     * Register an OPTIONS route
     */
    options(path, ...handlers) {
        this.router.options(path, handlers);
        return this;
    }
    /**
     * Register a middleware for all routes
     */
    use(...handlers) {
        this.router.use(handlers);
        return this;
    }
    /**
     * Get the router instance
     */
    getRouter() {
        return this.router;
    }
}
exports.ApiRouter = ApiRouter;
