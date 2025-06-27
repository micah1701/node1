import express from 'express';
import helmet from 'helmet';
import cors from 'cors';
import morgan from 'morgan';
import { config } from './config';
import { errorHandler } from './middlewares/error.middleware';
import routes from './routes';
import { logger } from './utils/logger';
import { testDatabaseConnection, isDatabaseConnected } from './utils/db';

// Initialize express app
const app = express();

// Apply middlewares
app.use(helmet()); // Security headers
app.use(cors()); // Enable CORS
app.use(express.json()); // Parse JSON bodies
app.use(express.urlencoded({ extended: true })); // Parse URL-encoded bodies
app.use(morgan('dev')); // Request logging

// Health check endpoint (should work without database)
app.get('/api/health', (req, res) => {
  const dbStatus = isDatabaseConnected();
  res.json({
    status: 'ok',
    timestamp: new Date().toISOString(),
    database: dbStatus ? 'connected' : 'disconnected',
    environment: config.environment
  });
});

// Apply routes
app.use('/api', routes);

// Error handling middleware
app.use(errorHandler);

// Start server
const server = app.listen(config.port, async () => {
  logger.info(`Server running on port ${config.port} in ${config.environment} mode`);
  
  // Test database connection after server starts (non-blocking)
  await testDatabaseConnection();
});

process.on('SIGTERM', () => {
  logger.info('SIGTERM signal received: closing HTTP server');
  server.close(() => {
    logger.info('HTTP server closed');
  });
});

export default app;