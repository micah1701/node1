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

// Landing page route
app.get('/', (req, res) => {
  const dbStatus = isDatabaseConnected();
  
  res.send(`
    <!DOCTYPE html>
    <html lang="en">
    <head>
      <meta charset="UTF-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <title>TypeScript API Framework</title>
      <style>
        body {
          font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
          max-width: 800px;
          margin: 0 auto;
          padding: 2rem;
          line-height: 1.6;
          color: #333;
          background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
          min-height: 100vh;
        }
        .container {
          background: white;
          padding: 2rem;
          border-radius: 12px;
          box-shadow: 0 10px 30px rgba(0,0,0,0.1);
        }
        h1 {
          color: #2c3e50;
          margin-bottom: 0.5rem;
        }
        .subtitle {
          color: #7f8c8d;
          margin-bottom: 2rem;
        }
        .status {
          display: inline-block;
          padding: 0.25rem 0.75rem;
          border-radius: 20px;
          font-size: 0.875rem;
          font-weight: 500;
          margin-left: 0.5rem;
        }
        .status.connected {
          background: #d4edda;
          color: #155724;
        }
        .status.disconnected {
          background: #f8d7da;
          color: #721c24;
        }
        .endpoints {
          background: #f8f9fa;
          padding: 1.5rem;
          border-radius: 8px;
          margin: 1.5rem 0;
        }
        .endpoint {
          margin: 0.75rem 0;
          font-family: 'Monaco', 'Menlo', monospace;
          font-size: 0.9rem;
        }
        .method {
          display: inline-block;
          padding: 0.2rem 0.5rem;
          border-radius: 4px;
          font-weight: bold;
          margin-right: 0.5rem;
          min-width: 60px;
          text-align: center;
        }
        .get { background: #28a745; color: white; }
        .post { background: #007bff; color: white; }
        .put { background: #ffc107; color: #212529; }
        .footer {
          text-align: center;
          margin-top: 2rem;
          color: #6c757d;
          font-size: 0.875rem;
        }
      </style>
    </head>
    <body>
      <div class="container">
        <h1>🚀 TypeScript API Framework</h1>
        <p class="subtitle">A robust Node.js and TypeScript framework for building RESTful APIs</p>
        
        <div>
          <strong>Server Status:</strong> 
          <span class="status connected">Running</span>
        </div>
        
        <div style="margin-top: 1rem;">
          <strong>Database Status:</strong> 
          <span class="status ${dbStatus ? 'connected' : 'disconnected'}">
            ${dbStatus ? 'Connected' : 'Disconnected'}
          </span>
        </div>
        
        <div class="endpoints">
          <h3>📡 Available API Endpoints</h3>
          
          <div class="endpoint">
            <span class="method get">GET</span>
            <code>/api/health</code> - Health check endpoint
          </div>
          
          <div class="endpoint">
            <span class="method post">POST</span>
            <code>/api/auth/register</code> - Register a new user
          </div>
          
          <div class="endpoint">
            <span class="method post">POST</span>
            <code>/api/auth/login</code> - User login
          </div>
          
          <div class="endpoint">
            <span class="method get">GET</span>
            <code>/api/auth/profile</code> - Get user profile (protected)
          </div>
          
          <div class="endpoint">
            <span class="method post">POST</span>
            <code>/api/auth/refresh-token</code> - Refresh access token (protected)
          </div>
          
          <div class="endpoint">
            <span class="method post">POST</span>
            <code>/api/key-values</code> - Store key-value pair (protected)
          </div>
          
          <div class="endpoint">
            <span class="method get">GET</span>
            <code>/api/key-values/:uuid</code> - Retrieve key-value pair (protected)
          </div>
          
          <div class="endpoint">
            <span class="method put">PUT</span>
            <code>/api/key-values/:uuid</code> - Update key-value pair (protected)
          </div>
        </div>
        
        <div style="background: #e3f2fd; padding: 1rem; border-radius: 6px; margin: 1.5rem 0;">
          <strong>💡 Getting Started:</strong>
          <ul style="margin: 0.5rem 0;">
            <li>Use <code>/api/health</code> to check server status</li>
            <li>Register a user with <code>/api/auth/register</code></li>
            <li>Login to get access tokens with <code>/api/auth/login</code></li>
            <li>Include <code>Authorization: Bearer &lt;token&gt;</code> header for protected routes</li>
          </ul>
        </div>
        
        <div class="footer">
          <p>Environment: <strong>${config.environment}</strong> | Port: <strong>${config.port}</strong></p>
          <p>Built with ❤️ using TypeScript, Express, and JWT</p>
        </div>
      </div>
    </body>
    </html>
  `);
});

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