# TypeScript API Framework

A modular Node.js and TypeScript framework for building RESTful APIs with JWT authentication and encrypted key-value storage.

## 🏗️ Framework Architecture

This framework is designed with a modular architecture that separates core functionality from application-specific features:

### Core Framework (`src/core/`)
- **Authentication & Authorization** - JWT-based user management
- **Database Abstraction** - Support for MySQL and PostgreSQL (Supabase)
- **Encryption** - AES-CBC and RSA encryption utilities
- **Key-Value Storage** - Encrypted data storage system
- **Middleware** - Error handling, validation, authentication
- **Utilities** - Logging, JWT handling, database connections

### Application Layer (`src/app/`)
- **Controllers** - Application-specific business logic
- **Routes** - Custom API endpoints for your application
- **Middlewares** - App-specific middleware functions
- **Types** - Application-specific TypeScript interfaces

## Features

- 🔐 JWT-based authentication with refresh tokens
- 🛣️ Modular Express routing system
- 🔄 TypeScript for complete type safety
- 🛡️ Comprehensive request validation
- 🚦 Flexible middleware architecture
- 📝 Structured logging with Winston
- 🔒 Security best practices with Helmet
- 🔑 AES-CBC and RSA encryption support
- 🗄️ Multi-database support (MySQL/PostgreSQL)
- 📊 Dynamic table prefixing for multi-tenancy
- 🏗️ Extensible framework architecture

## Getting Started

### Prerequisites

- Node.js (v16+)
- npm or yarn
- MySQL server OR Supabase account

### Installation

1. Clone or copy this framework
2. Install dependencies:
   ```bash
   npm install
   ```

3. Create environment configuration:
   ```bash
   cp .env.example .env
   ```

4. Configure your `.env` file:
   ```env
   # Database Configuration
   DATABASE_TYPE=postgres  # or 'mysql'
   TABLE_PREFIX=myapp_     # or leave empty for no prefix
   
   # For MySQL
   DB_HOST=localhost
   DB_USER=root
   DB_PASSWORD=your_password
   DB_NAME=your_database
   
   # For Supabase
   VITE_SUPABASE_URL=your_supabase_url
   VITE_SUPABASE_ANON_KEY=your_supabase_anon_key
   
   # Security
   JWT_SECRET=your_jwt_secret_here
   MASTER_ENCRYPTION_KEY=your_master_encryption_key_here
   ```

5. Set up your database:
   ```bash
   npm run db:setup
   ```

6. Start development server:
   ```bash
   npm run dev
   ```

## Core API Endpoints

### Authentication
- `POST /api/auth/register` - Register a new user
- `POST /api/auth/login` - User login
- `GET /api/auth/profile` - Get user profile (protected)
- `POST /api/auth/refresh-token` - Refresh access token (protected)

### Key-Value Storage
- `POST /api/key-values` - Store encrypted key-value pair (protected)
- `GET /api/key-values/:uuid` - Retrieve key-value pair (protected)
- `PUT /api/key-values/:uuid` - Update key-value pair (protected)

### System
- `GET /api/health` - Health check endpoint
- `GET /` - Framework information page

## Extending the Framework

### Adding Application-Specific Features

1. **Create Controllers** in `src/app/controllers/`:
   ```typescript
   // src/app/controllers/product.controller.ts
   import { Request, Response, NextFunction } from 'express';
   import { ApiResponse, HttpStatus } from '../../core/types';
   
   export const getProducts = async (req: Request, res: Response, next: NextFunction) => {
     // Your application logic here
   };
   ```

2. **Define Routes** in `src/app/routes/`:
   ```typescript
   // src/app/routes/product.routes.ts
   import { Router } from 'express';
   import * as productController from '../controllers/product.controller';
   import { authenticate } from '../../core/middlewares/auth.middleware';
   
   const router = Router();
   router.get('/', authenticate, productController.getProducts);
   export default router;
   ```

3. **Register Routes** in `src/app/routes/index.ts`:
   ```typescript
   import { Router } from 'express';
   import productRoutes from './product.routes';
   
   const router = Router();
   router.use('/products', productRoutes);
   export default router;
   ```

### Using Core Framework Features

```typescript
// Import core utilities
import { db } from '../../core/utils/db';
import { logger } from '../../core/utils/logger';
import { authenticate } from '../../core/middlewares/auth.middleware';
import { ApiError } from '../../core/middlewares/error.middleware';
import { HttpStatus } from '../../core/types';

// Use database abstraction
const tableName = db.getTableName('my_table');
const result = await db.execute(`SELECT * FROM ${tableName}`);

// Use encryption
import { encryptWithMasterKey, decryptWithMasterKey } from '../../core/utils/encryption';
const encrypted = encryptWithMasterKey('sensitive data');
```

## Project Structure

```
src/
├── core/                 # Core framework functionality
│   ├── config/          # Configuration management
│   ├── controllers/     # Core controllers (auth, key-value)
│   ├── middlewares/     # Core middleware functions
│   ├── routes/          # Core API routes
│   ├── scripts/         # Database setup scripts
│   ├── types/           # Core TypeScript definitions
│   └── utils/           # Core utilities (db, encryption, jwt, logger)
├── app/                 # Application-specific code
│   ├── controllers/     # Your application controllers
│   ├── routes/          # Your application routes
│   ├── middlewares/     # Your application middleware
│   └── types/           # Your application types
├── routes/              # Route orchestration
└── index.ts             # Application entry point
```

## Database Support

### MySQL
- Full SQL support with connection pooling
- Automatic reconnection handling
- Transaction support

### PostgreSQL (Supabase)
- Supabase client integration
- Row Level Security (RLS) ready
- Real-time subscriptions available

### Table Prefixing
Configure `TABLE_PREFIX` in your `.env` to support:
- Multi-tenancy
- Environment separation
- Database organization

## Security Features

- **Password Hashing** - bcrypt with configurable salt rounds
- **JWT Authentication** - Access and refresh token system
- **Request Validation** - express-validator integration
- **Encryption** - AES-CBC for data, RSA for key exchange
- **Security Headers** - Helmet.js integration
- **CORS** - Configurable cross-origin resource sharing

## Development Scripts

```bash
npm run dev          # Start development server with hot reload
npm run build        # Build TypeScript to JavaScript
npm run start        # Start production server
npm run db:setup     # Set up database tables
npm run lint         # Run ESLint
npm run test         # Run tests
```

## Environment Variables

See `.env.example` for all available configuration options.

## Contributing

This framework is designed to be extended. When adding core features:

1. Add them to `src/core/`
2. Maintain backward compatibility
3. Update documentation
4. Add appropriate tests

For application-specific features, use `src/app/`.

## License

MIT License - Feel free to use this framework for your projects.