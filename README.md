# TypeScript API Framework

A robust Node.js and TypeScript framework for building RESTful APIs with JWT authentication and encrypted key-value storage.

## Features

- 🔐 JWT-based authentication
- 🛣️ Express routing system
- 🔄 TypeScript for type safety
- 🛡️ Request validation
- 🚦 Middleware architecture
- 📝 Comprehensive logging
- 🔒 Security best practices
- 🔑 Encrypted key-value storage
- 🗄️ MySQL database integration

## Getting Started

### Prerequisites

- Node.js (v14+)
- npm or yarn
- MySQL server

### Installation

1. Clone the repository
2. Install dependencies

```bash
npm install
```

3. Create a `.env` file based on `.env.example`

```bash
cp .env.example .env
```

4. Update the `.env` file with your configuration:

   - Database credentials
   - JWT secret
   - Master encryption key
   - Other environment variables

5. Set up the database

```bash
npm run db:setup
```

6. Start the development server

```bash
npm run dev
```

## API Endpoints

### Authentication

- `POST /api/auth/register` - Register a new user
- `POST /api/auth/login` - Log in a user
- `GET /api/auth/profile` - Get user profile (protected)
- `POST /api/auth/refresh-token` - Refresh access token

### Key-Value Storage (Protected Routes)

- `POST /api/key-values` - Store a new key-value pair

  ```json
  {
    "key": "example_key",
    "value": "sensitive_data"
  }
  ```

- `PUT /api/key-values/:uuid` - Update an existing key-value pair

  ```json
  {
    "value": "new_sensitive_data"
  }
  ```

- `GET /api/key-values/:uuid` - Retrieve a key-value pair

## Project Structure

```
src/
├── config/       # Configuration settings
├── controllers/  # Request handlers
├── middlewares/  # Middleware functions
├── routes/       # Route definitions
├── scripts/      # Database scripts
├── types/        # TypeScript type definitions
├── utils/        # Utility functions
└── index.ts      # Application entry point
```

## Database Setup

The project uses MySQL for data storage. The database schema includes:

### Users Table

- Stores user authentication and profile information
- Tracks login attempts
- Handles API credentials

### Key-Values Table

- Securely stores encrypted key-value pairs
- Uses UUID for secure retrieval
- Tracks usage statistics

To set up the database:

1. Create a MySQL database
2. Configure database connection in `.env`
3. Run the setup script:
   ```bash
   npm run db:setup
   ```

## Security Features

- Password hashing with bcrypt
- JWT-based authentication
- Request validation
- AES-CBC encryption for sensitive data
- RSA encryption support
- Secure key derivation (PBKDF2)
- Row-level access control

## Extending the Framework

To add new features:

1. Create new controllers in the `controllers` directory
2. Define new routes in the `routes` directory
3. Import and use the routes in `routes/index.ts`

## License

MIT
