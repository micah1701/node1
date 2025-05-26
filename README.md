# TypeScript API Framework

A robust Node.js and TypeScript framework for building RESTful APIs with JWT authentication.

## Features

- 🔐 JWT-based authentication
- 🛣️ Express routing system
- 🔄 TypeScript for type safety
- 🛡️ Request validation
- 🚦 Middleware architecture
- 📝 Comprehensive logging
- 🔒 Security best practices

## Getting Started

### Prerequisites

- Node.js (v14+)
- npm or yarn

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

4. Start the development server

```bash
npm run dev
```

## API Endpoints

### Authentication

- `POST /api/auth/register` - Register a new user
- `POST /api/auth/login` - Log in a user
- `GET /api/auth/profile` - Get user profile (protected)
- `POST /api/auth/refresh-token` - Refresh access token

## Project Structure

```
src/
├── config/       # Configuration settings
├── controllers/  # Request handlers
├── middlewares/  # Middleware functions
├── routes/       # Route definitions
├── types/        # TypeScript type definitions
├── utils/        # Utility functions
└── index.ts      # Application entry point
```

## Extending the Framework

To add new features:

1. Create new controllers in the `controllers` directory
2. Define new routes in the `routes` directory
3. Import and use the routes in `routes/index.ts`

## License

MIT