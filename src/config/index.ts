import dotenv from 'dotenv';
import { SignOptions } from 'jsonwebtoken';

// Load environment variables from .env file
dotenv.config();

if (!process.env.JWT_SECRET) {
  throw new Error('JWT_SECRET environment variable must be defined');
}

if (!process.env.MASTER_ENCRYPTION_KEY) {
  throw new Error('MASTER_ENCRYPTION_KEY environment variable must be defined');
}

type JwtExpiration = SignOptions['expiresIn'];
type DatabaseType = 'mysql' | 'postgres';

export const config = {
  port: process.env.PORT || 3000,
  environment: process.env.NODE_ENV || 'development',
  
  database: {
    type: (process.env.DATABASE_TYPE || 'postgres') as DatabaseType,
    
    // MySQL configuration
    mysql: {
      host: process.env.DB_HOST || 'localhost',
      user: process.env.DB_USER || 'root',
      password: process.env.DB_PASSWORD || '',
      database: process.env.DB_NAME || '',
      port: parseInt(process.env.DB_PORT || '3306', 10)
    },
    
    // Supabase configuration
    supabase: {
      url: process.env.VITE_SUPABASE_URL || '',
      anonKey: process.env.VITE_SUPABASE_ANON_KEY || ''
    }
  },
  
  jwt: {
    secret: process.env.JWT_SECRET,
    expiresIn: (process.env.JWT_EXPIRATION || '1h') as JwtExpiration,
    refreshExpiresIn: (process.env.JWT_REFRESH_EXPIRATION || '7d') as JwtExpiration
  },
  
  encryption: {
    masterKey: process.env.MASTER_ENCRYPTION_KEY
  },
  
  logging: {
    level: process.env.LOG_LEVEL || 'info'
  }
};