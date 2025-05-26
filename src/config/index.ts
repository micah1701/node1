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

export const config = {
  port: process.env.PORT || 3000,
  environment: process.env.NODE_ENV || 'development',
  
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