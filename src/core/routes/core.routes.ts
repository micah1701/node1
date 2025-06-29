import { Router } from 'express';
import authRoutes from './auth.routes';
import keyValueRoutes from './keyValue.routes';

const router = Router();

// Health check endpoint
router.get('/health', (req, res) => {
  res.json({ status: 'ok', timestamp: new Date() });
});

// Core framework routes
router.use('/auth', authRoutes);
router.use('/key-values', keyValueRoutes);

export default router;