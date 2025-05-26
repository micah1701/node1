import { Router } from 'express';
import authRoutes from './auth.routes';

const router = Router();

// Health check endpoint
router.get('/health', (req, res) => {
  res.json({ status: 'ok', timestamp: new Date() });
});

// Routes
router.use('/auth', authRoutes);

// Handle 404 - API endpoint not found
router.use('*', (req, res) => {
  res.status(404).json({
    success: false,
    error: 'API endpoint not found'
  });
});

export default router;