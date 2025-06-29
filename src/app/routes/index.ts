import { Router } from 'express';
import keychainRoutes from './keychain.routes';

const router = Router();

// Application-specific routes
router.use('/keychain', keychainRoutes);

// Handle 404 for app-specific routes
router.use('*', (req, res, next) => {
  // Pass through to next middleware if no app routes match
  next();
});

export default router;