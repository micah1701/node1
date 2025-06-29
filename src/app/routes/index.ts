import { Router } from 'express';

const router = Router();

// Application-specific routes will go here
// Example:
// import userRoutes from './user.routes';
// router.use('/users', userRoutes);

// Handle 404 for app-specific routes
router.use('*', (req, res, next) => {
  // Pass through to next middleware if no app routes match
  next();
});

export default router;