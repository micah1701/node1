import { Router } from 'express';
import { body, param, query } from 'express-validator';
import * as keychainController from '../controllers/keychain.controller';
import { validate } from '../../core/middlewares/validation.middleware';
import { authenticate } from '../../core/middlewares/auth.middleware';

const router = Router();

// Validation rules
const createAppValidation = [
  body('account_id').notEmpty().withMessage('Account ID is required'),
  body('account_secret').isLength({ min: 8 }).withMessage('Account secret must be at least 8 characters long'),
  body('app_name').notEmpty().withMessage('App name is required'),
  body('encrypt_type').optional().isIn(['default', 'passphrase', 'public_key']).withMessage('Invalid encrypt type'),
  body('encrypt_public_key').optional().isInt().withMessage('Encrypt public key must be an integer')
];

const updateAppValidation = [
  param('account_id').notEmpty().withMessage('Account ID is required'),
  body('app_name').optional().notEmpty().withMessage('App name cannot be empty'),
  body('active').optional().isBoolean().withMessage('Active must be a boolean'),
  body('encrypt_type').optional().isIn(['default', 'passphrase', 'public_key']).withMessage('Invalid encrypt type'),
  body('encrypt_public_key').optional().isInt().withMessage('Encrypt public key must be an integer')
];

const addPublicKeyValidation = [
  param('account_id').notEmpty().withMessage('Account ID is required'),
  body('key_name').notEmpty().withMessage('Key name is required'),
  body('key').notEmpty().withMessage('Key is required')
];

const getPublicKeysValidation = [
  param('account_id').notEmpty().withMessage('Account ID is required'),
  query('status').optional().isIn(['active', 'previous_key', 'deleted']).withMessage('Invalid status')
];

const storePrivateKeyValidation = [
  param('account_id').notEmpty().withMessage('Account ID is required'),
  body('retrieval_id').notEmpty().withMessage('Retrieval ID is required'),
  body('private_key').notEmpty().withMessage('Private key is required')
];

const getPrivateKeyValidation = [
  param('account_id').notEmpty().withMessage('Account ID is required'),
  param('retrieval_id').notEmpty().withMessage('Retrieval ID is required')
];

const authenticateAppValidation = [
  body('account_id').notEmpty().withMessage('Account ID is required'),
  body('account_secret').notEmpty().withMessage('Account secret is required')
];

// Authentication endpoint (no JWT required)
router.post(
  '/authenticate',
  validate(authenticateAppValidation),
  keychainController.authenticateKeychainApp
);

// Protected routes (require JWT authentication)
router.post(
  '/apps',
  authenticate,
  validate(createAppValidation),
  keychainController.createKeychainApp
);

router.get(
  '/apps/:account_id',
  authenticate,
  validate([param('account_id').notEmpty().withMessage('Account ID is required')]),
  keychainController.getKeychainApp
);

router.put(
  '/apps/:account_id',
  authenticate,
  validate(updateAppValidation),
  keychainController.updateKeychainApp
);

router.post(
  '/apps/:account_id/public-keys',
  authenticate,
  validate(addPublicKeyValidation),
  keychainController.addPublicKey
);

router.get(
  '/apps/:account_id/public-keys',
  authenticate,
  validate(getPublicKeysValidation),
  keychainController.getPublicKeys
);

router.post(
  '/apps/:account_id/private-keys',
  authenticate,
  validate(storePrivateKeyValidation),
  keychainController.storePrivateKey
);

router.get(
  '/apps/:account_id/private-keys/:retrieval_id',
  authenticate,
  validate(getPrivateKeyValidation),
  keychainController.getPrivateKey
);

router.get(
  '/apps/:account_id/private-keys',
  authenticate,
  validate([param('account_id').notEmpty().withMessage('Account ID is required')]),
  keychainController.listPrivateKeys
);

export default router;