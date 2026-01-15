const express = require('express');
const router = express.Router();
const authController = require('../controllers/auth.controller');
const { validateBody } = require('../middlewares/validate.middleware');
const { registerSchema, loginSchema } = require('../utils/validators');
const { authenticate, authorize } = require('../middlewares/auth.middleware');

// Public
router.post('/register', validateBody(registerSchema), authController.register);
router.post('/login', validateBody(loginSchema), authController.login);

// Refresh route: rotate refresh tokens
router.post('/refresh', authController.refresh);

// Logout (clears the current refresh token)
router.post('/logout', authController.logout);

// Admin-only: create user with arbitrary role (no Employee created)
router.post('/create', authenticate, authorize('admin'), validateBody(registerSchema), authController.createUserByAdmin);
// Optional: revoke all tokens (admin or user endpoint)
router.post('/revoke', authController.revokeAll);

module.exports = router;