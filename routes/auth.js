const express = require('express');
const router = express.Router();
const authController = require('../controllers/AuthController');
const { protect } = require('../middleware/auth');

// Public routes
router.post('/register', authController.registrationLimiter, authController.register);
router.post('/login', authController.login);
router.get('/verify-email/:token', authController.verifyEmail);
router.post('/forgot-password', authController.forgotPassword);
router.patch('/reset-password/:token', authController.resetPassword);

// Protected routes (require authentication)
router.use(protect); // Apply authentication middleware to all routes below
router.patch('/update-profile', authController.updateProfile);
router.patch('/change-password', authController.changePassword);

module.exports = router;