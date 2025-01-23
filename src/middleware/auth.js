const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const { body, validationResult } = require('express-validator');
const logger = require('../utils/logger');

// Password strength validation middleware
const validatePassword = [
  body('password')
    .isLength({ min: 8 })
    .withMessage('Password must be at least 8 characters long')
    .matches(/^(?=.*[A-Z])(?=.*[a-z])(?=.*[0-9])(?=.*[!@#$%^&*])/)
    .withMessage('Password must contain at least one uppercase letter, one lowercase letter, one number, and one special character'),
];

// User registration validation middleware
const validateRegistration = [
  body('email').isEmail().normalizeEmail().withMessage('Please enter a valid email'),
  body('username').trim().isLength({ min: 3 }).withMessage('Username must be at least 3 characters long'),
  ...validatePassword,
  body('captchaToken').notEmpty().withMessage('CAPTCHA verification required'),
];

// Authentication middleware
const authenticateToken = async (req, res, next) => {
  try {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
      return res.status(401).json({ message: 'Authentication token required' });
    }

    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;
    
    logger.info(`User ${decoded.id} authenticated successfully`);
    next();
  } catch (error) {
    logger.error(`Authentication error: ${error.message}`);
    return res.status(403).json({ message: 'Invalid or expired token' });
  }
};

// Password reset validation middleware
const validatePasswordReset = [
  body('email').isEmail().normalizeEmail().withMessage('Please enter a valid email'),
  body('token').notEmpty().withMessage('Reset token is required'),
  ...validatePassword,
];

// Profile update validation middleware
const validateProfileUpdate = [
  body('email').optional().isEmail().normalizeEmail().withMessage('Please enter a valid email'),
  body('username').optional().trim().isLength({ min: 3 }).withMessage('Username must be at least 3 characters long'),
  body('currentPassword').notEmpty().withMessage('Current password is required for verification'),
];

// Validation error handler middleware
const handleValidationErrors = (req, res, next) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    logger.warn(`Validation errors in request: ${JSON.stringify(errors.array())}`);
    return res.status(400).json({ errors: errors.array() });
  }
  next();
};

// Hash password middleware
const hashPassword = async (req, res, next) => {
  try {
    if (req.body.password) {
      const salt = await bcrypt.genSalt(10);
      req.body.password = await bcrypt.hash(req.body.password, salt);
    }
    next();
  } catch (error) {
    logger.error(`Password hashing error: ${error.message}`);
    return res.status(500).json({ message: 'Error processing password' });
  }
};

module.exports = {
  validateRegistration,
  validatePassword,
  validatePasswordReset,
  validateProfileUpdate,
  authenticateToken,
  handleValidationErrors,
  hashPassword
};