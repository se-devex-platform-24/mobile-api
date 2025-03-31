const { check, validationResult } = require('express-validator');
const logger = require('../utils/logger');

// Validation middleware for user registration
const validateRegistration = [
  check('username')
    .trim()
    .notEmpty().withMessage('Username is required')
    .isLength({ min: 3 }).withMessage('Username must be at least 3 characters long')
    .matches(/^[a-zA-Z0-9_]+$/).withMessage('Username can only contain letters, numbers and underscores'),
    
  check('email')
    .trim()
    .notEmpty().withMessage('Email is required')
    .isEmail().withMessage('Please enter a valid email address')
    .normalizeEmail(),
    
  check('password')
    .trim()
    .notEmpty().withMessage('Password is required')
    .isLength({ min: 8 }).withMessage('Password must be at least 8 characters long')
    .matches(/^(?=.*[A-Za-z])(?=.*\d)(?=.*[@$!%*#?&])[A-Za-z\d@$!%*#?&]{8,}$/)
    .withMessage('Password must contain at least one letter, one number and one special character'),
    
  check('confirmPassword')
    .trim()
    .notEmpty().withMessage('Password confirmation is required')
    .custom((value, { req }) => {
      if (value !== req.body.password) {
        throw new Error('Password confirmation does not match password');
      }
      return true;
    }),

  check('phoneNumber')
    .trim()
    .optional()
    .matches(/^\+?[\d\s-]+$/).withMessage('Please enter a valid phone number'),

  (req, res, next) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      logger.error('Registration validation failed', {
        userId: req.body.email,
        errors: errors.array()
      });
      return res.status(400).json({ errors: errors.array() });
    }
    next();
  }
];

// Validation middleware for login
const validateLogin = [
  check('email')
    .trim()
    .notEmpty().withMessage('Email is required')
    .isEmail().withMessage('Please enter a valid email address')
    .normalizeEmail(),
    
  check('password')
    .trim()
    .notEmpty().withMessage('Password is required'),

  (req, res, next) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      logger.error('Login validation failed', {
        userId: req.body.email,
        errors: errors.array()
      });
      return res.status(400).json({ errors: errors.array() });
    }
    next();
  }
];

// Validation middleware for password reset request
const validatePasswordResetRequest = [
  check('email')
    .trim()
    .notEmpty().withMessage('Email is required')
    .isEmail().withMessage('Please enter a valid email address')
    .normalizeEmail(),

  (req, res, next) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      logger.error('Password reset request validation failed', {
        userId: req.body.email,
        errors: errors.array()
      });
      return res.status(400).json({ errors: errors.array() });
    }
    next();
  }
];

// Validation middleware for password reset
const validatePasswordReset = [
  check('password')
    .trim()
    .notEmpty().withMessage('Password is required')
    .isLength({ min: 8 }).withMessage('Password must be at least 8 characters long')
    .matches(/^(?=.*[A-Za-z])(?=.*\d)(?=.*[@$!%*#?&])[A-Za-z\d@$!%*#?&]{8,}$/)
    .withMessage('Password must contain at least one letter, one number and one special character'),
    
  check('confirmPassword')
    .trim()
    .notEmpty().withMessage('Password confirmation is required')
    .custom((value, { req }) => {
      if (value !== req.body.password) {
        throw new Error('Password confirmation does not match password');
      }
      return true;
    }),

  (req, res, next) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      logger.error('Password reset validation failed', {
        errors: errors.array()
      });
      return res.status(400).json({ errors: errors.array() });
    }
    next();
  }
];

// Validation middleware for profile update
const validateProfileUpdate = [
  check('username')
    .optional()
    .trim()
    .isLength({ min: 3 }).withMessage('Username must be at least 3 characters long')
    .matches(/^[a-zA-Z0-9_]+$/).withMessage('Username can only contain letters, numbers and underscores'),
    
  check('phoneNumber')
    .optional()
    .trim()
    .matches(/^\+?[\d\s-]+$/).withMessage('Please enter a valid phone number'),

  (req, res, next) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      logger.error('Profile update validation failed', {
        userId: req.user.id,
        errors: errors.array()
      });
      return res.status(400).json({ errors: errors.array() });
    }
    next();
  }
];

module.exports = {
  validateRegistration,
  validateLogin,
  validatePasswordResetRequest,
  validatePasswordReset,
  validateProfileUpdate
};