const jwt = require('jsonwebtoken');
const User = require('../models/User');
const logger = require('../utils/logger'); // Assuming a logger utility exists
const { promisify } = require('util');

/**
 * Middleware to protect routes that require authentication
 */
exports.protect = async (req, res, next) => {
  try {
    // 1. Get token from authorization header
    let token;
    if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
      token = req.headers.authorization.split(' ')[1];
    }

    if (!token) {
      return res.status(401).json({
        status: 'error',
        message: 'You are not logged in. Please log in to get access.'
      });
    }

    // 2. Verify token
    const decoded = await promisify(jwt.verify)(token, process.env.JWT_SECRET);

    // 3. Check if user still exists
    const user = await User.findById(decoded.id);
    if (!user) {
      return res.status(401).json({
        status: 'error',
        message: 'The user belonging to this token no longer exists.'
      });
    }

    // 4. Check if user changed password after token was issued
    if (user.lastPasswordChange && decoded.iat < user.lastPasswordChange.getTime() / 1000) {
      return res.status(401).json({
        status: 'error',
        message: 'User recently changed password. Please log in again.'
      });
    }

    // 5. Check if account is locked
    if (user.accountLockUntil && user.accountLockUntil > Date.now()) {
      return res.status(423).json({
        status: 'error',
        message: 'Account is temporarily locked. Please try again later.',
        lockUntil: user.accountLockUntil
      });
    }

    // Grant access to protected route
    req.user = user;
    next();
  } catch (error) {
    logger.error('Authentication error:', error);
    return res.status(401).json({
      status: 'error',
      message: 'Invalid token or authentication failed.'
    });
  }
};

/**
 * Middleware to verify email verification status
 */
exports.requireEmailVerification = async (req, res, next) => {
  if (!req.user.isEmailVerified) {
    return res.status(403).json({
      status: 'error',
      message: 'Please verify your email address to access this resource.'
    });
  }
  next();
};

/**
 * Middleware to restrict access to specific roles
 */
exports.restrictTo = (...roles) => {
  return (req, res, next) => {
    if (!roles.includes(req.user.role)) {
      return res.status(403).json({
        status: 'error',
        message: 'You do not have permission to perform this action'
      });
    }
    next();
  };
};

/**
 * Middleware to validate reCAPTCHA token
 */
exports.validateRecaptcha = async (req, res, next) => {
  try {
    const recaptchaToken = req.body.recaptchaToken;
    
    if (!recaptchaToken) {
      return res.status(400).json({
        status: 'error',
        message: 'reCAPTCHA verification failed. Please try again.'
      });
    }

    // Verify with Google reCAPTCHA API
    const response = await fetch('https://www.google.com/recaptcha/api/siteverify', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: `secret=${process.env.RECAPTCHA_SECRET_KEY}&response=${recaptchaToken}`
    });

    const data = await response.json();

    if (!data.success) {
      return res.status(400).json({
        status: 'error',
        message: 'reCAPTCHA verification failed. Please try again.'
      });
    }

    next();
  } catch (error) {
    logger.error('reCAPTCHA verification error:', error);
    return res.status(500).json({
      status: 'error',
      message: 'Error verifying reCAPTCHA. Please try again.'
    });
  }
};

/**
 * Middleware to check password strength
 */
exports.checkPasswordStrength = (req, res, next) => {
  const password = req.body.password;
  
  if (!password) {
    return res.status(400).json({
      status: 'error',
      message: 'Password is required'
    });
  }

  // Password strength requirements
  const minLength = 8;
  const hasUpperCase = /[A-Z]/.test(password);
  const hasLowerCase = /[a-z]/.test(password);
  const hasNumbers = /\d/.test(password);
  const hasSpecialChar = /[!@#$%^&*(),.?":{}|<>]/.test(password);

  const errors = [];
  if (password.length < minLength) errors.push(`Password must be at least ${minLength} characters long`);
  if (!hasUpperCase) errors.push('Password must contain at least one uppercase letter');
  if (!hasLowerCase) errors.push('Password must contain at least one lowercase letter');
  if (!hasNumbers) errors.push('Password must contain at least one number');
  if (!hasSpecialChar) errors.push('Password must contain at least one special character');

  if (errors.length > 0) {
    return res.status(400).json({
      status: 'error',
      message: 'Password does not meet strength requirements',
      errors
    });
  }

  next();
};

/**
 * Middleware to rate limit requests
 */
exports.rateLimit = {
  loginAttempts: async (req, res, next) => {
    try {
      const user = await User.findOne({ email: req.body.email });
      
      if (user && user.accountLockUntil && user.accountLockUntil > Date.now()) {
        return res.status(423).json({
          status: 'error',
          message: 'Account is temporarily locked due to too many failed attempts. Please try again later.',
          lockUntil: user.accountLockUntil
        });
      }
      
      next();
    } catch (error) {
      logger.error('Rate limit check error:', error);
      next(error);
    }
  }
};