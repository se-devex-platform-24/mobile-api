const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { validationResult } = require('express-validator');
const UserService = require('../services/UserService');
const EmailService = require('../services/EmailService');
const CaptchaService = require('../services/CaptchaService');
const logger = require('../utils/logger');
const { ValidationError, ConflictError } = require('../utils/errors');

class UserController {
  constructor() {
    this.userService = new UserService();
    this.emailService = new EmailService();
    this.captchaService = new CaptchaService();
  }

  /**
   * Register a new user
   * @param {Request} req - Express request object
   * @param {Response} res - Express response object
   * @param {NextFunction} next - Express next middleware function
   */
  async registerUser(req, res, next) {
    try {
      // Validate request body
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        throw new ValidationError('Invalid input data', errors.array());
      }

      const { email, password, firstName, lastName, phoneNumber, captchaToken } = req.body;

      // Verify CAPTCHA
      const isCaptchaValid = await this.captchaService.verify(captchaToken);
      if (!isCaptchaValid) {
        throw new ValidationError('Invalid CAPTCHA');
      }

      // Validate password strength
      this.validatePasswordStrength(password);

      // Check if email already exists
      const existingUser = await this.userService.findByEmail(email);
      if (existingUser) {
        throw new ConflictError('Email already registered');
      }

      // Hash password
      const hashedPassword = await bcrypt.hash(password, 10);

      // Create user
      const user = await this.userService.create({
        email,
        password: hashedPassword,
        firstName,
        lastName,
        phoneNumber,
        isEmailVerified: false
      });

      // Generate email verification token
      const verificationToken = this.generateVerificationToken(user.id);

      // Send verification email
      await this.emailService.sendVerificationEmail(email, verificationToken);

      // Log registration
      logger.info(`New user registered: ${user.id}`, { userId: user.id, email });

      // Return success response
      res.status(201).json({
        id: user.id,
        email: user.email,
        message: 'Registration successful. Please check your email to verify your account.'
      });
    } catch (error) {
      next(error);
    }
  }

  /**
   * Verify user email
   * @param {Request} req - Express request object
   * @param {Response} res - Express response object
   * @param {NextFunction} next - Express next middleware function
   */
  async verifyEmail(req, res, next) {
    try {
      const { token } = req.params;

      // Verify token
      const decoded = jwt.verify(token, process.env.JWT_SECRET);
      
      // Update user verification status
      await this.userService.verifyEmail(decoded.userId);

      // Log verification
      logger.info(`Email verified for user: ${decoded.userId}`);

      res.json({ message: 'Email verification successful' });
    } catch (error) {
      next(error);
    }
  }

  /**
   * Request password reset
   * @param {Request} req - Express request object
   * @param {Response} res - Express response object
   * @param {NextFunction} next - Express next middleware function
   */
  async requestPasswordReset(req, res, next) {
    try {
      const { email } = req.body;

      const user = await this.userService.findByEmail(email);
      if (!user) {
        // Return success even if email doesn't exist for security
        return res.json({ message: 'If your email exists in our system, you will receive a password reset link.' });
      }

      // Generate password reset token
      const resetToken = this.generateResetToken(user.id);

      // Send password reset email
      await this.emailService.sendPasswordResetEmail(email, resetToken);

      // Log password reset request
      logger.info(`Password reset requested for user: ${user.id}`);

      res.json({ message: 'If your email exists in our system, you will receive a password reset link.' });
    } catch (error) {
      next(error);
    }
  }

  /**
   * Reset password using token
   * @param {Request} req - Express request object
   * @param {Response} res - Express response object
   * @param {NextFunction} next - Express next middleware function
   */
  async resetPassword(req, res, next) {
    try {
      const { token } = req.params;
      const { newPassword } = req.body;

      // Verify token
      const decoded = jwt.verify(token, process.env.JWT_SECRET);

      // Validate new password strength
      this.validatePasswordStrength(newPassword);

      // Hash new password
      const hashedPassword = await bcrypt.hash(newPassword, 10);

      // Update password
      await this.userService.updatePassword(decoded.userId, hashedPassword);

      // Log password reset
      logger.info(`Password reset completed for user: ${decoded.userId}`);

      res.json({ message: 'Password has been successfully reset' });
    } catch (error) {
      next(error);
    }
  }

  /**
   * Validate password strength
   * @param {string} password - Password to validate
   * @throws {ValidationError} If password doesn't meet requirements
   */
  validatePasswordStrength(password) {
    const minLength = 8;
    const hasUpperCase = /[A-Z]/.test(password);
    const hasLowerCase = /[a-z]/.test(password);
    const hasNumbers = /\d/.test(password);
    const hasSpecialChar = /[!@#$%^&*(),.?":{}|<>]/.test(password);

    if (
      password.length < minLength ||
      !hasUpperCase ||
      !hasLowerCase ||
      !hasNumbers ||
      !hasSpecialChar
    ) {
      throw new ValidationError(
        'Password must be at least 8 characters long and contain at least one uppercase letter, one lowercase letter, one number, and one special character'
      );
    }
  }

  /**
   * Generate email verification token
   * @param {string} userId - User ID
   * @returns {string} JWT token
   */
  generateVerificationToken(userId) {
    return jwt.sign(
      { userId, purpose: 'email-verification' },
      process.env.JWT_SECRET,
      { expiresIn: '24h' }
    );
  }

  /**
   * Generate password reset token
   * @param {string} userId - User ID
   * @returns {string} JWT token
   */
  generateResetToken(userId) {
    return jwt.sign(
      { userId, purpose: 'password-reset' },
      process.env.JWT_SECRET,
      { expiresIn: '1h' }
    );
  }
}

module.exports = new UserController();