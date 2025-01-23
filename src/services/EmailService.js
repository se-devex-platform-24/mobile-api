const nodemailer = require('nodemailer');
const config = require('../config/email.config');
const logger = require('../utils/logger');

class EmailService {
    constructor() {
        this.transporter = nodemailer.createTransport({
            host: config.SMTP_HOST,
            port: config.SMTP_PORT,
            secure: config.SMTP_SECURE,
            auth: {
                user: config.SMTP_USER,
                pass: config.SMTP_PASSWORD
            }
        });
    }

    /**
     * Send verification email to user after registration
     * @param {string} to - Recipient email address
     * @param {string} verificationToken - Token for email verification
     * @returns {Promise} - Resolves when email is sent
     */
    async sendVerificationEmail(to, verificationToken) {
        try {
            const verificationLink = `${config.APP_URL}/verify-email?token=${verificationToken}`;
            
            const mailOptions = {
                from: config.FROM_EMAIL,
                to: to,
                subject: 'Verify Your Email Address',
                html: `
                    <h1>Welcome to Our Platform!</h1>
                    <p>Thank you for registering. Please verify your email address by clicking the link below:</p>
                    <a href="${verificationLink}">Verify Email Address</a>
                    <p>This link will expire in 24 hours.</p>
                    <p>If you did not create an account, please ignore this email.</p>
                `
            };

            const info = await this.transporter.sendMail(mailOptions);
            logger.info(`Verification email sent to ${to}: ${info.messageId}`);
            return info;
        } catch (error) {
            logger.error(`Error sending verification email to ${to}: ${error.message}`);
            throw new Error('Failed to send verification email');
        }
    }

    /**
     * Send password reset email to user
     * @param {string} to - Recipient email address
     * @param {string} resetToken - Token for password reset
     * @returns {Promise} - Resolves when email is sent
     */
    async sendPasswordResetEmail(to, resetToken) {
        try {
            const resetLink = `${config.APP_URL}/reset-password?token=${resetToken}`;
            
            const mailOptions = {
                from: config.FROM_EMAIL,
                to: to,
                subject: 'Password Reset Request',
                html: `
                    <h1>Password Reset Request</h1>
                    <p>You have requested to reset your password. Click the link below to set a new password:</p>
                    <a href="${resetLink}">Reset Password</a>
                    <p>This link will expire in 1 hour.</p>
                    <p>If you did not request a password reset, please ignore this email and ensure your account is secure.</p>
                `
            };

            const info = await this.transporter.sendMail(mailOptions);
            logger.info(`Password reset email sent to ${to}: ${info.messageId}`);
            return info;
        } catch (error) {
            logger.error(`Error sending password reset email to ${to}: ${error.message}`);
            throw new Error('Failed to send password reset email');
        }
    }

    /**
     * Send welcome email after successful registration
     * @param {string} to - Recipient email address
     * @param {string} username - User's name or username
     * @returns {Promise} - Resolves when email is sent
     */
    async sendWelcomeEmail(to, username) {
        try {
            const mailOptions = {
                from: config.FROM_EMAIL,
                to: to,
                subject: 'Welcome to Our Platform!',
                html: `
                    <h1>Welcome ${username}!</h1>
                    <p>Thank you for joining our platform. We're excited to have you as a member!</p>
                    <p>You can now access all our features and services.</p>
                    <p>If you have any questions or need assistance, please don't hesitate to contact our support team.</p>
                `
            };

            const info = await this.transporter.sendMail(mailOptions);
            logger.info(`Welcome email sent to ${to}: ${info.messageId}`);
            return info;
        } catch (error) {
            logger.error(`Error sending welcome email to ${to}: ${error.message}`);
            throw new Error('Failed to send welcome email');
        }
    }
}

module.exports = new EmailService();