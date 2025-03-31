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
                pass: config.SMTP_PASS
            }
        });
    }

    async sendVerificationEmail(userEmail, verificationToken) {
        try {
            const mailOptions = {
                from: config.FROM_EMAIL,
                to: userEmail,
                subject: 'Email Verification - MFIRST',
                html: `
                    <h2>Welcome to MFIRST!</h2>
                    <p>Please verify your email address by clicking the link below:</p>
                    <a href="${config.APP_URL}/verify-email/${verificationToken}">
                        Verify Email Address
                    </a>
                    <p>This link will expire in 24 hours.</p>
                    <p>If you did not create an account, please ignore this email.</p>
                `
            };

            const info = await this.transporter.sendMail(mailOptions);
            logger.info(`Verification email sent to ${userEmail}: ${info.messageId}`);
            return true;
        } catch (error) {
            logger.error(`Error sending verification email to ${userEmail}: ${error.message}`);
            throw new Error('Failed to send verification email');
        }
    }

    async sendPasswordResetEmail(userEmail, resetToken) {
        try {
            const mailOptions = {
                from: config.FROM_EMAIL,
                to: userEmail,
                subject: 'Password Reset Request - MFIRST',
                html: `
                    <h2>Password Reset Request</h2>
                    <p>You have requested to reset your password. Click the link below to proceed:</p>
                    <a href="${config.APP_URL}/reset-password/${resetToken}">
                        Reset Password
                    </a>
                    <p>This link will expire in 1 hour.</p>
                    <p>If you did not request a password reset, please ignore this email.</p>
                `
            };

            const info = await this.transporter.sendMail(mailOptions);
            logger.info(`Password reset email sent to ${userEmail}: ${info.messageId}`);
            return true;
        } catch (error) {
            logger.error(`Error sending password reset email to ${userEmail}: ${error.message}`);
            throw new Error('Failed to send password reset email');
        }
    }

    async sendRegistrationConfirmationEmail(userEmail, userName) {
        try {
            const mailOptions = {
                from: config.FROM_EMAIL,
                to: userEmail,
                subject: 'Welcome to MFIRST!',
                html: `
                    <h2>Welcome to MFIRST, ${userName}!</h2>
                    <p>Thank you for registering with MFIRST. Your account has been successfully created.</p>
                    <p>You can now log in to access all our features and services.</p>
                    <a href="${config.APP_URL}/login">Login to Your Account</a>
                    <p>If you have any questions or need assistance, please don't hesitate to contact our support team.</p>
                `
            };

            const info = await this.transporter.sendMail(mailOptions);
            logger.info(`Registration confirmation email sent to ${userEmail}: ${info.messageId}`);
            return true;
        } catch (error) {
            logger.error(`Error sending registration confirmation email to ${userEmail}: ${error.message}`);
            throw new Error('Failed to send registration confirmation email');
        }
    }
}

module.exports = new EmailService();