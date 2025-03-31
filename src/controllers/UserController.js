const express = require('express');
const rateLimit = require('express-rate-limit');
const { body, validationResult } = require('express-validator');
const UserRegistrationService = require('../services/UserRegistrationService');

class UserController {
    constructor() {
        this.router = express.Router();
        this.userRegistrationService = new UserRegistrationService();
        this.setupRoutes();
    }

    // Rate limiter for registration attempts
    registrationLimiter = rateLimit({
        windowMs: 60 * 60 * 1000, // 1 hour window
        max: 5, // limit each IP to 5 registration requests per window
        message: 'Too many registration attempts from this IP, please try again after an hour'
    });

    // Input validation middleware
    registrationValidation = [
        body('email')
            .isEmail()
            .normalizeEmail()
            .withMessage('Invalid email address'),
        body('password')
            .isLength({ min: 8 })
            .matches(/^(?=.*[A-Za-z])(?=.*\d)(?=.*[@$!%*#?&])[A-Za-z\d@$!%*#?&]{8,}$/)
            .withMessage('Password must be at least 8 characters long and contain letters, numbers, and special characters'),
        body('firstName')
            .trim()
            .isLength({ min: 2 })
            .withMessage('First name is required and must be at least 2 characters'),
        body('lastName')
            .trim()
            .isLength({ min: 2 })
            .withMessage('Last name is required and must be at least 2 characters'),
        body('phoneNumber')
            .optional()
            .matches(/^\+?[\d\s-]+$/)
            .withMessage('Invalid phone number format')
    ];

    setupRoutes() {
        // Register new user
        this.router.post('/register',
            this.registrationLimiter,
            this.registrationValidation,
            this.register.bind(this)
        );

        // Update user data
        this.router.put('/:userId',
            this.registrationValidation,
            this.updateUser.bind(this)
        );
    }

    /**
     * Handle user registration
     * @param {express.Request} req 
     * @param {express.Response} res 
     */
    async register(req, res) {
        try {
            // Check for validation errors
            const errors = validationResult(req);
            if (!errors.isEmpty()) {
                return res.status(400).json({ 
                    status: 'error',
                    errors: errors.array() 
                });
            }

            // Register user
            const userData = {
                email: req.body.email,
                password: req.body.password,
                firstName: req.body.firstName,
                lastName: req.body.lastName,
                phoneNumber: req.body.phoneNumber
            };

            const user = await this.userRegistrationService.registerUser(userData);

            res.status(201).json({
                status: 'success',
                data: user
            });

        } catch (error) {
            console.error('Registration error:', error);
            res.status(error.message.includes('already exists') ? 409 : 500).json({
                status: 'error',
                message: error.message
            });
        }
    }

    /**
     * Handle user data update
     * @param {express.Request} req 
     * @param {express.Response} res 
     */
    async updateUser(req, res) {
        try {
            // Check for validation errors
            const errors = validationResult(req);
            if (!errors.isEmpty()) {
                return res.status(400).json({ 
                    status: 'error',
                    errors: errors.array() 
                });
            }

            const userId = req.params.userId;
            const updateData = {
                email: req.body.email,
                firstName: req.body.firstName,
                lastName: req.body.lastName,
                phoneNumber: req.body.phoneNumber
            };

            // Only include password if it's being updated
            if (req.body.password) {
                updateData.password = req.body.password;
            }

            const updatedUser = await this.userRegistrationService.updateUserData(userId, updateData);

            res.json({
                status: 'success',
                data: updatedUser
            });

        } catch (error) {
            console.error('Update error:', error);
            res.status(error.message.includes('not found') ? 404 : 500).json({
                status: 'error',
                message: error.message
            });
        }
    }
}

module.exports = UserController;