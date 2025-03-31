const bcrypt = require('bcrypt');
const UserRepository = require('../repositories/UserRepository');
const User = require('../models/User');

class UserRegistrationService {
    constructor() {
        this.userRepository = new UserRepository();
        this.SALT_ROUNDS = 10; // Number of salt rounds for bcrypt
    }

    /**
     * Register a new user with encrypted credentials
     * @param {Object} userData - User registration data
     * @returns {Promise<User>} - Newly created user object
     * @throws {Error} - If registration fails
     */
    async registerUser(userData) {
        try {
            // Validate required fields
            if (!userData.email || !userData.password) {
                throw new Error('Email and password are required');
            }

            // Check if user already exists
            const existingUser = await this.userRepository.findByEmail(userData.email);
            if (existingUser) {
                throw new Error('User with this email already exists');
            }

            // Encrypt password
            const hashedPassword = await bcrypt.hash(userData.password, this.SALT_ROUNDS);

            // Create user object with encrypted password
            const user = new User({
                email: userData.email,
                password: hashedPassword,
                firstName: userData.firstName,
                lastName: userData.lastName,
                phoneNumber: userData.phoneNumber,
                // Additional fields can be added here
            });

            // Save user to database
            const savedUser = await this.userRepository.save(user);

            // Remove sensitive data before returning
            delete savedUser.password;
            
            return savedUser;
        } catch (error) {
            throw new Error(`Registration failed: ${error.message}`);
        }
    }

    /**
     * Validate user credentials
     * @param {string} email - User email
     * @param {string} password - User password
     * @returns {Promise<boolean>} - True if credentials are valid
     */
    async validateCredentials(email, password) {
        try {
            const user = await this.userRepository.findByEmail(email);
            if (!user) {
                return false;
            }

            return await bcrypt.compare(password, user.password);
        } catch (error) {
            throw new Error(`Validation failed: ${error.message}`);
        }
    }

    /**
     * Update user registration data
     * @param {string} userId - User ID
     * @param {Object} updateData - Updated user data
     * @returns {Promise<User>} - Updated user object
     */
    async updateUserData(userId, updateData) {
        try {
            // If password is being updated, encrypt it
            if (updateData.password) {
                updateData.password = await bcrypt.hash(updateData.password, this.SALT_ROUNDS);
            }

            const updatedUser = await this.userRepository.update(userId, updateData);
            if (!updatedUser) {
                throw new Error('User not found');
            }

            // Remove sensitive data before returning
            delete updatedUser.password;
            
            return updatedUser;
        } catch (error) {
            throw new Error(`Update failed: ${error.message}`);
        }
    }
}

module.exports = UserRegistrationService;