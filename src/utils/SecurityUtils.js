const crypto = require('crypto');
const bcrypt = require('bcrypt');

class SecurityUtils {
    // Encryption key and initialization vector settings
    static ENCRYPTION_KEY = process.env.ENCRYPTION_KEY || crypto.randomBytes(32);
    static IV_LENGTH = 16;

    /**
     * Encrypts sensitive data using AES-256-CBC
     * @param {string} text - Text to encrypt
     * @returns {string} - Encrypted text in hex format with IV prepended
     */
    static encryptData(text) {
        const iv = crypto.randomBytes(SecurityUtils.IV_LENGTH);
        const cipher = crypto.createCipheriv('aes-256-cbc', Buffer.from(SecurityUtils.ENCRYPTION_KEY), iv);
        let encrypted = cipher.update(text);
        encrypted = Buffer.concat([encrypted, cipher.final()]);
        return iv.toString('hex') + ':' + encrypted.toString('hex');
    }

    /**
     * Decrypts data that was encrypted using encryptData
     * @param {string} text - Encrypted text with IV prepended
     * @returns {string} - Decrypted text
     */
    static decryptData(text) {
        const textParts = text.split(':');
        const iv = Buffer.from(textParts.shift(), 'hex');
        const encryptedText = Buffer.from(textParts.join(':'), 'hex');
        const decipher = crypto.createDecipheriv('aes-256-cbc', Buffer.from(SecurityUtils.ENCRYPTION_KEY), iv);
        let decrypted = decipher.update(encryptedText);
        decrypted = Buffer.concat([decrypted, decipher.final()]);
        return decrypted.toString();
    }

    /**
     * Hashes a password using bcrypt
     * @param {string} password - Password to hash
     * @returns {Promise<string>} - Hashed password
     */
    static async hashPassword(password) {
        const saltRounds = 10;
        return await bcrypt.hash(password, saltRounds);
    }

    /**
     * Compares a password with a hashed password
     * @param {string} password - Password to compare
     * @param {string} hashedPassword - Hashed password to compare against
     * @returns {Promise<boolean>} - True if passwords match
     */
    static async comparePassword(password, hashedPassword) {
        return await bcrypt.compare(password, hashedPassword);
    }

    /**
     * Generates a secure random token
     * @param {number} length - Length of token to generate
     * @returns {string} - Random token in hex format
     */
    static generateSecureToken(length = 32) {
        return crypto.randomBytes(length).toString('hex');
    }

    /**
     * Sanitizes user input to prevent XSS attacks
     * @param {string} input - User input to sanitize
     * @returns {string} - Sanitized input
     */
    static sanitizeInput(input) {
        return input
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#x27;')
            .replace(/\//g, '&#x2F;');
    }

    /**
     * Validates password strength
     * @param {string} password - Password to validate
     * @returns {boolean} - True if password meets strength requirements
     */
    static validatePasswordStrength(password) {
        // Password must be at least 8 characters long and contain:
        // - At least one uppercase letter
        // - At least one lowercase letter
        // - At least one number
        // - At least one special character
        const strongPasswordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/;
        return strongPasswordRegex.test(password);
    }
}

module.exports = SecurityUtils;