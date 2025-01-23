const bcrypt = require('bcrypt');

/**
 * Password strength requirements constants
 */
const PASSWORD_REQUIREMENTS = {
  MIN_LENGTH: 8,
  REQUIRE_UPPERCASE: true,
  REQUIRE_LOWERCASE: true,
  REQUIRE_NUMBERS: true,
  REQUIRE_SPECIAL: true,
  MIN_UNIQUE_CHARS: 6,
  SPECIAL_CHARS: '!@#$%^&*()_+-=[]{}|;:,.<>?'
};

/**
 * Validates password strength according to requirements
 * @param {string} password - The password to validate
 * @returns {Object} Object containing validation result and error messages
 */
const validatePasswordStrength = (password) => {
  const errors = [];
  
  if (!password || password.length < PASSWORD_REQUIREMENTS.MIN_LENGTH) {
    errors.push(`Password must be at least ${PASSWORD_REQUIREMENTS.MIN_LENGTH} characters long`);
  }

  if (PASSWORD_REQUIREMENTS.REQUIRE_UPPERCASE && !/[A-Z]/.test(password)) {
    errors.push('Password must contain at least one uppercase letter');
  }

  if (PASSWORD_REQUIREMENTS.REQUIRE_LOWERCASE && !/[a-z]/.test(password)) {
    errors.push('Password must contain at least one lowercase letter');
  }

  if (PASSWORD_REQUIREMENTS.REQUIRE_NUMBERS && !/\d/.test(password)) {
    errors.push('Password must contain at least one number');
  }

  if (PASSWORD_REQUIREMENTS.REQUIRE_SPECIAL && 
      !new RegExp(`[${PASSWORD_REQUIREMENTS.SPECIAL_CHARS}]`).test(password)) {
    errors.push('Password must contain at least one special character');
  }

  const uniqueChars = new Set(password).size;
  if (uniqueChars < PASSWORD_REQUIREMENTS.MIN_UNIQUE_CHARS) {
    errors.push(`Password must contain at least ${PASSWORD_REQUIREMENTS.MIN_UNIQUE_CHARS} unique characters`);
  }

  return {
    isValid: errors.length === 0,
    errors
  };
};

/**
 * Hashes a password using bcrypt
 * @param {string} password - The plain text password to hash
 * @returns {Promise<string>} The hashed password
 */
const hashPassword = async (password) => {
  const saltRounds = 10;
  return await bcrypt.hash(password, saltRounds);
};

/**
 * Verifies a password against its hash
 * @param {string} password - The plain text password to verify
 * @param {string} hash - The hashed password to compare against
 * @returns {Promise<boolean>} Whether the password matches the hash
 */
const verifyPassword = async (password, hash) => {
  return await bcrypt.compare(password, hash);
};

/**
 * Generates a secure random token for password reset
 * @param {number} length - Length of the token to generate
 * @returns {string} The generated token
 */
const generateResetToken = (length = 32) => {
  const buffer = new Uint8Array(length);
  crypto.getRandomValues(buffer);
  return Array.from(buffer)
    .map(byte => byte.toString(16).padStart(2, '0'))
    .join('');
};

/**
 * Checks if a password has been previously compromised
 * using common password lists or patterns
 * @param {string} password - The password to check
 * @returns {Promise<boolean>} Whether the password is compromised
 */
const isPasswordCompromised = async (password) => {
  // This is a placeholder for implementing actual password breach checking
  // In a production environment, this should check against known password breach databases
  // or use services like HaveIBeenPwned API
  return false;
};

module.exports = {
  validatePasswordStrength,
  hashPassword,
  verifyPassword,
  generateResetToken,
  isPasswordCompromised,
  PASSWORD_REQUIREMENTS
};