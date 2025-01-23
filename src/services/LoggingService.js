/**
 * LoggingService.js
 * Service for handling audit logging of user registration activities
 */

class LoggingService {
    constructor() {
        this.LOG_LEVELS = {
            INFO: 'INFO',
            WARNING: 'WARNING',
            ERROR: 'ERROR'
        };
    }

    /**
     * Log user registration activity
     * @param {string} userId - User identifier
     * @param {string} action - Action performed
     * @param {Object} details - Additional details about the action
     * @param {string} level - Log level (INFO, WARNING, ERROR)
     */
    logUserActivity(userId, action, details = {}, level = 'INFO') {
        const timestamp = new Date().toISOString();
        const logEntry = {
            timestamp,
            userId,
            action,
            details,
            level: this.LOG_LEVELS[level] || this.LOG_LEVELS.INFO
        };

        // TODO: Implement actual logging mechanism (e.g., database, file system, or logging service)
        console.log(JSON.stringify(logEntry));
    }

    /**
     * Log registration attempt
     * @param {string} email - User's email
     * @param {boolean} success - Whether the registration was successful
     * @param {Object} details - Additional details about the registration
     */
    logRegistrationAttempt(email, success, details = {}) {
        const level = success ? this.LOG_LEVELS.INFO : this.LOG_LEVELS.WARNING;
        this.logUserActivity(
            email,
            'REGISTRATION_ATTEMPT',
            { ...details, success },
            level
        );
    }

    /**
     * Log password reset attempt
     * @param {string} userId - User identifier
     * @param {boolean} success - Whether the password reset was successful
     * @param {Object} details - Additional details about the password reset
     */
    logPasswordReset(userId, success, details = {}) {
        const level = success ? this.LOG_LEVELS.INFO : this.LOG_LEVELS.WARNING;
        this.logUserActivity(
            userId,
            'PASSWORD_RESET',
            { ...details, success },
            level
        );
    }

    /**
     * Log profile update
     * @param {string} userId - User identifier
     * @param {Object} changes - Changes made to the profile
     */
    logProfileUpdate(userId, changes) {
        this.logUserActivity(
            userId,
            'PROFILE_UPDATE',
            { changes }
        );
    }

    /**
     * Log email verification
     * @param {string} userId - User identifier
     * @param {boolean} success - Whether the verification was successful
     * @param {Object} details - Additional details about the verification
     */
    logEmailVerification(userId, success, details = {}) {
        const level = success ? this.LOG_LEVELS.INFO : this.LOG_LEVELS.WARNING;
        this.logUserActivity(
            userId,
            'EMAIL_VERIFICATION',
            { ...details, success },
            level
        );
    }

    /**
     * Log security events (e.g., CAPTCHA validation)
     * @param {string} userId - User identifier
     * @param {string} securityEvent - Type of security event
     * @param {boolean} success - Whether the security check passed
     * @param {Object} details - Additional details about the security event
     */
    logSecurityEvent(userId, securityEvent, success, details = {}) {
        const level = success ? this.LOG_LEVELS.INFO : this.LOG_LEVELS.WARNING;
        this.logUserActivity(
            userId,
            `SECURITY_${securityEvent}`,
            { ...details, success },
            level
        );
    }
}

// Export singleton instance
export default new LoggingService();