/**
 * LoggerService.js
 * Service for handling logging and auditing of user activities
 */

class LoggerService {
    constructor() {
        this.logLevels = {
            INFO: 'INFO',
            WARNING: 'WARNING',
            ERROR: 'ERROR',
            AUDIT: 'AUDIT'
        };
    }

    /**
     * Log user registration related activities
     * @param {string} userId - The ID of the user
     * @param {string} action - The action being performed
     * @param {Object} details - Additional details about the action
     * @param {string} status - The status of the action (success/failure)
     */
    logUserActivity(userId, action, details, status) {
        const timestamp = new Date().toISOString();
        const logEntry = {
            timestamp,
            userId,
            action,
            details,
            status,
            level: this.logLevels.AUDIT
        };

        // TODO: Implement actual logging mechanism (e.g., database, file system, external service)
        console.log(JSON.stringify(logEntry));
    }

    /**
     * Log registration attempts
     * @param {string} email - User's email
     * @param {string} status - Registration status
     * @param {Object} additionalInfo - Any additional information
     */
    logRegistrationAttempt(email, status, additionalInfo = {}) {
        this.logUserActivity(
            email,
            'USER_REGISTRATION',
            {
                ...additionalInfo,
                email
            },
            status
        );
    }

    /**
     * Log password reset attempts
     * @param {string} userId - User's ID
     * @param {string} status - Reset status
     * @param {Object} additionalInfo - Any additional information
     */
    logPasswordReset(userId, status, additionalInfo = {}) {
        this.logUserActivity(
            userId,
            'PASSWORD_RESET',
            additionalInfo,
            status
        );
    }

    /**
     * Log profile updates
     * @param {string} userId - User's ID
     * @param {Object} changes - Changes made to the profile
     * @param {string} status - Update status
     */
    logProfileUpdate(userId, changes, status) {
        this.logUserActivity(
            userId,
            'PROFILE_UPDATE',
            {
                changes
            },
            status
        );
    }

    /**
     * Log security events (e.g., failed login attempts, CAPTCHA failures)
     * @param {string} userId - User's ID or identifier
     * @param {string} eventType - Type of security event
     * @param {Object} details - Event details
     */
    logSecurityEvent(userId, eventType, details) {
        this.logUserActivity(
            userId,
            'SECURITY_EVENT',
            {
                eventType,
                ...details
            },
            'ALERT'
        );
    }

    /**
     * Log email verification events
     * @param {string} userId - User's ID
     * @param {string} status - Verification status
     * @param {Object} details - Additional details
     */
    logEmailVerification(userId, status, details = {}) {
        this.logUserActivity(
            userId,
            'EMAIL_VERIFICATION',
            details,
            status
        );
    }

    /**
     * Log general system errors
     * @param {Error} error - Error object
     * @param {string} context - Context where the error occurred
     */
    logError(error, context) {
        const logEntry = {
            timestamp: new Date().toISOString(),
            level: this.logLevels.ERROR,
            error: {
                message: error.message,
                stack: error.stack
            },
            context
        };

        // TODO: Implement error logging mechanism
        console.error(JSON.stringify(logEntry));
    }
}

module.exports = new LoggerService();