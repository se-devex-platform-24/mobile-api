/**
 * Service for handling CAPTCHA verification
 */
class CaptchaService {
    constructor() {
        this.CAPTCHA_EXPIRY_TIME = 5 * 60 * 1000; // 5 minutes in milliseconds
        this.captchaStore = new Map(); // Store captcha challenges temporarily
    }

    /**
     * Generates a new CAPTCHA challenge
     * @returns {Object} Object containing captchaId and challenge
     */
    generateCaptcha() {
        const captchaId = this._generateUniqueId();
        const challenge = this._generateChallenge();
        
        // Store the CAPTCHA with timestamp
        this.captchaStore.set(captchaId, {
            answer: challenge.answer,
            timestamp: Date.now()
        });

        return {
            captchaId,
            challenge: challenge.display
        };
    }

    /**
     * Verifies a CAPTCHA response
     * @param {string} captchaId - The ID of the CAPTCHA challenge
     * @param {string} userResponse - The user's answer to the CAPTCHA
     * @returns {boolean} True if verification successful, false otherwise
     */
    verifyCaptcha(captchaId, userResponse) {
        const captchaData = this.captchaStore.get(captchaId);
        
        if (!captchaData) {
            return false; // CAPTCHA not found
        }

        // Check if CAPTCHA has expired
        if (Date.now() - captchaData.timestamp > this.CAPTCHA_EXPIRY_TIME) {
            this.captchaStore.delete(captchaId);
            return false;
        }

        // Verify the response
        const isValid = captchaData.answer.toLowerCase() === userResponse.toLowerCase();
        
        // Clean up used CAPTCHA
        this.captchaStore.delete(captchaId);
        
        return isValid;
    }

    /**
     * Generates a unique identifier for the CAPTCHA
     * @private
     * @returns {string} Unique identifier
     */
    _generateUniqueId() {
        return Math.random().toString(36).substring(2) + Date.now().toString(36);
    }

    /**
     * Generates a CAPTCHA challenge
     * @private
     * @returns {Object} Object containing the challenge display and answer
     */
    _generateChallenge() {
        // Simple math-based CAPTCHA
        const num1 = Math.floor(Math.random() * 10);
        const num2 = Math.floor(Math.random() * 10);
        const operators = ['+', '-', '*'];
        const operator = operators[Math.floor(Math.random() * operators.length)];
        
        let answer;
        switch(operator) {
            case '+':
                answer = num1 + num2;
                break;
            case '-':
                answer = num1 - num2;
                break;
            case '*':
                answer = num1 * num2;
                break;
        }

        return {
            display: `What is ${num1} ${operator} ${num2}?`,
            answer: answer.toString()
        };
    }

    /**
     * Cleans up expired CAPTCHAs
     */
    cleanupExpiredCaptchas() {
        const now = Date.now();
        for (const [captchaId, data] of this.captchaStore.entries()) {
            if (now - data.timestamp > this.CAPTCHA_EXPIRY_TIME) {
                this.captchaStore.delete(captchaId);
            }
        }
    }
}

export default CaptchaService;