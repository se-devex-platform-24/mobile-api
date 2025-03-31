// Authentication Configuration Settings

module.exports = {
  // JWT Configuration
  jwt: {
    secret: process.env.JWT_SECRET || 'your-secret-key',
    expiresIn: '24h', // Token expiration time
    refreshTokenExpiry: '7d' // Refresh token expiration
  },

  // Password Requirements
  password: {
    minLength: 8,
    requireUppercase: true,
    requireLowercase: true,
    requireNumbers: true,
    requireSpecialChars: true,
    maxAttempts: 5, // Max login attempts before temporary lockout
    lockoutDuration: 15 // Lockout duration in minutes
  },

  // Email Verification
  email: {
    verificationRequired: true,
    verificationExpiry: '24h',
    verificationTokenLength: 32,
    passwordResetExpiry: '1h'
  },

  // Security Settings
  security: {
    enableCaptcha: true,
    captchaProvider: 'recaptcha',
    captchaSecret: process.env.CAPTCHA_SECRET,
    rateLimiting: {
      windowMs: 15 * 60 * 1000, // 15 minutes
      maxRequests: 100 // requests per windowMs
    }
  },

  // Session Configuration
  session: {
    name: 'sessionId',
    secret: process.env.SESSION_SECRET || 'session-secret',
    resave: false,
    saveUninitialized: false,
    cookie: {
      secure: process.env.NODE_ENV === 'production',
      httpOnly: true,
      maxAge: 24 * 60 * 60 * 1000 // 24 hours
    }
  },

  // Logging Configuration
  logging: {
    enabled: true,
    level: 'info',
    auditEvents: [
      'registration',
      'login',
      'logout',
      'passwordReset',
      'profileUpdate',
      'emailVerification'
    ]
  },

  // User Registration Settings
  registration: {
    allowedDomains: ['*'], // Restrict email domains if needed
    requirePhoneNumber: false,
    autoActivate: false, // Require email verification before activation
    welcomeEmail: true
  }
};