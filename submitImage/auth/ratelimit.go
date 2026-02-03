package auth

import (
	"context"
	"fmt"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

const (
	// LoginRateLimit defines max login attempts per minute per IP
	LoginRateLimit = 5
	// LoginBurstLimit defines burst limit for login attempts
	LoginBurstLimit = 10
	// PasswordResetRateLimit defines max password reset requests per hour per IP
	PasswordResetRateLimit = 3
	// PasswordResetBurstLimit defines burst limit for password reset
	PasswordResetBurstLimit = 5
	// MFAVerificationRateLimit defines max MFA verification attempts per minute
	MFAVerificationRateLimit = 10
	// MFAVerificationBurstLimit defines burst limit for MFA verification
	MFAVerificationBurstLimit = 15
)

// RateLimiter manages rate limiting for various operations
type RateLimiter struct {
	loginLimiters    map[string]*rate.Limiter
	passwordLimiters map[string]*rate.Limiter
	mfaLimiters      map[string]*rate.Limiter
	mu               sync.RWMutex
	cleanupInterval  time.Duration
	lastCleanup      time.Time
}

// NewRateLimiter creates a new rate limiter
func NewRateLimiter() *RateLimiter {
	rl := &RateLimiter{
		loginLimiters:    make(map[string]*rate.Limiter),
		passwordLimiters: make(map[string]*rate.Limiter),
		mfaLimiters:      make(map[string]*rate.Limiter),
		cleanupInterval:  time.Hour,
		lastCleanup:      time.Now(),
	}

	// Start cleanup goroutine
	go rl.cleanupRoutine()

	return rl
}

// CheckLoginRateLimit checks if login is allowed for the given IP
func (rl *RateLimiter) CheckLoginRateLimit(ctx context.Context, ipAddress string) error {
	limiter := rl.getLoginLimiter(ipAddress)
	
	if !limiter.Allow() {
		return fmt.Errorf("rate limit exceeded for login attempts from IP %s", ipAddress)
	}

	return nil
}

// CheckPasswordResetRateLimit checks if password reset is allowed for the given IP
func (rl *RateLimiter) CheckPasswordResetRateLimit(ctx context.Context, ipAddress string) error {
	limiter := rl.getPasswordResetLimiter(ipAddress)
	
	if !limiter.Allow() {
		return fmt.Errorf("rate limit exceeded for password reset requests from IP %s", ipAddress)
	}

	return nil
}

// CheckMFAVerificationRateLimit checks if MFA verification is allowed for the given IP
func (rl *RateLimiter) CheckMFAVerificationRateLimit(ctx context.Context, ipAddress string) error {
	limiter := rl.getMFALimiter(ipAddress)
	
	if !limiter.Allow() {
		return fmt.Errorf("rate limit exceeded for MFA verification attempts from IP %s", ipAddress)
	}

	return nil
}

// getLoginLimiter gets or creates a login rate limiter for the IP
func (rl *RateLimiter) getLoginLimiter(ipAddress string) *rate.Limiter {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	limiter, exists := rl.loginLimiters[ipAddress]
	if !exists {
		// Create new limiter: 5 requests per minute with burst of 10
		limiter = rate.NewLimiter(rate.Every(time.Minute/LoginRateLimit), LoginBurstLimit)
		rl.loginLimiters[ipAddress] = limiter
	}

	return limiter
}

// getPasswordResetLimiter gets or creates a password reset rate limiter for the IP
func (rl *RateLimiter) getPasswordResetLimiter(ipAddress string) *rate.Limiter {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	limiter, exists := rl.passwordLimiters[ipAddress]
	if !exists {
		// Create new limiter: 3 requests per hour with burst of 5
		limiter = rate.NewLimiter(rate.Every(time.Hour/PasswordResetRateLimit), PasswordResetBurstLimit)
		rl.passwordLimiters[ipAddress] = limiter
	}

	return limiter
}

// getMFALimiter gets or creates an MFA verification rate limiter for the IP
func (rl *RateLimiter) getMFALimiter(ipAddress string) *rate.Limiter {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	limiter, exists := rl.mfaLimiters[ipAddress]
	if !exists {
		// Create new limiter: 10 requests per minute with burst of 15
		limiter = rate.NewLimiter(rate.Every(time.Minute/MFAVerificationRateLimit), MFAVerificationBurstLimit)
		rl.mfaLimiters[ipAddress] = limiter
	}

	return limiter
}

// cleanupRoutine periodically cleans up old limiters
func (rl *RateLimiter) cleanupRoutine() {
	ticker := time.NewTicker(rl.cleanupInterval)
	defer ticker.Stop()

	for range ticker.C {
		rl.cleanup()
	}
}

// cleanup removes old limiters that haven't been used recently
func (rl *RateLimiter) cleanup() {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	cutoff := now.Add(-2 * rl.cleanupInterval)

	// Clean up login limiters
	for ip, limiter := range rl.loginLimiters {
		// If limiter has full tokens and hasn't been used recently, remove it
		if limiter.Tokens() == float64(LoginBurstLimit) {
			delete(rl.loginLimiters, ip)
		}
	}

	// Clean up password reset limiters
	for ip, limiter := range rl.passwordLimiters {
		if limiter.Tokens() == float64(PasswordResetBurstLimit) {
			delete(rl.passwordLimiters, ip)
		}
	}

	// Clean up MFA limiters
	for ip, limiter := range rl.mfaLimiters {
		if limiter.Tokens() == float64(MFAVerificationBurstLimit) {
			delete(rl.mfaLimiters, ip)
		}
	}

	rl.lastCleanup = now
}

// GetRemainingAttempts returns the number of remaining attempts for login
func (rl *RateLimiter) GetRemainingAttempts(ipAddress string, limitType string) int {
	rl.mu.RLock()
	defer rl.mu.RUnlock()

	var limiter *rate.Limiter
	var burstLimit int

	switch limitType {
	case "login":
		limiter = rl.loginLimiters[ipAddress]
		burstLimit = LoginBurstLimit
	case "password_reset":
		limiter = rl.passwordLimiters[ipAddress]
		burstLimit = PasswordResetBurstLimit
	case "mfa":
		limiter = rl.mfaLimiters[ipAddress]
		burstLimit = MFAVerificationBurstLimit
	default:
		return 0
	}

	if limiter == nil {
		return burstLimit
	}

	tokens := int(limiter.Tokens())
	if tokens > burstLimit {
		tokens = burstLimit
	}

	return tokens
}

// ResetLimiter resets the rate limiter for a specific IP and type
func (rl *RateLimiter) ResetLimiter(ipAddress string, limitType string) {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	switch limitType {
	case "login":
		delete(rl.loginLimiters, ipAddress)
	case "password_reset":
		delete(rl.passwordLimiters, ipAddress)
	case "mfa":
		delete(rl.mfaLimiters, ipAddress)
	}
}

// AccountLockManager manages account locking due to failed login attempts
type AccountLockManager struct {
	maxFailedAttempts int
	lockDuration      time.Duration
}

// NewAccountLockManager creates a new account lock manager
func NewAccountLockManager(maxFailedAttempts int, lockDuration time.Duration) *AccountLockManager {
	return &AccountLockManager{
		maxFailedAttempts: maxFailedAttempts,
		lockDuration:      lockDuration,
	}
}

// ShouldLockAccount determines if an account should be locked
func (alm *AccountLockManager) ShouldLockAccount(failedAttempts int) bool {
	return failedAttempts >= alm.maxFailedAttempts
}

// GetLockUntil calculates when the account should be unlocked
func (alm *AccountLockManager) GetLockUntil() time.Time {
	return time.Now().Add(alm.lockDuration)
}

// IsAccountLocked checks if an account is currently locked
func (alm *AccountLockManager) IsAccountLocked(lockedUntil time.Time) bool {
	return time.Now().Before(lockedUntil)
}

// GetRemainingLockTime returns the remaining lock time
func (alm *AccountLockManager) GetRemainingLockTime(lockedUntil time.Time) time.Duration {
	if !alm.IsAccountLocked(lockedUntil) {
		return 0
	}
	return time.Until(lockedUntil)
}