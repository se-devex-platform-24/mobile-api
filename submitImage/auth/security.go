package auth

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"strings"
	"time"

	"github.com/google/uuid"
)

// SecurityEvent types
const (
	EventUserRegistered      = "user_registered"
	EventUserLogin           = "user_login"
	EventUserLoginFailed     = "user_login_failed"
	EventUserLogout          = "user_logout"
	EventPasswordChanged     = "password_changed"
	EventPasswordResetRequest = "password_reset_request"
	EventPasswordReset       = "password_reset"
	EventMFAEnabled          = "mfa_enabled"
	EventMFADisabled         = "mfa_disabled"
	EventMFAVerified         = "mfa_verified"
	EventMFAFailed           = "mfa_failed"
	EventAccountLocked       = "account_locked"
	EventAccountUnlocked     = "account_unlocked"
	EventSuspiciousActivity  = "suspicious_activity"
	EventRateLimitExceeded   = "rate_limit_exceeded"
	EventTokenRefreshed      = "token_refreshed"
	EventSessionExpired      = "session_expired"
)

// Security severity levels
const (
	SeverityInfo     = "info"
	SeverityWarning  = "warning"
	SeverityError    = "error"
	SeverityCritical = "critical"
)

// SecurityLogger handles security event logging
type SecurityLogger struct {
	logChannel chan SecurityLog
}

// NewSecurityLogger creates a new security logger
func NewSecurityLogger() *SecurityLogger {
	sl := &SecurityLogger{
		logChannel: make(chan SecurityLog, 1000), // Buffer for 1000 logs
	}

	// Start log processing goroutine
	go sl.processLogs()

	return sl
}

// LogEvent logs a security event
func (sl *SecurityLogger) LogEvent(ctx context.Context, event string, userID string, ipAddress string, userAgent string, severity string, details map[string]interface{}) {
	logEntry := SecurityLog{
		ID:        uuid.New().String(),
		UserID:    userID,
		Event:     event,
		IPAddress: ipAddress,
		UserAgent: userAgent,
		Timestamp: time.Now(),
		Details:   details,
		Severity:  severity,
	}

	select {
	case sl.logChannel <- logEntry:
		// Log sent successfully
	default:
		// Channel is full, log to stderr
		log.Printf("Security log channel full, dropping log: %+v", logEntry)
	}
}

// processLogs processes security logs (in production, this would write to a secure log store)
func (sl *SecurityLogger) processLogs() {
	for logEntry := range sl.logChannel {
		// In production, this would write to a secure logging system
		// For now, we'll just log to stdout
		log.Printf("SECURITY_LOG: %s | %s | %s | %s | %s | %v",
			logEntry.Timestamp.Format(time.RFC3339),
			logEntry.Severity,
			logEntry.Event,
			logEntry.UserID,
			logEntry.IPAddress,
			logEntry.Details,
		)

		// In production, you would also:
		// 1. Write to a secure log aggregation system (e.g., ELK stack)
		// 2. Send alerts for critical events
		// 3. Store in a tamper-proof audit log
		// 4. Implement log rotation and retention policies
	}
}

// Close closes the security logger
func (sl *SecurityLogger) Close() {
	close(sl.logChannel)
}

// SecurityValidator provides security validation functions
type SecurityValidator struct {
	trustedProxies []net.IPNet
}

// NewSecurityValidator creates a new security validator
func NewSecurityValidator(trustedProxies []string) *SecurityValidator {
	var ipNets []net.IPNet
	for _, proxy := range trustedProxies {
		_, ipNet, err := net.ParseCIDR(proxy)
		if err != nil {
			log.Printf("Invalid trusted proxy CIDR: %s", proxy)
			continue
		}
		ipNets = append(ipNets, *ipNet)
	}

	return &SecurityValidator{
		trustedProxies: ipNets,
	}
}

// GetRealIP extracts the real client IP from request headers
func (sv *SecurityValidator) GetRealIP(remoteAddr string, xForwardedFor string, xRealIP string) string {
	// Parse remote address
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		host = remoteAddr
	}

	clientIP := net.ParseIP(host)
	if clientIP == nil {
		return host
	}

	// If the request is from a trusted proxy, check forwarded headers
	if sv.isFromTrustedProxy(clientIP) {
		// Check X-Real-IP first
		if xRealIP != "" {
			if realIP := net.ParseIP(xRealIP); realIP != nil {
				return realIP.String()
			}
		}

		// Check X-Forwarded-For
		if xForwardedFor != "" {
			ips := strings.Split(xForwardedFor, ",")
			for _, ip := range ips {
				ip = strings.TrimSpace(ip)
				if parsedIP := net.ParseIP(ip); parsedIP != nil && !sv.isFromTrustedProxy(parsedIP) {
					return parsedIP.String()
				}
			}
		}
	}

	return clientIP.String()
}

// isFromTrustedProxy checks if an IP is from a trusted proxy
func (sv *SecurityValidator) isFromTrustedProxy(ip net.IP) bool {
	for _, ipNet := range sv.trustedProxies {
		if ipNet.Contains(ip) {
			return true
		}
	}
	return false
}

// ValidateUserAgent performs basic user agent validation
func (sv *SecurityValidator) ValidateUserAgent(userAgent string) bool {
	// Basic validation - reject empty or suspicious user agents
	if userAgent == "" {
		return false
	}

	// Check for common bot patterns (simplified)
	suspiciousPatterns := []string{
		"bot", "crawler", "spider", "scraper",
		"curl", "wget", "python", "go-http-client",
	}

	lowerUA := strings.ToLower(userAgent)
	for _, pattern := range suspiciousPatterns {
		if strings.Contains(lowerUA, pattern) {
			return false
		}
	}

	return true
}

// DetectSuspiciousActivity detects potentially suspicious login patterns
func (sv *SecurityValidator) DetectSuspiciousActivity(ctx context.Context, userID string, ipAddress string, userAgent string, loginHistory []LoginAttempt) bool {
	if len(loginHistory) < 2 {
		return false
	}

	// Check for rapid login attempts from different IPs
	recentAttempts := 0
	uniqueIPs := make(map[string]bool)
	cutoff := time.Now().Add(-10 * time.Minute)

	for _, attempt := range loginHistory {
		if attempt.Timestamp.After(cutoff) {
			recentAttempts++
			uniqueIPs[attempt.IPAddress] = true
		}
	}

	// Suspicious if more than 5 attempts from more than 3 different IPs in 10 minutes
	if recentAttempts > 5 && len(uniqueIPs) > 3 {
		return true
	}

	// Check for login from unusual location (simplified - in production use GeoIP)
	// This is a placeholder for geolocation-based detection
	if sv.isUnusualLocation(ipAddress, loginHistory) {
		return true
	}

	return false
}

// isUnusualLocation checks if login is from an unusual location (placeholder)
func (sv *SecurityValidator) isUnusualLocation(ipAddress string, loginHistory []LoginAttempt) bool {
	// In production, this would use GeoIP to detect logins from unusual countries/regions
	// For now, we'll just check if it's a completely new IP
	for _, attempt := range loginHistory {
		if attempt.IPAddress == ipAddress && attempt.Success {
			return false // IP has been used successfully before
		}
	}

	// If we have successful logins but none from this IP, it might be unusual
	hasSuccessfulLogins := false
	for _, attempt := range loginHistory {
		if attempt.Success {
			hasSuccessfulLogins = true
			break
		}
	}

	return hasSuccessfulLogins
}

// GenerateSecureToken generates a cryptographically secure random token
func GenerateSecureToken(length int) (string, error) {
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		return "", fmt.Errorf("failed to generate secure token: %w", err)
	}
	return hex.EncodeToString(bytes), nil
}

// HashSensitiveData hashes sensitive data for logging (one-way hash)
func HashSensitiveData(data string) string {
	// In production, use a proper cryptographic hash
	// This is a simplified version
	if len(data) == 0 {
		return ""
	}

	// Show first 2 and last 2 characters, hash the middle
	if len(data) <= 4 {
		return "****"
	}

	return data[:2] + "****" + data[len(data)-2:]
}

// ValidateSessionSecurity validates session security requirements
func ValidateSessionSecurity(ctx context.Context, sessionID string, userID string, ipAddress string, userAgent string, createdAt time.Time) error {
	// Check session age
	if time.Since(createdAt) > 24*time.Hour {
		return fmt.Errorf("session too old")
	}

	// In production, you would also check:
	// 1. Session fingerprinting (IP + User-Agent consistency)
	// 2. Concurrent session limits
	// 3. Session hijacking detection
	// 4. Device fingerprinting

	return nil
}

// EncryptionHelper provides encryption utilities for data at rest
type EncryptionHelper struct {
	key []byte
}

// NewEncryptionHelper creates a new encryption helper
func NewEncryptionHelper(key []byte) *EncryptionHelper {
	return &EncryptionHelper{
		key: key,
	}
}

// EncryptData encrypts sensitive data (placeholder - use proper encryption in production)
func (eh *EncryptionHelper) EncryptData(data string) (string, error) {
	// In production, use AES-GCM or similar authenticated encryption
	// This is a placeholder implementation
	return fmt.Sprintf("encrypted_%s", data), nil
}

// DecryptData decrypts sensitive data (placeholder - use proper decryption in production)
func (eh *EncryptionHelper) DecryptData(encryptedData string) (string, error) {
	// In production, use proper decryption
	// This is a placeholder implementation
	if strings.HasPrefix(encryptedData, "encrypted_") {
		return strings.TrimPrefix(encryptedData, "encrypted_"), nil
	}
	return encryptedData, nil
}