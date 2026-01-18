package services

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"time"
)

// CaptchaConfig holds the configuration for CAPTCHA service
type CaptchaConfig struct {
	SecretKey string
	SiteKey   string
	Enabled   bool
}

// CaptchaServiceImpl handles CAPTCHA verification
type CaptchaServiceImpl struct {
	config     CaptchaConfig
	httpClient *http.Client
}

// RecaptchaResponse represents the response from Google reCAPTCHA API
type RecaptchaResponse struct {
	Success     bool      `json:"success"`
	ChallengeTS time.Time `json:"challenge_ts"`
	Hostname    string    `json:"hostname"`
	ErrorCodes  []string  `json:"error-codes"`
}

// NewCaptchaService creates a new instance of CaptchaService
func NewCaptchaService(config CaptchaConfig) *CaptchaServiceImpl {
	return &CaptchaServiceImpl{
		config: config,
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

// VerifyCaptcha verifies the CAPTCHA token with Google reCAPTCHA
func (s *CaptchaServiceImpl) VerifyCaptcha(token string) error {
	if !s.config.Enabled {
		log.Printf("[CAPTCHA] CAPTCHA verification disabled, skipping")
		return nil
	}

	if token == "" {
		return errors.New("CAPTCHA token is required")
	}

	// Prepare the request to Google reCAPTCHA API
	data := url.Values{}
	data.Set("secret", s.config.SecretKey)
	data.Set("response", token)

	resp, err := s.httpClient.PostForm("https://www.google.com/recaptcha/api/siteverify", data)
	if err != nil {
		log.Printf("[CAPTCHA ERROR] Failed to verify CAPTCHA: %v", err)
		return fmt.Errorf("failed to verify CAPTCHA: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Printf("[CAPTCHA ERROR] Failed to read response: %v", err)
		return fmt.Errorf("failed to read CAPTCHA response: %w", err)
	}

	var recaptchaResp RecaptchaResponse
	if err := json.Unmarshal(body, &recaptchaResp); err != nil {
		log.Printf("[CAPTCHA ERROR] Failed to parse response: %v", err)
		return fmt.Errorf("failed to parse CAPTCHA response: %w", err)
	}

	if !recaptchaResp.Success {
		log.Printf("[CAPTCHA] Verification failed: %v", recaptchaResp.ErrorCodes)
		return errors.New("CAPTCHA verification failed")
	}

	log.Printf("[CAPTCHA] Verification successful for hostname: %s", recaptchaResp.Hostname)
	return nil
}

// MockCaptchaService is a mock implementation for testing and development
type MockCaptchaService struct {
	ShouldFail bool
	Calls      []string
}

// NewMockCaptchaService creates a new mock CAPTCHA service
func NewMockCaptchaService(shouldFail bool) *MockCaptchaService {
	return &MockCaptchaService{
		ShouldFail: shouldFail,
		Calls:      make([]string, 0),
	}
}

// VerifyCaptcha mock implementation
func (m *MockCaptchaService) VerifyCaptcha(token string) error {
	m.Calls = append(m.Calls, token)
	
	if token == "" {
		return errors.New("CAPTCHA token is required")
	}
	
	if m.ShouldFail {
		log.Printf("[MOCK CAPTCHA] Verification failed for token: %s", token)
		return errors.New("CAPTCHA verification failed")
	}
	
	log.Printf("[MOCK CAPTCHA] Verification successful for token: %s", token)
	return nil
}

// Reset clears the call history (useful for testing)
func (m *MockCaptchaService) Reset() {
	m.Calls = make([]string, 0)
}

// GetCallCount returns the number of times VerifyCaptcha was called
func (m *MockCaptchaService) GetCallCount() int {
	return len(m.Calls)
}

// GetLastToken returns the last token that was verified
func (m *MockCaptchaService) GetLastToken() string {
	if len(m.Calls) == 0 {
		return ""
	}
	return m.Calls[len(m.Calls)-1]
}