package services

import (
	"bytes"
	"fmt"
	"html/template"
	"log"
	"net/smtp"
	"time"
)

// EmailConfig holds the configuration for email service
type EmailConfig struct {
	Host     string
	Port     int
	Username string
	Password string
	From     string
}

// EmailServiceImpl handles all email related operations
type EmailServiceImpl struct {
	config EmailConfig
}

// NewEmailService creates a new instance of EmailService
func NewEmailService(config EmailConfig) *EmailServiceImpl {
	return &EmailServiceImpl{
		config: config,
	}
}

// SendVerificationEmail sends an email with verification link to the user
func (s *EmailServiceImpl) SendVerificationEmail(email string, token string) error {
	subject := "Verify Your Email Address - MFIRST"
	verificationLink := fmt.Sprintf("https://app.mfirst.com/verify-email?token=%s", token)
	
	body := s.generateVerificationEmailBody(verificationLink)
	
	return s.sendEmail(email, subject, body)
}

// SendPasswordResetEmail sends an email with password reset link
func (s *EmailServiceImpl) SendPasswordResetEmail(email string, resetLink string) error {
	subject := "Password Reset Request - MFIRST"
	
	body := s.generatePasswordResetEmailBody(resetLink)
	
	return s.sendEmail(email, subject, body)
}

// SendWelcomeEmail sends a welcome email to newly registered users
func (s *EmailServiceImpl) SendWelcomeEmail(email string) error {
	subject := "Welcome to MFIRST!"
	
	body := s.generateWelcomeEmailBody()
	
	return s.sendEmail(email, subject, body)
}

// sendEmail handles the actual email sending logic
func (s *EmailServiceImpl) sendEmail(to string, subject string, body string) error {
	// Log email sending attempt for audit
	log.Printf("[EMAIL] Sending email to %s with subject: %s at %s", to, subject, time.Now().Format(time.RFC3339))
	
	auth := smtp.PlainAuth("", s.config.Username, s.config.Password, s.config.Host)
	
	mime := "MIME-version: 1.0;\nContent-Type: text/html; charset=\"UTF-8\";\n\n"
	msg := fmt.Sprintf("Subject: %s\nFrom: %s\nTo: %s\n%s\n%s", 
		subject, 
		s.config.From, 
		to,
		mime,
		body,
	)
	
	addr := fmt.Sprintf("%s:%d", s.config.Host, s.config.Port)
	err := smtp.SendMail(addr, auth, s.config.From, []string{to}, []byte(msg))
	if err != nil {
		log.Printf("[EMAIL ERROR] Failed to send email to %s: %v", to, err)
		return fmt.Errorf("error sending email: %v", err)
	}
	
	log.Printf("[EMAIL] Successfully sent email to %s", to)
	return nil
}

// generateVerificationEmailBody creates the HTML body for verification emails
func (s *EmailServiceImpl) generateVerificationEmailBody(verificationLink string) string {
	template := `
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Verify Your Email</title>
    <style>
        body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
        .container { max-width: 600px; margin: 0 auto; padding: 20px; }
        .header { background-color: #007bff; color: white; padding: 20px; text-align: center; }
        .content { padding: 20px; background-color: #f9f9f9; }
        .button { display: inline-block; padding: 12px 24px; background-color: #007bff; color: white; text-decoration: none; border-radius: 4px; margin: 20px 0; }
        .footer { padding: 20px; text-align: center; font-size: 12px; color: #666; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Welcome to MFIRST!</h1>
        </div>
        <div class="content">
            <h2>Verify Your Email Address</h2>
            <p>Thank you for registering with MFIRST. To complete your registration and start using our mobile app, please verify your email address by clicking the button below:</p>
            
            <a href="%s" class="button">Verify Email Address</a>
            
            <p>If the button doesn't work, you can copy and paste this link into your browser:</p>
            <p><a href="%s">%s</a></p>
            
            <p><strong>Important:</strong> This verification link will expire in 24 hours for security reasons.</p>
            
            <p>If you didn't create an account with MFIRST, please ignore this email.</p>
        </div>
        <div class="footer">
            <p>© 2023 MFIRST. All rights reserved.</p>
            <p>This is an automated message, please do not reply to this email.</p>
        </div>
    </div>
</body>
</html>`
	
	return fmt.Sprintf(template, verificationLink, verificationLink, verificationLink)
}

// generatePasswordResetEmailBody creates the HTML body for password reset emails
func (s *EmailServiceImpl) generatePasswordResetEmailBody(resetLink string) string {
	template := `
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Password Reset Request</title>
    <style>
        body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
        .container { max-width: 600px; margin: 0 auto; padding: 20px; }
        .header { background-color: #dc3545; color: white; padding: 20px; text-align: center; }
        .content { padding: 20px; background-color: #f9f9f9; }
        .button { display: inline-block; padding: 12px 24px; background-color: #dc3545; color: white; text-decoration: none; border-radius: 4px; margin: 20px 0; }
        .footer { padding: 20px; text-align: center; font-size: 12px; color: #666; }
        .warning { background-color: #fff3cd; border: 1px solid #ffeaa7; padding: 15px; border-radius: 4px; margin: 15px 0; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Password Reset Request</h1>
        </div>
        <div class="content">
            <h2>Reset Your Password</h2>
            <p>We received a request to reset your password for your MFIRST account. If you made this request, click the button below to reset your password:</p>
            
            <a href="%s" class="button">Reset Password</a>
            
            <p>If the button doesn't work, you can copy and paste this link into your browser:</p>
            <p><a href="%s">%s</a></p>
            
            <div class="warning">
                <p><strong>Security Notice:</strong></p>
                <ul>
                    <li>This password reset link will expire in 24 hours</li>
                    <li>If you didn't request this password reset, please ignore this email</li>
                    <li>Your password will remain unchanged until you create a new one</li>
                </ul>
            </div>
            
            <p>For security reasons, we recommend choosing a strong password that includes:</p>
            <ul>
                <li>At least 8 characters</li>
                <li>One uppercase letter</li>
                <li>One lowercase letter</li>
                <li>One number</li>
                <li>One special character</li>
            </ul>
        </div>
        <div class="footer">
            <p>© 2023 MFIRST. All rights reserved.</p>
            <p>This is an automated message, please do not reply to this email.</p>
        </div>
    </div>
</body>
</html>`
	
	return fmt.Sprintf(template, resetLink, resetLink, resetLink)
}

// generateWelcomeEmailBody creates the HTML body for welcome emails
func (s *EmailServiceImpl) generateWelcomeEmailBody() string {
	template := `
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Welcome to MFIRST</title>
    <style>
        body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
        .container { max-width: 600px; margin: 0 auto; padding: 20px; }
        .header { background-color: #28a745; color: white; padding: 20px; text-align: center; }
        .content { padding: 20px; background-color: #f9f9f9; }
        .button { display: inline-block; padding: 12px 24px; background-color: #28a745; color: white; text-decoration: none; border-radius: 4px; margin: 20px 0; }
        .footer { padding: 20px; text-align: center; font-size: 12px; color: #666; }
        .feature { background-color: white; padding: 15px; margin: 10px 0; border-radius: 4px; border-left: 4px solid #28a745; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🎉 Welcome to MFIRST!</h1>
        </div>
        <div class="content">
            <h2>Your email has been verified successfully!</h2>
            <p>Congratulations! Your MFIRST account is now active and ready to use. You can now log in to the mobile app and start exploring all the features we have to offer.</p>
            
            <h3>What's Next?</h3>
            <div class="feature">
                <h4>📱 Download the Mobile App</h4>
                <p>Get the MFIRST mobile app from your device's app store to access all features on the go.</p>
            </div>
            
            <div class="feature">
                <h4>👤 Complete Your Profile</h4>
                <p>Add more information to your profile to personalize your experience.</p>
            </div>
            
            <div class="feature">
                <h4>🔒 Security Settings</h4>
                <p>Review your security settings and enable additional protection features.</p>
            </div>
            
            <a href="https://app.mfirst.com/login" class="button">Login to Your Account</a>
            
            <h3>Need Help?</h3>
            <p>If you have any questions or need assistance, our support team is here to help:</p>
            <ul>
                <li>📧 Email: support@mfirst.com</li>
                <li>📞 Phone: 1-800-MFIRST</li>
                <li>💬 Live Chat: Available in the mobile app</li>
            </ul>
        </div>
        <div class="footer">
            <p>© 2023 MFIRST. All rights reserved.</p>
            <p>This is an automated message, please do not reply to this email.</p>
        </div>
    </div>
</body>
</html>`
	
	return template
}

// MockEmailService is a mock implementation for testing
type MockEmailService struct {
	SentEmails []MockEmail
}

type MockEmail struct {
	To      string
	Subject string
	Type    string
	Token   string
}

func NewMockEmailService() *MockEmailService {
	return &MockEmailService{
		SentEmails: make([]MockEmail, 0),
	}
}

func (m *MockEmailService) SendVerificationEmail(email, token string) error {
	m.SentEmails = append(m.SentEmails, MockEmail{
		To:      email,
		Subject: "Verification",
		Type:    "verification",
		Token:   token,
	})
	log.Printf("[MOCK EMAIL] Verification email sent to %s with token %s", email, token)
	return nil
}

func (m *MockEmailService) SendWelcomeEmail(email string) error {
	m.SentEmails = append(m.SentEmails, MockEmail{
		To:      email,
		Subject: "Welcome",
		Type:    "welcome",
	})
	log.Printf("[MOCK EMAIL] Welcome email sent to %s", email)
	return nil
}

func (m *MockEmailService) SendPasswordResetEmail(email, resetLink string) error {
	m.SentEmails = append(m.SentEmails, MockEmail{
		To:      email,
		Subject: "Password Reset",
		Type:    "password_reset",
		Token:   resetLink,
	})
	log.Printf("[MOCK EMAIL] Password reset email sent to %s with link %s", email, resetLink)
	return nil
}