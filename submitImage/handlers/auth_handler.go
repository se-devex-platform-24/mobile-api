package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"submit-image/models"
	"submit-image/services"

	"github.com/aws/aws-lambda-go/events"
)

// AuthHandler handles authentication-related HTTP requests
type AuthHandler struct {
	authService    *services.AuthService
	activityLogger ActivityLogger
}

// ActivityLogger interface for logging user activities
type ActivityLogger interface {
	LogRegistrationActivity(ctx context.Context, userID, email, ipAddress, userAgent, deviceType, appVersion, status string, details map[string]interface{}, errorDetail string) error
	LogEmailVerification(ctx context.Context, userID, email, ipAddress, status string, errorDetail string) error
	LogPasswordReset(ctx context.Context, userID, email, ipAddress, status string, errorDetail string) error
	LogProfileUpdate(ctx context.Context, userID, email, ipAddress, status string, details map[string]interface{}, errorDetail string) error
}

// NewAuthHandler creates a new AuthHandler instance
func NewAuthHandler(authService *services.AuthService, activityLogger ActivityLogger) *AuthHandler {
	return &AuthHandler{
		authService:    authService,
		activityLogger: activityLogger,
	}
}

// HandleRegister processes user registration requests
func (h *AuthHandler) HandleRegister(ctx context.Context, request events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {
	// Extract client information
	ipAddress := h.getClientIP(request)
	userAgent := h.getUserAgent(request)

	// Parse request body
	var req models.UserRegistrationRequest
	if err := json.Unmarshal([]byte(request.Body), &req); err != nil {
		return h.errorResponse(http.StatusBadRequest, "INVALID_REQUEST", "Invalid request format", nil), nil
	}

	// Process registration
	user, err := h.authService.RegisterUser(ctx, &req)
	if err != nil {
		// Log failed registration attempt
		h.activityLogger.LogRegistrationActivity(
			ctx, "", req.Email, ipAddress, userAgent, req.DeviceType, req.AppVersion,
			"FAILED", map[string]interface{}{"error": err.Error()}, err.Error(),
		)

		return h.handleRegistrationError(err), nil
	}

	// Log successful registration
	h.activityLogger.LogRegistrationActivity(
		ctx, user.ID, user.Email, ipAddress, userAgent, user.DeviceType, user.AppVersion,
		"SUCCESS", map[string]interface{}{
			"firstName": user.FirstName,
			"lastName":  user.LastName,
		}, "",
	)

	// Return success response
	response := map[string]interface{}{
		"message": "Registration successful. Please check your email for verification.",
		"userId":  user.ID,
	}

	return h.successResponse(http.StatusCreated, response), nil
}

// HandleVerifyEmail processes email verification requests
func (h *AuthHandler) HandleVerifyEmail(ctx context.Context, request events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {
	ipAddress := h.getClientIP(request)

	// Parse request body
	var req struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal([]byte(request.Body), &req); err != nil {
		return h.errorResponse(http.StatusBadRequest, "INVALID_REQUEST", "Invalid request format", nil), nil
	}

	if req.Token == "" {
		return h.errorResponse(http.StatusBadRequest, "MISSING_TOKEN", "Verification token is required", nil), nil
	}

	// Process email verification
	err := h.authService.VerifyEmail(ctx, req.Token)
	if err != nil {
		// Log failed verification attempt
		h.activityLogger.LogEmailVerification(ctx, "", "", ipAddress, "FAILED", err.Error())
		return h.handleVerificationError(err), nil
	}

	// Log successful verification
	h.activityLogger.LogEmailVerification(ctx, "", "", ipAddress, "SUCCESS", "")

	response := map[string]string{
		"message": "Email verified successfully. You can now log in.",
	}

	return h.successResponse(http.StatusOK, response), nil
}

// HandleForgotPassword processes password reset requests
func (h *AuthHandler) HandleForgotPassword(ctx context.Context, request events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {
	ipAddress := h.getClientIP(request)

	// Parse request body
	var req struct {
		Email        string `json:"email"`
		CaptchaToken string `json:"captchaToken"`
	}
	if err := json.Unmarshal([]byte(request.Body), &req); err != nil {
		return h.errorResponse(http.StatusBadRequest, "INVALID_REQUEST", "Invalid request format", nil), nil
	}

	if req.Email == "" {
		return h.errorResponse(http.StatusBadRequest, "MISSING_EMAIL", "Email is required", nil), nil
	}

	if req.CaptchaToken == "" {
		return h.errorResponse(http.StatusBadRequest, "MISSING_CAPTCHA", "CAPTCHA token is required", nil), nil
	}

	// Process password reset request
	err := h.authService.RequestPasswordReset(ctx, req.Email, req.CaptchaToken)
	if err != nil {
		// Log failed password reset attempt
		h.activityLogger.LogPasswordReset(ctx, "", req.Email, ipAddress, "FAILED", err.Error())
		
		if strings.Contains(err.Error(), "CAPTCHA") {
			return h.errorResponse(http.StatusBadRequest, "INVALID_CAPTCHA", "Invalid CAPTCHA verification", nil), nil
		}
		return h.errorResponse(http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to process password reset request", nil), nil
	}

	// Log successful password reset request
	h.activityLogger.LogPasswordReset(ctx, "", req.Email, ipAddress, "SUCCESS", "")

	response := map[string]string{
		"message": "If your email is registered, you will receive password reset instructions.",
	}

	return h.successResponse(http.StatusOK, response), nil
}

// HandleResetPassword processes password reset with token
func (h *AuthHandler) HandleResetPassword(ctx context.Context, request events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {
	ipAddress := h.getClientIP(request)

	// Parse request body
	var req struct {
		Token       string `json:"token"`
		NewPassword string `json:"newPassword"`
	}
	if err := json.Unmarshal([]byte(request.Body), &req); err != nil {
		return h.errorResponse(http.StatusBadRequest, "INVALID_REQUEST", "Invalid request format", nil), nil
	}

	if req.Token == "" {
		return h.errorResponse(http.StatusBadRequest, "MISSING_TOKEN", "Reset token is required", nil), nil
	}

	if req.NewPassword == "" {
		return h.errorResponse(http.StatusBadRequest, "MISSING_PASSWORD", "New password is required", nil), nil
	}

	// Process password reset
	err := h.authService.ResetPassword(ctx, req.Token, req.NewPassword)
	if err != nil {
		// Log failed password reset
		h.activityLogger.LogPasswordReset(ctx, "", "", ipAddress, "FAILED", err.Error())
		return h.handlePasswordResetError(err), nil
	}

	// Log successful password reset
	h.activityLogger.LogPasswordReset(ctx, "", "", ipAddress, "SUCCESS", "")

	response := map[string]string{
		"message": "Password has been reset successfully.",
	}

	return h.successResponse(http.StatusOK, response), nil
}

// HandleUpdateProfile processes user profile update requests
func (h *AuthHandler) HandleUpdateProfile(ctx context.Context, request events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {
	ipAddress := h.getClientIP(request)

	// Extract user ID from path parameters or JWT token
	userID := request.PathParameters["userId"]
	if userID == "" {
		return h.errorResponse(http.StatusBadRequest, "MISSING_USER_ID", "User ID is required", nil), nil
	}

	// Parse request body
	var updates map[string]interface{}
	if err := json.Unmarshal([]byte(request.Body), &updates); err != nil {
		return h.errorResponse(http.StatusBadRequest, "INVALID_REQUEST", "Invalid request format", nil), nil
	}

	// Get user for logging
	user, err := h.authService.GetUserByID(ctx, userID)
	if err != nil {
		return h.errorResponse(http.StatusNotFound, "USER_NOT_FOUND", "User not found", nil), nil
	}

	// Process profile update
	err = h.authService.UpdateProfile(ctx, userID, updates)
	if err != nil {
		// Log failed profile update
		h.activityLogger.LogProfileUpdate(ctx, userID, user.Email, ipAddress, "FAILED", updates, err.Error())
		return h.handleProfileUpdateError(err), nil
	}

	// Log successful profile update
	h.activityLogger.LogProfileUpdate(ctx, userID, user.Email, ipAddress, "SUCCESS", updates, "")

	response := map[string]string{
		"message": "Profile updated successfully.",
	}

	return h.successResponse(http.StatusOK, response), nil
}

// HandleGetProfile retrieves user profile information
func (h *AuthHandler) HandleGetProfile(ctx context.Context, request events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {
	// Extract user ID from path parameters or JWT token
	userID := request.PathParameters["userId"]
	if userID == "" {
		return h.errorResponse(http.StatusBadRequest, "MISSING_USER_ID", "User ID is required", nil), nil
	}

	// Get user profile
	user, err := h.authService.GetUserByID(ctx, userID)
	if err != nil {
		return h.errorResponse(http.StatusNotFound, "USER_NOT_FOUND", "User not found", nil), nil
	}

	// Return user profile (without sensitive data)
	profile := user.ToProfile()
	return h.successResponse(http.StatusOK, profile), nil
}

// Helper methods

func (h *AuthHandler) getClientIP(request events.APIGatewayProxyRequest) string {
	// Try to get real IP from headers
	if ip := request.Headers["X-Forwarded-For"]; ip != "" {
		return strings.Split(ip, ",")[0]
	}
	if ip := request.Headers["X-Real-IP"]; ip != "" {
		return ip
	}
	return request.RequestContext.Identity.SourceIP
}

func (h *AuthHandler) getUserAgent(request events.APIGatewayProxyRequest) string {
	return request.Headers["User-Agent"]
}

func (h *AuthHandler) successResponse(statusCode int, data interface{}) events.APIGatewayProxyResponse {
	body, _ := json.Marshal(data)
	return events.APIGatewayProxyResponse{
		StatusCode: statusCode,
		Headers: map[string]string{
			"Content-Type":                 "application/json",
			"Access-Control-Allow-Origin":  "*",
			"Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
			"Access-Control-Allow-Headers": "Content-Type, Authorization",
		},
		Body: string(body),
	}
}

func (h *AuthHandler) errorResponse(statusCode int, errorCode, message string, details []string) events.APIGatewayProxyResponse {
	errorResp := map[string]interface{}{
		"error":   errorCode,
		"message": message,
	}
	if details != nil {
		errorResp["details"] = details
	}

	body, _ := json.Marshal(errorResp)
	return events.APIGatewayProxyResponse{
		StatusCode: statusCode,
		Headers: map[string]string{
			"Content-Type":                 "application/json",
			"Access-Control-Allow-Origin":  "*",
			"Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
			"Access-Control-Allow-Headers": "Content-Type, Authorization",
		},
		Body: string(body),
	}
}

func (h *AuthHandler) handleRegistrationError(err error) events.APIGatewayProxyResponse {
	switch {
	case strings.Contains(err.Error(), "email already registered"):
		return h.errorResponse(http.StatusConflict, "EMAIL_EXISTS", "Email is already registered", nil)
	case strings.Contains(err.Error(), "invalid email"):
		return h.errorResponse(http.StatusBadRequest, "INVALID_EMAIL", "Please provide a valid email address", nil)
	case strings.Contains(err.Error(), "invalid CAPTCHA"):
		return h.errorResponse(http.StatusBadRequest, "INVALID_CAPTCHA", "Invalid CAPTCHA verification", nil)
	case strings.Contains(err.Error(), "password must"):
		return h.errorResponse(http.StatusBadRequest, "INVALID_PASSWORD", err.Error(), nil)
	case strings.Contains(err.Error(), "first name") || strings.Contains(err.Error(), "last name"):
		return h.errorResponse(http.StatusBadRequest, "INVALID_NAME", err.Error(), nil)
	case strings.Contains(err.Error(), "device"):
		return h.errorResponse(http.StatusBadRequest, "INVALID_DEVICE_INFO", err.Error(), nil)
	case strings.Contains(err.Error(), "app version"):
		return h.errorResponse(http.StatusBadRequest, "INVALID_APP_VERSION", err.Error(), nil)
	default:
		return h.errorResponse(http.StatusInternalServerError, "REGISTRATION_FAILED", "Registration failed. Please try again later.", nil)
	}
}

func (h *AuthHandler) handleVerificationError(err error) events.APIGatewayProxyResponse {
	switch {
	case strings.Contains(err.Error(), "invalid") || strings.Contains(err.Error(), "expired"):
		return h.errorResponse(http.StatusBadRequest, "INVALID_TOKEN", "Invalid or expired verification token", nil)
	case strings.Contains(err.Error(), "already verified"):
		return h.errorResponse(http.StatusBadRequest, "ALREADY_VERIFIED", "Email is already verified", nil)
	default:
		return h.errorResponse(http.StatusInternalServerError, "VERIFICATION_FAILED", "Email verification failed", nil)
	}
}

func (h *AuthHandler) handlePasswordResetError(err error) events.APIGatewayProxyResponse {
	switch {
	case strings.Contains(err.Error(), "invalid") || strings.Contains(err.Error(), "expired"):
		return h.errorResponse(http.StatusBadRequest, "INVALID_TOKEN", "Invalid or expired reset token", nil)
	case strings.Contains(err.Error(), "password must"):
		return h.errorResponse(http.StatusBadRequest, "INVALID_PASSWORD", err.Error(), nil)
	default:
		return h.errorResponse(http.StatusInternalServerError, "RESET_FAILED", "Password reset failed", nil)
	}
}

func (h *AuthHandler) handleProfileUpdateError(err error) events.APIGatewayProxyResponse {
	switch {
	case strings.Contains(err.Error(), "not found"):
		return h.errorResponse(http.StatusNotFound, "USER_NOT_FOUND", "User not found", nil)
	case strings.Contains(err.Error(), "invalid"):
		return h.errorResponse(http.StatusBadRequest, "INVALID_DATA", err.Error(), nil)
	default:
		return h.errorResponse(http.StatusInternalServerError, "UPDATE_FAILED", "Profile update failed", nil)
	}
}