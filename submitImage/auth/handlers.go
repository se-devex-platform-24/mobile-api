package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/aws/aws-lambda-go/events"
)

// AuthHandlers contains HTTP handlers for authentication endpoints
type AuthHandlers struct {
	authService       *AuthService
	securityValidator *SecurityValidator
}

// NewAuthHandlers creates new authentication handlers
func NewAuthHandlers(authService *AuthService) *AuthHandlers {
	return &AuthHandlers{
		authService:       authService,
		securityValidator: authService.securityValidator,
	}
}

// HandleRegister handles user registration
func (h *AuthHandlers) HandleRegister(ctx context.Context, request events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {
	// Extract client information
	ipAddress := h.getClientIP(request)
	userAgent := h.getUserAgent(request)

	// Validate user agent
	if !h.securityValidator.ValidateUserAgent(userAgent) {
		return h.errorResponse(http.StatusBadRequest, "Invalid user agent"), nil
	}

	// Parse request body
	var req UserRegistration
	if err := json.Unmarshal([]byte(request.Body), &req); err != nil {
		return h.errorResponse(http.StatusBadRequest, "Invalid request body"), nil
	}

	// Validate required fields
	if err := h.validateUserRegistration(&req); err != nil {
		return h.errorResponse(http.StatusBadRequest, err.Error()), nil
	}

	// Call auth service
	response, err := h.authService.RegisterUser(ctx, &req, ipAddress, userAgent)
	if err != nil {
		return h.handleServiceError(err), nil
	}

	return h.successResponse(http.StatusCreated, response), nil
}

// HandleLogin handles user login
func (h *AuthHandlers) HandleLogin(ctx context.Context, request events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {
	// Extract client information
	ipAddress := h.getClientIP(request)
	userAgent := h.getUserAgent(request)

	// Validate user agent
	if !h.securityValidator.ValidateUserAgent(userAgent) {
		return h.errorResponse(http.StatusBadRequest, "Invalid user agent"), nil
	}

	// Parse request body
	var req UserLogin
	if err := json.Unmarshal([]byte(request.Body), &req); err != nil {
		return h.errorResponse(http.StatusBadRequest, "Invalid request body"), nil
	}

	// Validate required fields
	if err := h.validateUserLogin(&req); err != nil {
		return h.errorResponse(http.StatusBadRequest, err.Error()), nil
	}

	// Call auth service
	response, err := h.authService.LoginUser(ctx, &req, ipAddress, userAgent)
	if err != nil {
		return h.handleServiceError(err), nil
	}

	return h.successResponse(http.StatusOK, response), nil
}

// HandleVerifyMFA handles MFA verification
func (h *AuthHandlers) HandleVerifyMFA(ctx context.Context, request events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {
	// Extract client information
	ipAddress := h.getClientIP(request)
	userAgent := h.getUserAgent(request)

	// Parse request body
	var req MFAVerification
	if err := json.Unmarshal([]byte(request.Body), &req); err != nil {
		return h.errorResponse(http.StatusBadRequest, "Invalid request body"), nil
	}

	// Validate required fields
	if err := h.validateMFAVerification(&req); err != nil {
		return h.errorResponse(http.StatusBadRequest, err.Error()), nil
	}

	// Call auth service
	response, err := h.authService.VerifyMFA(ctx, &req, ipAddress, userAgent)
	if err != nil {
		return h.handleServiceError(err), nil
	}

	return h.successResponse(http.StatusOK, response), nil
}

// HandleRefreshToken handles token refresh
func (h *AuthHandlers) HandleRefreshToken(ctx context.Context, request events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {
	// Extract client information
	ipAddress := h.getClientIP(request)
	userAgent := h.getUserAgent(request)

	// Parse request body
	var req RefreshTokenRequest
	if err := json.Unmarshal([]byte(request.Body), &req); err != nil {
		return h.errorResponse(http.StatusBadRequest, "Invalid request body"), nil
	}

	// Validate required fields
	if req.RefreshToken == "" {
		return h.errorResponse(http.StatusBadRequest, "Refresh token is required"), nil
	}

	// Call auth service
	response, err := h.authService.RefreshToken(ctx, &req, ipAddress, userAgent)
	if err != nil {
		return h.handleServiceError(err), nil
	}

	return h.successResponse(http.StatusOK, response), nil
}

// HandleLogout handles user logout
func (h *AuthHandlers) HandleLogout(ctx context.Context, request events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {
	// Extract client information
	ipAddress := h.getClientIP(request)
	userAgent := h.getUserAgent(request)

	// Extract access token from Authorization header
	accessToken, err := h.extractAccessToken(request)
	if err != nil {
		return h.errorResponse(http.StatusUnauthorized, "Authorization header required"), nil
	}

	// Call auth service
	response, err := h.authService.LogoutUser(ctx, accessToken, ipAddress, userAgent)
	if err != nil {
		return h.handleServiceError(err), nil
	}

	return h.successResponse(http.StatusOK, response), nil
}

// HandleForgotPassword handles password reset request
func (h *AuthHandlers) HandleForgotPassword(ctx context.Context, request events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {
	// Extract client information
	ipAddress := h.getClientIP(request)
	userAgent := h.getUserAgent(request)

	// Parse request body
	var req ForgotPasswordRequest
	if err := json.Unmarshal([]byte(request.Body), &req); err != nil {
		return h.errorResponse(http.StatusBadRequest, "Invalid request body"), nil
	}

	// Validate required fields
	if req.Email == "" {
		return h.errorResponse(http.StatusBadRequest, "Email is required"), nil
	}

	// Call auth service
	response, err := h.authService.ForgotPassword(ctx, &req, ipAddress, userAgent)
	if err != nil {
		return h.handleServiceError(err), nil
	}

	return h.successResponse(http.StatusOK, response), nil
}

// HandleResetPassword handles password reset confirmation
func (h *AuthHandlers) HandleResetPassword(ctx context.Context, request events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {
	// Extract client information
	ipAddress := h.getClientIP(request)
	userAgent := h.getUserAgent(request)

	// Parse request body
	var req ResetPasswordRequest
	if err := json.Unmarshal([]byte(request.Body), &req); err != nil {
		return h.errorResponse(http.StatusBadRequest, "Invalid request body"), nil
	}

	// Validate required fields
	if err := h.validateResetPasswordRequest(&req); err != nil {
		return h.errorResponse(http.StatusBadRequest, err.Error()), nil
	}

	// Call auth service
	response, err := h.authService.ResetPassword(ctx, &req, ipAddress, userAgent)
	if err != nil {
		return h.handleServiceError(err), nil
	}

	return h.successResponse(http.StatusOK, response), nil
}

// HandleGetCurrentUser handles getting current user information
func (h *AuthHandlers) HandleGetCurrentUser(ctx context.Context, request events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {
	// Extract access token from Authorization header
	accessToken, err := h.extractAccessToken(request)
	if err != nil {
		return h.errorResponse(http.StatusUnauthorized, "Authorization header required"), nil
	}

	// Call auth service
	user, err := h.authService.GetCurrentUser(ctx, accessToken)
	if err != nil {
		return h.handleServiceError(err), nil
	}

	return h.successResponse(http.StatusOK, user), nil
}

// Helper methods

// getClientIP extracts the real client IP address
func (h *AuthHandlers) getClientIP(request events.APIGatewayProxyRequest) string {
	// Get IP from various headers
	xForwardedFor := request.Headers["X-Forwarded-For"]
	xRealIP := request.Headers["X-Real-IP"]
	remoteAddr := request.RequestContext.Identity.SourceIP

	return h.securityValidator.GetRealIP(remoteAddr, xForwardedFor, xRealIP)
}

// getUserAgent extracts the User-Agent header
func (h *AuthHandlers) getUserAgent(request events.APIGatewayProxyRequest) string {
	userAgent := request.Headers["User-Agent"]
	if userAgent == "" {
		userAgent = "Unknown"
	}
	return userAgent
}

// extractAccessToken extracts the access token from Authorization header
func (h *AuthHandlers) extractAccessToken(request events.APIGatewayProxyRequest) (string, error) {
	authHeader := request.Headers["Authorization"]
	if authHeader == "" {
		// Try lowercase header (some proxies might change case)
		authHeader = request.Headers["authorization"]
	}

	return ExtractTokenFromHeader(authHeader)
}

// Validation methods

// validateUserRegistration validates user registration request
func (h *AuthHandlers) validateUserRegistration(req *UserRegistration) error {
	if req.Email == "" {
		return fmt.Errorf("email is required")
	}
	if req.Password == "" {
		return fmt.Errorf("password is required")
	}
	if req.FirstName == "" {
		return fmt.Errorf("first name is required")
	}
	if req.LastName == "" {
		return fmt.Errorf("last name is required")
	}

	// Basic email validation
	if !strings.Contains(req.Email, "@") {
		return fmt.Errorf("invalid email format")
	}

	// Validate name lengths
	if len(req.FirstName) > 50 {
		return fmt.Errorf("first name too long")
	}
	if len(req.LastName) > 50 {
		return fmt.Errorf("last name too long")
	}

	return nil
}

// validateUserLogin validates user login request
func (h *AuthHandlers) validateUserLogin(req *UserLogin) error {
	if req.Email == "" {
		return fmt.Errorf("email is required")
	}
	if req.Password == "" {
		return fmt.Errorf("password is required")
	}

	// Basic email validation
	if !strings.Contains(req.Email, "@") {
		return fmt.Errorf("invalid email format")
	}

	return nil
}

// validateMFAVerification validates MFA verification request
func (h *AuthHandlers) validateMFAVerification(req *MFAVerification) error {
	if req.SessionToken == "" {
		return fmt.Errorf("session token is required")
	}
	if req.Code == "" {
		return fmt.Errorf("MFA code is required")
	}

	// Validate MFA code format
	if !IsValidMFACode(req.Code) {
		return fmt.Errorf("invalid MFA code format")
	}

	return nil
}

// validateResetPasswordRequest validates password reset request
func (h *AuthHandlers) validateResetPasswordRequest(req *ResetPasswordRequest) error {
	if req.Token == "" {
		return fmt.Errorf("reset token is required")
	}
	if req.NewPassword == "" {
		return fmt.Errorf("new password is required")
	}

	return nil
}

// Response helpers

// successResponse creates a successful API Gateway response
func (h *AuthHandlers) successResponse(statusCode int, data interface{}) events.APIGatewayProxyResponse {
	body, _ := json.Marshal(data)

	return events.APIGatewayProxyResponse{
		StatusCode: statusCode,
		Headers: map[string]string{
			"Content-Type":                 "application/json",
			"Access-Control-Allow-Origin":  "*",
			"Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
			"Access-Control-Allow-Headers": "Content-Type, Authorization",
		},
		Body:            string(body),
		IsBase64Encoded: false,
	}
}

// errorResponse creates an error API Gateway response
func (h *AuthHandlers) errorResponse(statusCode int, message string) events.APIGatewayProxyResponse {
	errorResp := ErrorResponse{
		Code:    statusCode,
		Message: message,
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
		Body:            string(body),
		IsBase64Encoded: false,
	}
}

// handleServiceError converts service errors to HTTP responses
func (h *AuthHandlers) handleServiceError(err error) events.APIGatewayProxyResponse {
	if errorResp, ok := err.(*ErrorResponse); ok {
		return h.errorResponse(errorResp.Code, errorResp.Message)
	}

	// Default to internal server error
	return h.errorResponse(http.StatusInternalServerError, "Internal server error")
}

// AuthMiddleware provides authentication middleware for protected endpoints
func (h *AuthHandlers) AuthMiddleware(next func(context.Context, events.APIGatewayProxyRequest, *User) (events.APIGatewayProxyResponse, error)) func(context.Context, events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {
	return func(ctx context.Context, request events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {
		// Extract access token
		accessToken, err := h.extractAccessToken(request)
		if err != nil {
			return h.errorResponse(http.StatusUnauthorized, "Authorization header required"), nil
		}

		// Get current user
		user, err := h.authService.GetCurrentUser(ctx, accessToken)
		if err != nil {
			return h.handleServiceError(err), nil
		}

		// Call the protected handler with user context
		return next(ctx, request, user)
	}
}

// HandleOptions handles CORS preflight requests
func (h *AuthHandlers) HandleOptions(ctx context.Context, request events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {
	return events.APIGatewayProxyResponse{
		StatusCode: http.StatusOK,
		Headers: map[string]string{
			"Access-Control-Allow-Origin":  "*",
			"Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
			"Access-Control-Allow-Headers": "Content-Type, Authorization",
			"Access-Control-Max-Age":       "86400",
		},
		Body:            "",
		IsBase64Encoded: false,
	}, nil
}

// RouteRequest routes requests to appropriate handlers based on path and method
func (h *AuthHandlers) RouteRequest(ctx context.Context, request events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {
	path := request.Path
	method := request.HTTPMethod

	// Handle CORS preflight
	if method == "OPTIONS" {
		return h.HandleOptions(ctx, request)
	}

	// Route to appropriate handler
	switch {
	case path == "/auth/register" && method == "POST":
		return h.HandleRegister(ctx, request)
	case path == "/auth/login" && method == "POST":
		return h.HandleLogin(ctx, request)
	case path == "/auth/verify-mfa" && method == "POST":
		return h.HandleVerifyMFA(ctx, request)
	case path == "/auth/refresh" && method == "POST":
		return h.HandleRefreshToken(ctx, request)
	case path == "/auth/logout" && method == "POST":
		return h.HandleLogout(ctx, request)
	case path == "/auth/forgot-password" && method == "POST":
		return h.HandleForgotPassword(ctx, request)
	case path == "/auth/reset-password" && method == "POST":
		return h.HandleResetPassword(ctx, request)
	case path == "/auth/me" && method == "GET":
		return h.HandleGetCurrentUser(ctx, request)
	default:
		return h.errorResponse(http.StatusNotFound, "Endpoint not found"), nil
	}
}