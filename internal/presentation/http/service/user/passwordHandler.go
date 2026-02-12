package user

import (
	"DaraTilBackendV2/internal/application/utils"
	errs "DaraTilBackendV2/internal/domain/domErr"
	"DaraTilBackendV2/internal/domain/models"
	"DaraTilBackendV2/internal/infrastructure/logger"
	"DaraTilBackendV2/internal/presentation/http/response"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

type PasswordResetSession struct {
	Email     string    `json:"email"`
	Code      string    `json:"code"`
	CreatedAt time.Time `json:"createdAt"`
	Verified  bool      `json:"verified"`
}

func (h *UserHandler) ChangePassword(c *gin.Context) {
	email := c.Param("email")

	logger.Info("Password reset request received",
		zap.String("email", email),
		zap.String("ip", c.ClientIP()),
	)

	if email == "" {
		logger.Warn("Password reset failed - empty email param",
			zap.String("ip", c.ClientIP()),
		)
		response.HandleDomainError(c, errs.ErrInvalidInput)
		return
	}

	_, err := h.GetByEmailUC.Execute(c.Request.Context(), email)
	if err != nil {
		logger.Warn("Password reset failed - user not found or getByEmail error",
			zap.String("email", email),
			zap.Error(err),
		)
		response.HandleDomainError(c, err)
		return
	}

	code, err := rand.Int(rand.Reader, big.NewInt(1000000))
	if err != nil {
		logger.Error("Password reset failed - cannot generate random code",
			zap.String("email", email),
			zap.Error(err),
		)
		response.HandleDomainError(c, errs.ErrInternal)
		return
	}

	codeStr := fmt.Sprintf("%06d", code.Int64())

	logger.Info("Password reset code generated",
		zap.String("email", email),
	)

	subject := "Reset Your Password"
	text := fmt.Sprintf(
		"Hello,\n\n"+
			"We received a request to reset your password.\n\n"+
			"Your password reset code is: %s\n\n"+
			"This code is valid for 10 minutes.\n\n"+
			"If you did not request a password reset, please ignore this email.\n\n"+
			"Best regards,\n"+
			"DaraTil Support Team",
		codeStr,
	)

	data := &PasswordResetSession{
		Email:     email,
		Code:      codeStr,
		CreatedAt: time.Now(),
		Verified:  false,
	}

	jsonBytes, err := json.Marshal(data)
	encoded := base64.StdEncoding.EncodeToString(jsonBytes)

	if err != nil {
		logger.Error("Password reset failed - cannot marshal reset session",
			zap.String("email", email),
			zap.Error(err),
		)
		log.Printf("[FOLKLORE][ChangePassword] Error: %+v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "internal server error"})
		return
	}

	logger.Info("Sending password reset email",
		zap.String("email", email),
	)

	if err := utils.SendEmailSMTP(email, "danialshaimurat1105@gmail.com", subject, text, *h.cfg); err != nil {
		logger.Error("Password reset failed - email send error",
			zap.String("email", email),
			zap.Error(err),
		)
		response.HandleDomainError(c, errs.ErrInternal)
		return
	}

	logger.Info("Password reset email sent successfully",
		zap.String("email", email),
	)

	http.SetCookie(c.Writer, &http.Cookie{
		Name:     "password_reset",
		Value:    encoded,
		Path:     "/",
		MaxAge:   600,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteNoneMode,
	})

	logger.Info("Password reset cookie set",
		zap.String("email", email),
		zap.Int("max_age", 600),
	)

	c.JSON(http.StatusOK, gin.H{"email": email})
}

func (h *UserHandler) VerifyPasswordResetCode(c *gin.Context) {
	logger.Info("Password reset code verification started")

	var req struct {
		Code string `json:"code"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		logger.Warn("Invalid verification request body",
			zap.Error(err),
		)
		response.HandleDomainError(c, errs.ErrInvalidInput)
		return
	}

	ck, err := c.Request.Cookie("password_reset")
	if err != nil {
		logger.Warn("Password reset verification failed - no cookie")
		response.HandleDomainError(c, errs.ErrInternal)
		return
	}

	decoded, err := base64.StdEncoding.DecodeString(ck.Value)
	if err != nil {
		logger.Error("Failed to decode reset cookie",
			zap.Error(err),
		)
		response.HandleDomainError(c, errs.ErrInternal)
		return
	}

	var session PasswordResetSession
	if err := json.Unmarshal(decoded, &session); err != nil {
		logger.Error("Failed to unmarshal reset session",
			zap.Error(err),
		)
		response.HandleDomainError(c, errs.ErrInternal)
		return
	}

	logger.Info("Verifying reset code",
		zap.String("email", session.Email),
	)

	if time.Since(session.CreatedAt).Minutes() > 10 {
		logger.Warn("Password reset code expired",
			zap.String("email", session.Email),
		)

		http.SetCookie(c.Writer, &http.Cookie{
			Name:   "password_reset",
			Value:  "",
			Path:   "/",
			MaxAge: -1,
		})

		response.Fail(c, http.StatusRequestTimeout, "Password reset timeout")
		return
	}

	if subtle.ConstantTimeCompare([]byte(session.Code), []byte(req.Code)) != 1 {
		logger.Warn("Incorrect reset code",
			zap.String("email", session.Email),
		)
		response.Fail(c, http.StatusNotAcceptable, "Incorrect code")
		return
	}

	logger.Info("Password reset code verified",
		zap.String("email", session.Email),
	)

	session.Verified = true
	updated, err := json.Marshal(&session)
	if err != nil {
		logger.Error("Failed to marshal verified session",
			zap.Error(err),
		)
		response.HandleDomainError(c, errs.ErrInternal)
		return
	}

	encoded := base64.StdEncoding.EncodeToString(updated)

	http.SetCookie(c.Writer, &http.Cookie{
		Name:     "password_reset",
		Value:    encoded,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteNoneMode,
		MaxAge:   600,
	})

	c.JSON(http.StatusOK, gin.H{"message": "code verified"})
}

func (h *UserHandler) ConfirmPasswordChange(c *gin.Context) {
	logger.Info("Confirm password change started")

	var req struct {
		Password string `json:"password"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		logger.Warn("Invalid confirm password request",
			zap.Error(err),
		)
		response.HandleDomainError(c, errs.ErrInternal)
		return
	}

	ck, err := c.Request.Cookie("password_reset")
	if err != nil {
		logger.Warn("Password change failed - no reset cookie")
		response.HandleDomainError(c, errs.ErrInternal)
		return
	}

	decoded, err := base64.StdEncoding.DecodeString(ck.Value)
	if err != nil {
		logger.Error("Failed to decode reset cookie during confirm",
			zap.Error(err),
		)
		response.HandleDomainError(c, errs.ErrInternal)
		return
	}

	var session PasswordResetSession
	if err := json.Unmarshal(decoded, &session); err != nil {
		logger.Error("Failed to unmarshal reset session during confirm",
			zap.Error(err),
		)
		response.HandleDomainError(c, errs.ErrInternal)
		return
	}

	logger.Info("Processing password change",
		zap.String("email", session.Email),
	)

	if time.Since(session.CreatedAt) > 10*time.Minute {
		logger.Warn("Password change failed - reset session expired",
			zap.String("email", session.Email),
		)

		http.SetCookie(c.Writer, &http.Cookie{
			Name:   "password_reset",
			Value:  "",
			Path:   "/",
			MaxAge: -1,
		})

		response.Fail(c, http.StatusRequestTimeout, "Password reset timeout")
		return
	}

	if !session.Verified {
		logger.Warn("Password change failed - code not verified",
			zap.String("email", session.Email),
		)
		response.Fail(c, http.StatusForbidden, "Code is not verified")
		return
	}

	upd := models.UserUpdatableFields{
		Password: &req.Password,
	}

	user, err := h.GetByEmailUC.Execute(c.Request.Context(), session.Email)
	if err != nil {
		logger.Error("Password change failed - user fetch error",
			zap.String("email", session.Email),
			zap.Error(err),
		)
		response.HandleDomainError(c, err)
		return
	}

	_, err = h.UpdateUC.Execute(c.Request.Context(), int(user.ID), upd)
	if err != nil {
		logger.Error("Password update failed",
			zap.String("email", session.Email),
			zap.Error(err),
		)
		response.HandleDomainError(c, err)
		return
	}

	logger.Info("Password changed successfully",
		zap.String("email", session.Email),
	)

	http.SetCookie(c.Writer, &http.Cookie{
		Name:   "password_reset",
		Value:  "",
		Path:   "/",
		MaxAge: -1,
	})

	response.Success(c, http.StatusOK, "Password changed")
}
