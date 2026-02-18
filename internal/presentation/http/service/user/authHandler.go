package user

import (
	models2 "DaraTilBackendV2/internal/application/models"
	errs "DaraTilBackendV2/internal/domain/domErr"
	"DaraTilBackendV2/internal/domain/models"
	"DaraTilBackendV2/internal/infrastructure/logger"
	"DaraTilBackendV2/internal/presentation/dto"
	"DaraTilBackendV2/internal/presentation/dto/dtoMappers"
	"DaraTilBackendV2/internal/presentation/http/response"
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/markbates/goth/gothic"
	"go.uber.org/zap"
	"golang.org/x/crypto/bcrypt"
)

const (
	refreshCookieKey = "refreshToken"
	DeviceWeb        = "Web"
)

func (h *UserHandler) Register(c *gin.Context) {
	logger.Info("Register request started")

	var body dto.RegisterRequest
	if err := c.ShouldBindJSON(&body); err != nil {
		logger.Warn("Invalid register input",
			zap.Error(err),
		)
		response.Fail(c, http.StatusBadRequest, err.Error())
		return
	}

	if body.Role == "admin" {
		logger.Warn("Attempt to register as admin blocked",
			zap.String("email", body.Email),
		)
		body.Role = "user"
	}

	user := models.User{
		Username: body.Username,
		Email:    body.Email,
		Password: body.Password,
		Role:     body.Role,
	}

	userCr, err := h.CreateUC.Execute(c.Request.Context(), user)
	if err != nil {
		logger.Error("User registration failed",
			zap.String("email", body.Email),
			zap.Error(err),
		)
		response.HandleDomainError(c, err)
		return
	}

	logger.Info("User registered successfully",
		zap.Int("user_id", int(userCr.ID)),
		zap.String("email", userCr.Email),
	)

	accessToken, err := h.issueTokensAndSetCookie(c, userCr)
	if err != nil {
		logger.Error("Failed to issue tokens after register",
			zap.Int("user_id", int(userCr.ID)),
			zap.Error(err),
		)
		response.HandleDomainError(c, errs.ErrInternal)
		return
	}

	userDto := dtoMappers.UserToDto(*userCr)
	response.Success(c, 201, userDto, gin.H{"accessToken": accessToken})
}

func (h *UserHandler) Login(c *gin.Context) {
	logger.Info("Login request started")

	var body dto.LoginRequest
	if err := c.ShouldBindJSON(&body); err != nil {
		logger.Warn("Invalid login input",
			zap.Error(err),
		)
		response.HandleDomainError(c, errs.ErrBadRequest)
		return
	}

	user, err := h.GetByEmailUC.Execute(c.Request.Context(), body.Email)
	if err != nil {
		logger.Warn("Login failed - user not found",
			zap.String("email", body.Email),
		)
		response.HandleDomainError(c, err)
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(body.Password)); err != nil {
		logger.Warn("Login failed - incorrect password",
			zap.String("email", body.Email),
		)
		response.Fail(c, http.StatusUnauthorized, "Incorrect password")
		return
	}

	logger.Info("User authenticated successfully",
		zap.Int("user_id", int(user.ID)),
	)

	accessToken, err := h.issueTokensAndSetCookie(c, user)
	if err != nil {
		logger.Error("Failed to issue tokens after login",
			zap.Int("user_id", int(user.ID)),
			zap.Error(err),
		)
		response.HandleDomainError(c, err)
		return
	}

	userDto := dtoMappers.UserToDto(*user)
	response.Success(c, 200, userDto, gin.H{"accessToken": accessToken})
}
func (h *UserHandler) OauthLogin(c *gin.Context, provider string) {
	logger.Info("OAuth login started",
		zap.String("provider", provider),
	)

	req := c.Request.WithContext(
		context.WithValue(c.Request.Context(), "provider", provider),
	)
	c.Request = req

	gothic.BeginAuthHandler(c.Writer, c.Request)
}

func (h *UserHandler) OauthCallback(c *gin.Context, provider string) {
	state := c.Query("state")
	var redUrl string
	if state == "mobile" {
		redUrl = h.cfg.Server.MobileUrl
	} else if state == "web" {
		redUrl = h.cfg.Server.FrontendUrl
	} else {
		redUrl = h.cfg.Server.FrontendUrl
	}
	logger.Info("OAuth callback received",
		zap.String("provider", provider),
	)

	redirectError := func(msg string) {
		logger.Warn("OAuth callback error",
			zap.String("provider", provider),
			zap.String("reason", msg),
		)
		redirectURL := fmt.Sprintf("%s/login?oauth=error&error=%s", redUrl, msg)
		c.Redirect(http.StatusTemporaryRedirect, redirectURL)
	}

	req := c.Request.WithContext(
		context.WithValue(c.Request.Context(), "provider", provider),
	)
	c.Request = req

	userAuth, err := gothic.CompleteUserAuth(c.Writer, c.Request)
	if err != nil {
		redirectError("Failed to complete auth for provider")
		return
	}

	if userAuth.Email == "" {
		redirectError(fmt.Sprintf("No email provided by %s", provider))
		return
	}

	logger.Info("OAuth user data received",
		zap.String("provider", provider),
		zap.String("email", userAuth.Email),
	)

	user, err := h.GetByEmailUC.Execute(c.Request.Context(), userAuth.Email)

	if errors.Is(err, errs.ErrNotFound) {
		logger.Info("Creating new OAuth user",
			zap.String("provider", provider),
			zap.String("email", userAuth.Email),
		)

		baseUsername := userAuth.NickName
		if baseUsername == "" {
			parts := strings.Split(userAuth.Email, "@")
			if len(parts) > 0 {
				baseUsername = parts[0]
			} else {
				baseUsername = "user"
			}
		}

		username, err := GenerateUniqueUsername(c.Request.Context(), baseUsername, h)
		if err != nil {
			redirectError("Username generation failed")
			return
		}

		user = &models.User{
			Username:     username,
			Email:        userAuth.Email,
			Password:     "",
			Avatar:       userAuth.AvatarURL,
			Role:         "user",
			AuthProvider: provider,
		}

		user, err = h.CreateUC.Execute(c.Request.Context(), *user)
		if err != nil {
			redirectError("Failed to create user")
			return
		}
	} else if err != nil {
		redirectError("Internal server error")
		return
	}

	if user.AuthProvider != provider {
		logger.Warn("OAuth provider mismatch",
			zap.Int("user_id", int(user.ID)),
			zap.String("expected", user.AuthProvider),
			zap.String("actual", provider),
		)
		redirectError("User already signed in with another provider")
		return
	}

	logger.Info("OAuth successful",
		zap.Int("user_id", int(user.ID)),
		zap.String("provider", provider),
	)

	_, err = h.issueTokensAndSetCookie(c, user)
	if err != nil {
		logger.Error("Failed to issue tokens after OAuth",
			zap.Int("user_id", int(user.ID)),
			zap.Error(err),
		)
		return
	}

	redirectURL := fmt.Sprintf("%s/login?%s",
		redUrl,
		url.Values{"oauth": []string{provider}}.Encode(),
	)

	c.Redirect(http.StatusTemporaryRedirect, redirectURL)
}

func (h *UserHandler) issueTokensAndSetCookie(c *gin.Context, user *models.User) (string, error) {
	logger.Info("Issuing token pair",
		zap.Int("user_id", int(user.ID)),
	)

	meta := models2.TokenMeta{
		Device:    DeviceWeb,
		IpAddress: c.ClientIP(),
		UserAgent: c.Request.UserAgent(),
	}

	userClaims := models2.UserClaims{
		UserID:   user.ID,
		Username: user.Username,
		Email:    user.Email,
		Role:     user.Role,
	}

	issueRes, err := h.IssueTokenUC.Execute(c.Request.Context(), meta, userClaims)
	if err != nil {
		logger.Error("Failed to issue tokens",
			zap.Int("user_id", int(user.ID)),
			zap.Error(err),
		)
		return "", err
	}

	logger.Info("Refresh token created",
		zap.Int("user_id", int(user.ID)),
	)

	maxAgeSeconds := int(time.Until(issueRes.RefreshExp).Seconds())
	http.SetCookie(c.Writer, &http.Cookie{
		Name:     refreshCookieKey,
		Value:    issueRes.RefreshToken,
		Path:     "/",
		MaxAge:   maxAgeSeconds,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteNoneMode,
	})

	return issueRes.AccessToken, nil
}
