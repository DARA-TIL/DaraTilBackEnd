package auth

import (
	"DaraTilBackEnd/backend/internal/config"
	"DaraTilBackEnd/backend/internal/database"
	"errors"
	"time"

	"DaraTilBackEnd/backend/internal/models"
	"context"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/markbates/goth/gothic"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

type RefreshRequest struct {
	RefreshToken string `json:"refreshToken"`
}

type RegisterRequest struct {
	Username string `json:"username" binding:"required,min=3"`
	Email    string `json:"email" binding:"required,email"`
	Password string `json:"password" binding:"required,min=6"`
	Role     string `json:"role"`
}

type LoginRequest struct {
	Email    string `json:"email" binding:"required,email"`
	Password string `json:"password" binding:"required,min=6"`
}

type AuthResponse struct {
	AccessToken string      `json:"accessToken"`
	User        models.User `json:"user"`
}

type Handler struct {
	cfg *config.Config
}

func NewHandler(cfg *config.Config) *Handler {
	return &Handler{cfg: cfg}
}

func (h *Handler) Register(c *gin.Context) {
	log.Println("[REGISTER] Incoming request")

	var body RegisterRequest
	if err := c.ShouldBindJSON(&body); err != nil {
		log.Printf("[REGISTER] Invalid request body: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Bad Register Request"})
		return
	}

	log.Printf("[REGISTER] Parsed body: username=%s, email=%s, role=%s",
		body.Username, body.Email, body.Role)

	// Хэширование пароля
	hashed, err := bcrypt.GenerateFromPassword([]byte(body.Password), bcrypt.DefaultCost)
	if err != nil {
		log.Printf("[REGISTER] Failed to hash password: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Failed to hash password"})
		return
	}

	// Создание пользователя
	user := models.User{
		Username:     body.Username,
		Email:        body.Email,
		Password:     string(hashed),
		Avatar:       "",
		Role:         body.Role,
		Level:        0,
		Experience:   0,
		AuthProvider: "email",
	}

	if err := database.DB.Create(&user).Error; err != nil {
		log.Printf("[REGISTER] Failed to create user in DB: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Failed to create user"})
		return
	}

	log.Printf("[REGISTER] User created successfully: id=%d, username=%s, email=%s",
		user.ID, user.Username, user.Email)

	// Генерация токенов
	token, err := h.CreateAndStoreToken(c, user)
	if err != nil {
		log.Printf("[REGISTER] Error generating tokens: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Failed to create token"})
		return
	}

	log.Printf("[REGISTER] Tokens generated for user: id=%d", user.ID)

	// Ответ клиенту
	resp := AuthResponse{
		AccessToken: token.AccessToken,
		User:        user,
	}

	log.Printf("[REGISTER] Responding with JSON for user id=%d", user.ID)

	c.JSON(http.StatusOK, resp)
}

func (h *Handler) Login(c *gin.Context) {
	log.Println("[LOGIN] Incoming login request")

	var body LoginRequest
	if err := c.ShouldBindJSON(&body); err != nil {
		log.Printf("[LOGIN] Invalid request body: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Bad Login Request"})
		return
	}

	log.Printf("[LOGIN] Received login attempt: email=%s", body.Email)

	var user models.User
	if err := database.DB.Where("email = ?", body.Email).First(&user).Error; err != nil {
		log.Printf("[LOGIN] User not found: email=%s, error=%v", body.Email, err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "User not found"})
		return
	}

	log.Printf("[LOGIN] User found: id=%d, username=%s", user.ID, user.Username)

	// Проверка пароля
	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(body.Password)); err != nil {
		log.Printf("[LOGIN] Incorrect password for user id=%d", user.ID)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Password incorrect"})
		return
	}

	log.Printf("[LOGIN] Password correct for user id=%d", user.ID)

	// Генерация токенов
	token, err := h.CreateAndStoreToken(c, user)
	if err != nil {
		log.Printf("[LOGIN] Failed to generate JWT tokens for user id=%d: %v", user.ID, err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Failed to create token"})
		return
	}

	log.Printf("[LOGIN] Tokens generated successfully for user id=%d", user.ID)

	// Ответ клиенту
	resp := AuthResponse{
		AccessToken: token.AccessToken,
		User:        user,
	}

	log.Printf("[LOGIN] Responding with 200 OK for user id=%d", user.ID)
	c.JSON(http.StatusOK, resp)
}

func (h *Handler) OauthLogin(c *gin.Context, provider string) {
	log.Printf("[OAUTH-LOGIN] Incoming %s login request", provider)

	// кладём провайдера в context, чтобы его подхватил gothic
	req := c.Request.WithContext(
		context.WithValue(c.Request.Context(), "provider", provider),
	)
	c.Request = req

	gothic.BeginAuthHandler(c.Writer, c.Request)
}

func (h *Handler) OauthCallback(c *gin.Context, provider string) {
	redirectError := func(msg string) {
		redirectURL := fmt.Sprintf("%s/login?oauth=error&error=%s", h.cfg.FrontendUrl, msg)
		log.Printf("[OAUTH-CALLBACK] Redirecting with ERROR to %s", redirectURL)
		c.Redirect(http.StatusTemporaryRedirect, redirectURL)
	}

	log.Printf("[OAUTH-CALLBACK] Callback from provider=%s", provider)

	// снова кладём provider в контекст
	req := c.Request.WithContext(
		context.WithValue(c.Request.Context(), "provider", provider),
	)
	c.Request = req

	userAuth, err := gothic.CompleteUserAuth(c.Writer, c.Request)
	if err != nil {
		log.Printf("[OAUTH-CALLBACK] Failed to complete auth for provider=%s: %v", provider, err)
		redirectError("Failed to complete auth for provider")
		return
	}

	log.Printf("[OAUTH-CALLBACK] Got user from %s: email=%s, name=%s, nickname=%s",
		provider, userAuth.Email, userAuth.Name, userAuth.NickName)

	if userAuth.Email == "" {
		log.Printf("[OAUTH-CALLBACK] No email provided by %s", provider)
		redirectError(fmt.Sprintf("No email provided by %s", provider))
		return
	}

	var user models.User
	if err := database.DB.Where("email = ?", userAuth.Email).First(&user).Error; err != nil {
		log.Printf("[OAUTH-CALLBACK] User not found in DB, creating new one. email=%s provider=%s", userAuth.Email, provider)

		baseUsername := userAuth.NickName
		if baseUsername == "" {
			parts := strings.Split(userAuth.Email, "@")
			if len(parts) > 0 {
				baseUsername = parts[0]
			} else {
				baseUsername = "user"
			}
		}

		username := generateUniqueUsername(baseUsername)
		user = models.User{
			Username:     username,
			Email:        userAuth.Email,
			Password:     "",
			Avatar:       userAuth.AvatarURL,
			Role:         "user",
			Level:        0,
			Experience:   0,
			AuthProvider: provider,
		}

		if err := database.DB.Create(&user).Error; err != nil {
			log.Printf("[OAUTH-CALLBACK] Failed to create user in DB: %v", err)
			redirectError("Failed to create user in DB")
			return
		}

		log.Printf("[OAUTH-CALLBACK] New user created: id=%d, email=%s, provider=%s",
			user.ID, user.Email, user.AuthProvider)
	} else {
		log.Printf("[OAUTH-CALLBACK] Existing user found: id=%d, email=%s, provider=%s",
			user.ID, user.Email, user.AuthProvider)
	}

	// запрещаем логиниться другим провайдером на тот же email
	if user.AuthProvider != provider {
		log.Printf("[OAUTH-CALLBACK] Provider mismatch for email=%s: existing=%s, incoming=%s",
			user.Email, user.AuthProvider, provider)
		redirectError("User already signed in with another provider")
		return
	}

	log.Printf("[OAUTH-CALLBACK] Provider verified for user id=%d: %s", user.ID, provider)

	_, err = h.CreateAndStoreToken(c, user)
	if err != nil {
		log.Printf("[OAUTH-CALLBACK] Failed to create tokens for user id=%d: %v", user.ID, err)
		redirectError("Failed to create tokens for user")
		return
	}
	log.Printf("[OAUTH-CALLBACK] Tokens generated successfully for user id=%d", user.ID)

	redirectURL := fmt.Sprintf("%s/login?%s",
		h.cfg.FrontendUrl,
		url.Values{"oauth": []string{provider}}.Encode(),
	)

	log.Printf("[OAUTH-CALLBACK] Redirecting user id=%d to %s", user.ID, redirectURL)

	c.Redirect(http.StatusTemporaryRedirect, redirectURL)
}

func (h *Handler) CreateAndStoreToken(c *gin.Context, user models.User) (*TokenPair, error) {
	tokens, err := GenerateTokenPair(user, h.cfg)
	if err != nil {
		log.Printf("[AUTH] Failed to create tokens for user_id=%d: %v", user.ID, err)
		return nil, err
	}

	now := time.Now()

	refreshExp := now.Add(time.Hour * time.Duration(h.cfg.JwtRefreshExpires))

	tokenModel := models.Token{
		UserID:           user.ID,
		RefreshTokenHash: hashToken(tokens.RefreshToken),
		Device:           "Web",
		IpAddress:        c.ClientIP(),
		UserAgent:        c.Request.UserAgent(),
		IsRevoked:        false,
		Expires:          refreshExp,
		LastUsed:         now,
	}

	if err := database.DB.Create(&tokenModel).Error; err != nil {
		log.Printf("[AUTH] Failed to save refresh token for user_id=%d: %v", user.ID, err)
		return nil, err
	}

	maxAgeSeconds := int(time.Until(refreshExp).Seconds())
	http.SetCookie(c.Writer, &http.Cookie{
		Name:     "refreshToken",
		Value:    tokens.RefreshToken,
		Path:     "/",
		MaxAge:   maxAgeSeconds,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteNoneMode,
	})

	return tokens, nil
}

func (h *Handler) RefreshToken(c *gin.Context) {
	refreshToken, err := c.Cookie("refreshToken")

	if err != nil || refreshToken == "" {
		log.Printf("[OAUTH-CALLBACK] No refresh token found in cookie")
		var body RefreshRequest
		if bindErr := c.ShouldBindJSON(&body); bindErr != nil || body.RefreshToken == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "No refresh token provided"})
			return
		}
		refreshToken = body.RefreshToken
	}
	claims := &CustomClaims{}
	token, err := jwt.ParseWithClaims(refreshToken, claims, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, jwt.ErrTokenUnverifiable
		}
		return []byte(h.cfg.JwtRefreshSecret), nil
	})
	if err != nil || !token.Valid {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid refresh token"})
		return
	}
	if claims.Subject != "refresh" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid refresh token"})
		return
	}

	var storedToken models.Token
	if err := database.DB.Where("user_id = ? AND refresh_token_hash = ? AND is_revoked = ?", claims.UserID, hashToken(refreshToken), false).First(&storedToken).Error; err != nil {

		if errors.Is(err, gorm.ErrRecordNotFound) {
			log.Printf("[REFRESH] Refresh token not found or already used for user_id=%d", claims.UserID)
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Refresh token invalid or already used"})
			return
		}

		log.Printf("[OAUTH-CALLBACK] Failed to refresh token: %v", err)
		c.JSON(400, gin.H{"error": "Failed to refresh token"})
		return
	}

	if time.Now().After(storedToken.Expires) {
		log.Printf("[OAUTH-CALLBACK] Refresh token expired")
		c.JSON(400, gin.H{"error": "Refresh token expired"})
		return
	}

	var user models.User
	if err := database.DB.Find(&user, claims.UserID).Error; err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "User not found in DB"})
		return
	}

	if err := database.DB.Model(&storedToken).Update("is_revoked", true).Error; err != nil {
		log.Printf("[OAUTH-CALLBACK] Failed to revoke token: %v", err)
		c.JSON(400, gin.H{"error": "Failed to revoke token"})
		return
	}

	newTokens, err := h.CreateAndStoreToken(c, user)
	if err != nil {
		log.Printf("[OAUTH-CALLBACK] Failed to create tokens for user: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	resp := AuthResponse{
		AccessToken: newTokens.AccessToken,
		User:        user,
	}
	c.JSON(http.StatusOK, resp)
}

func (h *Handler) Logout(c *gin.Context) {
	deleteCookie := func() {
		http.SetCookie(c.Writer, &http.Cookie{
			Name:     "refreshToken",
			Value:    "",
			Path:     "/",
			MaxAge:   -1, // удалить
			HttpOnly: true,
			Secure:   true,
			SameSite: http.SameSiteNoneMode,
		})
	}
	refreshToken, err := c.Cookie("refreshToken")
	if err != nil || refreshToken == "" {
		deleteCookie()
		log.Printf("[OAUTH-CALLBACK] No refresh token found in cookie")
		c.Status(http.StatusNoContent)
		return
	}
	claims := &CustomClaims{}
	_, err = jwt.ParseWithClaims(refreshToken, claims, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, jwt.ErrTokenUnverifiable
		}
		return []byte(h.cfg.JwtRefreshSecret), nil
	})
	if err != nil || claims.Subject != "refresh" {
		log.Printf("[OAUTH-CALLBACK] Invalid refresh token: %v", err)
		deleteCookie()
		c.Status(http.StatusNoContent)
		return
	}
	if err := database.DB.Model(&models.Token{}).Where("refresh_token_hash = ? AND user_id = ?", hashToken(refreshToken), claims.UserID).Update("is_revoked", true).Error; err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
		log.Printf("[OAUTH-CALLBACK] Failed to revoke token: %v", err)
	}
	deleteCookie()
	c.Status(http.StatusNoContent)
}

func (h *Handler) GetMe(c *gin.Context) {
	authheader := c.Request.Header.Get("Authorization")
	if authheader == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "No Authorization header provided"})
		return
	}
	parts := strings.SplitN(authheader, " ", 2)
	if len(parts) != 2 || parts[0] != "Bearer" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "No Authorization header provided"})
		return
	}
	claims := &CustomClaims{}
	token, err := jwt.ParseWithClaims(parts[1], claims, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, jwt.ErrTokenUnverifiable
		}
		return []byte(h.cfg.JwtAccessSecret), nil
	})
	if err != nil || !token.Valid {
		if errors.Is(err, jwt.ErrTokenExpired) {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Token expired"})
			return
		}
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
		return
	}
	var user models.User
	if err := database.DB.Find(&user, claims.UserID).Error; err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "User not found in DB"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"user": user})
}
