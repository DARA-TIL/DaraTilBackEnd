package auth

import (
	"DaraTilBackEnd/backend/internal/config"
	"DaraTilBackEnd/backend/internal/database"
	"DaraTilBackEnd/backend/internal/models"
	"context"
	"log"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/markbates/goth/gothic"
	"golang.org/x/crypto/bcrypt"
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
	AccessToken  string      `json:"accessToken"`
	RefreshToken string      `json:"refreshToken"`
	User         models.User `json:"user"`
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
	token, err := GenerateTokenPair(user, h.cfg)
	if err != nil {
		log.Printf("[REGISTER] Error generating tokens: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Failed to create token"})
		return
	}

	log.Printf("[REGISTER] Tokens generated for user: id=%d", user.ID)

	// Ответ клиенту
	resp := AuthResponse{
		AccessToken:  token.AccessToken,
		RefreshToken: token.RefreshToken,
		User:         user,
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
	token, err := GenerateTokenPair(user, h.cfg)
	if err != nil {
		log.Printf("[LOGIN] Failed to generate JWT tokens for user id=%d: %v", user.ID, err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Failed to create token"})
		return
	}

	log.Printf("[LOGIN] Tokens generated successfully for user id=%d", user.ID)

	// Ответ клиенту
	resp := AuthResponse{
		AccessToken:  token.AccessToken,
		RefreshToken: token.RefreshToken,
		User:         user,
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
	log.Printf("[OAUTH-CALLBACK] Callback from provider=%s", provider)

	// снова кладём provider в контекст
	req := c.Request.WithContext(
		context.WithValue(c.Request.Context(), "provider", provider),
	)
	c.Request = req

	userAuth, err := gothic.CompleteUserAuth(c.Writer, c.Request)
	if err != nil {
		log.Printf("[OAUTH-CALLBACK] Failed to complete auth for provider=%s: %v", provider, err)
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	log.Printf("[OAUTH-CALLBACK] Got user from %s: email=%s, name=%s, nickname=%s",
		provider, userAuth.Email, userAuth.Name, userAuth.NickName)

	if userAuth.Email == "" {
		log.Printf("[OAUTH-CALLBACK] No email provided by %s", provider)
		c.JSON(http.StatusBadRequest, gin.H{"error": "No Email Provided"})
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
			c.JSON(http.StatusBadRequest, gin.H{"error": "Failed to create user"})
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
		c.JSON(http.StatusBadRequest, gin.H{"error": "User already signed in with another method"})
		return
	}

	log.Printf("[OAUTH-CALLBACK] Provider verified for user id=%d: %s", user.ID, provider)

	tokens, err := GenerateTokenPair(user, h.cfg)
	if err != nil {
		log.Printf("[OAUTH-CALLBACK] Failed to create tokens for user id=%d: %v", user.ID, err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Failed to create tokens"})
		return
	}

	log.Printf("[OAUTH-CALLBACK] Tokens generated successfully for user id=%d", user.ID)

	resp := AuthResponse{
		AccessToken:  tokens.AccessToken,
		RefreshToken: tokens.RefreshToken,
		User:         user,
	}

	log.Printf("[OAUTH-CALLBACK] Responding 200 OK for user id=%d", user.ID)
	c.JSON(http.StatusOK, resp)
}

func (h *Handler) RefreshToken(c *gin.Context) {
	var body RefreshRequest
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	claims := &CustomClaims{}
	token, err := jwt.ParseWithClaims(body.RefreshToken, claims, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, jwt.ErrTokenUnverifiable
		}
		return []byte(h.cfg.JwtRefreshSecret), nil
	})
	if err != nil || !token.Valid {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if claims.Subject != "refresh" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid refresh token"})
		return
	}

	var user models.User
	if err := database.DB.Find(&user, claims.UserID).Error; err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "User not found in DB"})
		return
	}
	tokens, err := GenerateTokenPair(user, h.cfg)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	resp := AuthResponse{
		AccessToken:  tokens.AccessToken,
		RefreshToken: tokens.RefreshToken,
		User:         user,
	}
	c.JSON(http.StatusOK, resp)
}
