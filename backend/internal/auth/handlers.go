package auth

import (
	"DaraTilBackEnd/backend/internal/config"
	"DaraTilBackEnd/backend/internal/database"
	"DaraTilBackEnd/backend/internal/models"
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/markbates/goth/gothic"
	"golang.org/x/crypto/bcrypt"
)

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
	var body RegisterRequest
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Bad Register Request"})
		return
	}
	hashed, err := bcrypt.GenerateFromPassword([]byte(body.Password), bcrypt.DefaultCost)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Failed to hash password"})
		return
	}
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
		c.JSON(http.StatusBadRequest, gin.H{"error": "Failed to create user"})
	}
	token, err := GenerateTokenPair(user, h.cfg)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Failed to create token"})
		return
	}
	resp := AuthResponse{
		AccessToken:  token.AccessToken,
		RefreshToken: token.RefreshToken,
		User:         user,
	}
	c.JSON(http.StatusOK, resp)
}

func (h *Handler) Login(c *gin.Context) {
	var body LoginRequest
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Bad Login Request"})
		return
	}
	var user models.User
	if err := database.DB.Where("email = ?", body.Email).First(&user).Error; err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "User not found"})
		return
	}
	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(body.Password)); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Password incorrect"})
		return
	}
	token, err := GenerateTokenPair(user, h.cfg)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Failed to create token"})
		return
	}
	resp := AuthResponse{
		AccessToken:  token.AccessToken,
		RefreshToken: token.RefreshToken,
		User:         user,
	}
	c.JSON(http.StatusOK, resp)
}

func (h *Handler) OauthLogin(c *gin.Context, provider string) {
	req := c.Request.WithContext(context.WithValue(c.Request.Context(), "provider", provider))
	c.Request = req
	gothic.BeginAuthHandler(c.Writer, c.Request)
}

func (h *Handler) OauthCallback(c *gin.Context, provider string) {
	req := c.Request.WithContext(context.WithValue(c.Request.Context(), "provider", provider))
	c.Request = req
	userAuth, err := gothic.CompleteUserAuth(c.Writer, c.Request)
	fmt.Println(userAuth)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if userAuth.Email == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "No Email Provided"})
		return
	}
	var user models.User
	if err := database.DB.Where("email = ?", userAuth.Email).First(&user).Error; err != nil {
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
			c.JSON(http.StatusBadRequest, gin.H{"error": "Failed to create user"})
			return
		}
	}
	if user.AuthProvider != provider {
		c.JSON(http.StatusBadRequest, gin.H{"error": "User already signed in with another method"})
		return
	}
	fmt.Println(user.AuthProvider, provider)
	tokens, err := GenerateTokenPair(user, h.cfg)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Failed to create tokens"})
		return
	}

	resp := AuthResponse{
		AccessToken:  tokens.AccessToken,
		RefreshToken: tokens.RefreshToken,
		User:         user,
	}
	c.JSON(http.StatusOK, resp)
}
