package user

import (
	"DaraTilBackEnd/backend/internal/config"
	"DaraTilBackEnd/backend/internal/database"
	"DaraTilBackEnd/backend/internal/middleware"
	"DaraTilBackEnd/backend/internal/models"
	"DaraTilBackEnd/backend/internal/utils"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

type Handler struct {
	cfg *config.Config
}

func NewHandler(cfg *config.Config) *Handler {
	return &Handler{cfg: cfg}
}

func (h *Handler) Update(c *gin.Context) {
	id := c.Param("id")
	var body map[string]interface{}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	log.Printf("[FOLKLORE][UPDATE] id: %s, Body: %+v", id, body)
	delete(body, "ID")
	delete(body, "id")
	delete(body, "CreatedAt")
	delete(body, "UpdatedAt")
	delete(body, "DeletedAt")
	delete(body, "password")
	delete(body, "email")

	if err := database.DB.Model(&models.User{}).Where("id = ?", id).Updates(&body).Error; err != nil {
		log.Printf("[FOLKLORE][UPDATE] Error: %+v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	var updatedUser models.User
	if err := database.DB.Where("id = ?", id).First(&updatedUser).Error; err != nil {
		log.Printf("[FOLKLORE][UPDATE] Error: %+v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	log.Printf("[FOLKLORE][UPDATE] Success: %+v", updatedUser)
	c.JSON(http.StatusOK, gin.H{"user": updatedUser})
}

type PasswordResetSession struct {
	Email     string    `json:"email"`
	Code      string    `json:"code"`
	CreatedAt time.Time `json:"createdAt"`
	Verified  bool      `json:"verified"`
}

func (h *Handler) ChangePassword(c *gin.Context) {
	email := c.Param("email")
	if email == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "email is required"})
		return
	}
	log.Printf("[FOLKLORE][CHANGE_PASSWORD] email: %s", email)
	var user models.User
	if err := database.DB.Model(&models.User{}).Where("email = ? AND auth_provider = ?", email, "email").First(&user).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			log.Println("[FOLKLORE][CHANGE_PASSWORD] email not found")
			c.JSON(http.StatusBadRequest, gin.H{"error": "email not found"})
			return
		}
		log.Printf("[FOLKLORE][CHANGE_PASSWORD] Error: %+v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "internal server error"})
		return
	}

	code, err := rand.Int(rand.Reader, big.NewInt(1000000))
	if err != nil {
		log.Printf("[FOLKLORE][ChangePassword] Error: %+v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	codeStr := fmt.Sprintf("%06d", code.Int64())
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
		log.Printf("[FOLKLORE][ChangePassword] Error: %+v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "internal server error"})
		return
	}

	if err := utils.SendEmail(email, "daratil@gmail.com", subject, text, *h.cfg); err != nil {
		log.Printf("[FOLKLORE][ChangePassword] Error: %+v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Internal server error"})
		return
	}
	http.SetCookie(c.Writer, &http.Cookie{
		Name:     "password_reset",
		Value:    encoded,
		Path:     "/",
		MaxAge:   600,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteNoneMode,
	})

	c.JSON(http.StatusOK, gin.H{"email": email})
}

func (h *Handler) VerifyPasswordResetCode(c *gin.Context) {
	var req struct {
		Code string `json:"code"`
	}
	log.Printf("[FOLKLORE][VerifyPasswordResetCode] code: %s", c.Param("code"))
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	ck, err := c.Request.Cookie("password_reset")
	if err != nil {
		log.Printf("[FOLKLORE][VerifyPasswordResetCode] Error: %+v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	decoded, err := base64.StdEncoding.DecodeString(ck.Value)
	if err != nil {
		log.Printf("[FOLKLORE][VerifyPasswordResetCode] Error: %+v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	var session PasswordResetSession
	if err := json.Unmarshal(decoded, &session); err != nil {
		log.Printf("[FOLKLORE][VerifyPasswordResetCode] Error: %+v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if time.Since(session.CreatedAt).Minutes() > 10 {
		log.Printf("[FOLKLORE][VerifyPasswordResetCode] PasswordReset Timeout")
		http.SetCookie(c.Writer, &http.Cookie{
			Name:   "password_reset",
			Value:  "",
			Path:   "/",
			MaxAge: -1,
		})
		c.JSON(http.StatusBadRequest, gin.H{"error": "Password reset code has expired"})
		return
	}
	if subtle.ConstantTimeCompare([]byte(session.Code), []byte(req.Code)) != 1 {
		log.Printf("[FOLKLORE][VerifyPasswordResetCode] Error: %+v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid code"})
		return
	}
	session.Verified = true
	updated, err := json.Marshal(&session)
	if err != nil {
		log.Printf("[FOLKLORE][VerifyPasswordResetCode] Error: %+v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "internal server error"})
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

func (h *Handler) ConfirmPasswordChange(c *gin.Context) {
	var req struct {
		Password string `json:"password"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "internal server error"})
		return
	}
	ck, err := c.Request.Cookie("password_reset")
	if err != nil {
		log.Printf("[FOLKLORE][ConfirmPasswordChange] Error: %+v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "internal server error"})
		return
	}
	decoded, err := base64.StdEncoding.DecodeString(ck.Value)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid reset session"})
		return
	}

	var session PasswordResetSession
	if err := json.Unmarshal(decoded, &session); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid reset session"})
		return
	}

	// еще раз проверим время
	if time.Since(session.CreatedAt) > 10*time.Minute {
		http.SetCookie(c.Writer, &http.Cookie{
			Name:   "password_reset",
			Value:  "",
			Path:   "/",
			MaxAge: -1,
		})
		c.JSON(http.StatusBadRequest, gin.H{"error": "code expired"})
		return
	}

	if !session.Verified {
		c.JSON(http.StatusBadRequest, gin.H{"error": "code is not verified"})
		return
	}
	hashed, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		log.Printf("[FOLKLORE][ConfirmPasswordChange] Error: %+v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "internal server error"})
		return
	}
	if err := database.DB.Model(&models.User{}).Where("email = ? AND auth_provider = ?", session.Email, "email").Update("password", string(hashed)).Error; err != nil {
		log.Printf("[FOLKLORE][ConfirmPasswordChange] Error: %+v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "internal server error"})
		return
	}
	http.SetCookie(c.Writer, &http.Cookie{
		Name:   "password_reset",
		Value:  "",
		Path:   "/",
		MaxAge: -1,
	})
	c.JSON(http.StatusOK, gin.H{"message": "password changed"})
}

func (h *Handler) GetLikedFolklore(c *gin.Context) {
	user, err := middleware.GetCurrentUser(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}
	log.Printf("[LIKE][USER] id = %s", user.ID)
	var folklore []models.Folklore
	if err := database.DB.Joins("JOIN folklore_likes ON folklore_likes.folklore_id = folklores.id").Where("folklore_likes.user_id = ?", user.ID).Find(&folklore).Error; err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": folklore})
}
