package user

import (
	"DaraTilBackEnd/backend/internal/database"
	"DaraTilBackEnd/backend/internal/middleware"
	"DaraTilBackEnd/backend/internal/models"
	"errors"
	"log"
	"net/http"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

type UpdatableFields struct {
	Username *string `json:"username"`
	Avatar   *string `json:"avatar"`
	Role     *string `json:"role"`
}

func (h *Handler) UpdateMe(c *gin.Context) {
	var body UpdatableFields
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "invalid request"})
		return
	}
	user, err := middleware.GetCurrentUser(c)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
		return
	}
	log.Printf("[User][UPDATE] id: %d, Body: %+v", user.ID, body)

	if body.Username != nil {
		user.Username = *body.Username
	}
	if body.Avatar != nil {
		user.Avatar = *body.Avatar
	}
	if err := database.DB.Save(user).Error; err != nil {
		if errors.Is(err, gorm.ErrDuplicatedKey) {
			c.JSON(http.StatusNotFound, gin.H{"error": "username already exists"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
		return
	}
	c.JSON(http.StatusOK, user)
}

func (h *Handler) UpdateByAdmin(c *gin.Context) {
	id := c.Param("id")
	var body UpdatableFields
	if err := c.ShouldBindJSON(&body); err != nil {
		log.Println("Failed Update User. Error:", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid body"})
		return
	}

	log.Printf("[User][UPDATE] id: %s, Body: %+v", id, body)
	var user models.User
	if err := database.DB.Where("id = ?", id).First(&user).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			c.JSON(http.StatusNotFound, gin.H{"error": "user not found"})
			return
		}
		log.Println("Failed Update User. Error:", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
		return
	}
	if body.Username != nil {
		user.Username = *body.Username
	}
	if body.Avatar != nil {
		user.Avatar = *body.Avatar
	}
	if body.Role != nil {
		user.Role = *body.Role
	}
	if err := database.DB.Save(&user).Error; err != nil {
		if errors.Is(err, gorm.ErrDuplicatedKey) {
			c.JSON(http.StatusNotFound, gin.H{"error": "username already exists"})
			return
		}
		log.Println("Failed Update User. Error:", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
		return
	}
	log.Printf("[User][UPDATE] id: %s, Body: %+v", id, body)
	c.JSON(http.StatusOK, user)
}

func (h *Handler) GetAllUsers(c *gin.Context) {
	var users []models.User
	log.Printf("[User][GETALL] Start")
	if err := database.DB.Find(&users).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
		return
	}
	log.Printf("[User][GETALL] End")
	c.JSON(http.StatusOK, users)
}
