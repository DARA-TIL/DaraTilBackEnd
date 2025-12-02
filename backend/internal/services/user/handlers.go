package user

import (
	"DaraTilBackEnd/backend/internal/config"
	"DaraTilBackEnd/backend/internal/database"
	"DaraTilBackEnd/backend/internal/middleware"
	"DaraTilBackEnd/backend/internal/models"
	"log"
	"net/http"

	"github.com/gin-gonic/gin"
)

type Handler struct {
	cfg *config.Config
}

func NewHandler(cfg *config.Config) *Handler {
	return &Handler{cfg: cfg}
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
