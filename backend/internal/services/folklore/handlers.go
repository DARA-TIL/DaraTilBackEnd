package folklore

import (
	"DaraTilBackEnd/backend/internal/config"
	"DaraTilBackEnd/backend/internal/database"
	"DaraTilBackEnd/backend/internal/models"
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
)

type Handler struct {
	cfg *config.Config
}

func NewHandler(cfg *config.Config) *Handler {
	return &Handler{cfg: cfg}
}

func (h *Handler) CreateFolklore(c *gin.Context) {
	var folklore models.Folklore
	if err := c.ShouldBindJSON(&folklore); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if err := database.DB.Create(&folklore).Error; err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
}

type folkloreRequest struct {
	Id int `json:"id"`
}

func (h *Handler) GetFolkloreById(c *gin.Context) {
	var body folkloreRequest
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	var folklore models.Folklore
	if err := database.DB.Where("id = ?", body.Id).First(&folklore).Error; err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, folklore)
}

func (h *Handler) GetAllFolklore(c *gin.Context) {
	var folklore []models.Folklore
	if err := database.DB.Find(&folklore).Error; err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	fmt.Println(folklore)
	c.JSON(http.StatusOK, folklore)
}
