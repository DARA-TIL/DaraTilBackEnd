package folklore

import (
	"DaraTilBackEnd/backend/internal/config"
	"DaraTilBackEnd/backend/internal/database"
	"DaraTilBackEnd/backend/internal/models"
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
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
	c.JSON(http.StatusCreated, folklore)
}

func (h *Handler) GetFolkloreById(c *gin.Context) {
	var folklore models.Folklore
	id := c.Param("id")
	if err := database.DB.Where("id = ?", id).First(&folklore).Error; err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, folklore)
}

func (h *Handler) GetFolkloreList(c *gin.Context) {
	var folklore []models.Folklore
	if err := database.DB.Find(&folklore).Error; err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	fmt.Println(folklore)
	c.JSON(http.StatusOK, folklore)
}

func (h *Handler) UpdateFolklore(c *gin.Context) {
	id := c.Param("id")
	var body map[string]interface{}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	delete(body, "ID")
	delete(body, "id")
	delete(body, "CreatedAt")
	delete(body, "UpdatedAt")
	delete(body, "DeletedAt")
	if err := database.DB.Model(&models.Folklore{}).Where("id = ?", id).Updates(body).Error; err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	var folklore models.Folklore
	if err := database.DB.Where("id = ?", id).First(&folklore).Error; err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, folklore)
}

func (h *Handler) DeleteFolklore(c *gin.Context) {
	var folklore models.Folklore
	id := c.Param("id")
	result := database.DB.Unscoped().Where("id = ?", id).Delete(&folklore)
	if result.RowsAffected == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Record not found"})
		return
	}
	if result.Error != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": result.Error.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "Record deleted"})
}

func (h *Handler) LikeFolklore(c *gin.Context) {
	var folklore models.Folklore
	id := c.Params.ByName("id")
	results := database.DB.Model(models.Folklore{}).Where("id = ?", id).UpdateColumn("likes", gorm.Expr("likes + ?", 1))

	if results.RowsAffected == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Record not found"})
		return
	}
	if results.Error != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": results.Error.Error()})
		return
	}
	if err := database.DB.Where("id = ?", id).First(&folklore).Error; err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, folklore)
}

func (h *Handler) GetFolkloreByType(c *gin.Context) {
	var folklore []models.Folklore
	folkType := c.Params.ByName("type")
	if err := database.DB.Where("type = ?", folkType).Find(&folklore).Error; err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err})
		return
	}
	c.JSON(http.StatusOK, folklore)
}
