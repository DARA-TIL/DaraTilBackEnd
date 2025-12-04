package folklore

import (
	"DaraTilBackEnd/backend/internal/config"
	"DaraTilBackEnd/backend/internal/database"
	"DaraTilBackEnd/backend/internal/middleware"
	"DaraTilBackEnd/backend/internal/models"
	"DaraTilBackEnd/backend/internal/utils"
	"errors"
	"fmt"
	"log"
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
	log.Println("[FOLKLORE][CREATE] Incoming request")

	var folklore models.Folklore
	if err := c.ShouldBindJSON(&folklore); err != nil {
		log.Printf("[FOLKLORE][CREATE] Bind error: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
		return
	}

	log.Printf("[FOLKLORE][CREATE] Creating: %+v", folklore)

	if err := database.DB.Create(&folklore).Error; err != nil {
		log.Printf("[FOLKLORE][CREATE] DB error: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "internal server error"})
		return
	}

	log.Printf("[FOLKLORE][CREATE] Success: id=%v", folklore.ID)
	c.JSON(http.StatusCreated, folklore)
}

func (h *Handler) GetFolkloreById(c *gin.Context) {
	id := c.Param("id")
	log.Printf("[FOLKLORE][GET BY ID] id=%s", id)

	var folklore models.Folklore
	if err := database.DB.Where("id = ?", id).First(&folklore).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			log.Printf("[FOLKLORE][GET BY ID] id=%s not found", id)
			c.JSON(http.StatusNotFound, "not found")
			return
		}
		log.Printf("[FOLKLORE][GET BY ID] DB error: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "internal server error"})
		return
	}

	log.Printf("[FOLKLORE][GET BY ID] Success: %+v", folklore)
	c.JSON(http.StatusOK, folklore)
}

func (h *Handler) GetFolkloreList(c *gin.Context) {
	log.Println("[FOLKLORE][GET ALL] Incoming request")

	var folklore []models.Folklore
	if err := database.DB.Find(&folklore).Error; err != nil {
		log.Printf("[FOLKLORE][GET ALL] DB error: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "internal server error"})
		return
	}
	if len(folklore) == 0 {
		log.Printf("[FOLKLORE][GET ALL] No Folklore")
		c.JSON(http.StatusOK, gin.H{"data": "There are no Folklore"})
		return
	}
	log.Printf("[FOLKLORE][GET ALL] Count=%d", len(folklore))
	fmt.Println(folklore)

	c.JSON(http.StatusOK, folklore)
}

func (h *Handler) UpdateFolklore(c *gin.Context) {
	id := c.Param("id")
	log.Printf("[FOLKLORE][UPDATE] id=%s", id)

	var body map[string]interface{}
	if err := c.ShouldBindJSON(&body); err != nil {
		log.Printf("[FOLKLORE][UPDATE] Bind error: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}

	log.Printf("[FOLKLORE][UPDATE] Body: %+v", body)

	delete(body, "ID")
	delete(body, "id")
	delete(body, "CreatedAt")
	delete(body, "UpdatedAt")
	delete(body, "DeletedAt")

	if err := database.DB.Model(&models.Folklore{}).Where("id = ?", id).Updates(body).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			log.Printf("[FOLKLORE][UPDATE] DB error: %v", err)
			c.JSON(http.StatusNotFound, "not found")
			return
		}
		log.Printf("[FOLKLORE][UPDATE] DB update error: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "internal server error"})
		return
	}

	var folklore models.Folklore
	if err := database.DB.Where("id = ?", id).First(&folklore).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			log.Printf("[FOLKLORE][UPDATE] DB error: %v", err)
			c.JSON(http.StatusNotFound, "not found")
			return
		}
		log.Printf("[FOLKLORE][UPDATE] Fetch error: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "internal server error"})
		return
	}

	log.Printf("[FOLKLORE][UPDATE] Success: %+v", folklore)
	c.JSON(http.StatusOK, folklore)
}

func (h *Handler) DeleteFolklore(c *gin.Context) {
	id := c.Param("id")
	log.Printf("[FOLKLORE][DELETE] id=%s", id)

	var folklore models.Folklore
	result := database.DB.Unscoped().Where("id = ?", id).Delete(&folklore)

	if result.RowsAffected == 0 {
		log.Printf("[FOLKLORE][DELETE] Not found: id=%s", id)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Record not found"})
		return
	}

	if result.Error != nil {
		log.Printf("[FOLKLORE][DELETE] DB error: %v", result.Error)
		c.JSON(http.StatusBadRequest, gin.H{"error": "internal server error"})
		return
	}

	log.Printf("[FOLKLORE][DELETE] Success: id=%s", id)
	c.JSON(http.StatusOK, gin.H{"message": "Record deleted"})
}

func (h *Handler) LikeFolklore(c *gin.Context) {
	id := c.Param("id")
	user, err := middleware.GetCurrentUser(c)

	if id == "" || err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "id is required"})
		return
	}
	uintId, err := utils.ToUint(id)
	log.Printf("[FOLKLORE][LIKE] id=%s", id)
	log.Printf("[FOLKLORE][LIKE] id=%s, [USER ID] id = %d", id, user.ID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Can't like without authorization"})
		return
	}
	like := models.FolkloreLike{
		UserID:     user.ID,
		FolkloreID: uintId,
	}
	if err := database.DB.Create(&like).Error; err != nil {
		if errors.Is(err, gorm.ErrDuplicatedKey) {
			log.Printf("[FOLKLORE][LIKE] DB error: %v", err)
			c.JSON(http.StatusConflict, gin.H{"error": "Already liked"})
			return
		}
		log.Printf("[FOLKLORE][LIKE] DB error: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "internal server error"})
		return
	}
	log.Printf("[FOLKLORE][LIKE] Success: %+v", like)
	c.JSON(http.StatusOK, "Liked")
}

func (h *Handler) UnlikeFolklore(c *gin.Context) {
	folkloreID := c.Param("id")
	user, err := middleware.GetCurrentUser(c)

	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "internal server error"})
		return
	}
	if folkloreID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "folkloreID is required"})
		return
	}
	//uintId, err := utils.ToUint(folkloreID)
	log.Printf("[FOLKLORE][LIKE] folkloreID=%s", folkloreID)
	log.Printf("[FOLKLORE][LIKE] folkloreID=%s, [USER ID] folkloreID = %d", folkloreID, user.ID)
	//if err != nil {
	//	c.JSON(http.StatusBadRequest, gin.H{"error": "invalid folkloreID"})
	//	return
	//}
	res := database.DB.Unscoped().Where("folklore_id = ? AND user_id = ?", folkloreID, user.ID).Delete(&models.FolkloreLike{})
	if res.Error != nil {
		log.Printf("[FOLKLORE][UNLIKE] DB error: %v", res.Error)
		c.JSON(http.StatusBadRequest, gin.H{"error": "internal server error"})
		return
	}
	log.Println("[FOLKLORE][UNLIKE] Success")
	c.JSON(http.StatusOK, "Unlike")

}

func (h *Handler) GetFolkloreByType(c *gin.Context) {
	folkType := c.Param("type")
	log.Printf("[FOLKLORE][GET BY TYPE] type=%s", folkType)

	var folklore []models.Folklore
	if err := database.DB.Where("type = ?", folkType).Find(&folklore).Error; err != nil {
		if !errors.Is(err, gorm.ErrRecordNotFound) {
			log.Printf("[FOLKLORE][GET BY TYPE] DB error: %v", err)
			c.JSON(http.StatusBadRequest, gin.H{"error": "not found"})
			return
		}
		log.Printf("[FOLKLORE][GET BY TYPE] DB error: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "internal server error"})
		return
	}

	if len(folklore) == 0 {
		log.Printf("[FOLKLORE][GET BY TYPE] No records found: type=%s", folkType)
		c.JSON(http.StatusNotFound, gin.H{"error": "Folklore with this type not found"})
		return
	}

	log.Printf("[FOLKLORE][GET BY TYPE] Found %d items", len(folklore))
	c.JSON(http.StatusOK, folklore)
}
