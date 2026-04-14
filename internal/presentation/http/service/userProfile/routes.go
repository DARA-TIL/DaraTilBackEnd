package userProfile

import (
	"DaraTilBackendV2/internal/presentation/http/middleware"

	"github.com/gin-gonic/gin"
)

func RegisterRoutes(r *gin.RouterGroup, h *UserProfileHandler) {
	r.GET("/getByUserId/:id", h.GetByUserID)
	r.POST("/create", middleware.RequireRole("admin"), h.Create)
	r.PATCH("/updatePinnedAchievements", h.UpdatePinnedAchievements)
}
