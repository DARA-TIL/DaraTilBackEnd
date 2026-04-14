package achievement

import (
	"DaraTilBackendV2/internal/presentation/http/middleware"

	"github.com/gin-gonic/gin"
)

func RegisterAchievementRoutes(r *gin.RouterGroup, h *AchievementHandler) {
	r.POST("/create", middleware.RequireRole("admin"), h.Create)
	r.GET("/getAll", h.GetAll)
	r.GET("/getById/:id", h.GetByID)
	r.PATCH("/update", middleware.RequireRole("admin"), h.Update)
	r.DELETE("/delete/:id", middleware.RequireRole("admin"), h.Delete)
	r.GET("/achieved", h.GetAchieved)
}
func RegisterUserAchievementRoutes(r *gin.RouterGroup, h *UserAchievementHandler) {
	r.POST("/create", h.Create)
	r.GET("/getById/:id", h.GetByID)
	r.GET("/getByUserId/:id", h.GetByUserID)
	r.PATCH("/update", h.Update)
	r.DELETE("/delete/:id", h.Delete)
}
