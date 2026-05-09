package notification

import (
	"DaraTilBackendV2/internal/presentation/http/middleware"

	"github.com/gin-gonic/gin"
)

func RegisterRoutes(r *gin.RouterGroup, h *NotificationHandler) {
	r.POST("/", middleware.RequireRole("admin"), h.Create)
	r.PATCH("/", middleware.RequireRole("admin"), h.Update)
	r.DELETE("/:id", middleware.RequireRole("admin"), h.Delete)

	r.GET("/:id", h.GetByID)
	r.GET("/", h.GetAll)
}
