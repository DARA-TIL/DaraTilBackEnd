package timeEvent

import (
	"DaraTilBackendV2/internal/presentation/http/middleware"

	"github.com/gin-gonic/gin"
)

func RegisterRoutes(r *gin.RouterGroup, h *TimeEventHandler) {
	r.POST("/", middleware.RequireRole("admin"), h.Create)
	r.PATCH("/", middleware.RequireRole("admin"), h.Update)
	r.DELETE("/:id", middleware.RequireRole("admin"), h.Delete)
	r.GET("/:id", h.GetByID)
	r.GET("/", h.GetAll)
	r.POST("/finish/:id", middleware.RequireRole("admin"), h.FinishTimeEvent)
}

func RegisterTimeEventParticipantRoutes(r *gin.RouterGroup, h *TimeEventParticipantHandler) {
	r.POST("/", middleware.RequireRole("admin"), h.Create)
	r.PATCH("/", middleware.RequireRole("admin"), h.Update)
	r.DELETE("/:id", middleware.RequireRole("admin"), h.Delete)

	r.GET("/:id", h.GetByID)
	r.GET("/event/:id/:limit", h.GetByEventID)
}
