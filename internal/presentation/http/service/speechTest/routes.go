package speechTest

import (
	"DaraTilBackendV2/internal/presentation/http/middleware"

	"github.com/gin-gonic/gin"
)

func RegisterRoutes(r *gin.RouterGroup, h *SpeechTestHandler) {
	r.POST("/", middleware.RequireRole("admin"), h.Create)
	r.PATCH("/:id", middleware.RequireRole("admin"), h.Update)
	r.DELETE("/:id", middleware.RequireRole("admin"), h.Delete)

	r.GET("/:id", h.GetByID)
	r.GET("/", h.GetAll)
}
func RegisterSessionRoutes(r *gin.RouterGroup, h *SpeechTestSessionHandler) {
	r.POST("/start", h.StartSession)
	r.GET("/next", h.GetNextTest)
	r.POST("/check", h.CheckPronounce)
	r.POST("/end", h.EndSession)
}
