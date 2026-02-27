package folklore

import (
	"DaraTilBackendV2/internal/presentation/http/middleware"

	"github.com/gin-gonic/gin"
)

func RegisterRoutes(r *gin.RouterGroup, h *FolkloreHandler) {
	r.POST("/create", middleware.RequireRole("admin"), h.Create)
	r.GET("/getAll", h.GetAll)
	r.GET("/getById/:id", h.GetByID)
	r.PATCH("/update/:id", middleware.RequireRole("admin"), h.Update)
	r.DELETE("/delete/:id", middleware.RequireRole("admin"), h.Delete)
	r.POST("/like/:id", h.ToggleLike)
	r.GET("/search", h.GetByQuery)
}
