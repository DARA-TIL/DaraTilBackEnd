package folklore

import (
	"DaraTilBackEnd/backend/internal/middleware"

	"github.com/gin-gonic/gin"
)

func RegisterRoutes(r *gin.RouterGroup, h *Handler) {
	r.POST("/create", middleware.RequireRole("admin"), h.CreateFolklore)
	r.GET("/getAll", h.GetFolkloreList)
	r.GET("/getById/:id", h.GetFolkloreById)
	r.PATCH("/update/:id", h.UpdateFolklore)
	r.DELETE("/delete/:id", h.DeleteFolklore)
	r.POST("/like/:id", h.LikeFolklore)
	r.GET("/type/:type", h.GetFolkloreByType)
}
