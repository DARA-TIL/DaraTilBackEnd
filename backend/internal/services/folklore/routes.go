package folklore

import "github.com/gin-gonic/gin"

func RegisterRoutes(r *gin.RouterGroup, h *Handler) {
	r.POST("/create", h.CreateFolklore)
	r.GET("/getAll", h.GetAllFolklore)
}
