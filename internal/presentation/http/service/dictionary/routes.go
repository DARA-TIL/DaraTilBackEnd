package dictionary

import (
	"DaraTilBackendV2/internal/presentation/http/middleware"

	"github.com/gin-gonic/gin"
)

func RegisterRoutes(r *gin.RouterGroup, h *DictionaryHandler) {
	r.POST("/create", middleware.RequireRole("admin"), h.Create)
	r.GET("/getById/:id", h.GetByID)
	r.GET("/getAll", h.GetAll)
	r.GET("/getByWord/:word", h.GetByWord)
	r.PATCH("/update", middleware.RequireRole("admin"), h.Update)
	r.DELETE("/delete/:id", middleware.RequireRole("admin"), h.Delete)

	r.POST("/favorite", h.AddToFavorite)
	r.POST("/favorite/:id", h.AddToFavoriteWithID)
	r.DELETE("/favorite/:id", h.DeleteFromFavorite)
	r.GET("/favorite", h.GetFavorite)
}
