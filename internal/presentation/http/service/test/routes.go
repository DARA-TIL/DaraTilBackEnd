package test

import (
	"DaraTilBackendV2/internal/presentation/http/middleware"

	"github.com/gin-gonic/gin"
)

func RegisterProtectedTestRoutes(r *gin.RouterGroup, h *TestHandler) {

	// Create
	r.POST("/create", middleware.RequireRole("admin"), h.Create)
	r.POST("/question/create", middleware.RequireRole("admin"), h.CreateQuestion)
	r.POST("/option/create", middleware.RequireRole("admin"), h.CreateOption)

	// Delete
	r.DELETE("/delete/:id", middleware.RequireRole("admin"), h.Delete)
	r.DELETE("/question/delete/:id", middleware.RequireRole("admin"), h.DeleteQuestion)
	r.DELETE("/option/delete/:id", middleware.RequireRole("admin"), h.DeleteOption)

	// Read
	r.GET("/get/:id", h.GetByID)
	r.GET("/lesson/:id", h.GetByLessonID)

	// Update
	r.PUT("/update", middleware.RequireRole("admin"), h.UpdateTest)
	r.PUT("/question/update", middleware.RequireRole("admin"), h.UpdateQuestion)
	r.PUT("/option/update", middleware.RequireRole("admin"), h.UpdateQuestionOption)
}
