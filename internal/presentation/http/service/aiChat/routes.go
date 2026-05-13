package aiChat

import "github.com/gin-gonic/gin"

func RegisterRoutes(r *gin.RouterGroup, h *AiChatHandler) {
	r.POST("", h.Create)
	r.GET("", h.GetAll)
	r.GET("/:id", h.GetByID)
	r.PATCH("/:id", h.Update)
	r.DELETE("/:id", h.Delete)

	r.GET("/:id/messages", h.GetMessages)
}
