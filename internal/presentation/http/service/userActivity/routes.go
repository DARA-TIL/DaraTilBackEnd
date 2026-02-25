package userActivity

import (
	"github.com/gin-gonic/gin"
)

func RegisterRoutes(r *gin.RouterGroup, h *UserActivityHandler) {
	r.GET("/", h.GetUserActivities)
}
