package leaderboard

import "github.com/gin-gonic/gin"

func RegisterRoutes(r *gin.RouterGroup, h *LeaderboardHandler) {
	r.GET("/:metric/:limit", h.Get)
	r.GET("/profile/:metric/:limit", h.GetProfile)
}
