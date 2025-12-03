package user

import (
	"github.com/gin-gonic/gin"
)

func RegisterRoutes(r *gin.RouterGroup, h *Handler) {
	r.GET("/getLikedFolklore", h.GetLikedFolklore)
	r.POST("/changePassword/:email", h.ChangePassword)
	r.POST("/verifyPasswordReset", h.VerifyPasswordResetCode)
	r.POST("/confirmPasswordReset", h.ConfirmPasswordChange)
}
