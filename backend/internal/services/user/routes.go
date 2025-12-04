package user

import (
	"DaraTilBackEnd/backend/internal/middleware"

	"github.com/gin-gonic/gin"
)

func RegisterRoutes(r *gin.RouterGroup, h *Handler) {
	r.POST("/changePassword/:email", h.ChangePassword)
	r.POST("/verifyPasswordReset", h.VerifyPasswordResetCode)
	r.POST("/confirmPasswordReset", h.ConfirmPasswordChange)
}
func RegisterProtectedRoutes(r *gin.RouterGroup, h *Handler) {
	r.GET("/getLikedFolklore", h.GetLikedFolklore)
	r.POST("/update", h.UpdateMe)
	r.POST("/update/:id", middleware.RequireRole("admin"), h.UpdateByAdmin)
	r.GET("/getAll", h.GetAllUsers)
}
