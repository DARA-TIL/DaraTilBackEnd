package user

import (
	"DaraTilBackendV2/internal/presentation/http/middleware"
	"DaraTilBackendV2/internal/presentation/http/response"
	"DaraTilBackendV2/internal/presentation/http/service/jwt"
	"net/http"

	"github.com/gin-gonic/gin"
)

var allowedProviders = map[string]bool{
	"github": true,
	"google": true,
}

func RegisterAuthRoutes(r *gin.RouterGroup, h *UserHandler, hj *jwt.JwtTokenHandler) {
	//auth
	r.POST("/login", h.Login)
	r.POST("/register", h.Register)
	r.GET(":provider", func(c *gin.Context) {
		provider := c.Param("provider")
		if !allowedProviders[provider] {
			response.Fail(c, http.StatusBadRequest, "Invalid provider")
			return
		}
		h.OauthLogin(c, provider)
	})
	r.GET("/refresh", hj.RefreshToken)
	r.GET(":provider/callback", func(c *gin.Context) {
		provider := c.Param("provider")
		if !allowedProviders[provider] {
			response.Fail(c, http.StatusBadRequest, "Invalid provider")
			return
		}
		h.OauthCallback(c, provider)
	})
}
func RegisterAuthProtectedRoutes(r *gin.RouterGroup, hj *jwt.JwtTokenHandler) {

	r.POST("/logout", hj.Logout)
	r.GET("/me", hj.GetMe)
}

func RegisterRoutes(r *gin.RouterGroup, h *UserHandler) {
	//password reset
	r.POST("/changePassword/:email", h.ChangePassword)
	r.POST("/verifyPasswordReset", h.VerifyPasswordResetCode)
	r.POST("/confirmPasswordReset", h.ConfirmPasswordChange)
}
func RegisterProtectedRoutes(r *gin.RouterGroup, h *UserHandler) {
	r.GET("/getLikedFolklore", h.GetLikedFolklore)
	r.POST("/update", h.UpdateMe)
	r.POST("/update/:id", middleware.RequireRole("admin"), h.UpdateByAdmin)
	r.GET("/getAll", h.GetAllUsers)
	r.GET("get/:id", h.GetUserByID)
	r.POST("/levelUp/:xp", h.LevelUp)
}
