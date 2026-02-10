package user

import (
	"DaraTilBackendV2/internal/presentation/http/response"
	"DaraTilBackendV2/internal/presentation/http/service/jwt"
	"net/http"

	"github.com/gin-gonic/gin"
)

var allowedProviders = map[string]bool{
	"github": true,
	"google": true,
}

func RegisterRoutes(r *gin.RouterGroup, h *UserHandler, hj *jwt.JwtTokenHandler) {
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
	r.GET(":provider/callback", func(c *gin.Context) {
		provider := c.Param("provider")
		if !allowedProviders[provider] {
			response.Fail(c, http.StatusBadRequest, "Invalid provider")
			return
		}
		h.OauthCallback(c, provider)
	})
}
func RegisterProtectedRoutes(r *gin.RouterGroup, hj *jwt.JwtTokenHandler) {
	r.GET("/refresh", hj.RefreshToken)
	r.POST("/logout", hj.Logout)
	r.GET("/me", hj.GetMe)
}
