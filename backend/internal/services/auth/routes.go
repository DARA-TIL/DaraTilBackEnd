package auth

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

var allowedProviders = map[string]bool{
	"github": true,
	"google": true,
}

func RegisterRoutes(r *gin.RouterGroup, h *Handler) {
	r.POST("/login", h.Login)
	r.POST("/register", h.Register)
	r.GET("/refresh", h.RefreshToken)
	r.GET(":provider", func(c *gin.Context) {
		provider := c.Param("provider")
		if !allowedProviders[provider] {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid provider name"})
			return
		}
		h.OauthLogin(c, provider)
	})
	r.GET(":provider/callback", func(c *gin.Context) {
		provider := c.Param("provider")
		if !allowedProviders[provider] {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid provider name"})
			return
		}
		h.OauthCallback(c, provider)
	})
}
