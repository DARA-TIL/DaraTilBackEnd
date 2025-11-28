package middleware

import (
	"DaraTilBackEnd/backend/internal/config"
	"DaraTilBackEnd/backend/internal/services/auth"
	"fmt"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
)

const ContextUserKey = "user"

func AuthMiddleware(cfg *config.Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "No Authorization header"})
			c.Abort()
			return
		}

		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) != 2 || parts[0] != "Bearer" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid Authorization header"})
			c.Abort()
			return
		}
		tokenStr := parts[1]

		claims := &auth.CustomClaims{}

		token, err := jwt.ParseWithClaims(tokenStr, claims, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("There was an error")
			}
			return []byte(cfg.JwtAccessSecret), nil
		})

		if err != nil || !token.Valid {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid Authorization header"})
			c.Abort()
			return
		}
		if claims.Subject != "access" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid Authorization header"})
			c.Abort()
			return
		}
		c.Set(ContextUserKey, claims)
		c.Next()
	}
}

func GetUserClaims(c *gin.Context) (*auth.CustomClaims, bool) {
	val, exists := c.Get(ContextUserKey)
	if !exists {
		return nil, false
	}
	claims, ok := val.(*auth.CustomClaims)
	return claims, ok
}

func RequireRole(requiredRoles ...string) gin.HandlerFunc {
	return func(c *gin.Context) {
		val, exists := c.Get(ContextUserKey)
		if !exists {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "No Authorization header"})
			c.Abort()
			return
		}
		if len(requiredRoles) == 0 {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Required role not provided"})
			c.Abort()
			return
		}
		claims, ok := val.(*auth.CustomClaims)
		if !ok {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid Authorization header"})
			c.Abort()
			return
		}
		for _, role := range requiredRoles {
			if role == claims.Role {
				c.Next()
				return
			}
		}
		ertxt := "Don't have enough role to do this request" + claims.Role
		c.JSON(http.StatusUnauthorized, gin.H{"error": ertxt})
		c.Abort()
		return
	}
}
