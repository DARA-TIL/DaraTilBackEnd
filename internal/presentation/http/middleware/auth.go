package middleware

import (
	"DaraTilBackendV2/internal/config"
	"DaraTilBackendV2/internal/domain/domErr"
	"DaraTilBackendV2/internal/presentation/dto"
	"DaraTilBackendV2/internal/presentation/http/response"
	"errors"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
)

const ContextUserKey = "user"

func AuthMiddleware(cfg *config.Config) gin.HandlerFunc {
	return func(c *gin.Context) {

		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			response.HandleDomainError(c, domErr.ErrUnauthorized)
			c.Abort()
			return
		}

		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) != 2 || parts[0] != "Bearer" {
			response.HandleDomainError(c, domErr.ErrUnauthorized)
			c.Abort()
			return
		}
		tokenStr := parts[1]

		claims := &dto.CustomClaims{}

		token, err := jwt.ParseWithClaims(tokenStr, claims, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, domErr.ErrUnauthorized
			}
			return []byte(cfg.Jwt.JwtAccessSecret), nil
		})
		if errors.Is(err, jwt.ErrTokenExpired) {
			response.HandleDomainError(c, domErr.ErrUnauthorized)
			c.Abort()
			return
		}
		if err != nil || !token.Valid {
			response.HandleDomainError(c, domErr.ErrUnauthorized)
			c.Abort()
			return
		}

		if claims.Subject != "access" {
			response.HandleDomainError(c, domErr.ErrUnauthorized)
			c.Abort()
			return
		}

		c.Set(ContextUserKey, claims)
		c.Next()
	}
}

func GetUserClaims(c *gin.Context) (*dto.CustomClaims, bool) {
	val, exists := c.Get(ContextUserKey)
	if !exists {
		return nil, false
	}
	claims, ok := val.(*dto.CustomClaims)
	if !ok {
		return nil, false
	}
	return claims, ok
}

func RequireRole(requiredRoles ...string) gin.HandlerFunc {
	return func(c *gin.Context) {

		val, exists := c.Get(ContextUserKey)
		if !exists {
			response.HandleDomainError(c, domErr.ErrUnauthorized)
			c.Abort()
			return
		}

		if len(requiredRoles) == 0 {
			response.HandleDomainError(c, domErr.ErrUnauthorized)
			c.Abort()
			return
		}
		claims, ok := val.(*dto.CustomClaims)
		if !ok {
			response.HandleDomainError(c, domErr.ErrUnauthorized)
			c.Abort()
			return
		}
		for _, role := range requiredRoles {
			if role == claims.Role {
				c.Next()
				return
			}
		}
		response.HandleDomainError(c, domErr.ErrForbidden)
		c.Abort()
		return
	}
}

func GetCurrentUserID(c *gin.Context) (*uint, error) {
	claims, ok := GetUserClaims(c)
	if !ok {
		return nil, domErr.ErrUnauthorized
	}

	return &claims.UserID, nil
}
