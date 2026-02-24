package middleware

import (
	"DaraTilBackendV2/internal/config"
	"DaraTilBackendV2/internal/domain/domErr"
	"DaraTilBackendV2/internal/infrastructure/logger"
	"DaraTilBackendV2/internal/presentation/dto"
	"DaraTilBackendV2/internal/presentation/http/response"
	"errors"
	"fmt"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"go.uber.org/zap"
)

const ContextUserKey = "user"

func AuthMiddleware(cfg *config.Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			logger.Error("No Authorization header")
			response.HandleDomainError(c, domErr.ErrUnauthorized)
			c.Abort()
			return
		}

		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) != 2 || parts[0] != "Bearer" {
			logger.Error("Wrong Authorization header")
			response.HandleDomainError(c, domErr.ErrUnauthorized)
			c.Abort()
			return
		}
		tokenStr := parts[1]

		claims := &dto.CustomClaims{}

		token, err := jwt.ParseWithClaims(tokenStr, claims, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				logger.Error("Unexpected signing method")
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
			logger.Error("Unexpected signing method")
			response.HandleDomainError(c, domErr.ErrUnauthorized)
			c.Abort()
			return
		}
		inf := fmt.Sprintf("User: %v", claims.Username)
		logger.Info(inf)
		c.Set(ContextUserKey, claims)
		c.Next()
	}
}

func GetUserClaims(c *gin.Context) (*dto.CustomClaims, bool) {
	logger.Info("Getting user claims")
	val, exists := c.Get(ContextUserKey)
	if !exists {
		logger.Error("User claims not found")
		return nil, false
	}
	claims, ok := val.(*dto.CustomClaims)
	if !ok {
		logger.Error("User claims not found")
		return nil, false
	}
	return claims, ok
}

func RequireRole(requiredRoles ...string) gin.HandlerFunc {
	return func(c *gin.Context) {
		val, exists := c.Get(ContextUserKey)
		if !exists {
			logger.Error("User claims not found")
			response.HandleDomainError(c, domErr.ErrUnauthorized)
			c.Abort()
			return
		}

		if len(requiredRoles) == 0 {
			logger.Error("Required roles is empty")
			response.HandleDomainError(c, domErr.ErrUnauthorized)
			c.Abort()
			return
		}
		claims, ok := val.(*dto.CustomClaims)
		if !ok {
			logger.Error("User claims not found")
			response.HandleDomainError(c, domErr.ErrUnauthorized)
			c.Abort()
			return
		}
		for _, role := range requiredRoles {
			if role == claims.Role {
				logger.Info("User doing protected action for", zap.String("role", role))
				c.Next()
				return
			}
		}
		logger.Error("Required role not found")
		response.HandleDomainError(c, domErr.ErrForbidden)
		c.Abort()
		return
	}
}

func GetCurrentUserID(c *gin.Context) (*uint, error) {
	claims, ok := GetUserClaims(c)
	if !ok {
		logger.Error("User claims not found")
		return nil, domErr.ErrUnauthorized
	}
	id := claims.UserID
	logger.Info("Got userID", zap.Int("id", int(id)))
	return &claims.UserID, nil
}
