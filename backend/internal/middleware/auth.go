package middleware

import (
	"DaraTilBackEnd/backend/internal/config"
	"DaraTilBackEnd/backend/internal/database"
	"DaraTilBackEnd/backend/internal/models"
	"DaraTilBackEnd/backend/internal/services/auth"
	"fmt"
	"log"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
)

const ContextUserKey = "user"

func AuthMiddleware(cfg *config.Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		log.Println("[AUTH MIDDLEWARE] Incoming request:", c.Request.Method, c.Request.URL.Path)

		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			log.Println("[AUTH MIDDLEWARE] No Authorization header")
			c.JSON(http.StatusUnauthorized, gin.H{"error": "No Authorization header"})
			c.Abort()
			return
		}

		log.Println("[AUTH MIDDLEWARE] Authorization header received")

		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) != 2 || parts[0] != "Bearer" {
			log.Println("[AUTH MIDDLEWARE] Invalid Authorization header format:", authHeader)
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid Authorization header"})
			c.Abort()
			return
		}
		tokenStr := parts[1]
		log.Println("[AUTH MIDDLEWARE] Token extracted")

		claims := &auth.CustomClaims{}

		token, err := jwt.ParseWithClaims(tokenStr, claims, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				log.Println("[AUTH MIDDLEWARE] Unexpected signing method")
				return nil, fmt.Errorf("There was an error")
			}
			return []byte(cfg.JwtAccessSecret), nil
		})

		if err != nil || !token.Valid {
			log.Printf("[AUTH MIDDLEWARE] Invalid or expired token: %v\n", err)
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid Authorization header"})
			c.Abort()
			return
		}

		if claims.Subject != "access" {
			log.Printf("[AUTH MIDDLEWARE] Invalid token subject: %s\n", claims.Subject)
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid Authorization header"})
			c.Abort()
			return
		}

		log.Printf("[AUTH MIDDLEWARE] Authenticated user id=%d, role=%s, email=%s\n",
			claims.UserID, claims.Role, claims.Email)

		c.Set(ContextUserKey, claims)
		c.Next()
	}
}

func GetUserClaims(c *gin.Context) (*auth.CustomClaims, bool) {
	val, exists := c.Get(ContextUserKey)
	if !exists {
		log.Println("[GET USER CLAIMS] No user in context")
		return nil, false
	}
	claims, ok := val.(*auth.CustomClaims)
	if !ok {
		log.Println("[GET USER CLAIMS] Context value is not *CustomClaims")
		return nil, false
	}
	log.Printf("[GET USER CLAIMS] Found claims: user_id=%d, role=%s\n", claims.UserID, claims.Role)
	return claims, ok
}

func RequireRole(requiredRoles ...string) gin.HandlerFunc {
	return func(c *gin.Context) {
		log.Println("[REQUIRE ROLE] Checking roles for route:", c.Request.Method, c.Request.URL.Path)

		val, exists := c.Get(ContextUserKey)
		if !exists {
			log.Println("[REQUIRE ROLE] No user in context (no Authorization header)")
			c.JSON(http.StatusUnauthorized, gin.H{"error": "No Authorization header"})
			c.Abort()
			return
		}

		if len(requiredRoles) == 0 {
			log.Println("[REQUIRE ROLE] Middleware misconfigured: no requiredRoles provided")
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Required role not provided"})
			c.Abort()
			return
		}

		claims, ok := val.(*auth.CustomClaims)
		user, err := GetCurrentUser(c)
		if err != nil {
			log.Println("[REQUIRE ROLE] No user in context")
			c.JSON(http.StatusUnauthorized, gin.H{"error": "No Authorization header"})
			c.Abort()
			return
		}

		if !ok {
			log.Println("[REQUIRE ROLE] Invalid user claims type in context")
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid Authorization header"})
			c.Abort()
			return
		}

		log.Printf("[REQUIRE ROLE] User role=%s, required=%v\n", user.Role, requiredRoles)

		for _, role := range requiredRoles {
			if role == user.Role {
				log.Println("[REQUIRE ROLE] Access granted")
				c.Next()
				return
			}
		}

		ertxt := "Don't have enough role to do this request" + claims.Role
		log.Printf("[REQUIRE ROLE] Access denied: %s\n", ertxt)
		c.JSON(http.StatusUnauthorized, gin.H{"error": ertxt})
		c.Abort()
		return
	}
}

func GetCurrentUser(c *gin.Context) (*models.User, error) {
	claims, ok := GetUserClaims(c)
	if !ok {
		return nil, fmt.Errorf("no user claims in context")
	}

	var user models.User
	if err := database.DB.First(&user, claims.UserID).Error; err != nil {
		return nil, err
	}

	return &user, nil
}
