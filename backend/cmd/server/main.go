package main

import (
	"DaraTilBackEnd/backend/internal/config"
	"DaraTilBackEnd/backend/internal/database"
	"DaraTilBackEnd/backend/internal/middleware"
	auth2 "DaraTilBackEnd/backend/internal/services/auth"
	"DaraTilBackEnd/backend/internal/services/folklore"
	"DaraTilBackEnd/backend/internal/services/user"
	"log"
	"time"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"
)

func main() {
	//
	//
	//Config
	_ = godotenv.Load()
	cfg := config.Load()
	cfg.SetupGoogleOAuth()
	cfg.SetupGithubOAuth()
	database.Connect(cfg)
	r := gin.Default()
	cfg.SetupSessionStore()

	r.Use(cors.New(cors.Config{
		AllowOrigins:     []string{"http://localhost:5173", "http://localhost:8080"},
		AllowCredentials: true,
		AllowMethods: []string{
			"GET",
			"POST",
			"PUT",
			"PATCH",
			"DELETE",
		},
		AllowHeaders: []string{
			"Authorization",
			"Content-Type",
			"X-CSRF-Token",
		},
		ExposeHeaders: []string{
			"Content-Length",
		},
		MaxAge: 12 * time.Hour,
	}))

	//Handlers
	authHandler := auth2.NewHandler(cfg)
	folkloreHandler := folklore.NewHandler(cfg)
	userHandler := user.NewHandler(cfg)

	//Groups
	api := r.Group("/api")
	authGroup := api.Group("/auth")
	auth2.RegisterRoutes(authGroup, authHandler)

	folkloreGroup := api.Group("/folklore")
	folkloreGroup.Use(middleware.AuthMiddleware(cfg))
	folklore.RegisterRoutes(folkloreGroup, folkloreHandler)

	protectedUserGroup := api.Group("/user")
	protectedUserGroup.Use(middleware.AuthMiddleware(cfg))
	user.RegisterProtectedRoutes(protectedUserGroup, userHandler)
	userGroup := api.Group("/user")
	user.RegisterRoutes(userGroup, userHandler)
	log.Printf("server started on :%s", cfg.Port)
	if err := r.Run(":" + cfg.Port); err != nil {
		log.Fatal(err)
	}
}
