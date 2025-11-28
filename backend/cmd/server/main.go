package main

import (
	"DaraTilBackEnd/backend/internal/config"
	"DaraTilBackEnd/backend/internal/database"
	auth2 "DaraTilBackEnd/backend/internal/services/auth"
	"DaraTilBackEnd/backend/internal/services/folklore"
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
		AllowOrigins:     []string{"*"},
		AllowCredentials: false,
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

	//Groups
	api := r.Group("/api")
	authGroup := api.Group("/auth")
	auth2.RegisterRoutes(authGroup, authHandler)

	folkloreGroup := api.Group("/folklore")
	folklore.RegisterRoutes(folkloreGroup, folkloreHandler)

	log.Printf("server started on :%s", cfg.Port)
	if err := r.Run(":" + cfg.Port); err != nil {
		log.Fatal(err)
	}
}
