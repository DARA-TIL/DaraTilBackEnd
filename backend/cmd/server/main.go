package main

import (
	"DaraTilBackEnd/backend/internal/auth"
	"DaraTilBackEnd/backend/internal/config"
	"DaraTilBackEnd/backend/internal/database"
	"log"

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

	//Handlers
	authHandler := auth.NewHandler(cfg)

	//Groups
	api := r.Group("/api")
	authGroup := api.Group("/auth")

	auth.RegisterRoutes(authGroup, authHandler)

	log.Printf("server started on :%s", cfg.Port)
	if err := r.Run(":" + cfg.Port); err != nil {
		log.Fatal(err)
	}
}
