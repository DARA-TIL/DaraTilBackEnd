package main

import (
	"DaraTilBackEnd/backend/internal/config"
	"DaraTilBackEnd/backend/internal/database"
	auth2 "DaraTilBackEnd/backend/internal/services/auth"
	"DaraTilBackEnd/backend/internal/services/folklore"
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
