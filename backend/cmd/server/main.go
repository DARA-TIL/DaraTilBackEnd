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
	_ = godotenv.Load()
	cfg := config.Load()
	database.Connect(cfg)
	r := gin.Default()
	api := r.Group("/api")

	//Handlers
	authHandler := auth.NewHandler(cfg)

	//Groups
	authGroup := api.Group("/auth")

	auth.RegisterRoutes(authGroup, authHandler)

	log.Printf("server started on :%s", cfg.Port)
	if err := r.Run(":" + cfg.Port); err != nil {
		log.Fatal(err)
	}
}
