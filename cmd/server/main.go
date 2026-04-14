package main

import (
	"DaraTilBackendV2/internal/app"
	"DaraTilBackendV2/internal/config"
	"log"

	"github.com/joho/godotenv"
)

// @title DaraTil Backend
// @version 0.2
// @description Api server for DaraTil PLatform

// @host https://daratilback.onrender.com
// @BasePath /api
// @schemes https
// @securityDefinitions.apikey BearerAuth
// @in header
// @name Authorization
func main() {
	if err := godotenv.Load(); err != nil {
		log.Println("Error loading .env file")
	}
	cfg, err := config.LoadConfig()
	if err != nil {
		log.Println("Failed to load config")
	}
	app := app.New(cfg)
	app.Run()
}
