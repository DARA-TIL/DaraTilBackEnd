package main

import (
	"DaraTilBackendV2/internal/app"
	"DaraTilBackendV2/internal/config"

	"github.com/joho/godotenv"
)

// @title DaraTil Backend
// @version 0.2
// @description Api server for DaraTil PLatform

// @host daratilback.onrender.com
// @BasePath /api
// @schemes https
// @securityDefinitions.apikey BearerAuth
// @in header
// @name Authorization
func main() {
	_ = godotenv.Load()
	cfg, err := config.LoadConfig()
	if err != nil {
		panic(err)
	}
	cfg.SetupGithubOAuth()
	cfg.SetupGoogleOAuth()
	app := app.New(cfg)
	app.Run()
}
