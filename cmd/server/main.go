package main

import (
	"DaraTilBackendV2/internal/app"
	"DaraTilBackendV2/internal/config"

	"github.com/joho/godotenv"
)

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
