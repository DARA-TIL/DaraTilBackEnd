package main

import (
	"DaraTilBackendV2/internal/application/usecases/folkloreUC"
	"DaraTilBackendV2/internal/config"
	"DaraTilBackendV2/internal/domain/models"
	"DaraTilBackendV2/internal/infrastructure/ai/gemini"
	"DaraTilBackendV2/internal/infrastructure/database/gorm/postgres"
	"DaraTilBackendV2/internal/infrastructure/database/gorm/repository"
	"fmt"
	"log"

	"github.com/joho/godotenv"
)

func main() {
	err := godotenv.Load()
	if err != nil {
		panic(err)
	}
	cfg, err := config.LoadConfig()
	if err != nil {
		log.Fatal(err)
	}
	db := postgres.NewPostgresRepository(*cfg)
	geminiAI := gemini.NewGeminiAI(*cfg)
}
