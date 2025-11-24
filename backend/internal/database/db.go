package database

import (
	"DaraTilBackEnd/backend/internal/config"
	"DaraTilBackEnd/backend/internal/models"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

var DB *gorm.DB

func Connect(cfg *config.Config) {
	db, err := gorm.Open(postgres.Open(cfg.DatabaseURL), &gorm.Config{})
	if err != nil {
		panic("failed to connect database")
	}

	//migrations
	if err := db.AutoMigrate(&models.User{}); err != nil {
		panic("failed to migrate database")
	}
	DB = db
}
