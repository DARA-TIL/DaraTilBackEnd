package postgres

import (
	"DaraTilBackendV2/internal/config"
	gormModels2 "DaraTilBackendV2/internal/infrastructure/database/gorm/gormModels"
	"log"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

type PostgresRepository struct {
	Db *gorm.DB
}

func NewPostgresRepository(cfg config.Config) *PostgresRepository {
	db, err := gorm.Open(postgres.Open(cfg.Database.DatabaseUrl), &gorm.Config{})
	log.Printf("Starting Database Connection")
	if err != nil {
		log.Printf("Database Connection Failed: %v", err)
		panic("failed to connect database")
	}
	log.Printf("Database Connection Established")
	log.Printf("Starting Database Migration")
	err = AutoMigration(db)
	if err != nil {
		log.Printf("Database Migration Failed: %v", err)
		panic("database migration failed")
	}
	return &PostgresRepository{
		Db: db,
	}
}

func AutoMigration(db *gorm.DB) error {
	err := db.AutoMigrate(
		&gormModels2.User{},
		&gormModels2.Folklore{},
		&gormModels2.Token{},
		&gormModels2.FolkloreLike{},
		&gormModels2.FolkloreTranslation{},
		&gormModels2.UserProgress{},
		&gormModels2.Lesson{},
		&gormModels2.LessonBlock{},
		&gormModels2.Test{},
		&gormModels2.Question{},
		&gormModels2.QuestionOption{},
	)
	return err
}
