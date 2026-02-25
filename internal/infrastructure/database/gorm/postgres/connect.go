package postgres

import (
	"DaraTilBackendV2/internal/config"
	"DaraTilBackendV2/internal/infrastructure/database/gorm/gormModels"
	"log"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

type PostgresRepository struct {
	Db *gorm.DB
}

func NewPostgresRepository(cfg *config.Config) *PostgresRepository {
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
		&gormModels.User{},
		&gormModels.UserProgress{},
		&gormModels.Folklore{},
		&gormModels.FolkloreTranslation{},
		&gormModels.Lesson{},
		&gormModels.LessonBlock{},
		&gormModels.Test{},
		&gormModels.Question{},
		&gormModels.QuestionOption{},
		&gormModels.LessonResult{},
		&gormModels.FolkloreLike{},
		&gormModels.Token{},
		&gormModels.UserActivity{},
	)
	return err
}
