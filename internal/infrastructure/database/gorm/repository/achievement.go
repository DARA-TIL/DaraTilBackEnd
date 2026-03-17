package repository

import (
	"DaraTilBackendV2/internal/domain/models"
	"DaraTilBackendV2/internal/infrastructure/database/gorm/errhandlers"
	"DaraTilBackendV2/internal/infrastructure/database/gorm/gormModels"
	"DaraTilBackendV2/internal/infrastructure/database/gorm/gormModels/gormMappers"
	"context"

	"gorm.io/gorm"
)

type AchievementRepository struct {
	db *gorm.DB
}

func NewAchievementRepository(db *gorm.DB) *AchievementRepository {
	return &AchievementRepository{
		db: db,
	}
}

func (a AchievementRepository) Create(ctx context.Context, achievement models.Achievement) error {
	gormAchievement := gormMappers.AchievementToGormModel(achievement)
	err := a.db.WithContext(ctx).Create(&gormAchievement).Error
	if err != nil {
		return errhandlers.DBErrHandler(err)
	}
	return nil
}

func (a AchievementRepository) Update(ctx context.Context, achievement models.Achievement) error {
	gormAchievement := gormMappers.AchievementToGormModel(achievement)
	err := a.db.WithContext(ctx).Where("id = ?", achievement.ID).Updates(gormAchievement).Error
	if err != nil {
		return errhandlers.DBErrHandler(err)
	}
	return nil
}

func (a AchievementRepository) Delete(ctx context.Context, id uint) error {
	if err := a.db.WithContext(ctx).Unscoped().Delete(&gormModels.Achievement{}, id).Error; err != nil {
		return errhandlers.DBErrHandler(err)
	}
	return nil
}

func (a AchievementRepository) GetByID(ctx context.Context, userID, id uint) (*models.Achievement, error) {
	var gormAchievement gormModels.Achievement
	err := a.db.WithContext(ctx).Preload("UserAchievements", "user_id = ?", userID).First(&gormAchievement, id).Error
	if err != nil {
		return nil, errhandlers.DBErrHandler(err)
	}
	achievement := gormMappers.GormAchievementToDomain(gormAchievement)
	return &achievement, nil
}

func (a AchievementRepository) GetAll(ctx context.Context, userID uint) ([]models.Achievement, error) {
	var gormAchievements []gormModels.Achievement
	err := a.db.WithContext(ctx).Preload("UserAchievements", "user_id = ?", userID).Find(&gormAchievements).Error
	if err != nil {
		return nil, errhandlers.DBErrHandler(err)
	}

	achievements := gormMappers.GormAchievementsToDomain(gormAchievements)
	return achievements, nil
}
func (a AchievementRepository) GetByAction(ctx context.Context, action models.Actions) ([]models.Achievement, error) {
	var gormAchievements []gormModels.Achievement
	if err := a.db.WithContext(ctx).Where("action = ?", action).Find(&gormAchievements).Error; err != nil {
		return nil, errhandlers.DBErrHandler(err)
	}
	ach := gormMappers.GormAchievementsToDomain(gormAchievements)
	return ach, nil
}
