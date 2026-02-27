package repository

import (
	"DaraTilBackendV2/internal/domain/models"
	"DaraTilBackendV2/internal/infrastructure/database/gorm/errhandlers"
	"DaraTilBackendV2/internal/infrastructure/database/gorm/gormModels"
	"DaraTilBackendV2/internal/infrastructure/database/gorm/gormModels/gormMappers"
	"DaraTilBackendV2/internal/infrastructure/utils"
	"context"

	"gorm.io/gorm"
)

type StreakRepository struct {
	db *gorm.DB
}

func NewStreakRepository(db *gorm.DB) *StreakRepository {
	return &StreakRepository{
		db: db,
	}
}

func (s *StreakRepository) Create(ctx context.Context, streak models.Streak) error {
	streakGorm := gormMappers.StreakToGormModel(streak)
	err := s.db.WithContext(ctx).Create(&streakGorm).Error
	if err != nil {
		return errhandlers.DBErrHandler(err)
	}
	return nil
}

func (s *StreakRepository) Increment(ctx context.Context, userID uint) error {
	today := utils.TodayUTC()
	err := s.db.WithContext(ctx).
		Model(&gormModels.Streak{}).
		Where("user_id = ?", userID).
		Updates(map[string]interface{}{
			"current_streak": gorm.Expr("current_streak + 1"),
			"last_activity":  today,
			"longest_streak": gorm.Expr("GREATEST(longest_streak, current_streak + 1)"),
		}).Error
	if err != nil {
		return errhandlers.DBErrHandler(err)
	}
	return nil
}
func (s *StreakRepository) GetByUserID(ctx context.Context, userID uint) (*models.Streak, error) {
	var streak gormModels.Streak
	if err := s.db.WithContext(ctx).Where("user_id = ?", userID).First(&streak).Error; err != nil {
		return nil, errhandlers.DBErrHandler(err)
	}
	streakDom := gormMappers.GormStreakToDomain(streak)
	return &streakDom, nil
}
func (s *StreakRepository) Reset(ctx context.Context, userID uint) error {
	err := s.db.WithContext(ctx).
		Model(&gormModels.Streak{}).
		Where("user_id = ?", userID).
		Updates(map[string]interface{}{
			"current_streak": 0,
		}).Error
	if err != nil {
		return errhandlers.DBErrHandler(err)
	}
	return nil
}

func (s *StreakRepository) Start(ctx context.Context, userID uint) error {
	today := utils.TodayUTC()
	err := s.db.WithContext(ctx).
		Model(&gormModels.Streak{}).
		Where("user_id = ?", userID).
		Updates(map[string]interface{}{
			"current_streak": 1,
			"last_activity":  today,
			"longest_streak": gorm.Expr("GREATEST(longest_streak, 1)"),
		}).Error
	if err != nil {
		return errhandlers.DBErrHandler(err)
	}
	return nil
}
