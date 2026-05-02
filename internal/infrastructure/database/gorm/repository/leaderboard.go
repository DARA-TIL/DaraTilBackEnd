package repository

import (
	"DaraTilBackendV2/internal/domain/models"
	"DaraTilBackendV2/internal/infrastructure/database/gorm/errhandlers"
	"DaraTilBackendV2/internal/infrastructure/database/gorm/gormModels"
	"DaraTilBackendV2/internal/infrastructure/database/gorm/gormModels/gormMappers"
	"context"

	"gorm.io/gorm"
)

type LeaderboardRepository struct {
	db *gorm.DB
}

func NewLeaderboardRepository(db *gorm.DB) *LeaderboardRepository {
	return &LeaderboardRepository{db: db}
}

func (l *LeaderboardRepository) GetByXP(ctx context.Context, limit int) ([]models.User, error) {
	var users []gormModels.User
	err := l.db.WithContext(ctx).Joins("LEFT JOIN user_progresses ON user_progresses.user_id = users.id").
		Preload("Progress").
		Limit(limit).
		Order("user_progresses.level DESC").
		Order("user_progresses.xp_total DESC").
		Find(&users).Error
	if err != nil {
		return nil, errhandlers.DBErrHandler(err)
	}
	usersDom := gormMappers.GormUsersToDomain(users)
	return usersDom, nil
}

func (l *LeaderboardRepository) GetByStreak(ctx context.Context, limit int) ([]models.User, error) {
	var users []gormModels.User
	err := l.db.WithContext(ctx).Joins("LEFT JOIN streaks ON streaks.user_id = users.id").
		Preload("Streak").
		Limit(limit).
		Order("streaks.current_streak DESC").
		Find(&users).Error
	if err != nil {
		return nil, errhandlers.DBErrHandler(err)
	}
	usersDom := gormMappers.GormUsersToDomain(users)
	return usersDom, nil
}

func (l *LeaderboardRepository) GetByWords(ctx context.Context, limit int) ([]models.UserProfile, error) {
	var up []gormModels.UserProfile
	err := l.db.WithContext(ctx).
		Preload("User").
		Limit(limit).
		Order("words_learned DESC").
		Find(&up).Error
	if err != nil {
		return nil, errhandlers.DBErrHandler(err)
	}
	upDom := gormMappers.UserProfilesToDomain(up)
	return upDom, nil
}
