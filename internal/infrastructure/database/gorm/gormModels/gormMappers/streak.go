package gormMappers

import (
	"DaraTilBackendV2/internal/domain/models"
	"DaraTilBackendV2/internal/infrastructure/database/gorm/gormModels"
)

func StreakToGormModel(streak models.Streak) gormModels.Streak {
	return gormModels.Streak{
		UserID:        streak.UserID,
		CurrentStreak: streak.CurrentStreak,
		LongestStreak: streak.LongestStreak,
		LastActivity:  streak.LastActivity,
	}
}
func GormStreakToDomain(streak gormModels.Streak) models.Streak {
	return models.Streak{
		ID:            streak.ID,
		UserID:        streak.UserID,
		CurrentStreak: streak.CurrentStreak,
		LongestStreak: streak.LongestStreak,
		LastActivity:  streak.LastActivity,
	}
}
