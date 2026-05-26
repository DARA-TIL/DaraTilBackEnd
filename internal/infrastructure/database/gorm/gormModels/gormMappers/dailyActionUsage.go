package gormMappers

import (
	"DaraTilBackendV2/internal/domain/models"
	"DaraTilBackendV2/internal/infrastructure/database/gorm/gormModels"
)

func DailyActionUsageToGormModel(usage models.DailyActionUsage) gormModels.DailyActionUsage {
	return gormModels.DailyActionUsage{
		ID:        usage.ID,
		UserID:    usage.UserID,
		Action:    usage.Action,
		UsageDate: usage.UsageDate,
		Count:     usage.Count,
		CreatedAt: usage.CreatedAt,
		UpdatedAt: usage.UpdatedAt,
	}
}

func GormDailyActionUsageToDomain(usage gormModels.DailyActionUsage) models.DailyActionUsage {
	return models.DailyActionUsage{
		ID:        usage.ID,
		UserID:    usage.UserID,
		Action:    usage.Action,
		UsageDate: usage.UsageDate,
		Count:     usage.Count,
		CreatedAt: usage.CreatedAt,
		UpdatedAt: usage.UpdatedAt,
	}
}
