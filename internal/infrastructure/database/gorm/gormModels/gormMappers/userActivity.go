package gormMappers

import (
	"DaraTilBackendV2/internal/domain/models"
	"DaraTilBackendV2/internal/infrastructure/database/gorm/gormModels"
)

func GormUserActivityToDomain(activity gormModels.UserActivity) models.UserActivity {
	return models.UserActivity{
		ID:         activity.ID,
		Time:       activity.CreatedAt,
		UserID:     activity.UserID,
		Action:     activity.Action,
		EntityType: models.EventEntityType(activity.EntityType),
		EntityID:   activity.EntityID,
	}
}
func UserActivityToGorm(activity models.UserActivity) gormModels.UserActivity {
	return gormModels.UserActivity{
		UserID:     activity.UserID,
		Action:     activity.Action,
		EntityType: string(activity.EntityType),
		EntityID:   activity.EntityID,
	}
}
func GormUserActivitiesToDomain(gormActivities []gormModels.UserActivity) []models.UserActivity {
	var activities []models.UserActivity
	for _, activity := range gormActivities {
		activities = append(activities, GormUserActivityToDomain(activity))
	}
	return activities
}
