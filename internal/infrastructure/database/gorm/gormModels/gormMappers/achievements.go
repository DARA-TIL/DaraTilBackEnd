package gormMappers

import (
	"DaraTilBackendV2/internal/domain/models"
	"DaraTilBackendV2/internal/infrastructure/database/gorm/gormModels"
)

func AchievementToGormModel(achievement models.Achievement) gormModels.Achievement {
	return gormModels.Achievement{
		Name:        achievement.Name,
		Description: achievement.Description,
		Action:      achievement.Action,
		Quantity:    achievement.Quantity,
		IconURL:     achievement.IconURL,
	}
}

func AchievementsToGormModel(achievements []models.Achievement) []gormModels.Achievement {
	var res []gormModels.Achievement

	for _, a := range achievements {
		res = append(res, AchievementToGormModel(a))
	}

	return res
}

func UserAchievementToGormModel(userAchievement models.UserAchievement) gormModels.UserAchievement {
	return gormModels.UserAchievement{
		ID:            userAchievement.ID,
		UserID:        userAchievement.UserID,
		AchievementID: userAchievement.AchievementID,
		Quantity:      userAchievement.Quantity,
		Achieved:      userAchievement.Achieved,
	}
}

func UserAchievementsToGormModel(userAchievements []models.UserAchievement) []gormModels.UserAchievement {
	var res []gormModels.UserAchievement

	for _, ua := range userAchievements {
		res = append(res, UserAchievementToGormModel(ua))
	}

	return res
}

func GormAchievementToDomain(achievement gormModels.Achievement) models.Achievement {
	return models.Achievement{
		ID:               achievement.ID,
		Name:             achievement.Name,
		Description:      achievement.Description,
		Action:           achievement.Action,
		Quantity:         achievement.Quantity,
		IconURL:          achievement.IconURL,
		UserAchievements: GormUserAchievementsToDomain(achievement.UserAchievements),
	}
}

func GormAchievementsToDomain(achievements []gormModels.Achievement) []models.Achievement {
	var res []models.Achievement

	for _, a := range achievements {
		res = append(res, GormAchievementToDomain(a))
	}

	return res
}

func GormUserAchievementToDomain(userAchievement gormModels.UserAchievement) models.UserAchievement {
	return models.UserAchievement{
		ID:            userAchievement.ID,
		UserID:        userAchievement.UserID,
		AchievementID: userAchievement.AchievementID,
		Quantity:      userAchievement.Quantity,
		Achieved:      userAchievement.Achieved,
	}
}

func GormUserAchievementsToDomain(userAchievements []gormModels.UserAchievement) []models.UserAchievement {
	var res []models.UserAchievement

	for _, ua := range userAchievements {
		res = append(res, GormUserAchievementToDomain(ua))
	}

	return res
}
