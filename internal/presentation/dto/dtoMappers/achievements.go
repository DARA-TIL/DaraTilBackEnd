package dtoMappers

import (
	"DaraTilBackendV2/internal/domain/models"
	"DaraTilBackendV2/internal/presentation/dto"
)

func AchievementToDTO(achievement models.Achievement) dto.Achievement {
	return dto.Achievement{
		ID:               achievement.ID,
		Name:             achievement.Name,
		Description:      achievement.Description,
		Action:           achievement.Action,
		Quantity:         achievement.Quantity,
		IconURL:          achievement.IconURL,
		UserAchievements: UserAchievementsToDTO(achievement.UserAchievements),
	}
}

func AchievementsToDTO(achievements []models.Achievement) []dto.Achievement {
	var res []dto.Achievement

	for _, a := range achievements {
		res = append(res, AchievementToDTO(a))
	}

	return res
}

func AchievementToDomain(achievement dto.Achievement) models.Achievement {
	return models.Achievement{
		ID:          achievement.ID,
		Name:        achievement.Name,
		Description: achievement.Description,
		Action:      achievement.Action,
		Quantity:    achievement.Quantity,
		IconURL:     achievement.IconURL,
	}
}

func AchievementsToDomain(achievements []dto.Achievement) []models.Achievement {
	var res []models.Achievement

	for _, a := range achievements {
		res = append(res, AchievementToDomain(a))
	}

	return res
}

func UserAchievementToDTO(userAchievement models.UserAchievement) dto.UserAchievement {
	return dto.UserAchievement{
		ID:            userAchievement.ID,
		UserID:        userAchievement.UserID,
		AchievementID: userAchievement.AchievementID,
		Quantity:      userAchievement.Quantity,
		Achieved:      userAchievement.Achieved,
	}
}

func UserAchievementsToDTO(userAchievements []models.UserAchievement) []dto.UserAchievement {
	var res []dto.UserAchievement

	for _, ua := range userAchievements {
		res = append(res, UserAchievementToDTO(ua))
	}

	return res
}

func UserAchievementToDomain(userAchievement dto.UserAchievement) models.UserAchievement {
	return models.UserAchievement{
		ID:            userAchievement.ID,
		UserID:        userAchievement.UserID,
		AchievementID: userAchievement.AchievementID,
		Quantity:      userAchievement.Quantity,
		Achieved:      userAchievement.Achieved,
	}
}

func UserAchievementsToDomain(userAchievements []dto.UserAchievement) []models.UserAchievement {
	var res []models.UserAchievement

	for _, ua := range userAchievements {
		res = append(res, UserAchievementToDomain(ua))
	}

	return res
}
