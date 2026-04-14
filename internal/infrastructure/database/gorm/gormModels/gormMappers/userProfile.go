package gormMappers

import (
	"DaraTilBackendV2/internal/domain/models"
	"DaraTilBackendV2/internal/infrastructure/database/gorm/gormModels"
)

func UserProfileToDomain(up gormModels.UserProfile) models.UserProfile {
	return models.UserProfile{
		UserID:             up.UserID,
		PinnedAchievements: PinnedAchievementsToDomain(up.PinnedAchievements),
		WordsLearned:       up.WordsLearned,
		User:               GormUserToDomain(up.User),
	}
}
func PinnedAchievementsToDomain(a []gormModels.PinnedAchievement) []models.Achievement {
	var res []models.Achievement
	for _, ac := range a {
		res = append(res, GormAchievementToDomain(ac.Achievement))
	}
	return res
}

func PinnedAchievementsFromIDs(u models.UserProfileUpdate) []gormModels.PinnedAchievement {
	res := make([]gormModels.PinnedAchievement, 0, len(u.PinnedAchievementIDS))

	for _, id := range u.PinnedAchievementIDS {
		res = append(res, gormModels.PinnedAchievement{
			UserID:        u.UserID,
			AchievementID: id,
		})
	}

	return res
}
