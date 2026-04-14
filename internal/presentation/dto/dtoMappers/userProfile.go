package dtoMappers

import (
	"DaraTilBackendV2/internal/domain/models"
	"DaraTilBackendV2/internal/presentation/dto"
)

func UserProfileToDTO(up models.UserProfile) dto.UserProfile {
	return dto.UserProfile{
		UserID:             up.UserID,
		PinnedAchievements: AchievementsToDTO(up.PinnedAchievements),
		LessonsCompleted:   up.LessonsCompleted,
		WordsLearned:       up.WordsLearned,
		User:               UserToDto(up.User),
	}
}
func CreateUserProfileToDomain(dto dto.CreateUserProfile) models.CreateUserProfile {
	return models.CreateUserProfile{
		UserID: dto.UserID,
	}
}
func UpdatePinnedAchievementsToDomain(dto dto.UserProfileUpdate, userID uint) models.UserProfileUpdate {
	return models.UserProfileUpdate{
		UserID:               userID,
		PinnedAchievementIDS: dto.PinnedAchievementIDS,
	}
}
