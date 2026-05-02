package dtoMappers

import (
	"DaraTilBackendV2/internal/domain/models"
	"DaraTilBackendV2/internal/presentation/dto"
)

func DtoUserProgressToDomain(progress dto.UserProgress) models.UserProgress {
	return models.UserProgress{
		ID:             progress.ID,
		UserID:         progress.UserID,
		Level:          progress.Level,
		XpTotal:        progress.XpTotal,
		XpForNextLevel: progress.XpForNextLevel,
	}
}
func UserProgressToDto(progress models.UserProgress) dto.UserProgress {
	return dto.UserProgress{
		ID:             progress.ID,
		UserID:         progress.UserID,
		Level:          progress.Level,
		XpTotal:        progress.XpTotal,
		XpForNextLevel: progress.XpForNextLevel,
	}
}
func DtoUserToDomain(user dto.User) models.User {
	return models.User{
		ID:           user.ID,
		Username:     user.Username,
		Email:        user.Email,
		Password:     user.Password,
		Avatar:       user.Avatar,
		Role:         user.Role,
		AuthProvider: user.AuthProvider,
		Progress:     DtoUserProgressToDomain(user.Progress),
	}
}
func UserToDto(user models.User) dto.User {
	return dto.User{
		ID:           user.ID,
		Username:     user.Username,
		Email:        user.Email,
		Avatar:       user.Avatar,
		Role:         user.Role,
		AuthProvider: user.AuthProvider,
		Progress:     UserProgressToDto(user.Progress),
		Streak:       StreakToDTO(user.Streak),
	}
}

func UsersToDto(users []models.User) []dto.User {
	dtos := make([]dto.User, len(users))
	for i, user := range users {
		dtos[i] = UserToDto(user)
	}
	return dtos
}

func StreakToDTO(streak models.Streak) dto.Streak {
	return dto.Streak{
		ID:            streak.ID,
		UserID:        streak.UserID,
		CurrentStreak: streak.CurrentStreak,
		LongestStreak: streak.LongestStreak,
	}
}
