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
	}
}
