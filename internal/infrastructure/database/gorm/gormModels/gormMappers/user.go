package gormMappers

import (
	"DaraTilBackendV2/internal/domain/models"
	"DaraTilBackendV2/internal/infrastructure/database/gorm/gormModels"
)

func UserToGormModel(user models.User) gormModels.User {
	return gormModels.User{
		Username:     user.Username,
		Email:        user.Email,
		Password:     user.Password,
		Avatar:       user.Avatar,
		Role:         user.Role,
		AuthProvider: user.AuthProvider,
	}
}

func GormUserToDomain(user gormModels.User) models.User {
	return models.User{
		ID:           user.ID,
		Username:     user.Username,
		Email:        user.Email,
		Password:     user.Password,
		Avatar:       user.Avatar,
		Role:         user.Role,
		AuthProvider: user.AuthProvider,
		Progress:     GormUserProgressToDomain(user.Progress),
	}
}

func GormUserProgressToDomain(userP gormModels.UserProgress) models.UserProgress {
	return models.UserProgress{
		ID:             userP.ID,
		UserID:         userP.UserID,
		Level:          userP.Level,
		XpTotal:        userP.XpTotal,
		XpForNextLevel: userP.XpForNextLevel,
	}
}
