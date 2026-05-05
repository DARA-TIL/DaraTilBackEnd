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
		Streak:       GormStreakToDomain(user.Streak),
		AuthProvider: user.AuthProvider,
		Progress:     GormUserProgressToDomain(user.Progress),
	}
}
func GormUsersToDomain(users []gormModels.User) []models.User {
	result := make([]models.User, len(users))
	for i, user := range users {
		result[i] = GormUserToDomain(user)
	}
	return result
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
func UsersToGormModel(users []models.User) []gormModels.User {
	var gormUsers []gormModels.User

	for _, user := range users {
		gormUsers = append(gormUsers, UserToGormModel(user))
	}

	return gormUsers
}

func GormUsersToDomainModel(users []gormModels.User) []models.User {
	var domainUsers []models.User

	for _, user := range users {
		domainUsers = append(domainUsers, GormUserToDomain(user))
	}

	return domainUsers
}
