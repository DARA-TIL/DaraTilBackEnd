package repo

import (
	"DaraTilBackendV2/internal/domain/models"
	"context"
)

type AchievementRepo interface {
	Create(ctx context.Context, achievement models.Achievement) error
	Update(ctx context.Context, achievement models.Achievement) error
	Delete(ctx context.Context, id uint) error
	GetByID(ctx context.Context, userID, id uint) (*models.Achievement, error)
	GetAll(ctx context.Context, userID uint) ([]models.Achievement, error)
	GetByAction(ctx context.Context, action models.Actions) ([]models.Achievement, error)
}
type UserAchievementRepo interface {
	Create(ctx context.Context, ua models.UserAchievement) error
	Update(ctx context.Context, ua models.UserAchievement) error
	IncrementQuantity(ctx context.Context, userID uint, action models.Actions) ([]models.UserAchievement, error)
	CreateMissingUserAchievements(ctx context.Context, userID uint, action models.Actions) error
	Delete(ctx context.Context, id uint) error
	GetByUserID(ctx context.Context, userID uint) ([]models.UserAchievement, error)
	GetByID(ctx context.Context, id uint) (*models.UserAchievement, error)
}
