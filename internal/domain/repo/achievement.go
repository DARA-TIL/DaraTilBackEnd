package repo

import (
	"DaraTilBackendV2/internal/domain/models"
	"context"
)

type AchievementRepo interface {
	Create(ctx context.Context, achievement models.Achievement) error
	Update(ctx context.Context, achievement models.Achievement) error
	Delete(ctx context.Context, achievement models.Achievement) error
	Get(ctx context.Context, id uint) (*models.Achievement, error)
	GetAll(ctx context.Context) ([]models.Achievement, error)
}
type UserAchievementRepo interface {
	Create(ctx context.Context, ua models.UserAchievement) error
	Update(ctx context.Context, ua models.UserAchievement) error
	IncrementQuantity(ctx context.Context, userID, achievementID uint) error
	Delete(ctx context.Context, ua models.UserAchievement) error
	GetByUserID(ctx context.Context, userID uint) ([]models.UserAchievement, error)
	GetByUserAndAchieveID(ctx context.Context, userID uint, achievementID uint) (*models.UserAchievement, error)
}
