package repo

import (
	"DaraTilBackendV2/internal/domain/models"
	"context"
)

type UserProfileRepo interface {
	Create(ctx context.Context, up models.CreateUserProfile) error
	UpdatePinnedAchievements(ctx context.Context, up models.UserProfileUpdate) error
	IncreaseWordsLearned(ctx context.Context, userID uint) error
	IncreaseLessonsCompleted(ctx context.Context, userID uint) error
	GetByUserID(ctx context.Context, uid uint) (*models.UserProfile, error)
}
