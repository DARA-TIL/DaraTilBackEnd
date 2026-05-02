package repo

import (
	"DaraTilBackendV2/internal/domain/models"
	"context"
)

type LeaderboardRepo interface {
	GetByXP(ctx context.Context, limit int) ([]models.User, error)
	GetByStreak(ctx context.Context, limit int) ([]models.User, error)
	GetByWords(ctx context.Context, limit int) ([]models.UserProfile, error)
}
