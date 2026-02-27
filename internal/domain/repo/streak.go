package repo

import (
	"DaraTilBackendV2/internal/domain/models"
	"context"
)

type StreakRepo interface {
	Create(ctx context.Context, streak models.Streak) error
	Increment(ctx context.Context, userID uint) error
	GetByUserID(ctx context.Context, userID uint) (*models.Streak, error)
	Reset(ctx context.Context, userID uint) error
	Start(ctx context.Context, userID uint) error
}
