package repo

import (
	"DaraTilBackendV2/internal/domain/models"
	"context"
)

type UserActivityRepo interface {
	Log(ctx context.Context, activity models.UserActivity) error
	Get(ctx context.Context, id uint) ([]models.UserActivity, error)
}
