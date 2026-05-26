package repo

import (
	"DaraTilBackendV2/internal/domain/models"
	"context"
	"time"
)

type DailyActionUsageRepo interface {
	GetByUserActionDate(
		ctx context.Context,
		userID uint,
		action string,
		date time.Time,
	) (*models.DailyActionUsage, error)

	Increment(
		ctx context.Context,
		userID uint,
		action string,
		date time.Time,
	) error
}
