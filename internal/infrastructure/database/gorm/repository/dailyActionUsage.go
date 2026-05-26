package repository

import (
	"DaraTilBackendV2/internal/domain/models"
	"DaraTilBackendV2/internal/infrastructure/database/gorm/errhandlers"
	"DaraTilBackendV2/internal/infrastructure/database/gorm/gormModels"
	"DaraTilBackendV2/internal/infrastructure/database/gorm/gormModels/gormMappers"
	"context"
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

type DailyActionUsageRepository struct {
	db *gorm.DB
}

func NewDailyActionUsageRepository(db *gorm.DB) *DailyActionUsageRepository {
	return &DailyActionUsageRepository{db: db}
}

func (r *DailyActionUsageRepository) GetByUserActionDate(
	ctx context.Context,
	userID uint,
	action string,
	date time.Time,
) (*models.DailyActionUsage, error) {
	var gormUsage gormModels.DailyActionUsage

	usageDate := normalizeDate(date)

	err := r.db.WithContext(ctx).
		Where("user_id = ?", userID).
		Where("action = ?", action).
		Where("usage_date = ?", usageDate).
		First(&gormUsage).
		Error

	if err != nil {
		return nil, errhandlers.DBErrHandler(err)
	}

	usage := gormMappers.GormDailyActionUsageToDomain(gormUsage)
	return &usage, nil
}

func (r *DailyActionUsageRepository) Increment(
	ctx context.Context,
	userID uint,
	action string,
	date time.Time,
) error {
	usageDate := normalizeDate(date)

	gormUsage := gormModels.DailyActionUsage{
		UserID:    userID,
		Action:    action,
		UsageDate: usageDate,
		Count:     1,
	}

	err := r.db.WithContext(ctx).
		Clauses(clause.OnConflict{
			Columns: []clause.Column{
				{Name: "user_id"},
				{Name: "action"},
				{Name: "usage_date"},
			},
			DoUpdates: clause.Assignments(map[string]interface{}{
				"count":      gorm.Expr("daily_action_usages.count + 1"),
				"updated_at": time.Now(),
			}),
		}).
		Create(&gormUsage).
		Error

	if err != nil {
		return errhandlers.DBErrHandler(err)
	}

	err = r.db.WithContext(ctx).
		Where("user_id = ?", userID).
		Where("action = ?", action).
		Where("usage_date = ?", usageDate).
		First(&gormUsage).
		Error

	if err != nil {
		return errhandlers.DBErrHandler(err)
	}

	return nil
}

func normalizeDate(date time.Time) time.Time {
	return time.Date(
		date.Year(),
		date.Month(),
		date.Day(),
		0,
		0,
		0,
		0,
		date.Location(),
	)
}
