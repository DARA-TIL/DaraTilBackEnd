package repository

import (
	"DaraTilBackendV2/internal/domain/models"
	"DaraTilBackendV2/internal/infrastructure/database/gorm/errhandlers"
	"DaraTilBackendV2/internal/infrastructure/database/gorm/gormModels"
	"DaraTilBackendV2/internal/infrastructure/database/gorm/gormModels/gormMappers"
	"context"

	"gorm.io/gorm"
)

type UserActivityRepository struct {
	db *gorm.DB
}

func NewUserActivityRepository(db *gorm.DB) *UserActivityRepository {
	return &UserActivityRepository{db: db}
}

func (u *UserActivityRepository) Log(ctx context.Context, activity models.UserActivity) error {
	gormActivity := gormMappers.UserActivityToGorm(activity)
	if err := u.db.WithContext(ctx).Create(&gormActivity).Error; err != nil {
		return errhandlers.DBErrHandler(err)
	}
	return nil
}

func (u *UserActivityRepository) Get(ctx context.Context, id uint) ([]models.UserActivity, error) {
	var gormActivities []gormModels.UserActivity
	if err := u.db.WithContext(ctx).Where("user_id = ?", id).Order("created_at DESC").Find(&gormActivities).Error; err != nil {
		return nil, errhandlers.DBErrHandler(err)
	}
	return gormMappers.GormUserActivitiesToDomain(gormActivities), nil
}
