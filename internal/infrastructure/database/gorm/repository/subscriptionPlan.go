package repository

import (
	"DaraTilBackendV2/internal/domain/models"
	"DaraTilBackendV2/internal/infrastructure/database/gorm/errhandlers"
	"DaraTilBackendV2/internal/infrastructure/database/gorm/gormModels"
	"DaraTilBackendV2/internal/infrastructure/database/gorm/gormModels/gormMappers"
	"context"

	"gorm.io/gorm"
)

type SubscriptionPlanRepository struct {
	db *gorm.DB
}

func NewSubscriptionPlanRepository(db *gorm.DB) *SubscriptionPlanRepository {
	return &SubscriptionPlanRepository{db: db}
}

func (r *SubscriptionPlanRepository) Create(
	ctx context.Context,
	subscriptionPlan models.SubscriptionPlan,
) (*models.SubscriptionPlan, error) {
	gormPlan := gormMappers.SubscriptionPlanToGormModel(subscriptionPlan)

	err := r.db.WithContext(ctx).Create(&gormPlan).Error
	if err != nil {
		return nil, errhandlers.DBErrHandler(err)
	}

	result := gormMappers.GormSubscriptionPlanToDomain(gormPlan)
	return &result, nil
}

func (r *SubscriptionPlanRepository) Update(
	ctx context.Context,
	id uint,
	subscriptionPlan models.PatchSubscriptionPlanParams,
) (*models.SubscriptionPlan, error) {
	updates := make(map[string]interface{})

	if subscriptionPlan.Name != nil {
		updates["name"] = *subscriptionPlan.Name
	}

	if subscriptionPlan.Description != nil {
		updates["description"] = *subscriptionPlan.Description
	}

	if subscriptionPlan.Price != nil {
		updates["price"] = *subscriptionPlan.Price
	}

	if subscriptionPlan.DurationDays != nil {
		updates["duration_days"] = *subscriptionPlan.DurationDays
	}

	if subscriptionPlan.IsActive != nil {
		updates["is_active"] = *subscriptionPlan.IsActive
	}

	err := r.db.WithContext(ctx).
		Model(&gormModels.SubscriptionPlan{}).
		Where("id = ?", id).
		Updates(updates).
		Error

	if err != nil {
		return nil, errhandlers.DBErrHandler(err)
	}

	var gormPlan gormModels.SubscriptionPlan
	err = r.db.WithContext(ctx).
		First(&gormPlan, id).
		Error

	if err != nil {
		return nil, errhandlers.DBErrHandler(err)
	}

	result := gormMappers.GormSubscriptionPlanToDomain(gormPlan)
	return &result, nil
}

func (r *SubscriptionPlanRepository) Delete(ctx context.Context, id uint) error {
	err := r.db.WithContext(ctx).
		Unscoped().
		Where("id = ?", id).
		Delete(&gormModels.SubscriptionPlan{}).
		Error

	if err != nil {
		return errhandlers.DBErrHandler(err)
	}

	return nil
}

func (r *SubscriptionPlanRepository) GetByID(ctx context.Context, id uint) (*models.SubscriptionPlan, error) {
	var gormPlan gormModels.SubscriptionPlan

	err := r.db.WithContext(ctx).
		First(&gormPlan, id).
		Error

	if err != nil {
		return nil, errhandlers.DBErrHandler(err)
	}

	result := gormMappers.GormSubscriptionPlanToDomain(gormPlan)
	return &result, nil
}

func (r *SubscriptionPlanRepository) List(
	ctx context.Context,
	params models.ListSubscriptionPlansParams,
) ([]models.SubscriptionPlan, error) {
	gormPlans := make([]gormModels.SubscriptionPlan, 0)

	query := r.db.WithContext(ctx).Model(&gormModels.SubscriptionPlan{})

	if params.Search != nil && *params.Search != "" {
		query = query.Where("name ILIKE ?", "%"+*params.Search+"%")
	}

	if params.DurationDays != nil {
		query = query.Where("duration_days = ?", *params.DurationDays)
	}

	if params.IsActive != nil {
		query = query.Where("is_active = ?", *params.IsActive)
	}

	err := query.
		Order("created_at DESC").
		Find(&gormPlans).
		Error

	if err != nil {
		return nil, errhandlers.DBErrHandler(err)
	}

	if len(gormPlans) == 0 {
		return []models.SubscriptionPlan{}, nil
	}

	result := gormMappers.GormSubscriptionPlansToDomain(gormPlans)
	return result, nil
}
