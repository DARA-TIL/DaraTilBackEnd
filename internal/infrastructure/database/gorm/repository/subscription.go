package repository

import (
	"DaraTilBackendV2/internal/domain/models"
	"DaraTilBackendV2/internal/infrastructure/database/gorm/errhandlers"
	"DaraTilBackendV2/internal/infrastructure/database/gorm/gormModels"
	"DaraTilBackendV2/internal/infrastructure/database/gorm/gormModels/gormMappers"
	"context"
	"time"

	"gorm.io/gorm"
)

type SubscriptionRepository struct {
	db *gorm.DB
}

func NewSubscriptionRepository(db *gorm.DB) *SubscriptionRepository {
	return &SubscriptionRepository{db: db}
}

func (r *SubscriptionRepository) Create(ctx context.Context, subscription models.Subscription) (*models.Subscription, error) {
	gormSubscription := gormMappers.SubscriptionToGormModel(subscription)

	err := r.db.WithContext(ctx).Create(&gormSubscription).Error
	if err != nil {
		return nil, errhandlers.DBErrHandler(err)
	}

	err = r.db.WithContext(ctx).
		Preload("Plan").
		First(&gormSubscription, gormSubscription.ID).
		Error
	if err != nil {
		return nil, errhandlers.DBErrHandler(err)
	}

	result := gormMappers.GormSubscriptionToDomain(gormSubscription)
	return &result, nil
}

func (r *SubscriptionRepository) Update(
	ctx context.Context,
	id uint,
	subscription models.PatchSubscriptionParams,
) (*models.Subscription, error) {
	updates := make(map[string]interface{})

	if subscription.Status != nil {
		updates["status"] = *subscription.Status
	}

	if subscription.PlanID != nil {
		updates["plan_id"] = *subscription.PlanID
	}

	if subscription.ActiveUntil != nil {
		updates["active_until"] = *subscription.ActiveUntil
	}

	if subscription.CancelledAt != nil {
		updates["cancelled_at"] = *subscription.CancelledAt
	}

	err := r.db.WithContext(ctx).
		Model(&gormModels.Subscription{}).
		Where("id = ?", id).
		Updates(updates).
		Error
	if err != nil {
		return nil, errhandlers.DBErrHandler(err)
	}

	var gormSubscription gormModels.Subscription
	err = r.db.WithContext(ctx).
		Preload("Plan").
		First(&gormSubscription, id).
		Error
	if err != nil {
		return nil, errhandlers.DBErrHandler(err)
	}

	result := gormMappers.GormSubscriptionToDomain(gormSubscription)
	return &result, nil
}

func (r *SubscriptionRepository) Delete(ctx context.Context, id uint) error {
	err := r.db.WithContext(ctx).
		Unscoped().
		Where("id = ?", id).
		Delete(&gormModels.Subscription{}).
		Error

	if err != nil {
		return errhandlers.DBErrHandler(err)
	}

	return nil
}

func (r *SubscriptionRepository) GetActiveByUserID(ctx context.Context, userID uint) (*models.Subscription, error) {
	var gormSubscription gormModels.Subscription

	err := r.db.WithContext(ctx).
		Preload("Plan").
		Where("user_id = ?", userID).
		Where("status = ?", models.SubscriptionStatusActive).
		Where("active_until > ?", time.Now()).
		First(&gormSubscription).
		Error

	if err != nil {
		return nil, errhandlers.DBErrHandler(err)
	}

	result := gormMappers.GormSubscriptionToDomain(gormSubscription)
	return &result, nil
}

func (r *SubscriptionRepository) GetByID(ctx context.Context, id uint) (*models.Subscription, error) {
	var gormSubscription gormModels.Subscription

	err := r.db.WithContext(ctx).
		Preload("Plan").
		First(&gormSubscription, id).
		Error

	if err != nil {
		return nil, errhandlers.DBErrHandler(err)
	}

	result := gormMappers.GormSubscriptionToDomain(gormSubscription)
	return &result, nil
}

func (r *SubscriptionRepository) Cancel(ctx context.Context, id uint) error {
	now := time.Now()

	err := r.db.WithContext(ctx).
		Model(&gormModels.Subscription{}).
		Where("id = ?", id).
		Updates(map[string]interface{}{
			"status":       models.SubscriptionStatusCancelled,
			"cancelled_at": now,
		}).
		Error

	if err != nil {
		return errhandlers.DBErrHandler(err)
	}

	return nil
}

func (r *SubscriptionRepository) Expire(ctx context.Context, id uint) error {
	err := r.db.WithContext(ctx).
		Model(&gormModels.Subscription{}).
		Where("id = ?", id).
		Update("status", models.SubscriptionStatusExpired).
		Error

	if err != nil {
		return errhandlers.DBErrHandler(err)
	}

	return nil
}

func (r *SubscriptionRepository) List(
	ctx context.Context,
	params models.ListSubscriptionsParams,
) ([]models.Subscription, error) {
	gormSubscriptions := make([]gormModels.Subscription, 0)

	query := r.db.WithContext(ctx).
		Model(&gormModels.Subscription{}).
		Preload("Plan")

	if params.UserID != nil {
		query = query.Where("user_id = ?", *params.UserID)
	}

	if params.PlanID != nil {
		query = query.Where("plan_id = ?", *params.PlanID)
	}

	if params.Status != nil {
		query = query.Where("status = ?", *params.Status)
	}

	if params.Limit > 0 {
		query = query.Limit(params.Limit)
	}

	if params.Offset > 0 {
		query = query.Offset(params.Offset)
	}

	err := query.
		Order("created_at DESC").
		Find(&gormSubscriptions).
		Error

	if err != nil {
		return nil, errhandlers.DBErrHandler(err)
	}

	if len(gormSubscriptions) == 0 {
		return []models.Subscription{}, nil
	}

	result := gormMappers.GormSubscriptionsToDomain(gormSubscriptions)
	return result, nil
}
