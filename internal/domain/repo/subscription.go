package repo

import (
	"DaraTilBackendV2/internal/domain/models"
	"context"
)

type SubscriptionRepo interface {
	Create(ctx context.Context, subscription models.Subscription) (*models.Subscription, error)
	Update(ctx context.Context, id uint, subscription models.PatchSubscriptionParams) (*models.Subscription, error)
	Delete(ctx context.Context, id uint) error
	GetActiveByUserID(ctx context.Context, userID uint) (*models.Subscription, error)
	GetByID(ctx context.Context, id uint) (*models.Subscription, error)
	Cancel(ctx context.Context, id uint) error
	Expire(ctx context.Context, id uint) error

	List(ctx context.Context, params models.ListSubscriptionsParams) ([]models.Subscription, error)
}

type SubscriptionPlanRepo interface {
	Create(ctx context.Context, subscriptionPlan models.SubscriptionPlan) (*models.SubscriptionPlan, error)
	Update(ctx context.Context, id uint, subscriptionPlan models.PatchSubscriptionPlanParams) (*models.SubscriptionPlan, error)
	Delete(ctx context.Context, id uint) error
	GetByID(ctx context.Context, id uint) (*models.SubscriptionPlan, error)
	List(ctx context.Context, params models.ListSubscriptionPlansParams) ([]models.SubscriptionPlan, error)
}
