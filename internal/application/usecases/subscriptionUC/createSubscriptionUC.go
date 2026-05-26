package subscriptionUC

import (
	errs "DaraTilBackendV2/internal/domain/domErr"
	"DaraTilBackendV2/internal/domain/models"
	"DaraTilBackendV2/internal/domain/repo"
	"context"
	"time"
)

type CreateSubscriptionUC struct {
	subscriptionRepo repo.SubscriptionRepo
	planRepo         repo.SubscriptionPlanRepo
}

func NewCreateSubscriptionUC(
	subscriptionRepo repo.SubscriptionRepo,
	planRepo repo.SubscriptionPlanRepo,
) *CreateSubscriptionUC {
	return &CreateSubscriptionUC{
		subscriptionRepo: subscriptionRepo,
		planRepo:         planRepo,
	}
}

func (uc *CreateSubscriptionUC) Execute(
	ctx context.Context,
	subscription models.Subscription,
) (*models.Subscription, error) {
	if subscription.UserID == 0 || subscription.PlanID == 0 {
		return nil, errs.ErrInvalidInput
	}

	plan, err := uc.planRepo.GetByID(ctx, subscription.PlanID)
	if err != nil {
		return nil, err
	}

	if !plan.IsActive {
		return nil, errs.ErrInvalidInput
	}

	now := time.Now()

	subscription.Status = models.SubscriptionStatusActive

	if subscription.ActiveUntil.IsZero() {
		subscription.ActiveUntil = now.AddDate(0, 0, plan.DurationDays)
	}

	if !subscription.ActiveUntil.After(now) {
		return nil, errs.ErrInvalidInput
	}

	return uc.subscriptionRepo.Create(ctx, subscription)
}
