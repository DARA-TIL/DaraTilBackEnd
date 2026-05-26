package subscriptionUC

import (
	errs "DaraTilBackendV2/internal/domain/domErr"
	"DaraTilBackendV2/internal/domain/models"
	"DaraTilBackendV2/internal/domain/repo"
	"context"
	"time"
)

type UpdateSubscriptionUC struct {
	subscriptionRepo repo.SubscriptionRepo
	planRepo         repo.SubscriptionPlanRepo
}

func NewUpdateSubscriptionUC(
	subscriptionRepo repo.SubscriptionRepo,
	planRepo repo.SubscriptionPlanRepo,
) *UpdateSubscriptionUC {
	return &UpdateSubscriptionUC{
		subscriptionRepo: subscriptionRepo,
		planRepo:         planRepo,
	}
}

func (uc *UpdateSubscriptionUC) Execute(
	ctx context.Context,
	id uint,
	params models.PatchSubscriptionParams,
) (*models.Subscription, error) {
	if id == 0 {
		return nil, errs.ErrInvalidInput
	}

	if params.PlanID != nil {
		if *params.PlanID == 0 {
			return nil, errs.ErrInvalidInput
		}

		plan, err := uc.planRepo.GetByID(ctx, *params.PlanID)
		if err != nil {
			return nil, err
		}

		if !plan.IsActive {
			return nil, errs.ErrInvalidInput
		}
	}

	if params.ActiveUntil != nil && !params.ActiveUntil.After(time.Now()) {
		return nil, errs.ErrInvalidInput
	}

	if params.Status != nil {
		switch *params.Status {
		case models.SubscriptionStatusActive,
			models.SubscriptionStatusExpired,
			models.SubscriptionStatusCancelled:
		default:
			return nil, errs.ErrInvalidInput
		}
	}

	return uc.subscriptionRepo.Update(ctx, id, params)
}
