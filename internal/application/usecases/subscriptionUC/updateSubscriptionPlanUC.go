package subscriptionUC

import (
	errs "DaraTilBackendV2/internal/domain/domErr"
	"DaraTilBackendV2/internal/domain/models"
	"DaraTilBackendV2/internal/domain/repo"
	"context"
	"strings"
)

type UpdateSubscriptionPlanUC struct {
	repo repo.SubscriptionPlanRepo
}

func NewUpdateSubscriptionPlanUC(repo repo.SubscriptionPlanRepo) *UpdateSubscriptionPlanUC {
	return &UpdateSubscriptionPlanUC{repo: repo}
}

func (uc *UpdateSubscriptionPlanUC) Execute(
	ctx context.Context,
	id uint,
	params models.PatchSubscriptionPlanParams,
) (*models.SubscriptionPlan, error) {
	if id == 0 {
		return nil, errs.ErrInvalidInput
	}

	if params.Name != nil {
		name := strings.TrimSpace(*params.Name)
		if name == "" {
			return nil, errs.ErrInvalidInput
		}

		params.Name = &name
	}

	if params.Price != nil && *params.Price < 0 {
		return nil, errs.ErrInvalidInput
	}

	if params.DurationDays != nil && *params.DurationDays <= 0 {
		return nil, errs.ErrInvalidInput
	}

	return uc.repo.Update(ctx, id, params)
}
