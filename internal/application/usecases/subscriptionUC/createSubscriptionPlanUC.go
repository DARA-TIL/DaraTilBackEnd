package subscriptionUC

import (
	errs "DaraTilBackendV2/internal/domain/domErr"
	"DaraTilBackendV2/internal/domain/models"
	"DaraTilBackendV2/internal/domain/repo"
	"context"
	"strings"
)

type CreateSubscriptionPlanUC struct {
	repo repo.SubscriptionPlanRepo
}

func NewCreateSubscriptionPlanUC(repo repo.SubscriptionPlanRepo) *CreateSubscriptionPlanUC {
	return &CreateSubscriptionPlanUC{repo: repo}
}

func (uc *CreateSubscriptionPlanUC) Execute(
	ctx context.Context,
	plan models.SubscriptionPlan,
) (*models.SubscriptionPlan, error) {
	plan.Name = strings.TrimSpace(plan.Name)

	if plan.Name == "" || plan.Price < 0 || plan.DurationDays <= 0 {
		return nil, errs.ErrInvalidInput
	}

	plan.IsActive = true

	return uc.repo.Create(ctx, plan)
}
