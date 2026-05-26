package subscriptionUC

import (
	errs "DaraTilBackendV2/internal/domain/domErr"
	"DaraTilBackendV2/internal/domain/models"
	"DaraTilBackendV2/internal/domain/repo"
	"context"
)

type GetSubscriptionPlanByIDUC struct {
	repo repo.SubscriptionPlanRepo
}

func NewGetSubscriptionPlanByIDUC(repo repo.SubscriptionPlanRepo) *GetSubscriptionPlanByIDUC {
	return &GetSubscriptionPlanByIDUC{repo: repo}
}

func (uc *GetSubscriptionPlanByIDUC) Execute(ctx context.Context, id uint) (*models.SubscriptionPlan, error) {
	if id == 0 {
		return nil, errs.ErrInvalidInput
	}

	return uc.repo.GetByID(ctx, id)
}
