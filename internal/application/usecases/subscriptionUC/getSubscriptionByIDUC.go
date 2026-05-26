package subscriptionUC

import (
	errs "DaraTilBackendV2/internal/domain/domErr"
	"DaraTilBackendV2/internal/domain/models"
	"DaraTilBackendV2/internal/domain/repo"
	"context"
)

type GetSubscriptionByIDUC struct {
	repo repo.SubscriptionRepo
}

func NewGetSubscriptionByIDUC(repo repo.SubscriptionRepo) *GetSubscriptionByIDUC {
	return &GetSubscriptionByIDUC{repo: repo}
}

func (uc *GetSubscriptionByIDUC) Execute(ctx context.Context, id uint) (*models.Subscription, error) {
	if id == 0 {
		return nil, errs.ErrInvalidInput
	}

	return uc.repo.GetByID(ctx, id)
}
