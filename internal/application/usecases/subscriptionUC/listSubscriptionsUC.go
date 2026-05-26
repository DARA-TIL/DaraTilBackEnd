package subscriptionUC

import (
	"DaraTilBackendV2/internal/domain/models"
	"DaraTilBackendV2/internal/domain/repo"
	"context"
)

type ListSubscriptionsUC struct {
	repo repo.SubscriptionRepo
}

func NewListSubscriptionsUC(repo repo.SubscriptionRepo) *ListSubscriptionsUC {
	return &ListSubscriptionsUC{repo: repo}
}

func (uc *ListSubscriptionsUC) Execute(
	ctx context.Context,
	params models.ListSubscriptionsParams,
) ([]models.Subscription, error) {
	if params.Limit <= 0 {
		params.Limit = 20
	}

	if params.Limit > 100 {
		params.Limit = 100
	}

	if params.Offset < 0 {
		params.Offset = 0
	}

	return uc.repo.List(ctx, params)
}
