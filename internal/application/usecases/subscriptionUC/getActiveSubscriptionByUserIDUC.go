package subscriptionUC

import (
	errs "DaraTilBackendV2/internal/domain/domErr"
	"DaraTilBackendV2/internal/domain/models"
	"DaraTilBackendV2/internal/domain/repo"
	"context"
)

type GetActiveSubscriptionByUserIDUC struct {
	repo repo.SubscriptionRepo
}

func NewGetActiveSubscriptionByUserIDUC(repo repo.SubscriptionRepo) *GetActiveSubscriptionByUserIDUC {
	return &GetActiveSubscriptionByUserIDUC{repo: repo}
}

func (uc *GetActiveSubscriptionByUserIDUC) Execute(
	ctx context.Context,
	userID uint,
) (*models.Subscription, error) {
	if userID == 0 {
		return nil, errs.ErrInvalidInput
	}

	return uc.repo.GetActiveByUserID(ctx, userID)
}
