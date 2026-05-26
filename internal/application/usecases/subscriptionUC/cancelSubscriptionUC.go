package subscriptionUC

import (
	errs "DaraTilBackendV2/internal/domain/domErr"
	"DaraTilBackendV2/internal/domain/repo"
	"context"
)

type CancelSubscriptionUC struct {
	repo repo.SubscriptionRepo
}

func NewCancelSubscriptionUC(repo repo.SubscriptionRepo) *CancelSubscriptionUC {
	return &CancelSubscriptionUC{repo: repo}
}

func (uc *CancelSubscriptionUC) Execute(ctx context.Context, id uint) error {
	if id == 0 {
		return errs.ErrInvalidInput
	}

	return uc.repo.Cancel(ctx, id)
}
