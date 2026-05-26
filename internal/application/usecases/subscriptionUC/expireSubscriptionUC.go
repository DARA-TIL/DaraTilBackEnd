package subscriptionUC

import (
	errs "DaraTilBackendV2/internal/domain/domErr"
	"DaraTilBackendV2/internal/domain/repo"
	"context"
)

type ExpireSubscriptionUC struct {
	repo repo.SubscriptionRepo
}

func NewExpireSubscriptionUC(repo repo.SubscriptionRepo) *ExpireSubscriptionUC {
	return &ExpireSubscriptionUC{repo: repo}
}

func (uc *ExpireSubscriptionUC) Execute(ctx context.Context, id uint) error {
	if id == 0 {
		return errs.ErrInvalidInput
	}

	return uc.repo.Expire(ctx, id)
}
