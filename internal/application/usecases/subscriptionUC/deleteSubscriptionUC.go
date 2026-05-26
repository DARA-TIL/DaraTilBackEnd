package subscriptionUC

import (
	errs "DaraTilBackendV2/internal/domain/domErr"
	"DaraTilBackendV2/internal/domain/repo"
	"context"
)

type DeleteSubscriptionUC struct {
	repo repo.SubscriptionRepo
}

func NewDeleteSubscriptionUC(repo repo.SubscriptionRepo) *DeleteSubscriptionUC {
	return &DeleteSubscriptionUC{repo: repo}
}

func (uc *DeleteSubscriptionUC) Execute(ctx context.Context, id uint) error {
	if id == 0 {
		return errs.ErrInvalidInput
	}

	return uc.repo.Delete(ctx, id)
}
