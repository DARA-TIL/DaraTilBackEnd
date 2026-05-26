package subscriptionUC

import (
	errs "DaraTilBackendV2/internal/domain/domErr"
	"DaraTilBackendV2/internal/domain/repo"
	"context"
)

type DeleteSubscriptionPlanUC struct {
	repo repo.SubscriptionPlanRepo
}

func NewDeleteSubscriptionPlanUC(repo repo.SubscriptionPlanRepo) *DeleteSubscriptionPlanUC {
	return &DeleteSubscriptionPlanUC{repo: repo}
}

func (uc *DeleteSubscriptionPlanUC) Execute(ctx context.Context, id uint) error {
	if id == 0 {
		return errs.ErrInvalidInput
	}

	return uc.repo.Delete(ctx, id)
}
