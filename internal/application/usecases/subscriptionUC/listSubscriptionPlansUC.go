package subscriptionUC

import (
	"DaraTilBackendV2/internal/domain/models"
	"DaraTilBackendV2/internal/domain/repo"
	"context"
	"strings"
)

type ListSubscriptionPlansUC struct {
	repo repo.SubscriptionPlanRepo
}

func NewListSubscriptionPlansUC(repo repo.SubscriptionPlanRepo) *ListSubscriptionPlansUC {
	return &ListSubscriptionPlansUC{repo: repo}
}

func (uc *ListSubscriptionPlansUC) Execute(
	ctx context.Context,
	params models.ListSubscriptionPlansParams,
) ([]models.SubscriptionPlan, error) {
	if params.Search != nil {
		search := strings.TrimSpace(*params.Search)
		if search == "" {
			params.Search = nil
		} else {
			params.Search = &search
		}
	}

	return uc.repo.List(ctx, params)
}
