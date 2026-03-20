package actionRuleUC

import (
	"DaraTilBackendV2/internal/domain/models"
	"DaraTilBackendV2/internal/domain/repo"
	"context"
)

type GetActionRuleByActionUC struct {
	repo repo.ActionRuleRepo
}

func NewGetByActionUC(repo repo.ActionRuleRepo) *GetActionRuleByActionUC {
	return &GetActionRuleByActionUC{repo: repo}
}

func (uc *GetActionRuleByActionUC) Execute(ctx context.Context, action models.Actions) (models.ActionRule, error) {
	return uc.repo.GetByAction(ctx, action)
}
