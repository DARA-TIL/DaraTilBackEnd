package actionRuleUC

import (
	"DaraTilBackendV2/internal/domain/models"
	"DaraTilBackendV2/internal/domain/repo"
	"context"
)

type CreateMultiUC struct {
	repo repo.ActionRuleRepo
}

func NewCreateMultiUC(repo repo.ActionRuleRepo) *CreateMultiUC {
	return &CreateMultiUC{repo: repo}
}

func (uc *CreateMultiUC) Execute(ctx context.Context, rules []models.ActionRule) error {
	return uc.repo.CreateMulti(ctx, rules)
}
