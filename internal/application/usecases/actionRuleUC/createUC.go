package actionRuleUC

import (
	"DaraTilBackendV2/internal/domain/models"
	"DaraTilBackendV2/internal/domain/repo"
	"context"
)

type CreateUC struct {
	repo repo.ActionRuleRepo
}

func NewCreateUC(repo repo.ActionRuleRepo) *CreateUC {
	return &CreateUC{repo: repo}
}

func (uc *CreateUC) Execute(ctx context.Context, rule models.ActionRule) error {
	return uc.repo.Create(ctx, rule)
}
