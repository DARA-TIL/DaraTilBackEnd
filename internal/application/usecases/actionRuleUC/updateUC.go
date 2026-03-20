package actionRuleUC

import (
	"DaraTilBackendV2/internal/domain/models"
	"DaraTilBackendV2/internal/domain/repo"
	"context"
)

type UpdateUC struct {
	repo repo.ActionRuleRepo
}

func NewUpdateUC(repo repo.ActionRuleRepo) *UpdateUC {
	return &UpdateUC{repo: repo}
}

func (uc *UpdateUC) Execute(ctx context.Context, rule models.ActionRule) error {
	return uc.repo.Update(ctx, rule)
}
