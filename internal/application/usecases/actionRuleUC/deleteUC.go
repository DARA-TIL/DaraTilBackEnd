package actionRuleUC

import (
	"DaraTilBackendV2/internal/domain/models"
	"DaraTilBackendV2/internal/domain/repo"
	"context"
)

type DeleteUC struct {
	repo repo.ActionRuleRepo
}

func NewDeleteUC(repo repo.ActionRuleRepo) *DeleteUC {
	return &DeleteUC{repo: repo}
}

func (uc *DeleteUC) Execute(ctx context.Context, action models.Actions) error {
	return uc.repo.Delete(ctx, action)
}
