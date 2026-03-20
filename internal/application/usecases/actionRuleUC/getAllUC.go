package actionRuleUC

import (
	"DaraTilBackendV2/internal/domain/models"
	"DaraTilBackendV2/internal/domain/repo"
	"context"
)

type GetAllUC struct {
	repo repo.ActionRuleRepo
}

func NewGetAllUC(repo repo.ActionRuleRepo) *GetAllUC {
	return &GetAllUC{repo: repo}
}

func (uc *GetAllUC) Execute(ctx context.Context) ([]models.ActionRule, error) {
	return uc.repo.GetAll(ctx)
}
