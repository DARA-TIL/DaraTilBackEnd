package regionTraditionsUC

import (
	"DaraTilBackendV2/internal/domain/models"
	"DaraTilBackendV2/internal/domain/repo"
	"context"
)

type CreateUC struct {
	repo repo.RegionTraditionRepo
}

func NewCreateUC(repo repo.RegionTraditionRepo) *CreateUC {
	return &CreateUC{repo: repo}
}

func (uc *CreateUC) Execute(ctx context.Context, tr models.RegionTraditions) error {
	return uc.repo.Create(ctx, tr)
}
