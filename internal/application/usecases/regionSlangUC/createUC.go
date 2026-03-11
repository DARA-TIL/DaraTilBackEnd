package regionUC

import (
	"DaraTilBackendV2/internal/domain/models"
	"DaraTilBackendV2/internal/domain/repo"
	"context"
)

type CreateUC struct {
	repo repo.RegionSlangRepo
}

func NewCreateUC(repo repo.RegionSlangRepo) *CreateUC {
	return &CreateUC{repo: repo}
}

func (uc *CreateUC) Execute(ctx context.Context, sl models.RegionSlang) error {
	return uc.repo.Create(ctx, sl)
}
