package regionUC

import (
	"DaraTilBackendV2/internal/domain/models"
	"DaraTilBackendV2/internal/domain/repo"
	"context"
)

type CreateUC struct {
	repo repo.RegionRepo
}

func NewCreateUC(repo repo.RegionRepo) *CreateUC {
	return &CreateUC{repo: repo}
}

func (uc *CreateUC) Execute(ctx context.Context, region models.Region) error {
	return uc.repo.Create(ctx, region)
}
