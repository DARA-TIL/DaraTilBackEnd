package regionUC

import (
	"DaraTilBackendV2/internal/domain/models"
	"DaraTilBackendV2/internal/domain/repo"
	"context"
)

type CreateMultiUC struct {
	repo repo.RegionRepo
}

func NewCreateMultiUC(repo repo.RegionRepo) *CreateMultiUC {
	return &CreateMultiUC{repo: repo}
}

func (uc *CreateMultiUC) Execute(ctx context.Context, regions []models.Region) error {
	return uc.repo.CreateMulti(ctx, regions)
}
