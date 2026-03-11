package regionUC

import (
	"DaraTilBackendV2/internal/domain/models"
	"DaraTilBackendV2/internal/domain/repo"
	"context"
)

type GetAllUC struct {
	repo repo.RegionRepo
}

func NewGetAllUC(repo repo.RegionRepo) *GetAllUC {
	return &GetAllUC{repo: repo}
}

func (uc *GetAllUC) Execute(ctx context.Context) ([]models.Region, error) {
	return uc.repo.GetAll(ctx)
}
