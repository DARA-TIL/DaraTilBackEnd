package regionTraditionsUC

import (
	"DaraTilBackendV2/internal/domain/models"
	"DaraTilBackendV2/internal/domain/repo"
	"context"
)

type GetByIDUC struct {
	repo repo.RegionTraditionRepo
}

func NewGetByIDUC(repo repo.RegionTraditionRepo) *GetByIDUC {
	return &GetByIDUC{repo: repo}
}
func (uc *GetByIDUC) Execute(ctx context.Context, id uint) (*models.RegionTraditions, error) {
	return uc.repo.GetByID(ctx, id)
}
